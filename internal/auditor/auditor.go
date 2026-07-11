package auditor

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azemoning/corso/internal/alerts"
	"github.com/azemoning/corso/internal/allowlist"
	"github.com/azemoning/corso/internal/enforcer"
	"github.com/azemoning/corso/internal/metrics"
	corsoebpf "github.com/azemoning/corso/pkg/ebpf"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const alertThrottleWindow = 5 * time.Minute

// Auditor is the core audit engine
type Auditor struct {
	mu           sync.RWMutex
	clientset    kubernetes.Interface
	pidResolver  *PIDResolver
	allowlist    *allowlist.Allowlist
	nodeName     string
	namespace    string
	pollInterval time.Duration

	// State
	knownPrograms map[uint32]*ProgramState
	alertEmitter  *AlertEmitter
	webhookAlert  *alerts.WebhookAlert
	lastAlertTime map[uint32]time.Time
	syscallMon    *SyscallMonitor
	enforcer      *enforcer.Enforcer

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// ProgramState tracks the state of a detected program
type ProgramState struct {
	Program   *corsoebpf.LoadedProgram
	PodInfo   *PodInfo
	Context   *ProcessInfo
	PID       int32
	IsAllowed bool
	FirstSeen time.Time
	LastSeen  time.Time
	Alerted   bool
}

// NewAuditor creates a new auditor instance
func NewAuditor(
	clientset kubernetes.Interface,
	resolver *PIDResolver,
	al *allowlist.Allowlist,
	nodeName, namespace string,
	pollInterval time.Duration,
	enforcementMode string,
) *Auditor {
	ctx, cancel := context.WithCancel(context.Background())
	aud := &Auditor{
		clientset:     clientset,
		pidResolver:   resolver,
		allowlist:     al,
		nodeName:      nodeName,
		namespace:     namespace,
		pollInterval:  pollInterval,
		knownPrograms: make(map[uint32]*ProgramState),
		alertEmitter:  NewAlertEmitter(clientset, namespace, nodeName),
		webhookAlert:  alerts.NewWebhookAlert(),
		lastAlertTime: make(map[uint32]time.Time),
		syscallMon:    NewSyscallMonitor(resolver, 256),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Create enforcer if mode is not "alert"
	if enforcementMode != "alert" {
		aud.enforcer = enforcer.NewEnforcer(al, enforcementMode)
	}

	return aud
}

// Run starts the audit loop
func (a *Auditor) Run() {
	klog.Infof("Corso auditor starting on node %s, poll interval %v", a.nodeName, a.pollInterval)

	// Start the BPF LSM enforcer if configured
	if a.enforcer != nil {
		if err := a.enforcer.Start(); err != nil {
			klog.Warningf("Failed to start BPF LSM enforcer (non-fatal, still monitoring): %v", err)
		}
	}

	// Start the real-time syscall monitor
	if err := a.syscallMon.Start(); err != nil {
		klog.Warningf("Failed to start syscall monitor (non-fatal, polling still works): %v", err)
	} else {
		go a.processSyscallEvents()
	}

	// Initial scan
	a.scanAndAudit()

	ticker := time.NewTicker(a.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.scanAndAudit()
		case <-a.ctx.Done():
			klog.Info("Corso auditor shutting down")
			a.syscallMon.Stop()
			if a.enforcer != nil {
				a.enforcer.Stop()
			}
			return
		}
	}
}

// scanAndAudit performs a full enumeration and audit
func (a *Auditor) scanAndAudit() {
	start := time.Now()
	klog.V(3).Info("Running eBPF program scan")

	// Enumerate all loaded eBPF programs using cilium/ebpf API
	programs, err := corsoebpf.EnumeratePrograms()
	if err != nil {
		klog.Errorf("Failed to enumerate eBPF programs: %v", err)
		return
	}

	elapsed := time.Since(start)
	metrics.ScanDurationSeconds.Observe(elapsed.Seconds())
	klog.V(3).Infof("Scan completed in %v, found %d programs", elapsed, len(programs))

	a.mu.Lock()
	defer a.mu.Unlock()

	// Track which programs are still alive
	aliveIDs := make(map[uint32]bool)

	for i := range programs {
		prog := &programs[i]
		aliveIDs[prog.ID] = true

		state, exists := a.knownPrograms[prog.ID]
		if !exists {
			// New program detected!
			state = &ProgramState{
				Program:   prog,
				FirstSeen: time.Now(),
			}
			a.knownPrograms[prog.ID] = state

			// Find PID and collect context
			if pid := findPIDForProgram(prog.ID); pid > 0 {
				state.PID = pid
				ctx := CollectProcessInfo(pid)
				state.Context = &ctx
			}

			// Check allowlist
			checkProg := &allowlist.ProgramToCheck{
				ID:   prog.ID,
				Name: prog.Name,
				Type: prog.Type,
			}

			state.IsAllowed = a.allowlist.IsAllowed(checkProg)

			if !state.IsAllowed {
				if a.shouldAlert(prog.ID) {
					klog.Warningf("UNAUTHORIZED eBPF program detected: id=%d name=%s type=%s",
						prog.ID, prog.Name, prog.Type)

					a.alertEmitter.EmitViolation(state)
					a.emitWebhookAlert(state)
					a.lastAlertTime[prog.ID] = time.Now()
					metrics.ViolationsTotal.WithLabelValues(a.nodeName).Inc()
				}
			} else {
				klog.V(3).Infof("eBPF program allowed: id=%d name=%s type=%s",
					prog.ID, prog.Name, prog.Type)
			}
		}

		state.LastSeen = time.Now()
	}

	// Detect programs that have been unloaded
	for id, state := range a.knownPrograms {
		if !aliveIDs[id] {
			klog.V(2).Infof("eBPF program unloaded: id=%d name=%s", id, state.Program.Name)
			delete(a.knownPrograms, id)
			delete(a.lastAlertTime, id)
		}
	}

	// Update programs_total gauge
	programsByType := make(map[string]struct{ allowed, denied int })
	for _, state := range a.knownPrograms {
		key := state.Program.Type
		entry := programsByType[key]
		if state.IsAllowed {
			entry.allowed++
		} else {
			entry.denied++
		}
		programsByType[key] = entry
	}
	metrics.ProgramsTotal.Reset()
	for progType, counts := range programsByType {
		metrics.ProgramsTotal.WithLabelValues(a.nodeName, progType, "true").Set(float64(counts.allowed))
		metrics.ProgramsTotal.WithLabelValues(a.nodeName, progType, "false").Set(float64(counts.denied))
	}
}

// processSyscallEvents handles real-time events from the eBPF ring buffer
func (a *Auditor) processSyscallEvents() {
	for evt := range a.syscallMon.Events() {
		klog.V(2).Infof("Real-time eBPF program load: pid=%d prog_id=%d prog_type=%d comm=%s",
			evt.PID, evt.ProgID, evt.ProgType, evt.Comm)

		// Collect context from the loading process
		ctx := CollectProcessInfo(int32(evt.PID))
		klog.V(3).Infof("Process context: %s", FormatContextString(&ctx))

		// Check allowlist for real-time detection
		checkProg := &allowlist.ProgramToCheck{
			ID:   evt.ProgID,
			Name: evt.Comm,
			Type: fmt.Sprintf("%d", evt.ProgType),
		}

		if !a.allowlist.IsAllowed(checkProg) {
			klog.Warningf("UNAUTHORIZED eBPF program loaded in real-time: pid=%d prog_id=%d comm=%s %s",
				evt.PID, evt.ProgID, evt.Comm, FormatContextString(&ctx))
			metrics.ViolationsTotal.WithLabelValues(a.nodeName).Inc()
		}
	}
}

// shouldAlert returns true if enough time has passed since the last alert for this program
func (a *Auditor) shouldAlert(progID uint32) bool {
	last, ok := a.lastAlertTime[progID]
	if !ok {
		return true
	}
	return time.Since(last) >= alertThrottleWindow
}

// emitWebhookAlert sends a violation alert to the configured webhook
func (a *Auditor) emitWebhookAlert(state *ProgramState) {
	ownerPod := ""
	ownerNS := ""
	if state.PodInfo != nil {
		ownerPod = state.PodInfo.PodName
		ownerNS = state.PodInfo.PodNamespace
	}

	payload := &alerts.AlertPayload{
		Node:           a.nodeName,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ProgramID:      state.Program.ID,
		ProgramName:    state.Program.Name,
		ProgramType:    state.Program.Type,
		OwnerPod:       ownerPod,
		OwnerNamespace: ownerNS,
		Severity:       "high",
		Context:        FormatContextString(state.Context),
	}
	a.webhookAlert.SendAlert(payload)
}

// Stop stops the auditor
func (a *Auditor) Stop() {
	a.cancel()
	if a.enforcer != nil {
		a.enforcer.Stop()
	}
}

// GetState returns current audit state for CLI/dashboard
func (a *Auditor) GetState() map[uint32]*ProgramState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make(map[uint32]*ProgramState, len(a.knownPrograms))
	for k, v := range a.knownPrograms {
		copy := *v
		result[k] = &copy
	}
	return result
}

// GetViolationCount returns the number of violations detected
func (a *Auditor) GetViolationCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	count := 0
	for _, state := range a.knownPrograms {
		if !state.IsAllowed {
			count++
		}
	}
	return count
}

// GetProgramCount returns the number of tracked programs
func (a *Auditor) GetProgramCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.knownPrograms)
}

// GetSummary returns a human-readable summary
func (a *Auditor) GetSummary() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	allowed := 0
	violations := 0
	for _, state := range a.knownPrograms {
		if state.IsAllowed {
			allowed++
		} else {
			violations++
		}
	}

	return fmt.Sprintf("Programs: %d total, %d allowed, %d violations",
		len(a.knownPrograms), allowed, violations)
}

// findPIDForProgram scans /proc to find a PID that has the given BPF program ID
// attached to one of its file descriptors. Returns 0 if not found.
func findPIDForProgram(progID uint32) int32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		klog.V(4).Infof("Failed to read /proc: %v", err)
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if err != nil {
				continue
			}

			// BPF program FDs appear as "bpf_prog:<id>" or similar
			if strings.Contains(link, "bpf_prog") {
				// Try to extract program ID from the link
				// Format varies: "bpf_prog:<type> <id>" or "bpf_prog:<id>"
				if idMatches(link, progID) {
					return int32(pid)
				}
			}
		}
	}

	return 0
}

// idMatches checks if a bpf_prog link contains the given program ID
func idMatches(link string, progID uint32) bool {
	// bpf_prog links can look like:
	// "bpf_prog:<type> <id>"
	// "bpf_prog:<id>"
	parts := strings.Split(link, ":")
	if len(parts) < 2 {
		return false
	}
	idStr := strings.TrimSpace(parts[len(parts)-1])
	// Handle "type id" format
	fields := strings.Fields(idStr)
	if len(fields) == 0 {
		return false
	}
	// The last field should be the ID
	id, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
	if err != nil {
		return false
	}
	return uint32(id) == progID
}
