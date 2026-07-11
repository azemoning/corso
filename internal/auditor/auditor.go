package auditor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/azemoning/corso/internal/allowlist"
	corsoebpf "github.com/azemoning/corso/pkg/ebpf"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

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

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// ProgramState tracks the state of a detected program
type ProgramState struct {
	Program   *corsoebpf.LoadedProgram
	PodInfo   *PodInfo
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
) *Auditor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Auditor{
		clientset:     clientset,
		pidResolver:   resolver,
		allowlist:     al,
		nodeName:      nodeName,
		namespace:     namespace,
		pollInterval:  pollInterval,
		knownPrograms: make(map[uint32]*ProgramState),
		alertEmitter:  NewAlertEmitter(clientset, namespace, nodeName),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Run starts the audit loop
func (a *Auditor) Run() {
	klog.Infof("Corso auditor starting on node %s, poll interval %v", a.nodeName, a.pollInterval)

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

			// Check allowlist
			checkProg := &allowlist.ProgramToCheck{
				ID:   prog.ID,
				Name: prog.Name,
				Type: prog.Type,
			}

			state.IsAllowed = a.allowlist.IsAllowed(checkProg)

			if !state.IsAllowed && !state.Alerted {
				klog.Warningf("UNAUTHORIZED eBPF program detected: id=%d name=%s type=%s",
					prog.ID, prog.Name, prog.Type)

				// Emit alert
				a.alertEmitter.EmitViolation(state)
				state.Alerted = true
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
		}
	}
}

// Stop stops the auditor
func (a *Auditor) Stop() {
	a.cancel()
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
