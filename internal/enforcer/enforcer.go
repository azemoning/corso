package enforcer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"sync"

	"github.com/azemoning/corso/internal/allowlist"
	"github.com/azemoning/corso/internal/metrics"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"k8s.io/klog/v2"
)

// EnforcementMode defines the enforcement behavior
type EnforcementMode string

const (
	ModeAlert EnforcementMode = "alert" // Log only (default)
	ModeLog   EnforcementMode = "log"   // Log but allow
	ModeBlock EnforcementMode = "block" // Deny unauthorized programs
)

// enforceEvent matches the C struct in bpf_lsm.c
type enforceEvent struct {
	PID      uint32
	ProgID   uint32
	ProgType uint32
	Action   uint32 // 0=allowed, 1=blocked
	Comm     [16]byte
}

// Enforcer manages BPF LSM enforcement
type Enforcer struct {
	mu          sync.RWMutex
	allowlist   *allowlist.Allowlist
	mode        EnforcementMode
	lsmLink     link.Link
	objs        *bpfLsmObjects
	eventsReader *ringbuf.Reader
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewEnforcer creates a new BPF LSM enforcer
func NewEnforcer(al *allowlist.Allowlist, mode string) *Enforcer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Enforcer{
		allowlist: al,
		mode:     EnforcementMode(mode),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start loads and attaches the BPF LSM program
func (e *Enforcer) Start() error {
	if e.mode == ModeAlert {
		klog.Info("Enforcement mode is 'alert', BPF LSM enforcer not started")
		return nil
	}

	klog.Infof("Starting BPF LSM enforcer in %q mode", e.mode)

	// Load the BPF LSM program
	objs := &bpfLsmObjects{}
	if err := loadBpfLsmObjects(objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF LSM objects: %w", err)
	}
	e.objs = objs

	// Set enforcement mode in the BPF program
	modeVal := uint32(0)
	switch e.mode {
	case ModeLog:
		modeVal = 1
	case ModeBlock:
		modeVal = 2
	}
	if err := objs.bpfLsmVariables.EnforcementMode.Set(modeVal); err != nil {
		objs.Close()
		return fmt.Errorf("failed to set enforcement mode: %w", err)
	}

	// Attach LSM program
	l, err := link.AttachLSM(link.LSMOptions{
		Program: objs.EnforceBpfProgLoad,
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("failed to attach LSM program (kernel may not support BPF LSM): %w", err)
	}
	e.lsmLink = l

	// Open ring buffer reader for enforcement events
	rd, err := ringbuf.NewReader(objs.EnforceEvents)
	if err != nil {
		e.lsmLink.Close()
		objs.Close()
		return fmt.Errorf("failed to open ring buffer reader: %w", err)
	}
	e.eventsReader = rd

	// Start processing events
	go e.processEvents()

	// Sync allowlist to BPF map
	if err := e.syncAllowlist(); err != nil {
		klog.Warningf("Failed to sync initial allowlist to BPF map: %v", err)
	}

	klog.Info("BPF LSM enforcer started successfully")
	return nil
}

// Stop detaches the BPF LSM program and cleans up
func (e *Enforcer) Stop() {
	klog.Info("Stopping BPF LSM enforcer")
	e.cancel()

	if e.eventsReader != nil {
		e.eventsReader.Close()
	}
	if e.lsmLink != nil {
		e.lsmLink.Close()
	}
	if e.objs != nil {
		e.objs.Close()
	}
}

// processEvents reads and logs enforcement events from the ring buffer
func (e *Enforcer) processEvents() {
	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		record, err := e.eventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			klog.V(4).Infof("Error reading enforcement event: %v", err)
			continue
		}

		var evt enforceEvent
		if err := binary.Read(strings.NewReader(string(record.RawSample)), binary.LittleEndian, &evt); err != nil {
			klog.V(4).Infof("Error parsing enforcement event: %v", err)
			continue
		}

		comm := strings.TrimRight(string(evt.Comm[:]), "\x00")

		if evt.Action == 1 {
			klog.Warningf("BLOCKED eBPF program: pid=%d prog_id=%d type=%d comm=%s",
				evt.PID, evt.ProgID, evt.ProgType, comm)
			metrics.EnforcementTotal.WithLabelValues(string(e.mode), "blocked").Inc()
		} else {
			klog.V(3).Infof("Allowed eBPF program: pid=%d prog_id=%d type=%d comm=%s",
				evt.PID, evt.ProgID, evt.ProgType, comm)
			metrics.EnforcementTotal.WithLabelValues(string(e.mode), "allowed").Inc()
		}
	}
}

// syncAllowlist updates the BPF allowlist map with current allowed programs
func (e *Enforcer) syncAllowlist() error {
	if e.objs == nil {
		return fmt.Errorf("enforcer not started")
	}

	// For now, we sync known daemon patterns as allowed
	// In a full implementation, this would read from the allowlist's program list
	knownPatterns := []string{
		"cilium_", "calico_", "flannel_", "falco_",
		"tetragon_", "kubearmor_", "polymorphic_",
		"bpf_prog_", "socket_", "__sk_",
	}

	for _, pattern := range knownPatterns {
		hash := hashName(pattern)
		val := uint8(1)
		if err := e.objs.AllowedProgs.Put(hash, val); err != nil {
			klog.V(4).Infof("Failed to add %q to BPF allowlist map: %v", pattern, err)
		}
	}

	klog.Infof("Synced %d patterns to BPF allowlist map", len(knownPatterns))
	return nil
}

// UpdateAllowlist updates the BPF allowlist map with new allowed programs
func (e *Enforcer) UpdateAllowlist(programs []allowlist.AllowedProgram) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.objs == nil {
		return fmt.Errorf("enforcer not started")
	}

	// Clear existing entries (BPF maps don't have a clear method, so we track them)
	// In production, you'd want to diff and update incrementally

	for _, prog := range programs {
		hash := hashName(prog.Name)
		val := uint8(1)
		if err := e.objs.AllowedProgs.Put(hash, val); err != nil {
			klog.V(4).Infof("Failed to add %q to BPF allowlist map: %v", prog.Name, err)
		}
	}

	klog.Infof("Updated BPF allowlist map with %d programs", len(programs))
	return nil
}

// IsSupported checks if the kernel supports BPF LSM
func IsSupported() bool {
	// Check if LSM BPF is available by checking kernel features
	// A more robust check would try to load a minimal LSM program
	_, err := os.Stat("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}

	// Read the LSM file and check for "bpf"
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}

	return strings.Contains(string(data), "bpf")
}

// hashName computes a FNV-1a hash of a program name
// Must match the hash function in the BPF C program
func hashName(name string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(name))
	return h.Sum32()
}
