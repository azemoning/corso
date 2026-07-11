package auditor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"k8s.io/klog/v2"
)

//go:generate bpf2go -cc clang -cflags -O2 -target bpf bpf_monitor bpf/bpf_monitor.c

// ProgramLoadEvent represents an eBPF program load detected via ring buffer
type ProgramLoadEvent struct {
	PID       uint32
	ProgID    uint32
	ProgType  uint32
	Comm      string
	Timestamp time.Time
}

// SyscallMonitor watches for eBPF program loads in real-time via ring buffer
type SyscallMonitor struct {
	resolver *PIDResolver
	events   chan ProgramLoadEvent
	reader   *ringbuf.Reader
	link     link.Link
	stopCh   chan struct{}
}

// NewSyscallMonitor creates a new monitor
func NewSyscallMonitor(resolver *PIDResolver, bufSize int) *SyscallMonitor {
	if bufSize <= 0 {
		bufSize = 256
	}
	return &SyscallMonitor{
		resolver: resolver,
		events:   make(chan ProgramLoadEvent, bufSize),
		stopCh:   make(chan struct{}),
	}
}

// Start loads the eBPF program and begins reading events
func (m *SyscallMonitor) Start() error {
	objs := bpf_monitorObjects{}
	if err := loadBpf_monitorObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading bpf objects: %w", err)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "bpf_prog_load",
		Program: objs.TraceBpfProgLoad,
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attaching raw tracepoint: %w", err)
	}
	m.link = tp

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return fmt.Errorf("creating ringbuf reader: %w", err)
	}
	m.reader = rd

	go m.processEvents(objs)

	klog.Info("Syscall monitor started - watching for eBPF program loads")
	return nil
}

// Stop halts the monitor
func (m *SyscallMonitor) Stop() {
	close(m.stopCh)
	if m.reader != nil {
		m.reader.Close()
	}
	if m.link != nil {
		m.link.Close()
	}
}

// Events returns the channel of program load events
func (m *SyscallMonitor) Events() <-chan ProgramLoadEvent {
	return m.events
}

// processEvents reads from the ring buffer and dispatches to the channel
func (m *SyscallMonitor) processEvents(objs bpf_monitorObjects) {
	defer objs.Close()

	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			if err.Error() == "ringbuf reader closed" {
				return
			}
			klog.Errorf("ringbuf read error: %v", err)
			continue
		}

		var raw struct {
			PID      uint32
			ProgID   uint32
			ProgType uint32
			Comm     [16]byte
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			klog.Errorf("decoding ringbuf event: %v", err)
			continue
		}

		comm := string(bytes.TrimRight(raw.Comm[:], "\x00"))

		evt := ProgramLoadEvent{
			PID:       raw.PID,
			ProgID:    raw.ProgID,
			ProgType:  raw.ProgType,
			Comm:      comm,
			Timestamp: time.Now(),
		}

		select {
		case m.events <- evt:
		default:
			klog.Warning("SyscallMonitor event buffer full, dropping event")
		}
	}
}

// bpfEventSize is the size of the C struct prog_load_event
const bpfEventSize = int(unsafe.Sizeof(struct {
	PID      uint32
	ProgID   uint32
	ProgType uint32
	Comm     [16]byte
}{}))
