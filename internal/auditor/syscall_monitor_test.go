package auditor

import (
	"testing"
	"unsafe"
)

func TestNewSyscallMonitor(t *testing.T) {
	monitor := NewSyscallMonitor(nil, 128)
	if monitor == nil {
		t.Fatal("NewSyscallMonitor returned nil")
	}
	if monitor.events == nil {
		t.Fatal("events channel is nil")
	}
	if cap(monitor.events) != 128 {
		t.Fatalf("expected buffer size 128, got %d", cap(monitor.events))
	}
	if monitor.stopCh == nil {
		t.Fatal("stopCh is nil")
	}
}

func TestNewSyscallMonitorDefaultBuffer(t *testing.T) {
	monitor := NewSyscallMonitor(nil, 0)
	if monitor == nil {
		t.Fatal("NewSyscallMonitor returned nil")
	}
	if cap(monitor.events) != 256 {
		t.Fatalf("expected default buffer size 256, got %d", cap(monitor.events))
	}
}

func TestProgramLoadEventSize(t *testing.T) {
	type cStruct struct {
		PID      uint32
		ProgID   uint32
		ProgType uint32
		Comm     [16]byte
	}

	size := int(unsafe.Sizeof(cStruct{}))
	if size != 28 {
		t.Fatalf("expected C struct size 28, got %d", size)
	}

	if bpfEventSize != 28 {
		t.Fatalf("expected bpfEventSize 28, got %d", bpfEventSize)
	}
}

func TestSyscallMonitorEventsChannel(t *testing.T) {
	monitor := NewSyscallMonitor(nil, 10)

	evt := ProgramLoadEvent{
		PID:      1234,
		ProgID:   5678,
		ProgType: 1,
		Comm:     "test-prog",
	}

	monitor.events <- evt

	select {
	case received := <-monitor.Events():
		if received.PID != 1234 {
			t.Errorf("expected PID 1234, got %d", received.PID)
		}
		if received.ProgID != 5678 {
			t.Errorf("expected ProgID 5678, got %d", received.ProgID)
		}
		if received.Comm != "test-prog" {
			t.Errorf("expected Comm 'test-prog', got '%s'", received.Comm)
		}
	default:
		t.Fatal("no event received on channel")
	}
}
