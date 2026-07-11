package allowlist

import (
	"testing"
)

func TestIsAllowedByName(t *testing.T) {
	a := NewAllowlist()
	a.Update([]AllowedProgram{
		{Name: "my_tracer", Type: "kprobe"},
		{Name: "my_xdp", Type: "xdp"},
	}, "alert", true)

	tests := []struct {
		name     string
		program  *ProgramToCheck
		expected bool
	}{
		{
			name:     "allowed kprobe by name",
			program:  &ProgramToCheck{ID: 1, Name: "my_tracer", Type: "kprobe"},
			expected: true,
		},
		{
			name:     "allowed xdp by name",
			program:  &ProgramToCheck{ID: 2, Name: "my_xdp", Type: "xdp"},
			expected: true,
		},
		{
			name:     "unknown program",
			program:  &ProgramToCheck{ID: 3, Name: "evil_rootkit", Type: "kprobe"},
			expected: false,
		},
		{
			name:     "wrong type",
			program:  &ProgramToCheck{ID: 4, Name: "my_tracer", Type: "xdp"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.IsAllowed(tt.program)
			if got != tt.expected {
				t.Errorf("IsAllowed(%+v) = %v, want %v", tt.program, got, tt.expected)
			}
		})
	}
}

func TestIsAllowedByHash(t *testing.T) {
	a := NewAllowlist()
	a.Update([]AllowedProgram{
		{Name: "known", Type: "kprobe", Hash: "abc123"},
	}, "alert", true)

	prog := &ProgramToCheck{ID: 1, Name: "something", Type: "kprobe", Hash: "abc123"}
	if !a.IsAllowed(prog) {
		t.Error("program with matching hash should be allowed")
	}
}

func TestIsKnownDaemonProgram(t *testing.T) {
	a := NewAllowlist()
	a.Update(nil, "alert", true)

	// Cilium program should be auto-allowed
	prog := &ProgramToCheck{
		ID:      1,
		Name:    "cilium_container",
		Type:    "kprobe",
		PodName: "cilium-agent-xxxxx",
	}
	if !a.IsAllowed(prog) {
		t.Error("cilium program should be auto-allowed when IgnoreKnownDaemons=true")
	}

	// Unknown pod should not be auto-allowed
	prog2 := &ProgramToCheck{
		ID:      2,
		Name:    "mysterious_prog",
		Type:    "kprobe",
		PodName: "suspicious-pod-xxxxx",
	}
	if a.IsAllowed(prog2) {
		t.Error("unknown program should not be allowed")
	}
}

func TestComputeHash(t *testing.T) {
	data := []byte("test eBPF bytecode")
	hash := ComputeHash(data)
	if len(hash) != 64 { // SHA256 hex = 64 chars
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestProgramCount(t *testing.T) {
	a := NewAllowlist()
	if a.ProgramCount() != 0 {
		t.Error("new allowlist should have 0 programs")
	}

	a.Update([]AllowedProgram{
		{Name: "prog1", Type: "kprobe"},
		{Name: "prog2", Type: "xdp"},
	}, "alert", true)

	if a.ProgramCount() != 2 {
		t.Errorf("ProgramCount() = %d, want 2", a.ProgramCount())
	}
}
