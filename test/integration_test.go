package test

import (
	"testing"

	"github.com/azemoning/corso/internal/allowlist"
)

func TestFullAuditFlow(t *testing.T) {
	// 1. Create allowlist
	al := allowlist.NewAllowlist()

	// 2. Add known programs
	al.Update([]allowlist.AllowedProgram{
		{Name: "my_app_kprobe", Type: "kprobe"},
	}, "alert", true)

	// 3. Test allowed program
	allowed := al.IsAllowed(&allowlist.ProgramToCheck{
		Name: "my_app_kprobe", Type: "kprobe",
	})
	if !allowed {
		t.Error("known program should be allowed")
	}

	// 4. Test known daemon
	daemonAllowed := al.IsAllowed(&allowlist.ProgramToCheck{
		Name: "cilium_container", Type: "kprobe", PodName: "cilium-agent-xxx",
	})
	if !daemonAllowed {
		t.Error("cilium program should be auto-allowed")
	}

	// 5. Test unknown program
	unknownAllowed := al.IsAllowed(&allowlist.ProgramToCheck{
		Name: "sneaky_rootkit", Type: "kprobe", PodName: "suspicious-pod",
	})
	if unknownAllowed {
		t.Error("unknown program should NOT be allowed")
	}

	// 6. Verify default action
	if al.DefaultAction() != "alert" {
		t.Errorf("default action = %q, want 'alert'", al.DefaultAction())
	}
}
