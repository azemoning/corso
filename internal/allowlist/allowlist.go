package allowlist

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

// KnownDaemons lists eBPF programs from well-known Kubernetes DaemonSets
// These are auto-allowed when IgnoreKnownDaemons is true
var KnownDaemons = []string{
	"cilium-agent",
	"calico-node",
	"falco",
	"tetragon",
	"kubearmor",
	"neuvector-agent",
	"pixie",
	"parca-agent",
	"odigos-instrumentor",
	"inspektor-gadget",
}

// KnownDaemonPatterns are program name prefixes from known Daemons
var KnownDaemonPatterns = []string{
	"cilium_",
	"calico_",
	"flannel_",
	"falco_",
	"tetragon_",
	"kubearmor_",
	"polymorphic_",
	"bpf_prog_",
	"socket_",
	"__sk_",
}

// ProgramToCheck represents an eBPF program to validate against the allowlist
type ProgramToCheck struct {
	ID        uint32 `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Hash      string `json:"hash,omitempty"`
	PodName   string `json:"pod_name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// AllowedProgram defines an allowed eBPF program pattern
type AllowedProgram struct {
	Name               string   `json:"name"`
	Type               string   `json:"type"`
	Hash               string   `json:"hash,omitempty"`
	Namespace          string   `json:"namespace,omitempty"`
	ContainerName      string   `json:"container_name,omitempty"`
	AllowedAttachPoints []string `json:"allowed_attach_points,omitempty"`
}

// Allowlist manages the set of allowed eBPF programs
type Allowlist struct {
	mu              sync.RWMutex
	programHashes   map[string]bool
	programNames    map[string]bool
	programs        []AllowedProgram
	defaultAction   string
	ignoreKnownDaemons bool
}

// NewAllowlist creates a new allowlist manager
func NewAllowlist() *Allowlist {
	return &Allowlist{
		programHashes:   make(map[string]bool),
		programNames:    make(map[string]bool),
		defaultAction:   "alert",
		ignoreKnownDaemons: true,
	}
}

// Update replaces the allowlist with new programs
func (a *Allowlist) Update(programs []AllowedProgram, defaultAction string, ignoreKnownDaemons bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.programs = programs
	a.programHashes = make(map[string]bool)
	a.programNames = make(map[string]bool)
	a.defaultAction = defaultAction
	a.ignoreKnownDaemons = ignoreKnownDaemons

	if a.defaultAction == "" {
		a.defaultAction = "alert"
	}

	for _, prog := range programs {
		if prog.Hash != "" {
			a.programHashes[prog.Hash] = true
		}
		key := programKey(prog.Name, prog.Type)
		a.programNames[key] = true
	}

	klog.Infof("Allowlist updated: %d named programs, %d hashed programs, default=%s",
		len(a.programNames), len(a.programHashes), a.defaultAction)
}

// IsAllowed checks if a program is permitted
func (a *Allowlist) IsAllowed(prog *ProgramToCheck) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check by hash (most strict)
	if prog.Hash != "" && a.programHashes[prog.Hash] {
		return true
	}

	// Check by name + type
	key := programKey(prog.Name, prog.Type)
	if a.programNames[key] {
		return true
	}

	// Check known daemons
	if a.ignoreKnownDaemons && isKnownDaemonProgram(prog) {
		return true
	}

	return false
}

// programKey creates a composite key for name+type matching
func programKey(name, progType string) string {
	return fmt.Sprintf("%s/%s", strings.ToLower(progType), strings.ToLower(name))
}

// isKnownDaemonProgram checks if the program belongs to a known eBPF DaemonSet
func isKnownDaemonProgram(prog *ProgramToCheck) bool {
	// Check pod name against known daemon patterns
	if prog.PodName != "" {
		podLower := strings.ToLower(prog.PodName)
		for _, daemon := range KnownDaemons {
			if strings.Contains(podLower, daemon) {
				return true
			}
		}
	}

	// Check program name against known patterns
	nameLower := strings.ToLower(prog.Name)
	for _, pattern := range KnownDaemonPatterns {
		if strings.HasPrefix(nameLower, pattern) {
			return true
		}
	}

	return false
}

// ComputeHash computes SHA256 of eBPF program bytecode
func ComputeHash(bytecode []byte) string {
	h := sha256.Sum256(bytecode)
	return fmt.Sprintf("%x", h)
}

// DefaultAction returns the current default action
func (a *Allowlist) DefaultAction() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.defaultAction
}

// IgnoreKnownDaemons returns whether known daemons are auto-allowed
func (a *Allowlist) IgnoreKnownDaemons() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ignoreKnownDaemons
}

// ProgramCount returns the number of allowed programs
func (a *Allowlist) ProgramCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.programs)
}
