package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:shortName=bpfa
// +kubebuilder:subresource:status

// BPFProgramAllowlist is the Schema for the bpfprogramallowlists API
type BPFProgramAllowlist struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BPFProgramAllowlistSpec   `json:"spec,omitempty"`
	Status BPFProgramAllowlistStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BPFProgramAllowlistList contains a list of BPFProgramAllowlist
type BPFProgramAllowlistList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BPFProgramAllowlist `json:"items"`
}

// BPFProgramAllowlistSpec defines the desired state of BPFProgramAllowlist
type BPFProgramAllowlistSpec struct {
	// DefaultAction is the action to take for programs not in the allowlist.
	// Valid values: "alert", "block", "audit".
	// +kubebuilder:validation:Enum=alert;block;audit
	// +kubebuilder:default=alert
	DefaultAction string `json:"defaultAction,omitempty"`

	// IgnoreKnownDaemons auto-allows programs from well-known DaemonSets
	// (cilium, calico, falco, etc.)
	// +kubebuilder:default=true
	IgnoreKnownDaemons *bool `json:"ignoreKnownDaemons,omitempty"`

	// Programs is the list of explicitly allowed eBPF programs
	Programs []AllowedProgramSpec `json:"programs,omitempty"`
}

// AllowedProgramSpec defines an allowed eBPF program entry
type AllowedProgramSpec struct {
	// Name is the eBPF program name (supports glob patterns)
	Name string `json:"name"`

	// Type is the eBPF program type (kprobe, tracepoint, xdp, etc.)
	// +optional
	Type string `json:"type,omitempty"`

	// Hash is the SHA256 hash of the program bytecode (most strict match)
	// +optional
	Hash string `json:"hash,omitempty"`

	// Namespace is the Kubernetes namespace of the owning pod
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// ContainerName is the container name within the pod
	// +optional
	ContainerName string `json:"containerName,omitempty"`
}

// BPFProgramAllowlistStatus defines the observed state of BPFProgramAllowlist
type BPFProgramAllowlistStatus struct {
	// LastSyncTime is the last time the allowlist was synced to agents
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// TotalPrograms is the total number of allowed programs
	TotalPrograms int `json:"totalPrograms,omitempty"`

	// NodesEnforcing is the number of nodes enforcing this allowlist
	NodesEnforcing int `json:"nodesEnforcing,omitempty"`
}
