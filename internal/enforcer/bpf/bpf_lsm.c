// SPDX-License-Identifier: GPL-2.0
// BPF LSM program for enforcing eBPF program allowlist
// Hooks security_bpf_prog_load to block unauthorized programs

#include <linux/bpf.h>
#include <linux/lsm_hooks.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum program name length
#define PROG_NAME_LEN 16

// Enforcement modes
#define MODE_ALERT  0  // Log only (default)
#define MODE_LOG    1  // Log but allow
#define MODE_BLOCK  2  // Deny unauthorized programs

// Event structure for logging enforcement actions
struct enforce_event {
    __u32 pid;
    __u32 prog_id;
    __u32 prog_type;
    __u32 action;       // 0=allowed, 1=blocked
    char  comm[PROG_NAME_LEN];
};

// Map of allowed program names (populated from userspace)
// Key: program name hash, Value: 1 if allowed
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // hash of program name
    __type(value, __u8);   // 1 = allowed
} allowed_progs SEC(".maps");

// Ring buffer for enforcement events (for logging)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} enforce_events SEC(".maps");

// Global variable to control enforcement mode (set from userspace)
const volatile __u32 enforcement_mode = MODE_ALERT;

// Simple hash function for program names
static __always_inline __u32 hash_name(const char *name, __u32 len) {
    __u32 hash = 5381;
    for (__u32 i = 0; i < len && i < PROG_NAME_LEN; i++) {
        if (name[i] == '\0') break;
        hash = ((hash << 5) + hash) + (__u32)name[i];
    }
    return hash;
}

// LSM hook for security_bpf_prog_load
// Returns 0 to allow, -EPERM to deny
SEC("lsm/bpf_prog_load")
int BPF_PROG(enforce_bpf_prog_load, struct bpf_prog *prog, union bpf_attr *attr, unsigned int attr_size) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Read program name and type from the bpf_prog struct
    char prog_name[PROG_NAME_LEN] = {};
    bpf_probe_read_kernel_str(prog_name, sizeof(prog_name), prog->aux->name);

    __u32 prog_type = prog->type;

    // Compute hash of program name for lookup
    __u32 name_hash = hash_name(prog_name, PROG_NAME_LEN);

    // Check if program is in the allowlist
    __u8 *allowed = bpf_map_lookup_elem(&allowed_progs, &name_hash);

    // Determine action based on enforcement mode
    __u32 action = 0; // allowed

    if (enforcement_mode == MODE_BLOCK) {
        if (!allowed) {
            action = 1; // blocked
        }
    }

    // Emit event for logging (regardless of mode)
    struct enforce_event *evt;
    evt = bpf_ringbuf_reserve(&enforce_events, sizeof(*evt), 0);
    if (evt) {
        evt->pid = pid;
        evt->prog_id = prog->aux->id;
        evt->prog_type = prog_type;
        evt->action = action;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_ringbuf_submit(evt, 0);
    }

    // In block mode, deny unauthorized programs
    if (action == 1) {
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
