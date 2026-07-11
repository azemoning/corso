package ebpf.allowlist

import future.keywords.in
import future.keywords.if
import future.keywords.contains
import future.keywords.every

# Default deny
default allow := false

# Valid enforcement actions for programs
valid_actions := {"alert", "block", "audit"}

# Valid eBPF program types
valid_types := {"kprobe", "kretprobe", "tracepoint", "raw_tracepoint", "xdp", "tc", "lsm", "cgroup", "sockops", "sk_msg", "classifier", "flow_dissector", "struct_ops"}

# SHA256 hash pattern (64 hex characters)
sha256_pattern := `^[a-fA-F0-9]{64}$`

# Top-level validation: allow if the CRD spec is valid
allow if {
	input.review.kind.kind == "BPFProgramAllowlist"
	input.review.kind.group == "corso.io"
	spec_is_valid(input.review.object.spec)
}

# Spec must have a valid defaultAction
spec_is_valid(spec) if {
	spec.defaultAction in valid_actions
}

# Spec programs array must have valid entries
spec_is_valid(spec) if {
	every program in spec.programs {
		program_is_valid(program)
	}
}

# Each program must have a name (required) and valid type if provided
program_is_valid(program) if {
	program.name != ""
}

program_is_valid(program) if {
	program.name != ""
	program.type == ""
}

program_is_valid(program) if {
	program.name != ""
	program.type in valid_types
}

# If hash is provided, it must be a valid SHA256
program_is_valid(program) if {
	program.name != ""
	program.hash == ""
}

program_is_valid(program) if {
	program.name != ""
	program.hash != ""
	regex.match(sha256_pattern, program.hash)
}

# ignoreKnownDaemons defaults to true when not specified
default ignore_known_daemons := true

ignore_known_daemons if {
	input.review.object.spec.ignoreKnownDaemons == true
}

ignore_known_daemons if {
	not has_field(input.review.object.spec, "ignoreKnownDaemons")
}

# Helper to check if a field exists
has_field(obj, field) if {
	_ = obj[field]
}

# Violation messages for debugging
violation[msg] if {
	input.review.kind.kind == "BPFProgramAllowlist"
	not spec_is_valid(input.review.object.spec)
	msg := "BPFProgramAllowlist spec is invalid: defaultAction must be one of alert/block/audit"
}

violation[msg] if {
	input.review.kind.kind == "BPFProgramAllowlist"
	some program in input.review.object.spec.programs
	program.name == ""
	msg := sprintf("Program entry has empty name at index %d", [indexof(input.review.object.spec.programs, program)])
}

violation[msg] if {
	input.review.kind.kind == "BPFProgramAllowlist"
	some program in input.review.object.spec.programs
	program.type != ""
	not program.type in valid_types
	msg := sprintf("Program '%s' has invalid type '%s', must be one of: kprobe, kretprobe, tracepoint, raw_tracepoint, xdp, tc, lsm, cgroup, sockops, sk_msg, classifier, flow_dissector, struct_ops", [program.name, program.type])
}

violation[msg] if {
	input.review.kind.kind == "BPFProgramAllowlist"
	some program in input.review.object.spec.programs
	program.hash != ""
	not regex.match(sha256_pattern, program.hash)
	msg := sprintf("Program '%s' has invalid hash: must be a valid SHA256 (64 hex characters)", [program.name])
}