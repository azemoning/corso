package ebpf.enforcement

import future.keywords.in
import future.keywords.if

# Valid enforcement modes
valid_modes := {"alert", "log", "block"}

default allow := false

# Allow if the enforcement mode configuration is valid
allow if {
	input.mode in valid_modes
}

# block mode requires BPF LSM kernel support
allow if {
	input.mode == "block"
	input.bpf_lsm_supported == true
}

# alert and log modes always allowed (no special kernel requirements)
allow if {
	input.mode == "alert"
}

allow if {
	input.mode == "log"
}

# Violation: invalid mode
violation[msg] if {
	not input.mode in valid_modes
	msg := sprintf("Invalid enforcement mode '%s': must be one of alert, log, block", [input.mode])
}

# Violation: block mode without BPF LSM support
violation[msg] if {
	input.mode == "block"
	input.bpf_lsm_supported == false
	msg := "Block enforcement mode requires BPF LSM kernel support (CONFIG_BPF_LSM=y). Current kernel does not support BPF LSM."
}

# Validate environment variable format
validate_env_mode(env_value) := result if {
	env_value == "alert" := result
}

validate_env_mode(env_value) := result if {
	env_value == "log" := result
}

validate_env_mode(env_value) := result if {
	env_value == "block" := result
}

validate_env_mode(env_value) := result if {
	not env_value in valid_modes
	result := sprintf("CORSO_ENFORCEMENT_MODE value '%s' is not valid", [env_value])
}