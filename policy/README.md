# Corso Policy Definitions

Policy-as-code definitions for validating Corso eBPF allowlist configurations.

## Directory Structure

```
policy/
├── opa/                          # OPA Rego policies (standalone)
│   ├── ebpf_allowlist.rego       # BPFProgramAllowlist CRD validation
│   └── ebpf_enforcement.rego     # Enforcement mode validation
├── constraints/                  # Gatekeeper ConstraintTemplates
│   ├── constraint_template.yaml  # Template for allowlist validation
│   └── allowlist_constraint.yaml # Example constraint instance
├── gatekeeper/                   # Gatekeeper integration
│   ├── template.yaml             # ConstraintTemplate (EbpfProgramAllowlist)
│   ├── constraint.yaml           # Example constraint
│   └── sample_constraints/       # Additional constraint examples
│       ├── allowlist_must_have_default_action.yaml
│       └── programs_must_have_name_and_type.yaml
└── README.md                     # This file
```

## OPA Standalone Policies

### ebpf_allowlist.rego

Validates `BPFProgramAllowlist` CRD specs:

- `spec.defaultAction` must be one of: `alert`, `block`, `audit`
- Each program in `spec.programs` must have a non-empty `name`
- If `type` is provided, it must be a valid eBPF program type
- If `hash` is provided, it must be a valid SHA256 (64 hex characters)
- `ignoreKnownDaemons` defaults to `true` when not specified

Test with:

```bash
opa eval --data policy/opa/ebpf_allowlist.rego \
  --input crd.yaml 'data.ebpf.allowlist.allow'
```

### ebpf_enforcement.rego

Validates enforcement mode configuration:

- `CORSO_ENFORCEMENT_MODE` must be `alert`, `log`, or `block`
- `block` mode requires BPF LSM kernel support (`CONFIG_BPF_LSM=y`)

Test with:

```bash
opa eval --data policy/opa/ebpf_enforcement.rego \
  --input '{"mode": "block", "bpf_lsm_supported": true}' \
  'data.ebpf.enforcement.allow'
```

## Gatekeeper Integration

Gatekeeper enforces these policies as Kubernetes admission webhooks.

### Prerequisites

1. [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) installed in the cluster
2. Corso CRDs applied (`kubectl apply -f deploy/crds/`)

### Installation

```bash
# Apply the ConstraintTemplate
kubectl apply -f policy/gatekeeper/template.yaml

# Apply the constraint
kubectl apply -f policy/gatekeeper/constraint.yaml

# (Optional) Apply sample constraints
kubectl apply -f policy/gatekeeper/sample_constraints/
```

### ConstraintTemplate: EbpfProgramAllowlist

Validates `BPFProgramAllowlist` CRDs on create/update:

- Rejects invalid `defaultAction` values
- Rejects programs with empty `name`
- Rejects programs with invalid `type`
- Rejects programs with malformed SHA256 `hash`
- Requires at least one program entry

Parameters:

- `allowedActions` (array): Override default allowed actions (default: `["alert", "block", "audit"]`)

### ConstraintTemplate: EbpfAllowlistValidation

Simpler validation template focused on required fields:

- Can require `defaultAction` to be present
- Requires `name` and `type` on each program entry

Parameters:

- `requireDefaultAction` (boolean): Whether to require the `defaultAction` field

### Testing

```bash
# Create a valid BPFProgramAllowlist
kubectl apply -f - <<EOF
apiVersion: corso.io/v1alpha1
kind: BPFProgramAllowlist
metadata:
  name: test-allowlist
spec:
  defaultAction: alert
  ignoreKnownDaemons: true
  programs:
    - name: "my_program"
      type: "kprobe"
EOF

# This should be rejected by Gatekeeper (invalid defaultAction)
kubectl apply -f - <<EOF
apiVersion: corso.io/v1alpha1
kind: BPFProgramAllowlist
metadata:
  name: bad-allowlist
spec:
  defaultAction: invalid
  programs:
    - name: "test"
      type: "kprobe"
EOF
```

### Dry-Run Mode

To test without blocking, set `enforcementAction: warn` in the constraint:

```yaml
spec:
  enforcementAction: warn  # instead of deny
```

## Use Without Gatekeeper

The Rego policies can be used with any OPA-compatible tool:

- **OPA CLI**: Local evaluation against YAML files
- **OPA Gatekeeper**: Kubernetes admission webhook
- **Conftest**: Test configuration files in CI/CD
- **kube-mgmt**: Sidecar OPA for Kubernetes

```bash
# Using conftest
conftest test my-allowlist.yaml -p policy/opa/ebpf_allowlist.rego
```