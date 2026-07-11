# Corso

> Kubernetes-native eBPF program auditor. Detect and audit all eBPF programs
> loaded on your cluster nodes in real-time.

Named after the [Cane Corso](https://en.wikipedia.org/wiki/Cane_Corse), an ancient Italian livestock guardian dog. Corso guards your Kubernetes cluster's eBPF programs the way a Cane Corso guards the herd — treating your infrastructure as cattle, not pets.

## What it does

Corso runs as a DaemonSet on every node and:

- **Enumerates** all loaded eBPF programs continuously using `BPF_PROG_GET_NEXT_ID`
- **Attributes** each program to the pod/container that loaded it via cgroup resolution
- **Enforces** an allowlist of permitted programs (name, type, hash matching)
- **Auto-allows** known eBPF DaemonSets (Cilium, Calico, Falco, Tetragon, etc.)
- **Alerts** on unauthorized program loads via Kubernetes Events
- **Exposes** Prometheus metrics for monitoring

## Quick Start

```bash
# Build
make build

# Scan local node for eBPF programs
./bin/corsoctl scan

# Count programs
./bin/corsoctl count

# Show type breakdown
./bin/corsoctl stats
```

## Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace corso-system

# Apply RBAC
kubectl apply -f deploy/rbac.yaml

# Deploy DaemonSet
kubectl apply -f deploy/daemonset.yaml

# Check logs
kubectl -n corso-system logs -l app=corso -f
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `corsoctl scan` | Enumerate all loaded eBPF programs on this node |
| `corsoctl count` | Quick count of loaded programs |
| `corsoctl stats` | Show program type breakdown |
| `corsoctl status` | Show Corso audit status |
| `corsoctl nodes` | Show eBPF programs per node (requires DaemonSet) |

## Architecture

```
┌──────────────────────────────────────────┐
│            Corso Architecture            │
├──────────────────────────────────────────┤
│                                          │
│  DaemonSet (per node)                    │
│  ├── eBPF enumeration via cilium/ebpf    │
│  │   (BPF_PROG_GET_NEXT_ID syscall)      │
│  ├── PID → cgroup → Pod resolver         │
│  ├── Allowlist enforcement               │
│  └── K8s Event emission                  │
│                                          │
│  Allowlist (CRD-backed)                  │
│  ├── Name + Type matching                │
│  ├── SHA256 hash matching                │
│  └── Known daemon auto-allow             │
│                                          │
│  CLI (corso-ctl)                         │
│  ├── scan    - enumerate all programs    │
│  ├── count   - quick count               │
│  └── stats   - type breakdown            │
│                                          │
└──────────────────────────────────────────┘
```

## Why Corso?

| Tool | Enumerates eBPF progs | K8s-native | Allowlist | Real-time |
|------|----------------------|------------|-----------|-----------|
| bpftool | Manual CLI | No | No | No |
| Elastic SIEM | Detects bpftool binary only | No | No | No |
| Tetragon | Behavior monitoring, not program enumeration | Yes | No | Yes |
| **Corso** | **Yes (kernel syscall)** | **Yes** | **Yes** | **Yes** |

## Security Model

Corso uses the same kernel-level approach as academic research:

- **[Bomfather](https://arxiv.org/abs/2503.02097)** (2025): Uses eBPF to monitor file access at kernel level for tamper-evident SBOMs
- **[RICe](https://sp2026.ieee-security.org/posters.html)** (IEEE S&P 2026): Uses eBPF + IMA to enforce container runtime integrity

Corso applies this philosophy to eBPF programs themselves — using the kernel's own mechanisms to audit what's running in the kernel.

## Requirements

- Kubernetes 1.25+
- Linux kernel 4.18+ (5.7+ recommended)
- DaemonSet needs `privileged: true` or `CAP_BPF + CAP_SYS_ADMIN`

## Development

```bash
# Run tests
make test

# Build binaries
make build

# Build Docker image
make docker-build
```

## E2E Testing

End-to-end tests run against a real kind Kubernetes cluster with Corso deployed as a DaemonSet.

### Prerequisites

- [kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker)
- Docker
- Go 1.24+

### Quick Run

```bash
# Full e2e: create cluster, deploy, test, cleanup
cd e2e && make e2e
```

### Step by Step

```bash
cd e2e

# 1. Create kind cluster with eBPF mounts, build images, deploy Corso
make e2e-setup

# 2. Run the test suite
make e2e-run

# 3. Clean up (delete kind cluster)
make e2e-cleanup
```

### Test Scenarios

| Test | Description |
|------|-------------|
| `TestCorsoPodsRunning` | DaemonSet pods running on all nodes |
| `TestCorsoCLIScan` | `corsoctl scan` lists eBPF programs |
| `TestCorsoCLICount` | `corsoctl count` returns a number |
| `TestCorsoCLIStats` | `corsoctl stats` shows program types |
| `TestMetricsEndpoint` | `/metrics` serves Prometheus metrics |
| `TestLoadAndDetectEBPFProgram` | Load eBPF program, verify Corso detects it |
| `TestUnauthorizedProgramAlert` | Unauthorized program triggers violation event |
| `TestKnownDaemonAutoAllow` | Known daemons (cilium/calico) auto-allowed |
| `TestAllowlistCRD` | BPFProgramAllowlist CRD respected |

### Kind Cluster Config

The kind cluster (`corso-e2e`) mounts `/sys/kernel/debug`, `/sys/fs/bpf`, and `/proc` from the host to enable eBPF operations inside the cluster nodes. See `e2e/kind-config.yaml`.

## License

Apache 2.0
