# Corso

Kubernetes-native eBPF program auditor. Detect and audit every eBPF program loaded on your cluster nodes, in real time.

Named after the [Cane Corso](https://en.wikipedia.org/wiki/Cane_Corso), an Italian livestock guardian dog. Corso guards your cluster's eBPF programs the way a Cane Corso guards the herd. Your infrastructure is cattle, not pets.

## What it does

Corso runs as a DaemonSet on every node. It uses `BPF_PROG_GET_NEXT_ID` to enumerate all loaded eBPF programs, then checks each one against an allowlist. Programs that aren't on the list trigger a Kubernetes Event and bump a Prometheus counter. That's the core loop.

The allowlist matches by program name, type, and SHA256 hash. It also auto-allows programs from known eBPF DaemonSets (Cilium, Calico, Falco, Tetragon, and others) so you don't get flooded with alerts from your own security tooling.

Each detected program gets attributed to the pod that loaded it through cgroup resolution. So when an alert fires, you know which container is responsible.

## Quick start

```bash
# Build both binaries
make build

# Scan this node for all loaded eBPF programs
./bin/corsoctl scan

# Quick count
./bin/corsoctl count

# Type breakdown
./bin/corsoctl stats
```

## Deploy to Kubernetes

```bash
kubectl create namespace corso-system
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/daemonset.yaml

# Watch the logs
kubectl -n corso-system logs -l app=corso -f
```

## CLI commands

| Command | What it does |
|---------|-------------|
| `corsoctl scan` | List all loaded eBPF programs on this node |
| `corsoctl count` | Print the number of loaded programs |
| `corsoctl stats` | Show program count by type |
| `corsoctl status` | Show Corso audit status |
| `corsoctl nodes` | Show eBPF programs per cluster node (needs DaemonSet) |

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
│  CLI (corsoctl)                          │
│  ├── scan    - enumerate all programs    │
│  ├── count   - quick count               │
│  └── stats   - type breakdown            │
│                                          │
└──────────────────────────────────────────┘
```

## How it compares

I built Corso because nothing else does what I needed: enumerate eBPF programs at the kernel level, attribute them to pods, and enforce an allowlist. Here's how it stacks up:

| Tool | Enumerates eBPF progs | K8s-native | Allowlist | Real-time |
|------|----------------------|------------|-----------|-----------|
| bpftool | Manual CLI only | No | No | No |
| Elastic SIEM | Detects the bpftool binary, not programs | No | No | No |
| Tetragon | Behavior monitoring, not program enumeration | Yes | No | Yes |
| **Corso** | **Yes (kernel syscall)** | **Yes** | **Yes** | **Yes** |

bpftool is great for one-off inspection but has no cluster awareness. Elastic SIEM watches for the bpftool binary being executed, which is easy to bypass. Tetragon monitors behavior (syscalls, file access) but doesn't enumerate or audit the eBPF programs themselves.

## Security model

Corso uses the same kernel-level approach as recent academic research:

- [Bomfather](https://arxiv.org/abs/2503.02097) (2025) uses eBPF to monitor file access at the kernel level for tamper-evident SBOMs
- [RICe](https://sp2026.ieee-security.org/posters.html) (IEEE S&P 2026) uses eBPF and IMA to enforce container runtime integrity

Corso applies this philosophy to eBPF programs themselves. It uses the kernel's own mechanisms to audit what's running in the kernel. The auditor calls `BPF_PROG_GET_NEXT_ID` to walk the program list, the same syscall the kernel exposes for this purpose.

## Configuration

The agent reads configuration from environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_NAME` | hostname | Node identifier (set by DaemonSet via downward API) |
| `CORSO_NAMESPACE` | `corso-system` | Namespace for Corso resources |
| `CORSO_ALLOWLIST` | `default` | Name of the BPFProgramAllowlist CRD to watch |
| `VERBOSE` | `false` | Enable verbose logging |
| `POLL_INTERVAL` | `30s` | How often to re-enumerate programs |

The allowlist is a Kubernetes CRD. Here's a minimal example:

```yaml
apiVersion: corso.io/v1alpha1
kind: BPFProgramAllowlist
metadata:
  name: default
  namespace: corso-system
spec:
  defaultAction: alert
  ignoreKnownDaemons: true
  programs:
    - name: my_tracer
      type: kprobe
    - name: network_monitor
      type: xdp
      hash: "a1b2c3..."
```

The CRD supports matching by name (with glob patterns), type, SHA256 hash, namespace, and container name. `ignoreKnownDaemons: true` auto-allows programs from Cilium, Calico, Falco, Tetragon, KubeArmor, NeuVector, Pixie, Parca, Odigos, and Inspektor Gadget.

## eBPF compilation

The eBPF bytecode is pre-compiled for two architectures:

- `bpf_monitor_bpfel.go` - little-endian (x86_64, aarch64)
- `bpf_monitor_bpfeb.go` - big-endian (s390x, mips)

If you change the eBPF C source (`internal/auditor/bpf_monitor.c`), regenerate the Go bindings:

```bash
# Install bpf2go
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Generate for both architectures
cd internal/auditor
bpf2go -target amd64 -type event BPF bpf_monitor.c -- -I/usr/include/bpf
bpf2go -target arm64 -type event BPF bpf_monitor.c -- -I/usr/include/bpf
```

You need clang, llvm, and libbpf-dev installed. The generated files are checked into the repo so most contributors don't need to run this.

## E2E testing

End-to-end tests run against a real kind cluster with Corso deployed as a DaemonSet.

### Prerequisites

- [kind](https://kind.sigs.k8s.io/)
- Docker
- Go 1.24+
- Linux kernel 4.18+ (5.7+ recommended for full eBPF support)

### Run the full suite

```bash
cd e2e && make e2e
```

This creates a kind cluster, builds and loads the Corso image, deploys the DaemonSet, runs the test suite, and tears everything down.

### Step by step

```bash
cd e2e

# 1. Create kind cluster with eBPF mounts, build images, deploy Corso
make e2e-setup

# 2. Run the test suite
make e2e-run

# 3. Clean up
make e2e-cleanup
```

### Test scenarios

| Test | What it checks |
|------|---------------|
| `TestCorsoPodsRunning` | DaemonSet pods are running on all nodes |
| `TestCorsoCLIScan` | `corsoctl scan` lists eBPF programs |
| `TestCorsoCLICount` | `corsoctl count` returns a number |
| `TestCorsoCLIStats` | `corsoctl stats` shows program types |
| `TestMetricsEndpoint` | `/metrics` serves Prometheus metrics |
| `TestLoadAndDetectEBPFProgram` | Load an eBPF program, verify Corso detects it |
| `TestUnauthorizedProgramAlert` | Unauthorized program triggers a violation event |
| `TestKnownDaemonAutoAllow` | Known daemons (cilium, calico) are auto-allowed |
| `TestAllowlistCRD` | BPFProgramAllowlist CRD is respected |

The kind cluster (`corso-e2e`) mounts `/sys/kernel/debug`, `/sys/fs/bpf`, and `/proc` from the host so eBPF operations work inside the cluster nodes. See `e2e/kind-config.yaml`.

## Requirements

- Kubernetes 1.25+
- Linux kernel 4.18+ (5.7+ recommended)
- DaemonSet needs `privileged: true` or `CAP_BPF` + `CAP_SYS_ADMIN`

## Development

```bash
make test          # run unit tests
make build         # build both binaries
make docker-build  # build container image
make lint          # run golangci-lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, commit conventions, and PR workflow.

## License

Apache 2.0. See [LICENSE](LICENSE).
