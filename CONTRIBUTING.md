# Contributing to Corso

Thanks for looking at Corso. This document covers how to get a dev environment running, what conventions we follow, and how to get your changes merged.

## Prerequisites

You need these installed before anything else:

- Go 1.24 or newer
- clang and llvm (for eBPF bytecode compilation)
- libbpf-dev (headers for BPF system calls)
- Docker (for container builds and e2e tests)
- [kind](https://kind.sigs.k8s.io/) (only for e2e tests)
- kubectl (for cluster interaction)

On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

On Fedora/RHEL:

```bash
sudo dnf install -y clang llvm libbpf-devel kernel-headers
```

## Dev environment setup

```bash
# Clone
git clone https://github.com/azemoning/corso.git
cd corso

# Build both binaries
make build

# Run unit tests
make test

# Run linter (requires golangci-lint)
make lint
```

The build produces two binaries in `bin/`:

- `corso` - the DaemonSet agent that runs on each node
- `corsoctl` - the CLI for scanning and inspecting eBPF programs

Both are built with `CGO_ENABLED=0` for static linking. No CGO dependency means the binaries run on any Linux distro without worrying about glibc versions.

## Git commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/). Every commit message starts with a type prefix:

- `feat:` - new feature
- `fix:` - bug fix
- `test:` - adding or updating tests
- `docs:` - documentation changes
- `refactor:` - code restructuring without behavior change
- `chore:` - build, CI, dependency updates
- `perf:` - performance improvement

Examples:

```
feat: add SHA256 hash matching to allowlist
fix: resolve PID to pod name correctly for init containers
test: add unit tests for known daemon pattern matching
docs: explain CRD spec fields in README
refactor: extract alert emission into separate struct
```

Keep the subject line under 72 characters. Use the body for context if the change is non-obvious.

## PR workflow

1. Fork the repo
2. Create a branch from `main`: `git checkout -b feat/my-feature`
3. Make your changes, following the conventions below
4. Run `make test` and make sure everything passes
5. Run `make lint` if you have golangci-lint installed
6. Commit with a conventional commit message
7. Push and open a PR against `main`
8. Wait for review. We try to respond within a few days.

PRs should be focused. One feature or fix per PR is easier to review than a 20-file omnibus. If you're doing something large, open an issue first to discuss the approach.

## Code style

- `gofmt` is the formatter. Run it on everything. Most editors do this automatically.
- `go vet` catches common mistakes. Run it before pushing.
- No CGO. The `CGO_ENABLED=0` flag in the Makefile is intentional. Corso runs in minimal containers and needs static binaries.
- Keep imports grouped: standard library, then external packages, then internal packages. `goimports` handles this.
- Error messages should be lowercase and not end with punctuation: `fmt.Errorf("failed to resolve pid: %w", err)`, not `fmt.Errorf("Failed to resolve PID.")`.

## Testing

### Unit tests

Run `make test` before every PR. This runs `go test ./... -v -count=1`.

Unit tests live next to the code they test. If you're changing `internal/auditor/auditor.go`, the tests should be in `internal/auditor/auditor_test.go` or a related test file in the same package.

When writing tests:

- Test the behavior, not the implementation
- Use table-driven tests for multiple input/output cases
- Mock external dependencies (Kubernetes client, eBPF calls) rather than requiring a live kernel

### E2E tests

E2E tests spin up a real kind cluster, deploy Corso as a DaemonSet, and run test scenarios against it. These take a few minutes to run.

```bash
cd e2e && make e2e
```

This does the full cycle: create cluster, build images, deploy, test, cleanup. You can also run steps individually:

```bash
cd e2e
make e2e-setup     # create cluster + deploy
make e2e-run       # run tests
make e2e-cleanup   # delete cluster
```

E2E tests are required for changes that touch the DaemonSet deployment, the audit loop, or the eBPF enumeration path. For pure CLI or config changes, unit tests are usually enough.

The kind cluster mounts `/sys/kernel/debug`, `/sys/fs/bpf`, and `/proc` from the host so eBPF operations work inside the cluster nodes. This means e2e tests only work on Linux with a kernel that supports eBPF (4.18+, 5.7+ recommended).

## Reporting issues

Open a GitHub issue. Include:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Kernel version (`uname -r`)
- Kubernetes version (`kubectl version`)
- Corso version or commit hash
- Relevant logs from `kubectl -n corso-system logs -l app=corso`

If the issue involves eBPF program detection, run `corsoctl scan` and include the output.

## Code of conduct

Be respectful. We're all here because we think kernel-level security monitoring in Kubernetes is interesting. Assume good intent, give constructive feedback, and don't be a jerk.

## License

By contributing to Corso, you agree that your contributions will be licensed under the Apache License 2.0.
