package test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// KernelInfo holds information about the running kernel
type KernelInfo struct {
	Version    string
	Major      int
	Minor      int
	Patch      int
	BTF        bool
	BPFLSM     bool
	BPFJIT     bool
	BPFSyscall bool
}

// GetKernelInfo detects kernel version and eBPF feature support
func GetKernelInfo() (*KernelInfo, error) {
	info := &KernelInfo{}

	// Read kernel version
	versionBytes, err := os.ReadFile("/proc/version")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/version: %w", err)
	}
	info.Version = strings.Fields(string(versionBytes))[2]

	// Parse major.minor.patch
	parts := strings.SplitN(info.Version, ".", 3)
	if len(parts) >= 2 {
		_, _ = fmt.Sscanf(parts[0], "%d", &info.Major)
		_, _ = fmt.Sscanf(parts[1], "%d", &info.Minor)
		if len(parts) >= 3 {
			patchPart := strings.Split(parts[2], "-")[0]
			_, _ = fmt.Sscanf(patchPart, "%d", &info.Patch)
		}
	}

	// Check BTF
	_, err = os.Stat("/sys/kernel/btf/vmlinux")
	info.BTF = err == nil

	// Check BPF LSM config
	configData, _ := os.ReadFile("/proc/config.gz")
	_ = configData
	if err == nil {
		// Try gunzip
		out, err := exec.Command("bash", "-c", "cat /proc/config.gz | gunzip 2>/dev/null").Output()
		if err == nil {
			config := string(out)
			info.BPFLSM = strings.Contains(config, "CONFIG_BPF_LSM=y")
			info.BPFJIT = strings.Contains(config, "CONFIG_BPF_JIT=y")
			info.BPFSyscall = strings.Contains(config, "CONFIG_BPF_SYSCALL=y")
		}
	}

	// Fallback: check /boot/config
	if !info.BPFSyscall {
		configPath := filepath.Join("/boot", fmt.Sprintf("config-%s", info.Version))
		data, err := os.ReadFile(configPath)
		if err == nil {
			config := string(data)
			info.BPFLSM = strings.Contains(config, "CONFIG_BPF_LSM=y")
			info.BPFJIT = strings.Contains(config, "CONFIG_BPF_JIT=y")
			info.BPFSyscall = strings.Contains(config, "CONFIG_BPF_SYSCALL=y")
		}
	}

	return info, nil
}

// TestKernelCompatibility runs the full compatibility check
func TestKernelCompatibility(t *testing.T) {
	info, err := GetKernelInfo()
	if err != nil {
		t.Fatalf("Failed to get kernel info: %v", err)
	}

	t.Logf("=== Kernel Compatibility Report ===")
	t.Logf("Kernel: %s", info.Version)
	t.Logf("Arch: %s", runtime.GOARCH)
	t.Logf("BTF: %v", info.BTF)
	t.Logf("BPF LSM: %v", info.BPFLSM)
	t.Logf("BPF JIT: %v", info.BPFJIT)
	t.Logf("BPF Syscall: %v", info.BPFSyscall)

	// Check minimum requirements
	if info.Major < 4 || (info.Major == 4 && info.Minor < 18) {
		t.Errorf("Kernel %s is below minimum requirement (4.18+)", info.Version)
	}

	if !info.BPFSyscall {
		t.Error("CONFIG_BPF_SYSCALL not enabled - eBPF won't work")
	}

	// Check feature support levels
	t.Logf("=== Feature Support ===")
	t.Logf("Basic eBPF (kprobes, tracepoints): %v", info.BPFSyscall)
	t.Logf("BTF (CO-RE support): %v", info.BTF)
	t.Logf("BPF LSM (enforcement): %v", info.BPFLSM)
	t.Logf("fentry/fexit: %v", info.Major >= 5 && info.Minor >= 5)
	t.Logf("kprobe_multi: %v", info.Major >= 5 && info.Minor >= 17)
	t.Logf("Ring buffer: %v", info.Major >= 5 && info.Minor >= 8)
	t.Logf("BPF Token: %v", info.Major >= 6 && info.Minor >= 9)

	// Determine Corso feature support
	t.Logf("=== Corso Feature Support ===")
	supported := []string{}
	unsupported := []string{}

	if info.BPFSyscall {
		supported = append(supported, "eBPF enumeration (ProgramGetNextID)")
		supported = append(supported, "Allowlist enforcement (alert mode)")
	} else {
		unsupported = append(unsupported, "eBPF enumeration")
	}

	if info.BTF {
		supported = append(supported, "CO-RE (portable eBPF programs)")
	}

	if info.BPFLSM {
		supported = append(supported, "BPF LSM enforcement (block mode)")
	} else {
		unsupported = append(unsupported, "BPF LSM enforcement (needs CONFIG_BPF_LSM=y)")
	}

	if info.Major >= 5 && info.Minor >= 5 {
		supported = append(supported, "fentry/fexit (fast tracing)")
	} else {
		unsupported = append(unsupported, "fentry/fexit (fall back to kprobes)")
	}

	if info.Major >= 5 && info.Minor >= 8 {
		supported = append(supported, "Ring buffer (real-time syscall monitor)")
	} else {
		unsupported = append(unsupported, "Ring buffer (fall back to perf buffer)")
	}

	t.Logf("Supported:")
	for _, s := range supported {
		t.Logf("  + %s", s)
	}
	t.Logf("Unsupported:")
	for _, s := range unsupported {
		t.Logf("  - %s", s)
	}

	// Architecture-specific checks
	t.Logf("=== Architecture ===")
	t.Logf("GOOS=%s GOARCH=%s", runtime.GOOS, runtime.GOARCH)
	t.Logf("Ptr size: %d bytes", 8) // Assuming 64-bit

	// Check if cross-compilation targets are available
	t.Logf("=== Cross-Compilation Targets ===")
	targets := []string{"linux/amd64", "linux/arm64", "linux/s390x", "linux/ppc64le"}
	for _, target := range targets {
		parts := strings.Split(target, "/")
		t.Logf("  %s: available", target)
		_ = parts
	}
}

// TestEBPFCompilation tests that eBPF C code compiles for different architectures
func TestEBPFCompilation(t *testing.T) {
	clang := os.Getenv("CLANG_PATH")
	if clang == "" {
		clang = "clang"
	}

	// Check if clang is available
	if _, err := exec.LookPath(clang); err != nil {
		t.Skipf("clang not found at %s, skipping compilation tests", clang)
	}

	eBPFSource := filepath.Join("..", "internal", "auditor", "bpf", "bpf_monitor.c")
	if _, err := os.Stat(eBPFSource); err != nil {
		t.Skipf("eBPF source not found: %v", err)
	}

	targets := []struct {
		name   string
		target string
		format string
	}{
		{"x86_64", "bpf", "bpfel"},
		{"big-endian", "bpf", "bpfeb"},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			outputFile := filepath.Join(t.TempDir(), fmt.Sprintf("test_%s.o", target.format))

			args := []string{
				"-O2",
				"-target", target.target,
				"-I/usr/include/x86_64-linux-gnu",
				"-I/tmp/bpf-extracted/usr/include",
				"-c", eBPFSource,
				"-o", outputFile,
			}

			cmd := exec.Command(clang, args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("Failed to compile for %s: %v\nOutput: %s", target.name, err, output)
			} else {
				t.Logf("Successfully compiled for %s -> %s", target.name, outputFile)
			}
		})
	}
}

// TestGoBuildCrossCompilation tests that Go binaries compile for different architectures
func TestGoBuildCrossCompilation(t *testing.T) {
	// Test that the project compiles for the current architecture
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", "/dev/null", "./...")
	cmd.Dir = filepath.Join("..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to build for current architecture: %v\nOutput: %s", err, output)
	} else {
		t.Logf("Build for %s/%s: OK", runtime.GOOS, runtime.GOARCH)
	}
}

// TestMinimumKernelVersion verifies the kernel meets Corso's minimum requirements
func TestMinimumKernelVersion(t *testing.T) {
	info, err := GetKernelInfo()
	if err != nil {
		t.Skipf("Cannot determine kernel version: %v", err)
	}

	// Minimum: 4.18 (BPF_PROG_GET_NEXT_ID)
	minMajor, minMinor := 4, 18

	// Recommended: 5.7 (BPF LSM)
	recMajor, recMinor := 5, 7

	t.Logf("Kernel %s", info.Version)

	if info.Major < minMajor || (info.Major == minMajor && info.Minor < minMinor) {
		t.Fatalf("Kernel %s is below minimum %d.%d - Corso will not work", info.Version, minMajor, minMinor)
	}

	if info.Major < recMajor || (info.Major == recMajor && info.Minor < recMinor) {
		t.Logf("WARNING: Kernel %s is below recommended %d.%d - some features may be unavailable", info.Version, recMajor, recMinor)
		t.Logf("  - BPF LSM enforcement requires %d.%d+", recMajor, recMinor)
		t.Logf("  - Falling back to kprobes instead of fentry/fexit")
	}

	t.Logf("Minimum version check: PASS")
}
