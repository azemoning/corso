// SPDX-License-Identifier: GPL-2.0
// simple_ebpf_loader.c - Minimal eBPF program loader for e2e tests
//
// Loads a trivial eBPF program that attaches to a tracepoint and returns 0.
// Used to verify that Corso can detect newly loaded eBPF programs.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

#ifndef __NR_bpf
#if defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#endif
#endif

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

// Minimal eBPF bytecode: load_imm64 r0, 0; exit
// This is the simplest valid eBPF program.
static const char bpf_prog[] = {
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
};

int main(void)
{
    union bpf_attr attr;
    int prog_fd;

    printf("Loading eBPF program...\n");

    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    attr.insns = (unsigned long long)bpf_prog;
    attr.insn_cnt = sizeof(bpf_prog) / 8;
    attr.license = (unsigned long long)"GPL";
    attr.log_buf = 0;
    attr.log_size = 0;
    attr.log_level = 0;

    // Set a program name so Corso can identify it
    const char *prog_name = "corso_e2e_test";
    size_t name_len = strlen(prog_name);
    if (name_len > BPF_OBJ_NAME_LEN - 1)
        name_len = BPF_OBJ_NAME_LEN - 1;
    memcpy(attr.prog_name, prog_name, name_len);

    prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to load eBPF program: %s (errno=%d)\n",
                strerror(errno), errno);
        return 1;
    }

    printf("eBPF program loaded successfully (fd=%d)\n", prog_fd);
    printf("Program name: %s\n", prog_name);
    printf("Program type: TRACEPOINT\n");

    // Keep the program loaded for a while so Corso can detect it
    printf("Holding program loaded for 120 seconds...\n");
    fflush(stdout);
    sleep(120);

    close(prog_fd);
    printf("eBPF program unloaded\n");
    return 0;
}
