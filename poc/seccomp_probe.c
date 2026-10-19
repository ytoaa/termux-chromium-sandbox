/*
 * Phase-0 feasibility probe for termux-chromium-sandbox.
 * Question: can an ordinary Termux (untrusted_app) process install its own
 * seccomp-bpf filter and receive SECCOMP_RET_TRAP as SIGSYS?
 * Expected on success: "trapped via SIGSYS" + exit 42.
 */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000BF
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef __NR_getuid
#if defined(__aarch64__)
#define __NR_getuid 174
#endif
#endif

static void sigsys_handler(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    dprintf(2, "probe: getuid trapped via SIGSYS (si_code=%d)\n", si->si_code);
    _exit(42);
}

int main(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(code) / sizeof(code[0])),
        .filter = code,
    };
    struct sigaction sa;
    sa.sa_sigaction = sigsys_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGSYS, &sa, NULL) != 0) { perror("sigaction"); return 3; }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { perror("nnp"); return 4; }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0) {
        dprintf(2, "probe: installed via prctl(PR_SET_SECCOMP)\n");
    } else {
        long r = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
        if (r == 0) { dprintf(2, "probe: installed via seccomp(2)\n"); }
        else { dprintf(2, "probe: BOTH install paths failed (errno=%d %s)\n", errno, strerror(errno)); return 5; }
    }
    int mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    dprintf(2, "probe: PR_GET_SECCOMP=%d (2=filter)\n", mode);
    pid_t p = getpid();
    dprintf(2, "probe: allowed syscall getpid=%d still works\n", (int)p);
    volatile uid_t u = getuid();
    dprintf(2, "probe: getuid returned %u WITHOUT trap -- filter NOT active\n", (unsigned)u);
    return 6;
}
