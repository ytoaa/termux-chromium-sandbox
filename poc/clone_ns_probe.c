/* Per-namespace feasibility via clone(2), mirroring Chromium's
 * Credentials::CanCreateProcessWithNewUserNS(): clone in a fresh child with
 * one namespace flag (plus SIGCHLD), child _exit(0)s immediately, parent
 * reports wait status. A blocked namespace => child dies with SIGSYS/SIGXCPU
 * or clone returns -1 EINVAL/EPERM. */
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

static int child_fn(void *arg) { (void)arg; _exit(0); }

static void test(const char *name, int flag) {
    const int STACK = 128 * 1024;
    void *mem = mmap(NULL, STACK, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (mem == MAP_FAILED) { printf("%-14s mmap FAIL\n", name); return; }
    int pid = (int)syscall(SYS_clone, flag | SIGCHLD,
                           (char *)mem + STACK, NULL, NULL, 0);
    if (pid < 0) {
        perror(name);
        printf("%-14s clone_ret=-1 (see errno above)\n", name);
    } else if (pid == 0) {
        child_fn(NULL);
        _exit(1);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            printf("%-14s OK (child exited cleanly)\n", name);
        else if (WIFSIGNALED(status))
            printf("%-14s KILLED by signal %d\n", name, WTERMSIG(status));
        else
            printf("%-14s abnormal status=%d\n", name, status);
    }
    munmap(mem, STACK);
}

int main(void) {
    test("CLONE_NEWUSER", CLONE_NEWUSER);
    test("CLONE_NEWPID", CLONE_NEWPID);
    test("CLONE_NEWNET", CLONE_NEWNET);
    test("CLONE_NEWNS", CLONE_NEWNS);
    test("CLONE_NEWIPC", CLONE_NEWIPC);
    test("CLONE_NEWUTS", CLONE_NEWUTS);
    return 0;
}
