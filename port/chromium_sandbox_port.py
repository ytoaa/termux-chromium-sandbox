#!/usr/bin/env python3
"""Termux Chromium seccomp-only sandbox port — semantic source transformer.

Single source of truth for Chromium-side compatibility changes (mirrors
termux-firefox-sandbox's firefox_sandbox_port.py model):
  - every rule is contract-checked against the real source shape;
  - outcomes per rule: APPLIED | ALREADY_PRESENT | (fail-closed) PortError;
  - the CI workflow is orchestration only and never embeds C++ patches.

Target: desktop-Linux Chromium built by Termux (Bionic aarch64), where
CLONE_NEWUSER is kernel-blocked (EINVAL) and no setuid helper can ship,
yet seccomp-bpf self-install is proven viable (poc/seccomp_probe.c).

Rules (see port/DESIGN.md Phase 0.3 / FINAL verdict):
  R1  content/browser/zygote_host/zygote_host_impl_linux.cc
      ZygoteHostImpl::Init(): under Bionic, do NOT LOG(FATAL) when neither
      userns nor setuid layer-1 is usable; continue with both layer-1 modes
      off (LaunchZygote/EnterLayerOneSandbox already tolerate that state).
  R2  sandbox/policy/linux/sandbox_linux.cc
      InitializeSandbox(): under Bionic, never EngageNamespaceSandbox();
      keep the BPF layer (StartSeccompBPF) exactly as upstream does.

Markers (also used by the future binary gate on libfrontend/chrome):
  "Termux seccomp-only sandbox:"   R1 marker string
  "Termux seccomp-only port:"      R2 marker string
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

R1_MARKER = "Termux seccomp-only sandbox:"
R2_MARKER = "Termux seccomp-only port:"
R3_MARKER = "Termux seccomp-only bionic-prctl:"
R4_MARKER = "Termux seccomp-only zygote passthrough:"
R5_MARKER = "Termux seccomp-only stack-top prewarm:"
R7_MARKER = "Termux seccomp-only bionic stack cache:"
R8_MARKER = "Termux seccomp-only bionic stack-top:"
R9A_MARKER = "Termux seccomp-only net-sockopt:"
R10_MARKER = "Termux seccomp-only bionic-sigsys:"
R11_BEFORE_MARKER = "Termux seccomp-only r11-before-reset:"
R11_TRAP_MARKER = "Termux seccomp-only r11-trap-owner:"
R11_REG_MARKER = "Termux seccomp-only r11-trap-create:"
R12_MARKER = "Termux seccomp-only r12-bionic-tid:"


class PortError(RuntimeError):
    pass


@dataclass
class Change:
    name: str
    path: str
    status: str
    detail: str = ""


class Port:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.changes: list[Change] = []
        self.before_sha: dict[str, str] = {}
        self.after_sha: dict[str, str] = {}

    # ---------- plumbing (mirrors the Firefox port) ----------
    def p(self, rel: str) -> Path:
        path = self.root / rel
        if not path.is_file():
            raise PortError(f"required source file missing: {rel}")
        return path

    @staticmethod
    def sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def remember_before(self, rel: str) -> None:
        self.before_sha.setdefault(rel, self.sha(self.p(rel)))

    def remember_after(self, rel: str) -> None:
        self.after_sha[rel] = self.sha(self.p(rel))

    def record(self, name: str, rel: str, status: str, detail: str = "") -> None:
        self.changes.append(Change(name, rel, status, detail))
        print(f"[{status:>15}] {name}: {detail}".rstrip())

    def replace_optional(self, rel: str, name: str, old: str, new: str) -> None:
        """Like replace_once but tolerates a missing file (vendored subtree
        that this build may not ship). Present-but-drifted still fails closed."""
        if not (self.root / rel).is_file():
            self.record(name, rel, "SKIPPED", "file not present in this source tree")
            return
        self.replace_once(rel, name, old, new)

    def replace_once(self, rel: str, name: str, old: str, new: str) -> None:
        path = self.p(rel)
        self.remember_before(rel)
        text = path.read_text()
        if new in text:
            self.record(name, rel, "ALREADY_PRESENT")
            return
        count = text.count(old)
        if count != 1:
            raise PortError(f"{name}: expected exactly one old form, found {count}")
        path.write_text(text.replace(old, new, 1))
        self.record(name, rel, "APPLIED")
        self.remember_after(rel)

    # ---------- rules ----------
    ZYGOTE_HOST = "content/browser/zygote_host/zygote_host_impl_linux.cc"
    SANDBOX_LINUX = "sandbox/policy/linux/sandbox_linux.cc"
    TRAP = "sandbox/linux/seccomp-bpf/trap.cc"
    SYSCALL_RESTRICT = "sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.cc"
    NETWORK_POLICY = "sandbox/policy/linux/bpf_network_policy_linux.cc"
    RENDERER_POLICY = "sandbox/policy/linux/bpf_renderer_policy_linux.cc"
    STACK_TRACE = "base/debug/stack_trace.cc"
    PA_STACK_TRACE = ("base/allocator/partition_allocator/src/partition_alloc/"
                      "partition_alloc_base/debug/stack_trace.cc")
    PA_STACK = ("base/allocator/partition_allocator/src/partition_alloc/"
                "stack/stack.cc")

    R1_OLD = '''LOG(FATAL)
        << "No usable sandbox! If you are running on Ubuntu 23.10+ or another "
           "Linux distro that has disabled unprivileged user namespaces with "
           "AppArmor, see "
           "https://chromium.googlesource.com/chromium/src/+/main/"
           "docs/security/apparmor-userns-restrictions.md. Otherwise see "
           "https://chromium.googlesource.com/chromium/src/+/main/"
           "docs/linux/suid_sandbox_development.md for more information on "
           "developing with the (older) SUID sandbox. "
           "If you want to live dangerously and need an immediate workaround, "
           "you can try using --"
        << sandbox::policy::switches::kNoSandbox << ".";'''

    R1_NEW = '''#if defined(__BIONIC__)
        // ''' + R1_MARKER + ''' neither the userns nor the setuid layer-1
        // sandbox is available on Android/Termux; proceed with both layer-1
        // modes off so forked children still install seccomp-bpf policy
        // filters via StartSeccompBPF (seccomp-only mode).
        DLOG(WARNING) << "''' + R1_MARKER + ''' no layer-1 sandbox; "
                      << "BPF policies remain the only sandbox layer.";
#else
        ''' + R1_OLD.replace("LOG(FATAL)", "LOG(FATAL)") + '''
#endif'''

    R2_OLD = '''if (options.engage_namespace_sandbox)
    EngageNamespaceSandbox(false /* from_zygote */);'''

    R2_NEW = '''#if defined(__BIONIC__)
    // ''' + R2_MARKER + ''' Android blocks CLONE_NEWUSER; the namespace
    // pivot is never available, and attempting it CHECK-fails. Skip it and
    // rely on the seccomp-bpf layer installed by StartSeccompBPF below.
    (void)options.engage_namespace_sandbox;
#else
    ''' + R2_OLD + '''
#endif'''

    # R3 (Phase 3, device gate round 1): RestrictPrctl() allow-lists the
    # arm64-Android prctl options only under BUILDFLAG(IS_ANDROID). Termux
    # builds chromium with os=linux (IS_ANDROID=false) yet runs on Android/
    # arm64, where bionic/zygote child setup issues prctl(PR_PAC_RESET_KEYS)
    # (0x36) - unlisted -> CrashSIGSYSPrctl -> boot-loop of every sandboxed
    # process (observed identically on kernel 6.1 main device and 4.19
    # test device; the exact class of failure termux cr-patch 1001 "solved"
    # by killing the whole sandbox). Extend the list under __BIONIC__ only.
    R3_OLD = """      .Cases({PR_GET_NAME, PR_SET_NAME, PR_GET_DUMPABLE, PR_SET_DUMPABLE"""

    R3_NEW = """      .Cases({PR_GET_NAME, PR_SET_NAME, PR_GET_DUMPABLE, PR_SET_DUMPABLE
#if defined(__BIONIC__)
              // """ + R3_MARKER + """ android-prctl options survive the
              // os=linux build tag: bionic clone/fork child setup resets PAC
              // keys and Android userspace probes MTE/SVE/seccomp-cache.
              // Without these, CrashSIGSYSPrctl boot-loops every process
              // that engages the seccomp-only sandbox.
              , 54   /* PR_PAC_RESET_KEYS */
              , 55   /* PR_PAC_GET_ENABLED_KEYS */
              , 56   /* PR_GET_TAGGED_ADDR_CTRL */
              , 44   /* PR_SET_THP_DISABLE */
              , 41   /* PR_SET_TIMERSLACK_PID (android-3.14) */
              , 43   /* PR_SET_TIMERSLACK_PID (android-3.18) */
              , 127  /* PR_SET_TIMERSLACK_PID (android-4.1+) */
              , 58   /* PR_SECCOMP_CACHE_FLUSH (bionic seccomp cache) */
#endif"""

    # R4 (device-gate round 2): the zygote installs a permissive-until-relaxed
    # BPF that is inherited by every forked child and can never be removed.
    # bionic issues prctl/set_tid_address in the clone-child path before the
    # broker relaxes it: strace shows the whole renderer dying simultaneously
    # with si_code=SYS_SECCOMP si_syscall=__NR_set_tid_address (glibc desktop
    # never calls it there, hence no upstream coverage). The zygote is a
    # launcher, not a security boundary — pass it through (same precedent as
    # IsUnsandboxedSandboxType returning true without installing). Child
    # processes still install their own policies via StartSeccompBPF.
    R4_OLD = '''  if (IsUnsandboxedSandboxType(sandbox_type) ||
      !SandboxSeccompBPF::IsSeccompBPFDesired() ||
      !SandboxSeccompBPF::SupportsSandbox()) {
    return true;
  }'''

    R4_NEW = '''  if (IsUnsandboxedSandboxType(sandbox_type) ||
      !SandboxSeccompBPF::IsSeccompBPFDesired() ||
      !SandboxSeccompBPF::SupportsSandbox()) {
    return true;
  }

#if defined(__BIONIC__)
  // ''' + R4_MARKER + ''' Android/Termux: do not install a BPF in
  // the zygote itself. bionic's clone-child setup (set_tid_address) trips the
  // inherited zygote filter and RET_KILLs every renderer before its ping.
  // Launcher stays on the Android platform baseline filter; each child type
  // still installs its own policy below — that is where this port's
  // enforcement lives.
  if (sandbox_type == sandbox::mojom::Sandbox::kZygoteIntermediateSandbox) {
    LOG(WARNING) << "''' + R4_MARKER + ''' no BPF in zygote; "
                 << "child policies enforce the sandbox.";
    seccomp_bpf_started_ = true;
    return true;
  }
#endif'''
    # R5 (device-gate round 3, abort() backtrace forensics): PartitionAlloc's
    # StackTopRegistry lazily calls pthread_getattr_np on first use per thread
    # (flat_map keyed by TID - a zygote prewarm cannot help forked children,
    # which have fresh TIDs). Post-filter, /proc is unreadable and BIONIC
    # pthread_getattr_np LOG(FATAL)s internally: the renderer aborts right
    # after "Activated seccomp-bpf" with no message (desktop survives because
    # glibc degrades gracefully and PA even has a __libc_stack_end fallback;
    # bionic has none). Prewarm the current thread BEFORE the filter engages.
    # NOTE(run #16/#17): forward decls must sit at TRUE file scope - namespace
    # declarations nest, so an insertion inside `namespace sandbox { ... }`
    # mangles as sandbox::policy::partition_alloc::... and fails to link.
    R5_OLD = '''namespace sandbox {'''

    R5_NEW = '''#if defined(__BIONIC__)
namespace base::debug {
uintptr_t GetStackEnd();
}  // namespace base::debug
namespace partition_alloc::internal::base::debug {
uintptr_t GetStackEnd();
}  // namespace partition_alloc::internal::base::debug
namespace partition_alloc::internal {
void* TermuxPrewarmStackTop();
}  // namespace partition_alloc::internal
#endif

// ''' + R5_MARKER + ''' (file-scope decl; warm call in StartSeccompBPF)
namespace sandbox {'''

    R5B_OLD = '''  CHECK(!seccomp_bpf_started_);
  CHECK(pre_initialized_);'''

    R5B_NEW = '''  CHECK(!seccomp_bpf_started_);
  CHECK(pre_initialized_);
#if defined(__BIONIC__)
  // Warm base::debug::internal::GetStackEnd() on the MAIN thread before the
  // BPF denies /proc: on bionic the glibc __libc_stack_end fast path is
  // compiled out, and pthread_getattr_np(main) LOG(FATAL)s when it cannot
  // read /proc/self/maps (upstream comment at base/debug/stack_trace.cc:228
  // documents the maps read; the renderer killed itself here post-activation
  // in device-gate rounds 3-4). The static-once cache is then inherited by
  // forked children; all later callers take the cached hit. [[gnu::used]]
  // prevents the optimizer from deleting the "unused" prewarm call.
  [[gnu::used]] const uintptr_t warmed_a = ::base::debug::GetStackEnd();
  [[gnu::used]] const uintptr_t warmed_b =
      ::partition_alloc::internal::base::debug::GetStackEnd();
  // R8: fill partition_alloc's main-thread stack-top cache as well; without
  // this the first lookup happens after the BPF denies /proc and bionic's
  // pthread_getattr_np LOG(FATAL)s (SIGABRT boot loop).
  [[gnu::used]] void* const warmed_c =
      ::partition_alloc::internal::TermuxPrewarmStackTop();
  (void)(warmed_a + warmed_b);
  (void)warmed_c;
#endif'''

    # R7 (device-gate round 5, the actual fix): R5/R6 prewarms were dead code
    # because upstream gates the bionic main-thread cache behind
    # BUILDFLAG(IS_ANDROID) - and termux builds chromium with os=linux, so the
    # `static uintptr_t main_stack_end` never existed, and GetStackEnd called
    # pthread_getattr_np on EVERY invocation. Post-BPF that is fatal: bionic's
    # implementation reads /proc/self/maps (main thread) and LOG(FATAL)s ->
    # SIGABRT (strace: 3 call sites, all tid==pid). Enable upstream's own
    # bionic cache under __BIONIC__ so the prewarm in StartSeccompBPF (R6)
    # actually stores a value that every later call reuses.
    R7_OLD = '''#if BUILDFLAG(IS_ANDROID)
  // Bionic reads proc/maps on every call to pthread_getattr_np() when called'''

    R7_NEW = '''#if BUILDFLAG(IS_ANDROID) || defined(__BIONIC__)
  // ''' + R7_MARKER + ''' os=linux on bionic: keep upstream's bionic
  // main-thread cache compiled in, so the value prewarmed before the seccomp
  // filter is installed is reused afterwards instead of hitting
  // pthread_getattr_np (which reads /proc/self/maps and LOG(FATAL)s once the
  // BPF denies openat).
  // Bionic reads proc/maps on every call to pthread_getattr_np() when called'''

    R7B_OLD = '''#if PA_BUILDFLAG(IS_ANDROID)
  // Bionic reads proc/maps on every call to pthread_getattr_np() when called'''

    R7B_NEW = '''#if PA_BUILDFLAG(IS_ANDROID) || defined(__BIONIC__)
  // ''' + R7_MARKER + ''' partition_alloc copy of the same bionic cache
  // (PA-Everywhere); see R7 above.
  // Bionic reads proc/maps on every call to pthread_getattr_np() when called'''

    # R8 (device-gate round 6): partition_alloc's per-thread stack-top lookup
    # calls pthread_getattr_np unconditionally. On bionic that reads
    # /proc/self/maps for the main thread and LOG(FATAL)s once the seccomp BPF
    # denies openat (strace/gnp-shim: 3 gnp sites per process, 2 pre-filter
    # (R6 prewarm) + 1 post-filter from this path -> SIGABRT boot loop).
    # Cache the main thread value (constant for the process) and export a
    # prewarm entry point so StartSeccompBPF can fill it before the filter
    # engages. Non-main threads keep bionic's cheap pthread_t path.
    R8A_OLD = '''void* GetStackTop() {
  pthread_attr_t attr;
  int error = pthread_getattr_np(pthread_self(), &attr);
  if (!error) {
    void* base;
    size_t size;
    error = pthread_attr_getstack(&attr, &base, &size);
    PA_CHECK(!error);
    pthread_attr_destroy(&attr);
    return PA_UNSAFE_TODO(reinterpret_cast<uint8_t*>(base) + size);
  }'''

    R8A_NEW = '''void* GetStackTop() {
#if defined(__BIONIC__)
  // ''' + R8_MARKER + ''' cache the main thread's stack top: it never
  // changes, and bionic's pthread_getattr_np reads /proc/self/maps (main
  // thread only) which the seccomp BPF denies after sandbox engagement.
  static void* cached_main_top = nullptr;
  const bool is_main_thread =
      pthread_equal(pthread_self(), g_termux_main_thread) != 0;
  if (is_main_thread && cached_main_top)
    return cached_main_top;
#endif
  pthread_attr_t attr;
  int error = pthread_getattr_np(pthread_self(), &attr);
  if (!error) {
    void* base;
    size_t size;
    error = pthread_attr_getstack(&attr, &base, &size);
    PA_CHECK(!error);
    pthread_attr_destroy(&attr);
#if defined(__BIONIC__)
    if (is_main_thread)
      cached_main_top = PA_UNSAFE_TODO(reinterpret_cast<uint8_t*>(base) + size);
#endif
    return PA_UNSAFE_TODO(reinterpret_cast<uint8_t*>(base) + size);
  }'''

    R8B_OLD = '''#else  // PA_BUILDFLAG(IS_WIN)
#error "Unsupported GetStackTop"
#endif  // PA_BUILDFLAG(IS_WIN)'''

    R8B_NEW = '''#else  // PA_BUILDFLAG(IS_WIN)
#error "Unsupported GetStackTop"
#endif  // PA_BUILDFLAG(IS_WIN)

#if defined(__BIONIC__)
// ''' + R8_MARKER + ''' prewarm entry point (called from
// SandboxLinux::StartSeccompBPF before the BPF is installed).
void* TermuxPrewarmStackTop() {
  return GetStackTop();
}
#endif  // defined(__BIONIC__)'''

    R8C_OLD = '''namespace partition_alloc::internal {'''

    R8C_NEW = '''namespace partition_alloc::internal {
#if defined(__BIONIC__)
// ''' + R8_MARKER + ''' captured during static init, i.e. on the main
// thread before any sandbox exists; used to recognise main-thread callers.
const pthread_t g_termux_main_thread = pthread_self();
#endif'''

    # R9a (round 10, A/B matrix on run #28): the network service queries
    # getsockopt(fd, SOL_SOCKET, SO_DOMAIN) at startup (socket tagging);
    # RestrictGetSockoptForNetworkService() allows only SO_ERROR at
    # SOL_SOCKET, so enabling NetworkServiceSandbox crash-looped the utility
    # (trap nr=209 __NR_getsockopt, args (fd, 1, 39=SO_DOMAIN) — observed on
    # the 4.19 testbed AND BPF install proven on kernel 6.1 census).
    # Approved scope (review, single-CI-candidate): this ONE (SOL_SOCKET,
    # SO_DOMAIN) get-pair under __BIONIC__ only. Do NOT extend here:
    # SO_PROTOCOL and any setsockopt change require their own observed trap.
    R9A_OLD = """  ResultExpr socket_optname_switch =
      Switch(optname).Case(SO_ERROR, Allow()).Default(CrashSIGSYSSockopt());"""

    R9A_NEW = """  ResultExpr socket_optname_switch =
      Switch(optname)
          .Case(SO_ERROR, Allow())
#if defined(__BIONIC__)
          // """ + R9A_MARKER + """ bionic net stack queries SO_DOMAIN at
          // network-service startup (socket tagging); upstream Linux never
          // reaches this optname from the network policy (feature is
          // default-off there). get-side only; setsockopt untouched.
          .Case(SO_DOMAIN, Allow())
#endif  // defined(__BIONIC__)
          .Default(CrashSIGSYSSockopt());"""


    # R12 (Issue #12 root cause, 2026-10-28): the renderer baseline chain
    # (baseline_policy.cc IsBaselinePolicyAllowed -> SyscallSets::
    # IsAllowedProcessStartOrDeath, syscall_sets.cc) does NOT list
    # __NR_set_tid_address on any arch: the case falls through to
    # default:false and the tail of EvaluateSyscallImpl returns
    # CrashSIGSYS(). Bionic's detached-pthread exit calls
    # set_tid_address(NULL) immediately after rt_sigprocmask(SIG_BLOCK,
    # ~[]) blocks EVERY signal; a seccomp RET_TRAP delivered to a thread
    # with SIGSYS blocked is force_sig'd by the kernel, so Chromium's
    # handler never runs and the WHOLE renderer dies silently with
    # wait-status 31 (the historical RESULT_CODE_INVALID_SANDBOX_STATE tab
    # deaths; crashpad never sees it). 21/21 strace siginfo captures:
    # si_syscall=__NR_set_tid_address si_code=SYS_SECCOMP si_errno=EPERM
    # (trap index 1); control traps on unblocked threads ran the handler
    # (rt_sigreturn) and survived. Upstream Android allows this exact
    # syscall unconditionally in BaselinePolicyAndroid
    # (baseline_policy_android.cc); this port builds with os=linux
    # (IS_ANDROID=false) so that list is compiled out — the same bionic
    # blind-spot class as R3 (prctl PAC) and R9a (SO_DOMAIN).
    # Scope lock: renderer policy only (the observed death site; zygote is
    # covered by R4, GPU never engages BPF on device, network utility has
    # its own policy), exactly ONE syscall arm, __BIONIC__ guard, no
    # parameter relaxation (the kernel only writes the tid to a caller
    # pointer), no KILL/TRAP disposition changes. The VLOG marker gives
    # both a binary strings gate and a per-activation runtime gate.
    R12_INCLUDE_OLD = '#include "build/build_config.h"'
    R12_INCLUDE_NEW = '''#include "build/build_config.h"
#if defined(__BIONIC__)
#include "base/logging.h"  // ''' + R12_MARKER + ''' VLOG (R12)
#endif'''
    R12_OLD = '''#if defined(__arm__) || defined(__aarch64__)
    case __NR_getcpu:
#endif
      return Allow();'''
    R12_NEW = '''#if defined(__arm__) || defined(__aarch64__)
    case __NR_getcpu:
#endif
#if defined(__BIONIC__)
    // ''' + R12_MARKER + ''' bionic detached-pthread exit calls
    // set_tid_address(NULL) with every signal blocked; RET_TRAP there is
    // force_sig'd by the kernel and kills the whole renderer without ever
    // running the SIGSYS handler (silent wait-status 31, Issue #12).
    // Upstream BaselinePolicyAndroid allows __NR_set_tid_address
    // unconditionally; os=linux builds compile that list out. Single
    // syscall arm, bionic guard only — see port/DESIGN.md Round 19.
    case __NR_set_tid_address:
      VLOG(1) << "Termux seccomp-only r12-bionic-tid: renderer allow active";
      return Allow();
#endif
      return Allow();'''

    # R10: Android's app zygote installs a seccomp policy AND SIGSYS
    # handler. Chromium's Android SeccompStarterAndroid::StartSandbox
    # explicitly resets SIGSYS to SIG_DFL before initializing Trap, but
    # Termux compiles desktop Linux paths on bionic (IS_ANDROID=false).
    # On device 2026-10-26 every sandboxed child logged
    # "Existing signal handler when trying to install SIGSYS" (trap.cc:106).
    # Do exactly what upstream Android does, in the child, immediately
    # before StartSandboxWithExternalPolicy, and only for bionic.
    # No syscall policy or privilege exception is introduced. Keep a CHECK
    # so failure to reserve SIGSYS cannot silently disable seccomp.
    R10_INCLUDE_OLD = "#include <stdint.h>"

    R10_INCLUDE_NEW = """#if defined(__BIONIC__)
#include <signal.h>
#endif
#include <stdint.h>"""

    R10_OLD = """  SandboxSeccompBPF::StartSandboxWithExternalPolicy(
      std::move(policy), OpenProc(proc_fd_), seccomp_level);"""

    R10_NEW = """#if defined(__BIONIC__)
  // """ + R10_MARKER + """ Chromium's Android SeccompStarterAndroid
  // resets the zygote-installed SIGSYS handler before installing its own
  // BPF trap handler. Termux is a desktop Linux build on bionic, so the
  // Android starter is not called. Reserve SIGSYS in this child, immediately
  // before Chromium installs the BPF policy; do not touch other signals.
  const auto old_sigsys_handler = signal(SIGSYS, SIG_DFL);
  CHECK(old_sigsys_handler != SIG_ERR)
      << "Termux seccomp-only bionic-sigsys: failed to reserve SIGSYS";
  if (old_sigsys_handler != SIG_DFL) {
    VLOG(1) << "Termux seccomp-only bionic-sigsys: "
               "replaced pre-existing Android SIGSYS handler";
  }
#endif  // defined(__BIONIC__)
""" + R10_OLD


    # R11 DIAGNOSTICS ONLY (2026-10-26, DEVICE NO-GO):
    # Trap::Trap() has been observed in a forked child with an existing
    # SIGSYS action about 25ms before the parent's R10 reset. Do NOT change
    # filter policy, signal dispositions or R10's reset in this experiment.
    # Log categorical signal-owner state, not raw handler pointers.
    # Chromium's existing log prefix supplies both PID and TID.
    R11_BEFORE_OLD = """  const auto old_sigsys_handler = signal(SIGSYS, SIG_DFL);"""
    R11_BEFORE_NEW = """  // """ + R11_BEFORE_MARKER + """ read-only ownership probe (before R10).
  struct sigaction termux_r11_before = {};
  CHECK(sigaction(SIGSYS, nullptr, &termux_r11_before) == 0);
  VLOG(1) << "Termux seccomp-only r11-before-reset: "
          << (termux_r11_before.sa_handler == SIG_DFL ? "default" :
              termux_r11_before.sa_handler == SIG_IGN ? "ignored" :
                                                            "installed")
          << " siginfo=" << !!(termux_r11_before.sa_flags & SA_SIGINFO);
""" + R11_BEFORE_OLD

    R11_TRAP_OLD = """  if (!IsDefaultSignalAction(old_sa)) {"""
    R11_TRAP_NEW = """#if defined(__BIONIC__)
  // """ + R11_TRAP_MARKER + """ classify the *previous* action. The
  // trap constructor already replaced it via sys_sigaction above.
  // Only this class can compare it against its own SigSysAction without
  // exposing a raw function pointer.
  const bool r11_previous_chromium =
      old_sa.sa_handler == reinterpret_cast<void (*)(int)>(SigSysAction);
  VLOG(1) << "Termux seccomp-only r11-trap-owner: prior="
          << (IsDefaultSignalAction(old_sa) ? "default" :
              r11_previous_chromium ? "chromium" :
              old_sa.sa_handler == SIG_IGN ? "ignored" : "foreign")
          << " siginfo=" << !!(old_sa.sa_flags & SA_SIGINFO);
#endif  // defined(__BIONIC__)
""" + R11_TRAP_OLD

    R11_REG_OLD = """  if (!global_trap_) {
    global_trap_ = new Trap();"""
    R11_REG_NEW = """  if (!global_trap_) {
#if defined(__BIONIC__)
    // """ + R11_REG_MARKER + """ first registry creation in this process.
    VLOG(1) << "Termux seccomp-only r11-trap-create: first construction";
#endif  // defined(__BIONIC__)
    global_trap_ = new Trap();"""

    def apply(self) -> None:
        self.replace_once(self.ZYGOTE_HOST, "R1 seccomp-only usable mode (Bionic)",
                          self.R1_OLD, self.R1_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R2 skip namespace engage (Bionic)",
                          self.R2_OLD, self.R2_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R10 bionic SIGSYS reservation include",
                          self.R10_INCLUDE_OLD, self.R10_INCLUDE_NEW)
        # R11 instruments *inside* the exact R10 patch body. On the
        # second invocation the original uninstrumented R10_NEW is no
        # longer contiguous, even though R10 is already applied. Recognize
        # only the exact fully instrumented R10 body. A partial or
        # corrupted body is NOT accepted as ALREADY_PRESENT.
        r10_instrumented = self.R10_NEW.replace(
            self.R11_BEFORE_OLD, self.R11_BEFORE_NEW)
        if self.p(self.SANDBOX_LINUX).read_text().count(r10_instrumented) == 1:
            self.record("R10 bionic SIGSYS reservation before BPF",
                        self.SANDBOX_LINUX, "ALREADY_PRESENT",
                        "exact R11-instrumented R10 body")
        else:
            self.replace_once(self.SANDBOX_LINUX,
                              "R10 bionic SIGSYS reservation before BPF",
                              self.R10_OLD, self.R10_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R11 SIGSYS action snapshot before R10",
                          self.R11_BEFORE_OLD, self.R11_BEFORE_NEW)
        self.replace_once(self.TRAP, "R11 classify prior handler at Trap::Trap",
                          self.R11_TRAP_OLD, self.R11_TRAP_NEW)
        self.replace_once(self.TRAP, "R11 report first Trap::Registry creation",
                          self.R11_REG_OLD, self.R11_REG_NEW)
        self.replace_once(self.SYSCALL_RESTRICT, "R3 bionic prctl options (arm64-Android)",
                          self.R3_OLD, self.R3_NEW)
        self.replace_once(self.RENDERER_POLICY, "R12 logging include (Bionic)",
                          self.R12_INCLUDE_OLD, self.R12_INCLUDE_NEW)
        self.replace_once(self.RENDERER_POLICY, "R12 bionic set_tid_address renderer allow",
                          self.R12_OLD, self.R12_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R4 zygote passthrough (Bionic)",
                          self.R4_OLD, self.R4_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R5 stack-top decl (Bionic)",
                          self.R5_OLD, self.R5_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R5 stack-top prewarm call (Bionic)",
                          self.R5B_OLD, self.R5B_NEW)
        self.replace_once(self.NETWORK_POLICY, "R9a getsockopt(SOL_SOCKET, SO_DOMAIN) (Bionic)",
                          self.R9A_OLD, self.R9A_NEW)
        self.replace_once(self.STACK_TRACE, "R7 bionic stack cache (base)",
                          self.R7_OLD, self.R7_NEW)
        self.replace_optional(self.PA_STACK_TRACE, "R7 bionic stack cache (PA copy)",
                              self.R7B_OLD, self.R7B_NEW)
        self.replace_optional(self.PA_STACK, "R8 main-thread capture (PA stack.cc)",
                              self.R8C_OLD, self.R8C_NEW)
        self.replace_optional(self.PA_STACK, "R8 bionic stack-top cache (PA stack.cc)",
                              self.R8A_OLD, self.R8A_NEW)
        self.replace_optional(self.PA_STACK, "R8 prewarm entry point (PA stack.cc)",
                              self.R8B_OLD, self.R8B_NEW)

    # ---------- verifier (fail-closed gates) ----------
    def verify(self) -> None:
        # Gate 1: both markers present exactly once in their files.
        for rel, marker, label in (
            (self.ZYGOTE_HOST, R1_MARKER, "R1"),
            (self.SANDBOX_LINUX, R2_MARKER, "R2"),
            (self.SYSCALL_RESTRICT, R3_MARKER, "R3"),
            (self.NETWORK_POLICY, R9A_MARKER, "R9a"),
            (self.RENDERER_POLICY, R12_MARKER, "R12"),
            (self.SANDBOX_LINUX, R10_MARKER, "R10"),
            (self.SANDBOX_LINUX, R11_BEFORE_MARKER, "R11 pre"),
            (self.TRAP, R11_TRAP_MARKER, "R11 trap"),
            (self.TRAP, R11_REG_MARKER, "R11 registry"),
            (self.SANDBOX_LINUX, R4_MARKER, "R4"),
            (self.SANDBOX_LINUX, R5_MARKER, "R5"),
            (self.STACK_TRACE, R7_MARKER, "R7"),
        ):
            text = self.p(rel).read_text()
            n = text.count(marker)
            if n < 1:
                raise PortError(f"verifier: {label} marker absent from {rel}")
            print(f"[     VERIFIED] {label} marker in {rel} ({n}x)")
        # Gate 2: no unguarded 'false' namespace engage removal — the Bionic
        # branch must be #if-guarded so glibc/Linux builds keep upstream code.
        text = self.p(self.SANDBOX_LINUX).read_text()
        if "#if defined(__BIONIC__)" not in text or "#else" not in text:
            raise PortError("verifier: R2 guard structure missing")
        print(f"[     VERIFIED] R2 preprocessor guard structure intact")
        # R10 is only valid on bionic and only before Chromium's BPF
        # installer. Refuse source drift, accidental removal of SIG_DFL
        # reset, and incomplete include/guard changes.
        pos = text.find(R10_MARKER)
        next_pos = text.find("SandboxSeccompBPF::StartSandboxWithExternalPolicy(", pos)
        if (pos < 0 or next_pos < 0 or next_pos - pos > 2200 or
                'signal(SIGSYS, SIG_DFL)' not in text[pos:next_pos] or
                'CHECK(old_sigsys_handler != SIG_ERR)' not in text[pos:next_pos] or
                '#if defined(__BIONIC__)' not in text[max(0, pos-12):pos+80] and
                '#if defined(__BIONIC__)' not in text[max(0, pos-250):pos]):
            raise PortError("verifier: R10 Bionic SIGSYS reset/guard/ordering drift")
        if '#include <signal.h>' not in text:
            raise PortError("verifier: R10 missing signal.h")
        print("[     VERIFIED] R10 Bionic-only SIGSYS reservation before BPF")
        # R11: fail closed on missing instrumentation, unsafe disposition
        # changes, unexpected order, or unguarded instrumentation.
        pre = text.index(R11_BEFORE_MARKER)
        reset = text.index("signal(SIGSYS, SIG_DFL)", pre)
        bpf = text.index("SandboxSeccompBPF::StartSandboxWithExternalPolicy(", reset)
        if not (pre < reset < bpf and
                text.count("sigaction(SIGSYS, nullptr, &termux_r11_before)") == 1 and
                text.count("const auto old_sigsys_handler = signal(SIGSYS, SIG_DFL);") == 1 and
                "CHECK(sigaction(SIGSYS, nullptr, &termux_r11_before) == 0)" in text[pre:reset]):
            raise PortError("verifier: R11 read-only pre-R10 snapshot/order drift")
        trap = self.p(self.TRAP).read_text()
        registry = trap.index(R11_REG_MARKER)
        constructor = trap.index(R11_TRAP_MARKER)
        old_checker = trap.index("if (!IsDefaultSignalAction(old_sa))", constructor)
        if not (constructor < old_checker < registry
                and "#if defined(__BIONIC__)" in trap[registry-130:registry]
                and "const bool r11_previous_chromium" in trap[constructor:old_checker]
                and "sigaction(LINUX_SIGSYS" not in trap[constructor:old_checker]
                and trap.count("sys_sigaction(LINUX_SIGSYS, &sa, &old_sa)") == 1
                and trap.count("global_trap_ = new Trap();") == 1):
            raise PortError("verifier: R11 Trap owner/create probe drift")
        print("[     VERIFIED] R11 read-only signal owner/order probes; BPF policy unchanged")
        # R12: fail closed on any scope drift in the renderer policy. The
        # patch must be the EXACT approved block (bionic-guarded, single
        # syscall arm), the include must be guarded, the marker must appear
        # exactly 3 times (include comment, policy comment, VLOG string) and
        # __NR_set_tid_address must be the only case added anywhere in the
        # file. Anything else rejects the candidate instead of shipping a
        # widened filter.
        rend = self.p(self.RENDERER_POLICY).read_text()
        if rend.count(R12_MARKER) != 3:
            raise PortError("verifier: R12 marker count drift (want include+comment+VLOG)")
        if rend.count(self.R12_NEW) != 1 or rend.count(self.R12_INCLUDE_NEW) != 1:
            raise PortError("verifier: R12 approved block/include drift")
        if rend.count("case __NR_set_tid_address:") != 1:
            raise PortError("verifier: R12 set_tid_address arm not exactly once")
        if '#include "base/logging.h"' not in rend:
            raise PortError("verifier: R12 missing guarded logging include")
        print("[     VERIFIED] R12 renderer-only bionic set_tid_address allow; scope intact")
        # Gate 3: vendored PA patches must be present WHENEVER the subtree is
        # shipped (silently skipping them would ship a build that still calls
        # pthread_getattr_np after the filter - the exact boot-loop we fix).
        for rel, marker, label in (
            (self.PA_STACK_TRACE, R7_MARKER, "R7 (PA copy)"),
            (self.PA_STACK, R8_MARKER, "R8 (PA stack.cc)"),
        ):
            if (self.root / rel).is_file():
                n = self.p(rel).read_text().count(marker)
                if n < 1:
                    raise PortError(f"verifier: {label} marker absent from {rel}")
                print(f"[     VERIFIED] {label} marker in {rel} ({n}x)")
            else:
                print(f"[     VERIFIED] {label} n/a (vendored tree absent)")

    # ---------- anti-injection scan ----------
    def anti_injection_scan(self, dirs: list[str]) -> None:
        """Fail closed if any source besides sandbox_type.cc appends the
        browser-visible --no-sandbox switch (the stock-binary silent
        downgrade mystery, DESIGN.md Phase 0.3)."""
        import re
        pattern = re.compile(r"AppendSwitch\(\s*(sandbox::policy::)?switches::kNoSandbox\s*\)")
        # Reviewed allowlist (production):
        #  - sandbox_type.cc: the official per-child-type token mechanism
        #  - render_process_host_impl.cc: upstream unsandboxed-relaunch site
        #    (browser-side child spawn, NOT a browser-process downgrade)
        # Test sources (unittest/browsertest/content/test, headless/test) are
        # exempt: they never ship in the package build graph.
        allowed = {
            "sandbox/policy/sandbox_type.cc",
            "content/browser/renderer_host/render_process_host_impl.cc",
        }
        test_pat = re.compile(r"(_unittest|_browsertest|_test)\.cc$|(^|/)tests?/")
        offenders: list[str] = []
        for d in dirs:
            base = self.root / d
            if not base.is_dir():
                continue
            for f in base.rglob("*.cc"):
                rel = str(f.relative_to(self.root))
                if test_pat.search(rel):
                    continue
                try:
                    txt = f.read_text(errors="ignore")
                except OSError as e:
                    # Audit round (2026-10-30): an unreadable scan target is a
                    # fail-closed OFFENDER, not a bare traceback. Previously
                    # the OSError escaped (stderr, rc invisible behind tee);
                    # now it is named in the PortError list and the hardened
                    # hook (DESIGN Round 25) surfaces both rc and marker.
                    offenders.append(f"{rel} (unreadable {type(e).__name__})")
                    continue
                if pattern.search(txt) and rel not in allowed:
                    offenders.append(rel)
        if offenders:
            raise PortError("anti-injection gate: unexpected --no-sandbox append sites: "
                            + ", ".join(sorted(offenders)[:10]))
        print("[     VERIFIED] anti-injection scan (--no-sandbox appenders)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["apply", "check", "verify"])
    ap.add_argument("--src", required=True, help="chromium checkout root (contains src/)")
    ap.add_argument("--scan", default="", help="comma-separated dirs for anti-injection scan")
    args = ap.parse_args(argv[1:])

    src = Path(args.src)
    if (src / "src").is_dir() and (src / "src" / "sandbox").is_dir():
        src = src / "src"  # accept either a termux work dir or the src/ itself
    port = Port(src)
    if args.command == "apply":
        port.apply()
        port.verify()
        if args.scan:
            port.anti_injection_scan([s for s in args.scan.split(",") if s])
    elif args.command == "check":
        port.verify()
        if args.scan:
            port.anti_injection_scan([s for s in args.scan.split(",") if s])
    elif args.command == "verify":
        port.verify()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except PortError as e:
        print(f"[    PORT ERROR] {e}", file=sys.stderr)
        sys.exit(1)
