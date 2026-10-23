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
    SYSCALL_RESTRICT = "sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.cc"
    NETWORK_POLICY = "sandbox/policy/linux/bpf_network_policy_linux.cc"
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

    def apply(self) -> None:
        self.replace_once(self.ZYGOTE_HOST, "R1 seccomp-only usable mode (Bionic)",
                          self.R1_OLD, self.R1_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R2 skip namespace engage (Bionic)",
                          self.R2_OLD, self.R2_NEW)
        self.replace_once(self.SYSCALL_RESTRICT, "R3 bionic prctl options (arm64-Android)",
                          self.R3_OLD, self.R3_NEW)
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
                txt = f.read_text(errors="ignore")
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
