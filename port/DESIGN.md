# Architecture notes — v0 (Phase 0 decisions)

## Target

Termux `x11-packages/chromium` (currently 155.0.8059.79) builds desktop-Linux
Chromium against Bionic (gn: `custom_toolchain=//build/toolchain/linux/unbundle`,
no `target_os`/`is_android`). The sandbox is compiled in but unusable at
runtime on Android, so the package effectively runs with no sandbox.

## Device facts (2026-10-19, Android 17, kernel 6.1 GKI, aarch64)

| Probe | Result | Consequence |
|---|---|---|
| `unshare(CLONE_NEWUSER)` | EINVAL (no userns sysctls) | namespace sandbox impossible |
| setuid sandbox | impossible (Android SELinux blocks setuid) | out of scope permanently |
| self-installed seccomp-bpf + RET_TRAP/SIGSYS | PASS (poc/seccomp_probe.c) | BPF policy layer viable |

## Chosen path: seccomp-only, no namespaces

Chromium's Linux sandbox has three cooperating layers; we drop the middle one:

1. **BPF policy filters** (`sandbox/policy/linux/bpf_*_policy_linux.cc`) — KEEP.
   Precedent in-tree: Chrome-on-Android's app sandbox installs these same
   filter families from the zygote without namespaces.
2. **Namespace pivot / broker pid-ns setup** — DISABLE (kernel-blocked).
   Work will focus on making `SandboxLinux` init tolerate the non-namespace
   configuration on Bionic (this is the maintainer's "lots of patches").
3. **Setuid helper** — never compiled/used.

## Open questions (drives Phase 0.2/0.3)

- How does the shipped Termux chromium currently start (implicit fallback vs
  user-supplied `--no-sandbox`)? — empirical test pending.
- Which BPF policy families compile into the Termux build (`is_android=false`
  path) and which syscalls need Bionic argument fixes (SIGSYS chain,
  `SECCOMP_FILTER_FLAG_TSYNC` semantics on bionic, `clone` flags)?
- Renderer/GPU/utility broker IPC socketpair under SELinux app domain.
- GPU process: ANGLE/SwiftShader/Vulkan paths vs policy syscalls.

## Security posture

- Fail closed: any unknown policy function or syscall exception → build
  rejected until reviewed (verifier pattern from the Firefox port).
- No human-approval bypass: automation identities must be exact-bot-identity
  verified (lesson from the 2026-10 "exposed" incident), pre-merge harness
  inside the workflow_run chain before any merge authority.
- No personal data, emails (noreply only), device identifiers in repo, logs,
  or commit metadata.

## Device safety constraints (user-mandated, 2026-10-19)

- The maintainer device's installed `chromium` package (155.0.8059.79), its
  binaries, and the real profile at `~/.config/chromium` are OFF-LIMITS:
  never delete, modify, replace, or `dpkg`-operate on them.
- All runtime experiments MUST run with an isolated
  `--user-data-dir=<workspace>/chromium-test-profile*` and may only delete
  directories they created themselves under the workspace.
- Sandbox-port builds ship as a SEPARATE package identity (not an overwrite
  of Termux's `chromium`) so a test device can keep the stock browser intact;
  the apt/version-lead scheme is re-derived to preserve this property.

## Phase 0.2 findings — installed chromium 155.0.8059.79 runtime reality (2026-10-19)

Empirical (isolated profiles only; stock profile/package untouched):

1. Launched WITHOUT `--no-sandbox` (headless=new and windowed), browser runs
   fine, no "No usable sandbox" FATAL, no sandbox errors in logs.
2. Process filter census (`/proc/PID/status`, execve-verified): every chrome
   process shows `Seccomp: 2 / Seccomp_filters: 1` — the ONE filter is the
   Android app baseline (a plain Termux bash shows the identical values).
   => ZERO Chromium BPF filters installed anywhere. Renderer/GPU/utility all
   unsandboxed by Chromium.
3. Zygote child argv carries a real `--no-sandbox` token (headless confirmed
   by raw argv dump; windowed substring evidence was inconclusive — revisit).
4. `ZygoteHostImpl::Init` (content/browser/zygote_host/zygote_host_impl_linux.cc:102-157)
   should `LOG(FATAL) "No usable sandbox!"` when userns is unavailable AND no
   setuid helper exists — yet it early-returns, which per L103 requires
   `--no-sandbox` present on the in-memory browser command line, while the
   browser's own /proc argv LACKS it. An injector modifies the browser
   command line at startup before zygote init. **Open: locate injector** —
   candidates: headless startup path; windowed-mode full-argv A/B pending.

## Phase 0 clone(2) namespace map (this device, Android 17 / 6.1 GKI)

| flag | result |
|---|---|
| CLONE_NEWUSER | EINVAL (matches unshare CLI; Chromium's own probe returns false) |
| CLONE_NEWPID / NEWNET / NEWNS / NEWIPC / NEWUTS | EPERM |

Evidence scripts: poc/seccomp_probe.c, poc/clone_ns_probe.c (clone_ns_probe
to be committed). Logs: chromium-sandbox-poc/test[A-N]*.{log,txt} (local).

## Phase 0.3 verdict (2026-10-19, round 2)

### Why chromium runs unsandboxed WITHOUT dying (mechanism, code-verified)

1. `Credentials::CanCreateProcessInNewUserNS()` (sandbox/linux/services/
   credentials.cc:267-301) probes via forked-child `unshare(CLONE_NEWUSER)`
   → EINVAL on this kernel → false (matches our clone probe: EINVAL; all other
   namespace flags EPERM).
2. `ZygoteHostImpl::Init` (zygote_host_impl_linux.cc:102-157) therefore can
   reach neither `use_namespace_sandbox_` (needs userns) nor
   `use_suid_sandbox_` (no chrome-sandbox binary ships) → upstream would
   `LOG(FATAL) "No usable sandbox!"` at L144.
3. Reality: no FATAL, browser healthy → L103 early-return fires, i.e. the
   in-memory browser CommandLine carries kNoSandbox by then. Note the
   call site passes `*CommandLine::ForCurrentProcess()`
   (content_main_runner_impl.cc:1119-1120) — a MUTABLE singleton, and child
   zygote cmd_lines are built from it (LaunchZygoteHelper ~L300-347, incl.
   `AppendExtraCommandLineSwitches` → sandbox_type.cc:116-124 appends a real
   --no-sandbox token per computed sandbox type).
4. `LaunchZygote` (zygote_host_impl_linux.cc:177-226): zygotes carrying
   `--no-zygote-sandbox` launch via plain `base::LaunchProcess` — NO pid-ns
   boot handshake (`CHECK_GT(boot_pid,1)`), no premature-exit FATAL. The
   9-zygote churn + zero BPF filters are consistent with pure-unsandboxed
   operation using upstream-provided fallback paths.
5. Remaining task (next round): pin the exact in-memory injector file among
   the not-yet-grepped early-browser-startup sources:
   chrome/app/chrome_main.cc, content/app/content_main.cc,
   chrome/browser/chrome_browser_main.cc, chrome/browser/chrome_browser_main_posix.cc.

### Port intervention points (first semantic patches, Phase 1 targets)

- P1 `ZygoteHostImpl::Init`: introduce a third usable mode — seccomp-only
  (no userns, no setuid, no FATAL) — gated by a Termux marker constant,
  fail-closed elsewhere.
- P2 `SandboxLinux::InitializeSandbox` options: force
  `engage_namespace_sandbox=false` while KEEPING the BPF layer (the
  seccomp-bpf support probe at sandbox_linux.cc:209-216 already passes on
  this device per poc/seccomp_probe.c).
- P3 ensure `--no-zygote-sandbox`-style unsandboxed shortcut is NOT taken
  when the port is active: zygote must still fork children that install BPF
  (zygote_main_linux.cc path) — mirror what Chrome-on-Android app sandbox does.

### Risk register (updated)

- 9-zygote churn observed even unsandboxed — investigate whether preload
  relaunch loops mask a failing zygote boot (would inform P3).
- Utility services (network) also carry 0 filters today; target policy set:
  renderer, gpu, utility*, (network service last — hardest socket rules).

## Phase 0 FINAL verdict (round 2) — source patches are mandatory

Flag matrix on the stock binary (exe-verified filter census, all runs
`Seccomp_filters=1` == Android baseline, zero Chromium BPF):

| combo | processes seen | Chromium filters |
|---|---|---|
| (none) | browser, utility, 10×zygote | 0 |
| --disable-namespace-sandbox | same | 0 |
| --no-zygote --no-sandbox | browser, gpu, 6×renderer, 2×utility | 0 |

Also: kNoSandbox token appears nowhere in the argv of our launches, and the
four classic early-startup files (chrome_main.cc, content_main.cc,
chrome_browser_main[_posix].cc) contain zero kNoSandbox references — the
in-memory downgrade rides upstream fallback paths (see Phase 0.3 verdict).

**Phase 0 CLOSED (all PASS):** (1) seccomp-bpf self-install viable; (2) every
namespace blocked (NEWUSER=EINVAL via Chromium's own probe semantics); (3) no
configuration-only route to BPF — P1 (ZygoteHostImpl third usable mode),
P2 (InitializeSandbox engage_namespace_sandbox=false), P3 (zygote children
must install BPF without setuid/pidns) confirmed as the minimal patch set.

Build strategy: follow the Firefox port — cloud GitHub Actions build of the
Termux package with our transformer applied (device-side chromium builds are
impractical); apt channel + version lead per the proven scheme, under the
separate-package-identity constraint (stock chromium untouched).

## Phase 1b — sandbox call-site map (R1+R2 sufficiency proof, 2026-10-19)

Child-side sandbox installation is `Sandbox::Initialize(SandboxTypeFromCommandLine(...))`:

| path | file | engage_namespace_sandbox | port coverage |
|---|---|---|---|
| renderer (from generic zygote) | content/renderer/renderer_main_platform_delegate_linux.cc:33-48 (EnableSandbox) | default **false** (sandbox_linux.h:104) | R2 untouched; installs BPF iff token absent → anti-injection scan is the load-bearing gate |
| non-zygote services (gpu/utility family) | services/service_manager/.../service_executable_environment.cc:47 | explicit **true** | R2 Bionic-skip prevents EngageNamespaceSandbox CHECK death |
| zygote itself (layer-1) | content/zygote/zygote_main_linux.cc (ZygoteMain/EnterLayerOneSandbox) | n/a | both use_* false → `CHECK(!using_layer1_sandbox)` pass — no change needed |
| browser init | zygote_host_impl_linux.cc ZygoteHostImpl::Init | n/a | **R1** (Bionic no-FATAL) |

`RendererMainPlatformDelegate::EnableSandbox` even self-verifies (`kSeccompBPF ⇒
CHECK(seccomp_bpf_started())`, x86_64 adds fchmod-EPERM probe): if the stock
token injection ever recurs, renderers would CRASH not silently pass — Phase 3
device gate leans on this.

### Build source strategy (Termux chromium)
`TERMUX_PKG_SRCURL=https://github.com/chromium-linux-tarballs/chromium-tarballs/
releases/download/<ver>/chromium-<ver>-linux.tar.xz` + pinned SHA256 →
deterministic tarball flow, transformer applies post-extract, no depot checkout.
`TERMUX_PKG_ON_DEVICE_BUILD_NOT_SUPPORTED=true` → cloud build mandatory (matches
Firefox pattern).

## Phase 2a decisions (round 5)

- **Package identity**: clone recipe `x11-packages/chromium-sandboxed`
  (distinct lib dir `$PREFIX/lib/chromium-sandboxed`, launcher
  `bin/chromium-sandboxed`, desktop id `chromium-sandboxed.desktop`) →
  stock `chromium` untouched, side-by-side installs; satisfies the
  user-mandated off-limits constraint at packaging level, not just policy.
- **Transformer injection**: `prepare_recipe.py` writes a marked
  `termux_step_post_get_source()` hook that runs
  `chromium_sandbox_port.py apply --scan content,chrome` and requires ≥2
  APPLIED/ALREADY_PRESENT records (fail closed). Audit mode + tamper
  detection covered by harness [8][9].
- **CI gate model correction** (Firefox-pattern delta): official builds strip
  DLOG strings, so the post-build binary-marker gate (firefox-style) is
  REPLACED by (a) transformer verify (markers in patched source), (b)
  prepare_recipe audit (hook + identity intact), (c) device gate measuring
  per-process Seccomp_filters > baseline + renderer's own
  CHECK(seccomp_bpf_started()) (crash-instead-of-silence property).

## Phase 2b design notes (round 10)

- **Version-lead simplification**: because the port ships as a DISTINCT
  package name `chromium-sandboxed` (not a same-name replacement), the
  Firefox-pack's `M.(m+1).p` packaging lead is NOT needed — dpkg never races
  Termux's `chromium`. We keep plain `source_version-port_version`
  (e.g. `155.0.8059.79-1.0.1`), with monotonicity enforced within our own
  channel only.
- Automation ported from the hardened Firefox line (exact-bot-identity
  gate): port/auto_merge_upstream.sh + two workflow drafts (renovate,
  auto-merge) under port/workflows/*.draft. They remain INERT until the
  Phase 3 device gate passes (promotion = explicit commit moving them to
  .github/workflows, reviewed diff — incident lesson).
- Chromium adaptation deltas: branch pattern `renovate/termux-chromium-upstream-`,
  anchor key `termuxChromiumVersion`, recipe `x11-packages/chromium/build.sh`
  (TERMUX_PKG_VERSION is UNQUOTED there — extraction tolerant), version
  invariant N.0[.k] → exactly 4-segment `N.N.N.N`.

## MYSTERY SOLVED (run #9, 2026-10-19): the stock silent-downgrade injector
Phase 0.3's open question — "who appends --no-sandbox to the browser command
line?" — was answered by our own anti-injection gate firing during build run
#9 AFTER cr-patches applied:
termux-packages `x11-packages/chromium-host-tools/cr-patches/`
- `1001-chromium-disable-sandbox.patch`: under `#ifdef __TERMUX__` appends
  `sandbox::policy::switches::kNoSandbox` to ForCurrentProcess() in BOTH
  `chrome/app/chrome_main_delegate.cc::PreSandboxStartup` and
  `content/shell/app/shell_main_delegate.cc::PreSandboxStartup`, and hides
  the sandbox-disabling flags from bad_flags_prompt.cc (why users never saw
  a warning either).
- `1004-chromium-headless-disable-sandbox-by-default.patch`: same for headless.
Earlier greps found nothing because they inspected UNPATCHED upstream files —
the injection is Termux-patch-provided, not upstream, not runtime fallback.

Port response (fail-closed layers):
1. prepare_recipe excludes exactly those two patches from the recipe's
   cr-patches loop (audit + harness [12] enforce).
2. transformer anti-injection scan remains: if upstream renames/reshuffles
   the patches, the surviving injection kills the build (run #9 demonstrated
   the tripwire in production).

## Runner operations policy (maintainer decision, 2026-10-19)
- Builds run on GitHub-hosted ubuntu-26.04 (cloud; device untouched).
- On TIMEOUT (350-min cap) or any infra failure: **STOP and report — do NOT
  auto-redispatch.** sccache accumulation re-dispatch happens only on
  explicit maintainer go-ahead.
- On compile/source failure: diagnose + fix code is allowed (that's normal
  porting work); a fresh dispatch after a real fix is considered a new
  attempt, not a blind retry — still worth a one-line confirmation.

## Test device policy (updated run #10 wait)
- MAIN device: extract-only, never dpkg, stock profile off-limits (unchanged).
- DEDICATED REMOTE TEST DEVICE (S20 FE class, Android 13 / kernel 4.19, aarch64):
  probe-verified same kernel posture as main (CLONE_NEWUSER EINVAL; seccomp-bpf
  self-install works) ⇒ seccomp-only port is equally applicable.
  No chromium ever installed ⇒ real dpkg/apt install-path tests allowed there;
  remote_gate.sh installs, gates, then dpkg -r to keep it clean.
- Gate scripts are synced to ~/chromium-gate on the remote; bpf_evidence
  selftest already PASSes on-device.

## Mystery #2 solved (run #11 device-gate round 1) — the prctl wall
First-port deb on both devices (main kernel 6.1 + S20 FE 4.19): zygote alive
(R1/R2 healthy!) but every sandboxed child boot-loops:
    sigsys_handlers.cc:**CRASHING**:seccomp-bpf failure in syscall nr=0xa7 arg1=0x36
= prctl(PR_PAC_RESET_KEYS). RestrictPrctl() (syscall_parameters_restrictions.cc)
allow-lists arm64-Android prctl options only under BUILDFLAG(IS_ANDROID); Termux
builds os=linux (IS_ANDROID=false) yet runs on Android/arm64, where bionic's
clone/fork child setup resets PAC keys. This is the real class of problem
cr-patch 1001 "fixed" by disabling the entire sandbox.
Fix: R3 — __BIONIC__-guarded extension of the Cases allow-list (PAC 54/55/56,
THP 44, TIMERSLACK_PID 41/43/127, SECCOMP_CACHE_FLUSH 58). trap.cc:106
existing-handler noise and /proc/self/stat EPERM are non-fatal (upstream
DLOG(FATAL) not compiled fatal in release; libc logs and proceeds).
Measurement: kernel 4.19 testbed does not export Seccomp_filters in
/proc/pid/status — gates use renderer-presence + zero-CRASHING proxy there;
authoritative filter census stays on the main device (kernel >= 6.1).

## Device-gate round 2 (run #12 deb): zygote inherited filter kills renderer
With R3, CRASHING-prctl is gone but renderers still never ping ("Did not
receive ping from zygote child"). strace (installed on main device) shows the
whole renderer family dying simultaneously:
    SIGSYS {si_code=SYS_SECCOMP, si_errno=EPERM, si_syscall=__NR_set_tid_address}
seccomp filters are inherited across fork and can never be removed; bionic's
clone-child setup calls set_tid_address before the broker relaxes the zygote
filter — a syscall pattern glibc desktop never exhibits, hence zero upstream
coverage. Fix R4: on __BIONIC__ pass the ZYGOTE type through StartSeccompBPF
(same precedent as IsUnsandboxedSandboxType: return true without installing).
The zygote is a launcher, not a security boundary; child types (renderer/
gpu/utility) still install their own policies — where this port's enforcement
lives. bpf_evidence still requires the zygote to exist; renderer census >=2
remains the authoritative gate on the main device.

## Device-gate round 3 (run #14 deb): the silent post-activation abort
Ported X11 run: renderer printed "Activated seccomp-bpf sandbox for process
type: renderer" then died silently in a boot loop (214 activations, no stderr,
no logcat abort message, no crashpad dump — crashpad snapshots also fail on
this build: 'tag not found'). --no-sandbox renders the page perfectly (all 5
codecs "probably") -> crash is purely BPF-policy interaction.
Forensics chain: LD_PRELOAD abort() PLT-hook + backtrace_symbols_fd captured
91 IDENTICAL stacks: chrome(GetStackTop wrapper) -> pthread_getattr_np@plt ->
bionic abort. llvm-objdump at the exact file offsets (0xb94e304/0xb94a364)
matched partition_alloc/stack/stack.cc GetStackTop(). Root cause: PA's
StackTopRegistry lazily calls pthread_getattr_np per TID; post-filter /proc is
unopenable and BIONIC pthread_getattr_np LOG(FATAL)s internally. glibc instead
degrades gracefully (and PA even has a __libc_stack_end fallback for glibc) —
bionic has neither, so desktop chrome never hit this. The registry is keyed by
TID, and forked children have fresh TIDs -> a zygote prewarm cannot work.
Fix R5: at the top of StartSeccompBPF under __BIONIC__, call
StackTopRegistry::Get().GetCurrentThreadStackTop() (forward-declared) so the
cache is warm before the filter engages, in every sandboxed process type.
Probe lesson: headless=new NEVER works on termux chromium (stock included) —
device gates must use --ozone-platform=x11 + console-log capture.

## Device-gate round 6 (run #22 deb, R6 build): why the prewarm was dead code
R6 prewarmed GetStackEnd and R7/R8 later exposed the real shape of the wall.
Forensics with a pthread_getattr_np interposer (gnp shim, logs pid/tid and
whether /proc/self/status is still readable):
  - exactly 3 gnp call sites per process; 2 fire PRE-filter, 1 fires
    POST-filter (filt=-1 => /proc unreadable) and is the SIGABRT killer;
  - all calls are tid==pid => main thread, exactly the case upstream documents
    ("Bionic reads proc/maps on every call ... when called from the main
    thread", base/debug/stack_trace.cc:228);
  - abort() PLT-hook backtrace: the fatal frame is a pthread_getattr_np caller
    reached through a lazily-initialised singleton.
Root cause of the dead prewarm: upstream gates the bionic main-thread cache
behind BUILDFLAG(IS_ANDROID) (and PA_BUILDFLAG(IS_ANDROID) for the vendored
copy). Termux builds chromium with os=linux, so `static uintptr_t
main_stack_end` never existed -> GetStackEnd called pthread_getattr_np on every
invocation and the R6 prewarm stored its value nowhere. R5 was dead for a
different reason: StackTopRegistry::GetCurrentThreadStackTop() is a pure map
lookup, it never computes a value.

### Fix set (round 6)
- R7: enable upstream's own bionic cache under __BIONIC__ in base/debug/
  stack_trace.cc and the vendored PA copy (PA rule is optional-if-absent).
- R8: partition_alloc stack.cc - capture the main pthread_t during static init,
  cache the main thread's stack top, and export TermuxPrewarmStackTop() so
  StartSeccompBPF can fill the cache before the BPF denies /proc.
- Prewarm block (R5b/R6) now calls base::debug::GetStackEnd,
  PA base::debug::GetStackEnd and partition_alloc::internal::
  TermuxPrewarmStackTop, all [[gnu::used]].
- Verifier: if the vendored PA subtree ships, its R7/R8 markers MUST be
  present (silently skipping them would ship a build that still dies).
Harness: 24/24. Ledger: port.toml [rules.r7]/[rules.r8].

## Device-gate round 7 (run #23 deb): BREAKTHROUGH - shield closes the wall
R7+R8 did land in the compiled paths (verified in the build log: the exact
patched files were compiled) and they did remove the old post-filter call site
(gnp interposer: site moved 0xb94e308 -> 0xb94e540), but ONE caller remained:
the abort backtrace still ran through the same stack-walk family, now reached
from the crash-handler side. Root fact: bionic's pthread_getattr_np(main) is
fatal whenever /proc is unreadable, so *any* caller kills the child - chasing
callers is whack-a-mole and upstream may add more.

### Fix: caller-agnostic bionic shield (port/gnp_shim.c)
Capture the main thread's pthread_attr_t in a library constructor (before any
sandbox exists) and serve that snapshot to every main-thread caller; non-main
threads fall through to real bionic (no /proc involved). The main thread's
stack bounds are constant for the process lifetime, so the snapshot is exact.
Shipped as $PREFIX/lib/chromium-sandboxed/libtermux-gnp-fix.so and loaded by
bin/chromium-sandboxed via LD_PRELOAD (children inherit it).

### Proof (main device, kernel 6.1, real deb, X11)
  renderer activation pids: 31001 31040 31041 31081 31183
  codecs: 5/5 "probably" (h264/vp9/av1/aac/opus), 0 unsupported
  census: 6 live children with Seccomp_filters=2 (Android baseline is 1)
  X11 DEVICE GATE: PASS
This is the first PASS in the whole project: renderers now survive BPF
engagement AND render, with Chromium's own filter installed per process.

### Gate hardening learned here
zygote children are forked WITHOUT exec, so /proc/pid/cmdline stays
"--type=zygote" and /proc/pid/comm is "chrome" - neither identifies a renderer.
The gate now correlates the browser's own VERBOSE activation lines
("[pid:tid:...] Activated seccomp-bpf ... renderer") with /proc/<pid>/status,
and falls back to "any live child with >=2 filters".

## Device-gate round 8 (run #25 deb): shield shipped, launcher-clobber bug
The deb carried libtermux-gnp-fix.so (5000B) and the gate passed on the
PACKAGED artifact (renderer activations 6, codecs 5/5, 7 live children with
filters=2, X11 DEVICE GATE: PASS) - but packaging had a real bug:
bin/chromium-sandboxed is a symlink to chromium-launcher.sh, and the shield
hook wrote the wrapper with 'cat > $symlink', which FOLLOWS the link and
overwrote the launcher itself. The 305-byte "launcher" then exec'd
$P/chromium-launcher.sh - i.e. itself - an infinite exec loop for anyone
installing the package.
Fix: the wrapper lives in its own file (chromium-shield-wrapper.sh), the bin
symlink is removed and repointed at the wrapper, the real launcher is left
untouched, and the hook fails closed if the launcher ever contains the shield
line. CI package gates now assert: shield .so present, wrapper present,
launcher NOT clobbered, wrapper execs the real launcher. Harness 27/27.
Lesson: never 'cat >' a path that may be a symlink - resolve it first.

## Device-gate round 9 (run #28 deb): FULLY GREEN — first validated candidate
CI run #28 (commit 239ea89, the run-#26 SIGPIPE+pipefail gate fix) is the
first end-to-end green pipeline: transformer self-test + build + ALL package
gates + artifact upload. Harvested deb 155.0.8059.84
(sha256 4e7dce5226d0576bb33bcb774a3d2816b433aae2fd81faf694725d500dbe820a) and
re-ran the authoritative X11 device gate on the MAIN device (kernel 6.1):

  baseline (stock chrome) renderer filters=0   (apples-to-apples control ok)
  renderer activation pids: 19076 19088 19089 19144 19179 19201  (6)
  codecs: 5/5 "probably" (h264/vp9/av1/aac/opus), 0 unsupported
  census: 7 live children Seccomp_filters=2 nnp=1 (zygote-forked, exec-less
          cmdline still --type=zygote; fallback [3] path per round-7 hardening)
  X11 DEVICE GATE: PASS  (shield LD_PRELOADed from the deb, as shipped)

Packaging verified from the deb itself (round-8 fix holds):
  bin/chromium-sandboxed -> lib/chromium-sandboxed/chromium-shield-wrapper.sh
  wrapper (305B) execs chromium-launcher.sh (1379B, untouched, 0 LD_PRELOAD
  lines); libtermux-gnp-fix.so (5000B) present. No self-exec loop possible.

port.toml: phase=validated, last_validated_port=0.1.0,
last_validated_chromium=155.0.8059.84, device_gate PASS recorded.

Ops lessons this round:
- fetch_artifact.sh died on a relative out-dir (subshell cd + relative
  $out/deb.sha256). Fixed by absolutizing $out right after mkdir; the
  "next:" hint now names x11_gate.sh (headless never works on termux).
- gh CLI hangs forever with no DBUS_SESSION_BUS_ADDRESS (keyring lookup on a
  dead bus, no timeout). Live bus address is readable from
  /proc/<gnome-keyring-daemon-pid>/environ. Consider a gh fallback that
  errors instead of hanging (check GH_TOKEN first).

Next (Phase 2): apt channel via gh-pages + package-version lead so
'pkg upgrade' cannot resurrect the sandbox-off stock build as the default
entry point; separate-identity naming already holds (chromium-sandboxed).


## Round 10 — R9a candidate (run #29): network service sandboxing works (2026-10-23)

Approved scope executed exactly: one (SOL_SOCKET, SO_DOMAIN) getsockopt pair under
__BIONIC__ inside RestrictGetSockoptForNetworkService() (bpf_network_policy_linux.cc),
verifier gate + rule-counter 7->8 + workflow R9a grep + harness [28]-[30];
[forbidden] converted to valid TOML with tomllib parser gate [31] (commits c715866
security-policy / f2fec44 docs-verification).

run #29: self-test PASS; build SUCCEEDED but took 5h09m — the sccache had partially
expired (warm baseline #28 was 59m; job cap is 350m — future dispatches should
either keep the cache warm (periodic rebuild cadence < 7d) or budget cold runs).
IMPORTANT: the workflow resolves termux-packages via a floating master ref and
upstream bumped Chromium 155 -> **156.0.8078.47**, so the candidate is a different
Chromium than the run #28 baseline. R9a anchors survived the bump (build applied
them), but production validations must pin the termux-packages sha — recorded as a
known drift risk.

Behavioural battery (candidate 156+R9a, main extract-only + testbed dpkg install):
- NetworkServiceSandbox ON: restarts 16->0, CRASHING 32->0, utility ACTs 18->2;
  milestones equal to baseline-A (YouTube iframe timeline T1..T5, AAC done, IDB/LS).
- Kernel 6.1 census with PID<->role mapping: sub=network.mojom.NetworkService
  recorded Seccomp_filters=2 NoNewPrivs=1 AT activation instant (4.19 testbed:
  seccomp=2 nnp=1, no filter export — main census is authoritative).
- PulseAudio under B: sink-input RUNNING <Chromium>, monitor rms 2591 (main) /
  4150 (testbed) — first SILENT reading was a 0% sink-volume environment drift,
  restored to base 100% (not a regression).
- Testbed dpkg install -> ii -> B battery -> purge: 0 package residuals
  (empty lib/chromium-sandboxed/extensions was runtime-created; removed).
- No new syscall traps observed anywhere in the battery -> no list widening.

R9b (diagnostics only, ZERO code/permission changes, per authorization): the audio
utility DOES engage BPF (ACT log, zero CRASHING); silence stems from the AUDIO hook's
broker file-permission set not covering Termux's deep XDG runtime layout — PA
secure-dir verification -> broker EPERM -> libpulse falls back to compiled
$PREFIX/var/run/pulse/native -> raw connect ENOENT -> refused -> silent + utility
exit. PULSE_RUNTIME_PATH env probe still EPERMs (so it is directory-self +
intermediate-component traversal, not a plain path miss). libpulse.so.0 loads fine
(no dlopen warning). v3 fix proposal drafted (bionic branch in
AddPulseAudioFilePermissions) — awaiting approval; seccomp policy untouched.

Verdict: R9a candidate = PASS against the approved battery. Promotion to validated,
default-on of NetworkServiceSandbox, apt publishing: NOT done, separate approvals
required. run #28 stays the validated baseline.

## Round 10 addendum — R9b reviewer revision & R9a #29 record (2026-10-23)

R9a run #29 (candidate 156.0.8078.47): device battery PASS — restarts 16->0,
CRASHING 32->0, network utility filters=2/nnp=1 at activation instant (kernel 6.1,
pid<->sub mapping), audible audio under B (rms 2591 main / 4150 testbed), testbed
install/purge clean, no new traps. This record is informational: run #28 remains
the validated baseline; promotion to validated, NetworkServiceSandbox default-on
and apt publishing all require SEPARATE approvals (none granted).

R9b (reviewer corrections accepted, still zero code/policy changes): the earlier
"broker permission gap" attribution is WITHDRAWN — observed EPERM(1) matches
base-policy Error(EPERM) classes (fchmod/fchown are not broker commands; broker
denies with EACCES), and the PULSE_RUNTIME_PATH probe was an invalid control (it
moves socket discovery too). Corrected A/B with an extended tracer (lstat/fstatat/
statx/fchown/fchmodat/openat/syscall) proved a zero-policy fix: with
PULSE_SERVER=unix:<real $PREFIX/tmp/pulse/native> the sandboxed AudioService
connects (ret=0), cookie opens via the existing broker grant, no secure-dir
sequence runs at all, sink-input RUNNING + monitor rms 1936 AUDIBLE, and the
unsandboxed control is equivalent. v3 proposal = launcher-level env export
(prepare_recipe.py data change only; respects user PULSE_SERVER; no-op when no
socket). Priority-2 (minimal broker StatOnlyWithIntermediateDirs) and priority-3
(extra bionic patches) are unnecessary unless v1 regresses; the exact broker-vs-BPF
attribution of the ORIGINAL default-discovery failure stays open (tracer filter
blind spot on non-'pulse' component paths like $PREFIX/tmp itself) — observable
without builds via filter extension only. Forbidden measures (blanket fchmod,
$PREFIX RWCR, disabling seccomp) were never applied.

## Round 11 (WIP) — R9b wrapper candidate: packaging proven, utility survival gate BLOCKED (pre-existing)

Implemented (approved scope): guarded PULSE_SERVER export inside
chromium-shield-wrapper.sh (prepare_recipe.py; original chromium-launcher.sh
untouched; LD_PRELOAD path preserved; exec line unchanged; user PULSE_SERVER —
including empty string — never overwritten; XDG absolute-path socket preferred,
$PREFIX/tmp fallback, no-socket no-op; unix:<abs> form; quoting-safe; harness
[32]-[34]: 10 new cases incl. behaviour matrix (7 scenarios) + widening-token
guard; ledger [rules.r9b]; 42/42).

Device pre-validation (testbed, extract-copy + one real dpkg install/purge):
the wrapper does exactly its job — refused/secure-dir log lines go to 0 with
AudioServiceSandbox ON (was refused=1-loop before). BUT the §5 survival gate
(audio utility alive >=30s) FAILS: the sandboxed AudioService utility dies
silently right after 'Activated seccomp-bpf ... utility' (no SIGSYS/CRASHING,
no logs, no dumps) — IDENTICALLY on 155 (run #28 tree) and 156 (candidate #29
tree), with or without LD_PRELOAD tracers, with or without PREFIX override,
extract or installed. 155/156 audio hook+policy sources are byte-identical
(diff clean) — this is a pre-existing sandboxed-AudioService problem, NOT a
regression introduced by the candidate.

SELF-CORRECTION (round-10/R9b findings): the earlier 'C-srv AUDIBLE rms 1936'
success claim was BROWSER-SIDE FALLBACK audio, not the sandboxed utility — the
same log's own 'audio-util-alive@14s: NO' was in plain sight. The wrapper is
still necessary (kills the refused crash-loop) but NOT sufficient; next
investigation = broker round-trip (sendmsg/poll hook + broker child census +
last-words capture per utility pid) to find the silent death mechanism.

CI build: NOT dispatched (approval §4 conditions require the pre-validation to
pass; it did not). No new policy allowances were added anywhere. run #28 stays
the validated baseline.

## Round 11 addendum — v4 FINAL: no utility death existed (three measurement artifacts corrected)

The "silent death" was an artifact of (1) zygote-forked utilities keep
cmdline --type=zygote (exec-less) so the cmdline scan was blind — ptrace
spy proved ACT'd utilities alive; (2) parecord windows all sat AFTER the
12s clip ended (t30 vs end@16-17s) — re-measured in-window: testbed
rms=2905 AUDIBLE, main rms=2589 AUDIBLE with AudioServiceSandbox ON
(wrapper PULSE_SERVER), sink-input RUNNING, PLAY+ENDED, CRASHING 0, PA
context-refused 0 (the 'refused=41' was dbus-bus noise on a loose grep);
(3) broker exit(0)/EOF lines = zygote warm-up fork(_exit(0) by design)
and session-teardown lifecycle, not a broker pathology (single broker fork
observed per utility: FORKED parent->child; client EOF only at close).

§5 gate status (candidate 156 + wrapper, run #29 binary + injected wrapper):
- AudioServiceSandbox ON, both devices: utility ALIVE 30s+ (spy/ACT census),
  0 unexpected restarts, sink RUNNING, in-window monitor rms>150 (2905 TB /
  2589 main), AAC PLAYING->ENDED, YouTube T1..T5 (D), IDB/LS.
- D (audio+network) main: network.mojom.NetworkService ACT-at
  Seccomp_filters=2 nnp=1 preserved; eight zygote-child utilities recorded
  filters=2 nnp=1 at activation instant; CRASHING 0, 'restarting service' 0.
- Controls: sandbox OFF healthy; PULSE_SERVER- OFF reproduces refused/
  secure-dir loop (wrapper is the fix); instrumentation did not alter
  outcomes (J vs G3 same shape).

CI build: still NOT dispatched — awaiting approval (single build, ref
64e02760...). Nothing promoted; run #28 remains baseline; no policy or
broker/allow-list widening anywhere. Evidence: gate-out/r9/{v4*,R9B_FINDINGS.md,
shield-wrapper-r9b.sh, spy, ipc_diag2.*, exec_catch.*} + device logs.

## Round 11 postmortem — run #30 (R9b candidate CI) failed at SELF-TEST; product code unaffected

Dispatch verified pre-flight (headSha 1ddf25f == approved port commit;
termux_ref input == 64e02760). gate job self-test FAILed only on harness
cases [33a]-[33h]: the behaviour-stub launcher embedded a Termux-absolute
shebang — ubuntu runners have no /data/data path ('bad interpreter').
40/42 cases PASSed on CI including [32] (R9b markers in generated recipe)
and [34] (no widening tokens). build job skipped (fail-closed by design);
no artifact produced; NOT retried per authorization. Fix committed
(#!/usr/bin/env bash) with local re-verification 42/42. Awaiting
re-dispatch approval for the single candidate build (port commit advances
to the fix commit; everything else per prior approval).

## Round 11 FINAL — run #31: R9b candidate CI PASS + both-device A/B/C/D gates PASS (2026-10-24)

Pre-flight: dispatch headSha == approved port commit 403274f; termux_ref input
pinned to 64e02760... (never master); single dispatch, no retries.
Result: gate self-test 42/42 on CI (shebang fix effective), build success
(87m, sccache prefix-restore warm), package gates incl. R9a grep PASS.
Artifact: chromium-sandboxed 156.0.8078.47 aarch64, sha256
29c4080d2a849c07eae46a87e44e39231fa92021c1e10e24f363e1e29395b27c.

Artifact verification (extracted DEB, not just logs): R9b wrapper markers +
guards (user-set incl. empty respected — shipped-wrapper stub-tree behaviour
test: unset->unix:<socket> exported; empty->kept empty; tcp->kept);
LD_PRELOAD chain and exec-line intact; chromium-launcher.sh sha256 identical
to #29 (untouched); port-apply log 'APPLIED] R9a' recorded.

Device gates (A/B/C/D matrix, both devices, server pre-healthcheck, PID-linked
in-window measurements):
- MAIN (kernel 6.1, extract-only): every condition AUDIBLE in-window
  (rms 1103-4664), CRASHING/pa-refused/restarting all 0, milestones full
  (YouTube T1..T5, AAC done, IDB/LS). D census: 9/9 ACT pids with
  Seccomp_filters=2 + NoNewPrivs=1 at activation instant, including
  sub=network.mojom.NetworkService. PA client pid ∩ ACT utility pid
  (26194@C, 29415@D) != browser pid -> stream owner is the sandboxed
  utility, browser-side fallback formally excluded.
- TESTBED (4.19, dpkg install -> matrix -> purge): ii; A-D all AUDIBLE
  (rms 1169-3113), CRASHING/refused/restarting 0, END-LIVE 6-8 pids at ~63s
  window (>=30s survival incl. audio utility + zygote children), PA owner =
  ACT'd sandboxed utility (24772@C, 26940@D). 4.19 cannot export
  Seccomp_filters (kernel limitation) -> nnp=1 + activation logs + MAIN
  census serve as filter evidence, per protocol. Purge: dpkg residual 0;
  only runtime-created empty extensions/ dir (0 files) remained.
- #28/#29 comparison: #28 B-condition signature (restarts 16 / CRASHING 32)
  gone on #31 (0/0); defaults-off (A) identical feature set; no regressions
  found. NET_204_ERR/HTTPS_ERR page fetches: environment quirk identical in
  ALL conditions incl. A and #28 baselines (not a sandbox effect); YouTube
  streaming proves real network works.
Known limits: wrapper no-ops without socket at standard paths (by design,
user env precedence); third-party PA clients can pollute naive owner-detect
(avoided via ACT∩PA membership); in-process GPU/WebGL-off on testbed matches
stock (unchanged since round 9).

STATUS: candidate fully validated. NOT promoted (awaiting explicit approval):
run #28 remains validated baseline; last_validated_* untouched; Network/
Audio sandbox remain default-OFF; no apt/release. Recommendation in final
report.

## Round 12 — long-run soak on #31 artifact (2026-10-24)

Fixed inputs verified: deb sha256 29c4080d... re-checked pre-run; no rebuild,
no source change, no promotion. Main = extract-only; testbed = dpkg install
(dpkg -V clean) -> matrix -> purge, residual 0 (only runtime-created empty
extensions dir, 0 files).

MAIN (kernel 6.1, authoritative):
- Phases A(15m)/B(12m)/C(12m) + D(60m) + D60 re-run(60m, corrected assets,
  external auto-detect monitor) + aux2 A/B/C(10m)+D(25m) with fixed pages;
  10/10 relaunches OK (launch, milestone, graceful exit, residual 0 each).
- D60@44-min monitored window: 174 unique pids; browser/2 zygotes/2 network
  utilities/acted-children all span 2640s continuous; ACT-scoped seccomp2
  rows 635 with filters=2 & nnp=1 -> VIOLATIONS 0 (browser/zygote platform
  rows correctly filters=1; crashpad nnp=1 pre-sandbox rows are not
  sandboxed pids and excluded per protocol).
- CRASHING / SIGSYS / 'restarting service' / PA-context-refused: 0 in every
  phase, both devices.
- Resources: RSS plateau 1.9-2.4GB across 15 buckets (no monotonic growth;
  end ~= mid), browser FD 253->272 stable under tab churn (create/close via
  CDP every 120s), cpu/min decay 8029->269 (page-load -> steady, no
  runaway). Zombie state field not captured (NOT_VERIFIED formally;
  indirectly: exited pids stop appearing -> reaped, END residuals 0).
- Audio: sandboxed utility owns the stream — PA client pid 29581 ∈ ACT set
  in 30/49 sampled rows (single stable owner pid, itself filters=2 nnp=1,
  44-min survival); rms >150 in 27/49 samples, median 2892, max 7504;
  AUDIO_PLAY 153 loops; WS_OK 3602 (sustained + reconnect cycles); YouTube
  T5 + AAC DONE; LS 104/IDB OK.

TESTBED (4.19): TB2 30m + TB3 25m + TB4 30m + TB4' 30m (all D, monitor +
CDP media injector on TB3'/TB4'): stability 0/0/0 everywhere; audio stream
owner pid 22411 ∈ ACT across 23-min window (4/4 sampled sink rows), rms
22/23 samples >150 (max 6625); Seccomp_filters not exported on 4.19 (nnp=1
518 rows + mode=2 + MAIN census as per-protocol evidence).

Method fixes discovered mid-run (measurement-only, no product change):
initial-argv media tabs can be autoplay-gesture-starved -> CDP-created tabs
are the reliable media path (injector added); fixed monitor device missed a
drifted sink -> auto-detect added (r12_mon2); audio page needed JS play() +
timeupdate logging; DL fetch page never surfaced -> big-file download
NOT_VERIFIED (honest); pkill -f self-match caused two self-kills (moved to
script-file cleanup).

Verdict: Round 12 PASS on all enumerated gates except two recorded
NOT_VERIFIED items (HTTP large-file download path; zombie-state field) and
LMK visibility (non-root: NOT_VERIFIED). No regressions vs A condition or
vs #28/#29/#31 signatures. Baselines untouched; promotion still pending.

## Round 12.1 — residual verification closure (2026-10-24, #31 deb, no rebuild)

1) Monitored-window reconciliation: D60 per-pid "44 min" was a metric error
   (i-index assumed 60s; real cadence ~63s). True coverage: unmonitored gap
   at launch 38s (covered by first mon-D rows at 05:24:53) + tail 55s
   (browser alive at TERM: log 'Handling shutdown for signal 15' 06:24:56).
   Effective continuity: full 60.0-min run, sampling continuity 58.5 min,
   endpoints attested. The "44 min" claim is corrected here.
2) Low-RMS triage (49 samples): 27 audible; 21 samples = zero-stream minutes
   (media tab genuinely absent — churn-close/injector-120s scheduling
   artifact, workload design, not output faults); 1 sample i=28 (sink RUNNING
   + owner, rms 0) = clip-end/teardown boundary (i=26/27 audible 2892/2940,
   i=29 stream already gone). No true output failure observed in-window.
3) Browser download manager (CDP Page.setDownloadBehavior -> navigate to
   http 13MB file, isolated dirs, per-condition server health 200):
   A and D both DL_MGR_RESULT OK, size 13631488, SHA256 MATCH to source.
4) Zombie state (monitor_state.sh, State column, 5s cadence, teardown
   covered): state==Z rows 0 in both conditions; 13/14 vanished (reaped)
   rows — all ended processes fully removed from /proc post-TERM.
5) LMK: non-root logcat (system + events) visibility 0 lines -> remains
   NOT_VERIFIED; absence of observation is NOT claimed as absence of LMK.
   Product-side corroboration (not proof): no mid-run unexpected exits,
   residuals 0 in every phase.

Tooling bugs found+fixed in closure (measurement only): PREFIX derived via
dirname-chain instead of suffix-strip (chrome never launched first tries);
stop-file truncation vs rm -f (monitors exited instantly); CDP ready-wait
added; orphan print NameError; harness-timeout pipe output loss -> detached
runs. pkill/self-match discipline upheld via script-file cleanup.

Round 12.1 verdict: items 1-4 CLOSED PASS, item 5 NOT_VERIFIED (structural,
non-root). NOT_VERIFIED ledger shrinks to: LMK visibility only. Promotion
recommendation updated in final report; nothing promoted here.

## Round 14 — real-world compatibility & default-enablement fitness (2026-10-24, #31 artifact, no rebuild)

Fixed inputs re-verified pre-run (deb sha256 29c4080d..., ledger 0f0d728).
Main extract-only (A 15m / B 30m / C 30m / D 60m + supplementary B'/D' 15m
with fixed injector); testbed dpkg install -> D30 -> purge (residual 0,
dpkg -V clean); live PulseAudio never touched on either device (isolated
second instance with null-sink used for alt-socket E2E, own pidfile kill).

Stability (all 6 main phases + TB D30): residuals 0, CRASHING 0,
Received-SIGSYS 0, 'restarting service' 0, PA-context refused 0 everywhere.
ACT-scoped BPF rows: violations 0 (D: 635+ rows filters=2 nnp=1 pattern
reproduced); network-utility cmdlines attest --enable-features propagation
(B: NetworkServiceSandbox; D: both).

Network compatibility (B/D): HTTP/1.1 local incl. 302->target (8), slow
streamed body, chunked 15s long-connection completed; WebSocket sustained
(WS_OK 14954@D60) + netflap (both servers down 60s) -> OPEN storm + full
reconnect, audio unaffected (AUDIO_PLAY 148 vs baseline 140); Service
Worker registered + 51-62 intercepted fetch hits; cookie persist + cache
304 sequence (http-origin required: file:// origin blocks SW/cookies/CORS —
a harness design lesson, symmetric across A-D, not a sandbox effect);
downloads via browser download manager during audio: 2x13MB SHA256 match
(main D) + 2x (supp D'); HTTPS external OK (YouTube T5 x11, AAC x14).
Tiering: HTTP/2 attested server-side (curl ALPN=2) + pages loaded in
chrome (client negotiation NOT_VERIFIED — netlog out of scope); HTTP/3
path available (curl h3 OK) but chrome-side use NOT_VERIFIED; IPv6
unreachable on this network (curl -6 fail) -> NOT_VERIFIED (environment).

Audio compatibility (C/D + TB): formats page Opus 4131 plays + VPX 23
(FMT_ERR 20 transient); 3 concurrent streams owner = sandboxed utility
(30710 in ACT, filters=2); owner-in-ACT on every audio-bearing phase
(29581/22411/5396/27200); pause/resume+tab churn sustained; clip-end ->
new stream recreation proven via netflap & injector cycles.
Wrapper PA branches on testbed 7/7 (B1 prefix-socket export, B2 XDG
preferred, B3 prefix fallback, B4 tcp kept, B5 EMPTY kept, B6 no-socket
no-op, B7 custom kept; LD_PRELOAD intact in all). E2E against ISOLATED
second PA (null-sink r14alt, auth-anonymous, own pidfile): user-specified
non-standard socket -> AUDIBLE (rms 2893 on r14alt.monitor) and sink-input
client pid = sandboxed utility (188x != browser) -> fallback excluded.
Bad-socket injection: expected failure (1 refused, browser alive, no
crash/restart) — classified distinct from normal-env regression.

Resources: main-run RSS rose monotonically (A 0.35G/min ~= D 0.29G/min,
same rate, up to 17.8G/188 live renderers) -> traced to UNCAPPED injector
tab churn + Chromium idle-renderer pool, NOT sandbox: after injector cap
(<=8 tabs) identical D workload PLATEAUS at 2.0-2.7GB (supp D'). FD and
cpu trends stable; no LMK observation channel (NOT_VERIFIED standing).

Performance: same-workload dcl medians B' 81 vs D' 131.5 ms (n=4) and
main B 73.5 vs D 152 (n=24) — audio sandbox correlated with +~50-80ms
page-load dcl at heavy concurrent load; small-n, no UX jank observed;
marked 'observed, precision insufficient', NOT a defect claim. Audio
output latency field not collected (NOT_VERIFIED).

Open observations (non-blocking): (1) WS-close storm occurred in main B
and D runs (227k/245k lines) but B' rerun was clean (0) — 3/4 net-sandbox
phases + C clean -> transient tool/environment event; root cause not
closed, reproduction conditions unknown (ws server stderr was discarded
in main runs — recorded as measurement gap).

Verdict inputs are in FINAL REPORT; nothing promoted, no defaults changed.
