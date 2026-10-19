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
