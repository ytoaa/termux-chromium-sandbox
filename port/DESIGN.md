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
