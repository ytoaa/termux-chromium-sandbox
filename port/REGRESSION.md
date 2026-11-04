# Device regression gate — Termux Chromium seccomp-only port

> Status: procedures are port-version-agnostic and constitute the device
> acceptance gate. No build may be marked `validated` in `port.toml`,
> published to the apt channel, or have its automation workflows promoted
> until EVERY section below passes on the maintainer device in one sitting,
> with evidence captured under `evidence/<port>-<chromium>/`.

Hardware/kernel context (re-measure if the device changes):
Android 17 (SDK 37), kernel 6.1 GKI, aarch64;
`unshare(CLONE_NEWUSER)`=EINVAL; every other namespace flag EPERM;
self-installed seccomp-bpf+RET_TRAP=PASS (poc/seccomp_probe.c).

## 0. Hard safety rails (always on)
- NEVER dpkg-install/remove/upgrade anything; the ported deb is EXTRACTED
  (`dpkg-deb -x`) and executed from the workspace.
- Every run uses `--user-data-dir` under the workspace. The stock profile
  (`~/.config/chromium`) and stock `chromium` package are never touched;
  record `dpkg -l chromium` and stock-profile mtime before/after.
- No new process-kill patterns that can self-match (see run_probe setsid
  history).

## 1. Artifact identity
- deb `Package` == `chromium-sandboxed`; `Architecture` aarch64; version
  == `<chromium-source>-<rev>.<port>` per port.toml.
- sha256 recorded in evidence and in the release body.

## 2. Seccomp filter census (the core gate) — `port/device_gate.sh <deb>`
| process type | baseline (stock) | ported requirement |
|---|---|---|
| browser        | 1 (Android app filter) | 1 (unchanged; not sandboxed by design) |
| zygote         | 1 | 1 acceptable (layer-1 impossible on Android) |
| renderer       | 1 | **>= 2** (Chromium BPF installed) |
| gpu-process    | 1 | >= 2 (informational v1: headless may skip) |
| utility*       | 1 | >= 2 preferred; record actual |

Renderer self-verification inside chrome (CHECK(seccomp_bpf_started()))
means silent downgrade is impossible: failure mode is CRASH, not stealth.
A renderer crash loop here = policy too strict for Bionic → capture
`--enable-logging=stderr --v=1` and the SIGSYS si_code/syscall; fix the
exact BPF contract. **Never bulk-allow syscalls seen in logs** (fail-closed).

## 2b. Renderer BPF 활성화 입증 — `port/bpf_evidence.sh <chrome-bin> --ws DIR`
Phase-2 gate, offline-selftested (`selftest` subcommand, fake /proc fixtures).
Checks (all fatal unless marked WARN/INFO):
- **P0 marker**: `grep -a "Termux seccomp-only"` on the binary — proves R1/R2 were compiled in (guards against a build that silently skipped the port hook).
- **P0 tripwire**: runtime `--no-sandbox` in the browser cmdline = FAIL. This is the exact signature termux cr-patches 1001/1004 injected; catching it on-device closes the loop with the CI anti-injection scan.
- **P2 census**: renderer `Seccomp_filters>=2` AND `Seccomp==2` AND `NoNewPrivs==1`; zygote process must exist (PPid-chain renderer→zygote).
- **P2 broker**: shared socket-pair inode between a zygote fd table and a renderer fd table ⇒ sandbox IPC broker live (kernel-level evidence, not just counters).
- **P2b causality control**: rerun with `--disable-seccomp-filter-sandbox`; renderer filter count MUST drop ⇒ the 2nd filter is demonstrably Chromium's own BPF, not the Android baseline.

**Failure diagnostics (priority order, encoded in script output):**
1. port-apply.log R1/R2 APPLIED markers (build side)
2. P0 marker string (link side)
3. zygote absent + `--no-zygote` in cmdline → shell_main_delegate PreSandboxStartup path
4. `No usable sandbox` in run log → ZygoteHostImpl::Init R1 not compiled
5. renderer filters==1 with marker present → R2 / EngageNamespaceSandbox path in sandbox_linux.cc
6. SIGSYS boot-loop → renderer EnableSandbox self-CHECK vs missing BPF (expected crash-not-stealth behavior)

## 2c. GPU·Utility·Network 확대 (Phase 3)
Same census table, per-type expectations (from `census-ported.txt`):
- `gpu-process >= 2` — **recommended** (WARN, not fatal: swiftshader/headless paths may legally fork gpu before filter engagement)
- `utility >= 2` — informational; upstream Linux network sandbox is opt-in, so `utility` (network service) at Android baseline 1 is NOT a port defect
- any new `Seccomp_filters` regression vs device_gate §2 table = investigate before §3

Extra Bionic-compat patches are added ONLY if a specific type shows the R1-style
LOG(FATAL) or SIGSYS boot-loop in its run log — one type at a time, A/B per §6.

## 3. Codec capability
media-capabilities.html via `--virtual-time-budget --dump-dom`:
H.264, VP9, AV1, AAC, Opus all `probably` (5/5).

## 4. Real-world render & playback (user-confirmed)
- Local HTML page with canvas/WebGL smoke (about:gpu-equivalent) renders.
- YouTube playback with audio (live PulseAudio), no broker EACCES spam.
- about:version shows the expected chromium source version.

## 5. Crash discipline
Zero SIGSYS crash-restart loops during sections 2-4 (browser stays up;
renderer crashes are counted via chrome://crashes absent + log scan).

## 6. One-variable A/B
If any gate fails, isolate with a single flag/feature change at a time.
No `--no-sandbox`-style fallback switches are ever shipped in the port;
they exist only transiently in diagnostics.

## 7. Graphics
Keep validated WebRender/ANGLE/SwiftShader paths unchanged; GPU driver
workarounds are OUT of sandbox scope (separate investigation only).

 
## Experimental R10 gate — inherited Android SIGSYS handler (2026-10-26)

**Status: OFFLINE CANDIDATE — DEVICE NOT VERIFIED; NO-GO for promotion.**

On main device, manually installed `chromium-sandboxed 156.0.8078.47-3`
launched without `--no-sandbox` but reported 14 occurrences of Chromium's
`trap.cc:106 Existing signal handler when trying to install SIGSYS` and
user-observed `RESULT_CODE_INVALID_SANDBOX_STATE` page failures. Stock
Termux Chromium 156.0.8078.47 launched with internally injected
`--no-sandbox` and did not produce the SIGSYS warnings; both built
against Mesa 26.2.5 / Turnip / Zink, and both reported accelerated WebGL.
This A/B does not prove the warning *caused* the tab crashes.

Root-cause *candidate*: official Chromium
`sandbox/linux/seccomp-bpf-helpers/seccomp_starter_android.cc` explicitly
runs `signal(SIGSYS, SIG_DFL)` because Android app zygotes inherit an
Android-owned SIGSYS handler. Termux's `os=linux` build runs on Bionic, but
does not invoke this Android initializer. Rule R10 mirrors only that
one-time SIGSYS reservation within `StartSeccompBPF()` before
`SandboxSeccompBPF::StartSandboxWithExternalPolicy`, under
`#if defined(__BIONIC__)` only. An unsuccessful reset triggers CHECK;
no other signal, sandbox policy, or syscall allow-list is changed.

**Off-device tests**: `python3 port/tests/sigsys_r10_test.py`, through
`bash port/ci.sh selftest`, enforce the pinned upstream installer anchor,
Bionic guard, reset ordering, fail-closed behavior, idempotence and tamper
refusals. Source tests are NOT evidence of runtime sandbox activation.

**Mandatory device gate before promoting any R10 build**:

1. Build an opt-out candidate (`publish=false`); never overwrite the
   published `-3` Release or frozen validated `-2` entry.
2. Use an isolated profile and `chromium-sandboxed --ozone-platform=x11`;
   no `--no-sandbox` or other sandbox-disabling flags.
3. Check the new pre-filter `R10` marker in runtime logs
   (`--enable-logging=stderr --v=1`), confirm **zero** old
   `Existing signal handler` warnings, and **zero** crashing tabs.
4. Execute `port/bpf_evidence.sh` with process census on the actual
   device: renderer `Seccomp:2`, `Seccomp_filters>=2`,
   `NoNewPrivs:1` and P2b causality control (filters drop when BPF is
   explicitly disabled for the controlled negative run).
5. Navigate real sites / exercise multi-tab, GPU/WebGL and lifecycle
   (start, quit, start); compare to the `-3` failure signature.
   Surviving page load without filters is a **FAIL**, not a pass.
6. If the SIGSYS warning disappears but the page still crashes, preserve
   the logs, collect renderer PIDs, `/proc/<pid>/status`, signal/exit
   information, and investigate remaining BPF traps. No syscall-policy
   widening without an observed specific syscall and separate review.

This R10 candidate does not affect `maintenance-state`, the existing
`-2` validated baseline, or the `-3` published Release.


## R10 device findings and R11 read-only instrumentation (2026-10-26)

**R10 DEVICE NO-GO**: Termux Android kernel 6.1.162, Chromium
156.0.8078.47 (unrevisioned R10 build artifact from Actions #40316851934;
this is NOT validated `-2` or published `-3`). Live census showed
multiple child processes `Seccomp:2 / Seccomp_filters:2 / NoNewPrivs:1`
and repeated successful `Activated seccomp-bpf sandbox` logs. R10
`replaced pre-existing Android SIGSYS handler` appeared 53 times. Yet a
`renderer process crashed` BackForwardCache diagnostic was observed and
one `trap.cc:106 Existing signal handler ... SIGSYS` recurred.

The exceptional sequence was **22:50:51.698** `[14698:14706]`
`trap.cc:106`, then **22:50:51.723** `[14698:14698]` R10 handler reset,
then **22:50:51.724** `[14698:14698]` BPF activation for `utility`.
The `/proc` snapshot later identified process PID 14698 (PPID 10340,
filters=2), with child PID 14706 (PPID 14698, filters=2). A PID:TID
logging prefix does not establish that the earlier message was emitted
by the same thread; after-fork logging/pid caching may matter. No
causal conclusion from the 25ms difference alone.

`chrome://gpu` still displayed accelerated ANGLE OpenGL via Zink /
Turnip Adreno 750 (Mesa 26.2.5); GPU crash count 0. An `eglGetMscRateANGLE`
warning flood and an independent WebGL/Vulkan warning are not established
as causes of the renderer failure. `Seccomp_filters=2` is strong BPF
evidence, not a completed P2b causality comparison.

**R11 scope = logging only; NOT a fix, NOT for publication**:

- In `sandbox_linux.cc`, use non-mutating
  `sigaction(SIGSYS, nullptr, &before)` to log the existing handler as
  `default`, `ignored`, or `installed`, immediately **before**
  the pre-existing R10 `signal(SIGSYS, SIG_DFL)`. The existing reset
  remains verbatim; still CHECK-fail on an error.
- In `trap.cc`, emit a single `r11-trap-create` event when
  `Trap::Registry()` creates its first `Trap` object. Immediately
  after upstream `sys_sigaction`, log old handler as `default`,
  `ignored`, `chromium` (same `SigSysAction` pointer) or `foreign`.
  **No raw handler addresses are logged**, no changes to handlers,
  and the original upstream warning and filter installation are preserved.
- All instrumentation is `#if defined(__BIONIC__)` and uses
  `VLOG(1)`. Do not add setuid/userns/no-sandbox fallbacks, policy
  exceptions, or changes to `LD_PRELOAD`.
- Source tests: `python3 port/tests/sigsys_r11_diag_test.py`, 15
  positive/negative checks; full fixture is pinned Chromium 156
  `trap.cc`. CI tests are *not* runtime evidence.

**Device capture** (new disposable profile; browser process only through
`chromium-sandboxed` wrapper, never direct `chrome` bypass):

```bash
TEST="$HOME/chromium-r11-test"
mkdir -p "$TEST/profile"
DISPLAY="${DISPLAY:-:0}" chromium-sandboxed \
  --ozone-platform=x11 --user-data-dir="$TEST/profile" \
  --no-first-run --enable-logging=stderr --v=1 \
  https://example.com >"$TEST/launch.log" 2>&1 &
# During tab crashes/restarts also capture exe/PPid/Tgid/Pid/Threads/
# Seccomp/Seccomp_filters/NoNewPrivs for relevant /proc/PID/status entries.
grep -aEn 'r11-before-reset|r11-trap-create|r11-trap-owner|\
Existing signal handler|Activated seccomp-bpf|renderer process crashed' \
  "$TEST/launch.log" >"$TEST/sigsys-events.txt"
```

**Interpretation**: group by PID and actual PPid/Tgid timeline and order
`r11-trap-create`, `r11-trap-owner`, `r11-before-reset`,
R10 replacement and BPF activation. `r11-trap-owner: prior=chromium`
suggests an already installed Chromium handler in the forked path;
`prior=foreign` suggests another installed handler but does NOT
prove Android ownership; `r11-before-reset: installed` confirms R10
is about to replace *some* nondefault action. If the pre-reset action
is an existing Chromium handler, applying SIG_DFL may break later
SECCOMP_RET_TRAP handling; **do not suppress this finding**.
A crash-free tab session and BPF causality control are still required
before any final approval. Keep this diagnostic PR unmerged and its
`publish` input `false`.

## Experimental R12 gate — renderer Bionic set_tid_address allow (2026-10-28)

Candidate ONLY (branch r12-bionic-set-tid-address, DEB 156.0.8078.47-12,
workflow_dispatch publish=false). Hard rails of §0 apply unchanged:
extract-only execution, installed chromium-sandboxed 156.0.8078.47-4
NEVER modified, real profile NEVER touched (isolated snapshot copy with
human approval only), --no-sandbox tripwire armed, no new allow-list
entries beyond the single approved R12 arm.

Required evidence in one sitting (else candidate = FAIL, no promotion):
1. Static: full run_tests.sh green incl. [47]-[51] + R12 suite 19/19;
   CI gate greps 'APPLIED ... R12'; verifier scope gates intact.
2. Binary/runtime markers: strings chrome contains
   "Termux seccomp-only r12-bionic-tid: renderer allow active"; with
   --enable-logging=stderr --v=1 the R12 VLOG line count == Activated
   renderer count (allow compiled into the built filter).
3. CORE regression gate: tab create/kill burst >= 40 consecutive trials,
   ZERO renderer SIGSYS deaths (raw wait-status 31 /
   CrashExitCodes.Renderer==31 forbidden), vs -4 baseline 8/8 = 100%.
4. Reproduction battery re-run on candidate: Aquarium 1K->5K->10K,
   reloads, >=33s idle worker trim, real-profile snapshot, Vulkan on/off,
   renderer/utility spawn-exit churn, clean teardown (browser exit 0).
5. Instrumented (strace) trials run SEPARATELY from uninstrumented:
   set_tid_address(0) = 0 at thread exits, no '+++ killed by SIGSYS',
   no siginfo(si_syscall=178) captures.
6. Security census per-process: browser 1 / zygote 1 / renderer
   Seccomp=2 Seccomp_filters=2 NoNewPrivs=1 (every renderer, every
   trial); GPU + network utility re-measured and reported vs the
   R11-known state (GPU BPF not engaged = pre-existing WARN, OUT of R12
   scope); P2b causality control still flips renderer 2->1.
7. Block-matrix integrity: live SIGSYS trap controls still fire and
   survive (openat/sched_getparam -> handler -> rt_sigreturn); the ten
   dangerous arm64 syscalls keep their documented deny path (static
   citation per syscall: execve/execveat/ptrace/mount/umount2/
   init_module/delete_module/seccomp/unshare/setns) — R12 must be the
   ONLY allowlist delta versus -4.
