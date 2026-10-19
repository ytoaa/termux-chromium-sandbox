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
