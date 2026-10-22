# termux-chromium-sandbox

Revive Chromium's Linux sandbox on Termux/Android (aarch64) with the smallest
possible, **fail-closed** compatibility layer — the Chromium sibling of
[ytoaa/termux-firefox-sandbox](https://github.com/ytoaa/termux-firefox-sandbox).

Termux's `x11-packages/chromium` ships with the sandbox unusable; its own
maintainer note (build.sh) says the seccomp-bpf path needs "lots of patches"
and invites a PR. This project is that attempt.

## Status

- **Phase 3 — device regression gate: PASS** (2026-10-22, main device: Android
  17 / kernel 6.1 GKI / aarch64, run #28 deb `155.0.8059.84`, sha256
  `4e7dce52…dbe820a`): fully-green gated build (self-test + build + all
  package gates), then X11 DEVICE GATE PASS on the packaged artifact — 6
  renderer seccomp-bpf activations, codecs 5/5 (h264/vp9/av1/aac/opus), 7 live
  children with `Seccomp_filters=2` + `NoNewPrivs=1` (stock baseline 0–1).
  Chromium's own BPF policy is installed per-process. See `port/DESIGN.md`
  round 7 (the bionic `pthread_getattr_np` shield) and round 9.
- **Phase 0 — feasibility: PASS** (2026-10-19, device: Android 17 / kernel 6.1 GKI / aarch64)
  - `poc/seccomp_probe.c`: a plain Termux process CAN install its own
    seccomp-bpf filter (`prctl PR_SET_SECCOMP` → `PR_GET_SECCOMP=2`), ALLOW
    rules pass through, and `SECCOMP_RET_TRAP` delivers SIGSYS
    (`si_code=SYS_SECCOMP`). Exit 42 = expected.
  - Unprivileged **user namespaces are unavailable** (`unshare(CLONE_NEWUSER)`
    → EINVAL; Android blocks them since 12+). Therefore the port targets
    **seccomp-only (non-namespace) mode**: BPF policy filters without the
    namespace pivot layer. Isolation is weaker than desktop Linux and is
    documented as such — it is still a large step up from today's no-sandbox.

## Design principles (carried over from the Firefox port)

- Fail-closed: a new upstream source shape never silently gets broader access.
- Single sources of truth: `port/port.toml` (version/validation contracts),
  `port/chromium_sandbox_port.py` (semantic source changes), recipe changes
  isolated to `prepare_recipe.py` (workflow = orchestration only).
- Explicit over-grant guards in a verifier; device regression gate before any
  `validated` mark.
- Package-version lead so `pkg upgrade` can never replace the sandboxed build
  with Termux's sandbox-off build (exact scheme to be re-derived for chromium).
- apt channel via gh-pages after a fully-green gated build.

## Layout

- `port/DESIGN.md` — architecture notes and the decision record (v0)
- `port/port.toml` — contract/state ledger
- `poc/seccomp_probe.c` — reproducible Phase-0 evidence

## Not yet

No CI workflows are defined yet; they will be introduced (already-hardened
patterns, exact bot-identity gate) in Phase 2 behind a review before enabling.
