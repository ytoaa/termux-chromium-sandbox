# R34 — 60-minute Chromium soak on the testbed

Executed 2026-11-16 03:22–04:27 KST (18:23–19:27Z) on the dedicated remote Termux
testbed (SM-G981N, aarch64, Android 13) with the **installed**
`chromium-sandboxed 157.0.8103.50` deb
(`sha256 1a9db80495a0d6caf14e595946810de136a0e175373edbdc382d79c674a7b75f`),
launched through the shipped `chromium-shield-wrapper.sh` (the product path, which
sets `LD_PRELOAD=libtermux-gnp-fix.so`).

## 1. Workload

A local `file://` page (`~/chromium-gate/soak4/page.html`) drawing to a 800×400
2D canvas on a `setInterval(..., 33)` (~30 fps) loop, updating a frame counter and
`document.visibilityState` text. This exercises: renderer JS timers, canvas
rasterization, compositor frame submission, IPC and the full sandbox.

## 2. Measured (one sample per minute, 60 samples)

| metric | value |
|---|---|
| browser alive | **60 / 60 samples** (`alive=yes`) |
| renderer processes | 9 (steady from t=2 onward), 11–16 child rows incl. utility/prefetch |
| zygote / utility / browser | 2 / 1 / 1 (steady) |
| browser `Seccomp` mode | **2** (filter mode) in every sample |
| total chrome RSS | 1,051 MB at t=1 → **293–295 MB steady from t=12 to t=60** |
| crash signatures (`CRASHING`/fatal) | **0** |
| animation counter | **frame 18,199 at t=10 min** → **frame 116,255 at t=60 min** |
| visibility state | `vis=visible` throughout |
| disk | stable during the run (external cleanup later freed the device to 67 GB) |

Frame-count cross-check: a 33 ms interval over 600 s predicts ~18,180 frames at
t=10 min — measured 18,199. Over the full hour the counter reached 116,255 with no
gap, i.e. **timers ran continuously for the whole hour**.

## 3. Observations (not failures)

* One `Existing signal handler when trying to install SIGSYS` line appeared once
  (t≈3 min, a child process startup) in the log. It is the known R10-class
  reservation warning; no crash followed and it did not recur.
* `vkCreateInstance failed with VK_ERROR_INCOMPATIBLE_DRIVER` (2 lines): the
  testbed has no Vulkan driver; Chrome used the software path, which rendered
  correctly for the full hour.
* No GPU process was present (`gpu=0`); software compositing was used.
* dbus/UPower connection errors are normal in Termux and were present from the
  first seconds.

## 4. Correction of an earlier false alarm (recorded for honesty)

The first soak attempt (and the anim2 probe) used a `data:` URL page whose JS
contained `n%360`. The data-URL parser percent-decodes `%36` to the character
`6`, so the served script contained `n60` (undefined) and threw on the first tick —
the page stayed blank and looked like a sandbox freeze. Re-running the same page
from a `file://` URL (no URL decoding) rendered and animated correctly. The
sandbox was never at fault; the soak was re-run with the file-based page above.

## 5. Verdict

| item | verdict |
|---|---|
| 60-minute process stability | **PASS** (alive 60/60, no crash signatures) |
| memory stability | **PASS** (293–295 MB steady after warm-up; no growth) |
| JS timers / 30 fps canvas animation | **PASS** (18,199 → 116,255 frames, continuous) |
| sandbox engagement | **PASS** (Seccomp=2 in every sample; renderers alive) |
| functional anomalies | none blocking; one SIGSYS-reservation WARN and missing Vulkan driver noted |
| release readiness | unchanged — device matrix 157 is PASS-with-noted-limits; release still needs approval |

Evidence: `gate-out/r34-soak60d.log`, device-side `~/chromium-gate/soak4/soak.log`,
screenshots `r34-soak4-snap10.png` / `r34-soak4-snap60.png`.
