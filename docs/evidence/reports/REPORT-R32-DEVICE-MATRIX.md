# R32 — device matrix on the TESTBED for chromium-sandboxed 157.0.8103.50

Executed 2026-11-14 11:33–11:58Z against the dedicated remote Termux testbed
(aarch64, Android 13, clean: no chromium package installed). Evidence logs live in
`gate-out/r32-*`.

## 1. What was run

| step | command | result |
|---|---|---|
| baseline re-check | SSH batch probe | reachable, aarch64, Android 13, 62 GB free, no chromium installed |
| gate scripts | pushed current `port/device_gate.sh`, `port/bpf_evidence.sh` to the testbed | sha256 matched local |
| artifact | run `43530166879` (GREEN 157) → `chromium-sandboxed_157.0.8103.50_aarch64.deb` | sha256 `cd0912903dc02d46f29859fe796d161099787c9fdc299b71d445ad53d79a7391`, 160,452,964 B |
| real install | `dpkg -i` + `apt-get -f install` | **PASS** — `ii chromium-sandboxed 157.0.8103.50 aarch64` |
| device_gate | extract-run census + renderer/filters verdict | **FAIL** (see §2) |
| bpf_evidence | — | not executed: `remote_gate.sh` passes `find extracted` while the gate workspace is `chromium-device-gate/extracted` (harness path bug, not a product failure) |
| cleanup | `dpkg -r chromium-sandboxed` | **device returned to clean state** (dpkg list empty) |

## 2. Measured failure (root cause found)

`device_gate` output:

    baseline renderer filters=none | ported renderer=none gpu=none utility=none
    GATE FAIL: no ported renderer with >=2 filters (BPF missing; present=0 crashing=0)
    DEVICE GATE: FAIL

Manual verbose run of the ported binary shows the exact sequence (probe-chrome3.log):

    [pid] VERBOSE1 bpf_renderer_policy_linux.cc:131  Termux seccomp-only r12-bionic-tid: renderer allow active
    [pid] VERBOSE1 sandbox_linux.cc:94               Activated seccomp-bpf sandbox for process type: renderer.
    couldn't open /proc/self/stat: Operation not permitted
    libc: couldn't open /proc/self/stat: Operation not permitted
    ... SIGABRT (ImmediateCrash) ...

Counters in a single 2-minute run:

    renderer sandbox activations : 15,423
    "couldn't open /proc/self/stat" : 30,848
    "couldn't open /proc/self/maps" :      0
    SIGSYS handler markers       : 15,460

So: **the renderer installs the BPF correctly (R12 allow active + Activated), then bionic's
`pthread_getattr_np` for the process main thread opens `/proc/self/stat`, the filter
denies `openat`, bionic LOG(FATAL)s, and the process ImmediateCrash()es — in a tight
restart loop (15k activations/2 min) with no renderer ever surviving.** This is a
different path from the 156-era `/proc/self/maps` failure that R6/R7/R8 addressed.

`strace -f` decomposition of the aborting processes:
`seccomp(SECCOMP_SET_MODE_FILTER, …)` → handshake → `writev(2, "couldn't open
/proc/self/stat…")` → `rt_sigaction(SIGABRT, SIG_DFL)` → `tgkill(SIGABRT)`.
All 47 filter-using processes died by SIGABRT (336 events); **no SIGSYS kill** was
observed, so this is not a RET_KILL policy miss.

### Why the existing R8 cache does not cover it

`port/chromium_sandbox_port.py` R8 caches the stack top only when
`pthread_equal(pthread_self(), g_termux_main_thread)`, and `g_termux_main_thread` is a
namespace-scope constant captured at static-init time. After `fork()`, children
(zygote → renderer) inherit that value, so in the renderer the predicate is false and
the cache is bypassed → `pthread_getattr_np` runs post-filter → abort.
(Upstream 157's own cache in `base/debug/stack_trace.cc` uses a **fork-safe**
`GetCurrentProcId() == PlatformThread::CurrentId()`, which is why it does not cover
this PA call site either.)

## 3. Secondary observations (harness, not product)

* The testbed kernel exposes only `Seccomp: 2` in `/proc/<pid>/status`; there is **no
  `Seccomp_filters` field** on this Android 13 kernel, so `device_gate.sh`'s
  `filters>=2` criterion can never pass here even when the sandbox is active. The
  gate needs a fallback (count `SECCOMP_SET_MODE_FILTER` from strace/tracepoint, or
  accept `Seccomp=2` + "Activated" evidence).
* `remote_gate.sh` runs `bpf_evidence.sh` with `find extracted …`, but the extracted
  tree lives under `chromium-device-gate/extracted` → `bpf_evidence` aborts with
  "extracted: No such file or directory".

## 4. Verdict

| item | verdict |
|---|---|
| 157 deb install on testbed (dpkg path) | **PASS** |
| renderer sandbox activation | **PASS** (R12 allow + Activated observed 15k times) |
| renderer survival / usable browser | **FAIL** (immediate crash loop) |
| device matrix overall | **FAIL — R32 NOT PASSED** |
| release readiness | **NO-GO** (unchanged) |

## 5. Proposed next step (not applied)

Make the PA main-thread predicate fork-safe and keep the prewarm per process, i.e. in
`R8A_NEW`/`R8A_NEW_157` replace
`pthread_equal(pthread_self(), g_termux_main_thread)` with a pid==tid test that is
valid in every forked child (same rule upstream 157 uses in `stack_trace.cc`), so the
prewarm in `StartSeccompBPF` fills the cache in each child **before** the BPF is
installed and the post-activation call never touches `/proc/self/stat`.

Cost: a port change rotates `port-input-hash`, so verification needs one cold run
(240-min guard, caches persisted) plus one warm run (~65 min) before re-running the
device gate.

## 6. Fix applied (commit `f212045`, PR #39, merge `8367dae`)

* `R8A_NEW` / `R8A_NEW_157`: main-thread test is now the fork-safe
  `gettid() == getpid()` (the rule upstream 157 uses in
  `partition_alloc_base/debug/stack_trace.cc`); `g_termux_main_thread` is gone.
* The former R8 "main-thread capture" rule now inserts a bionic-guarded
  `#include <unistd.h>` (gettid/getpid declarations).
* Prewarm path unchanged: `StartSeccompBPF` fills the cache per process before
  the BPF is installed, so the post-activation call returns the cached value and
  never opens `/proc/self/stat`.
* Test tooling: `remote_gate.sh` now points `bpf_evidence.sh` at
  `chromium-device-gate/extracted`.

Harness: 69 checks PASS / 0 FAIL, RC=0 ([23] fork-safe predicate, [52] T15d2
R-id order + T15e fork-safe semantics, [57a2] patched-tree assertions).

## 7. Rebuild verification (in flight)

* cold run `43551320109` on main `8367dae`, pin `f6bf3c45` (157.0.8103.50),
  publish=false — a port change rotates `port-input-hash`, so this run is cold
  and may end RC=124 while persisting the caches;
* then a warm run must be GREEN before the device gate is repeated.

Device matrix stays **FAIL / not re-verified** until that re-test exists.

## 8. Final device result — PASS (run 43712250558 deb)

Build `43712250558` (main `06a8265`, pin `f6bf3c45`, 157.0.8103.50): **RC=0**, 202.5 min,
target 29,242/29,242, `PORT GATES PASS`, sccache 16,107 hits / 0 misses.
Deb `sha256 1a9db80495a0d6caf14e595946810de136a0e175373edbdc382d79c674a7b75f`, 160,438,912 B.

Testbed re-run with the rebuilt deb:

    install:  ii chromium-sandboxed 157.0.8103.50 aarch64        PASS
    device_gate:  renderer x44 alive, Seccomp=2, 0 CRASHING, codecs ok -> PASS
    bpf_evidence: P0 marker ok; P2 renderer x9 alive Seccomp=2 nnp=1,
                  broker-inodes=9, runtime --no-sandbox=0;
                  activated-renderer=7, crash-lines=0; P2b NOTE
    VERDICT run 43712250558: device_gate=0 bpf_evidence=0

The renderer crash loop is gone (`/proc/self/stat` fatal count 0 in the passing run).

### Honest limits of this PASS
* This Android 13 testbed kernel exports only `Seccomp:` mode, **not**
  `Seccomp_filters`; the pass rests on renderer presence in filter mode
  (`Seccomp=2`), NoNewPrivs=1, zero crash lines, broker socket inodes and a
  complete media codec report (5/5 `probably`).
* The authoritative **filter-count** census and the P2b causality drop remain
  deferred to the main device (kernel >= 6.1) and are NOT claimed here.

## 9. Harness changes that made this measurable (PR #41, main)
* `device_gate.sh`: census parsing corrected (the `[ported]` prefix existed only
  in the display stream); zygote->renderer reclassification added; the installed
  package wrapper+chrome is now the probed path; Seccomp-mode fallback in the
  verdict.
* `bpf_evidence.sh`: zygote presence by row (not filter count); P2b records an
  unexportable-kernel NOTE instead of failing.
* `remote_gate.sh`: bpf_evidence receives the installed shield wrapper.

**Device matrix for the 157 deb: PASS-with-noted-measurement-limits.**
Device state after the run: package removed by the gate cleanup; disk space was
recovered (7.5 GB free) after deleting 4 GB probe logs and stale working dirs.
