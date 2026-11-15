# R33 — upstream 157 `GetStackTop()` refactor (R8 anchor drift) — fix & status

Started 2026-11-14 00:05 KST. Trigger: scheduled builds red for 6 days.

## 1. Symptom (measured)
Daily Maintenance runs 42178147103, 42346099370, 42454326054, 42575871293,
42974914685, 43175216128 all failed with

    [    PORT ERROR] R8 bionic stack-top cache (PA stack.cc): expected exactly one old form, found 0

while the probe logged `action=build reason=new-upstream-version`
(issues #29, #32-#36 for upstream 157.0.8103.38 / 157.0.8103.50).
`43382276901` "succeeded" only because it decided `action=skip reason=blocked-dedup`
(no build performed).

## 2. Root cause (verified against the real upstream file)
Fetched `refs/tags/157.0.8103.50` `base/allocator/partition_allocator/src/partition_alloc/stack/stack.cc`
from chromium.googlesource.com. Differences vs 156:

| aspect | 156 | 157 |
|---|---|---|
| return type | `void* GetStackTop()` | `uintptr_t GetStackTop()` |
| POSIX arm guard | plain `#else` | `#elif PA_BUILDFLAG(IS_POSIX) \|\| PA_BUILDFLAG(IS_FUCHSIA)` |
| base return | `PA_UNSAFE_TODO(reinterpret_cast<uint8_t*>(base) + size)` | `reinterpret_cast<uintptr_t>(base) + size` |

R8's anchor text is 156-shaped, so the count was 0 and the port refused (fail-closed
is the intended behaviour; the anchor was stale).

## 3. Fix (commit `8e413c9`, PR #37, merged `6c837f1`)
* `replace_optional_variants()`: exactly one matching shape is applied; 0 or 2+
  raise `PortError`; re-apply reports `ALREADY_PRESENT` with the variant label.
* R8A gains a 157 body with the same semantics: one `#if defined(__BIONIC__)`
  guard set, main-thread-only (`pthread_equal(pthread_self(), g_termux_main_thread)`)
  single cache, no syscall arm, no `Allow()`.
* `TermuxPrewarmStackTop()` returns `reinterpret_cast<void*>(GetStackTop())`
  so one definition compiles for both return types.
* Untouched: syscall policy, packaging, identity gate, release/publish surface.

## 4. Local verification (executed)
Ran the transformer over the **real 157.0.8103.50 sources** (11 patched files):
all rules APPLIED, all markers VERIFIED, re-apply idempotent (`variant 157`).

Harness:
    bash port/tests/run_tests.sh -> 68 checks PASS / 0 FAIL, RC=0
Authoritative suites: [52] cache layers 81 checks (T15d/T15d2/T15e pin
shape-independent constants to bae5316, patch order, and both R8 variants),
[56] C-5 22 checks, [57] new upstream-shape suite 4 checks:
    57a 157 -> variant 157 + marker verified
    57b re-apply -> ALREADY_PRESENT variant 157
    57c 156 fixture -> variant 156 still selected
    57d artificial third shape -> PORT ERROR (fail-closed)

## 5. CI acceptance (in progress at report time)
Run `43453888322` (main `6c837f1`, upstream 157.0.8103.38 pin
`88ecb5c7…`, pkg_revision 1, publish=false): the build step is **running**, i.e.
the transformer accepted the 157 tree (a stale anchor would have failed in ~10 s).
First run for a new upstream + rotated port hash is a cold cache run and is
expected to end RC=124 at the guard while persisting depcache/sccache/L4; only a
second (warm) run can be GREEN. No success is claimed until such a run exists.

## 6. What remains
1. Run 1 (cold) → confirm `R8 … variant 157` in the log + cache persistence.
2. Run 2 (warm) → GREEN build of 157 on main.
3. After GREEN: maintenance pipeline unblocks automatically (its `action=build`
   path reuses the same port) and the 157 candidate can be registered.
4. Open issues #29/#32-#36 stay blocked until that GREEN exists (they are the
   fail-closed record, not a false claim).

## 7. Run 1 measured (43453888322) — transformer fixed, second defect exposed

Pin `88ecb5c7` (host-tools 157.0.8103.38, chromium recipe **156.0.8078.79**),
publish=false, cold.

    [APPLIED] R8 bionic stack-top cache (PA stack.cc): variant 157 (uintptr_t)   <-- R33 fix works
    NOTE: aligned clone 156.0.8078.79 -> host-tools 157.0.8103.38
    building chromium-host-tools for arch aarch64...
    ... (235 min) ...
    ERROR at //v8/BUILD.gn:2819:7: Undefined identifier.
          deps += [ ":run_metagen" ]
    SCCACHE_PROFILE_BUILD_RC=1   SCCACHE_PROFILE_BUILD_SECONDS=14110
    depcache / sccache / L4 saves => success; gates & DEB save skipped (build failed)

So the port now accepts the 157 sources; the build then fails in `gn gen` because
the **pinned tree's recipe/cr-patches are one version behind** (termux bumped
host-tools first). RC=1, not 124 — it never reached the guard.

Evidence: `logs-compare/r33-157-cold-full.log`.

## 8. Fix 2 — maintenance gate (PR #38, merge `9ddd3f6`)

`decide()` refuses `recipe.version != host_version`
(`action=skip reason=upstream-recipe-not-ready`) instead of burning a 4-hour
runner on an upstream version the tree cannot build. Tests m1b/m1c/[16]/[16b],
maintenance suite 73 checks, harness 68 checks PASS / 0 FAIL.

## 9. Ready-pin build (43494827863) — in progress

termux master `f6bf3c4563bb6d0434619a6f4df035cc19920bfb` declares
**157.0.8103.50 in BOTH** `chromium/build.sh` and `chromium-host-tools/build.sh`
(verified via raw fetch). Dispatched on main @ `6c837f1` with
`pkg_revision=` (plain version), `publish=false`, DEB reuse off. Cold run:
RC=124 at the guard is expected; only a following warm run can be GREEN. No
success is claimed until such a run exists.

## 10. Status of the scheduled pipeline

With both fixes on main, the probe now:
* refuses to target a lagging tree (no daily 4h failure, no new blocked issues);
* builds as soon as the recipe declares the version — measured today as true for
  157.0.8103.50. The next scheduled run therefore retries with a ready pin.
Open auto-build issues #29/#32-#36 remain as the fail-closed record until a
GREEN 157 build exists.

## 11. Ready-pin cold run (43494827863, pin `f6bf3c45`, main `6c837f1`) — measured

    [APPLIED] R8 bionic stack-top cache (PA stack.cc): variant 157 (uintptr_t)
    (no "aligned clone" NOTE — recipe and host-tools both declare 157.0.8103.50)
    DEPSED seed cold (new termux pin)
    Found chromium-host-tools in https://packages-cf.termux.dev/apt/termux-x11/...   (no source build)
    GN passed — the v8/metagen error of run 43453888322 did NOT recur
    target progress: [28327/29242] at the guard (96.9 %)
    SCCACHE_PROFILE_BUILD_RC=124  SCCACHE_PROFILE_BUILD_SECONDS=14400
    sccache: 15,304 requests / 15,260 executed / 0 hits / 15,254 misses (cold)
    depcache / sccache (33,469 files) / L4 v2 saves => success
    DEPSED collect new=0 total=0

Interpretation: the two fixes did their job — the port accepted the 157 tree and
the build ran all the way into the target (29,242 edges), missing GREEN only by
the 240-minute guard (a cold cache: every one of the 15,254 compiles missed).
This is a TIMEOUT, not a completed build.

Cache-key check before run 3: the maintenance gate (PR #38) changed only
`port/maintenance.py`, which is NOT in `PORT_RAW_FILES`, so the port-input hash
stayed `8e2afc38afb0e4b3` (verified at both `6c837f1` and `9ddd3f6`) and run 3
can inherit run 2's 33k-object sccache archive.

## 12. Warm run (43530166879, same pin, main `9ddd3f6`) — in progress
Dispatched 23:51Z. Expected: depcache + sccache restore, near-100 % hits, target
finishing inside the guard. GREEN is claimed only if RC=0 and gates pass.

## 12. Warm run GREEN — measured (43530166879, main `9ddd3f6`)

    [APPLIED] R8 bionic stack-top cache (PA stack.cc): variant 157 (uintptr_t)
    DEPSED seed entries=0 (new termux pin, depcache had no dependency debs yet)
    Found chromium-host-tools in https://packages-cf.termux.dev/apt/termux-x11/...
    build start 23:57:32 -> [29242/29242] complete
    SCCACHE_PROFILE_BUILD_RC=0   SCCACHE_PROFILE_BUILD_SECONDS=3862   (64.4 min)
    PORT GATES PASS: chromium-sandboxed 157.0.8103.50
    Package gates / Emit outputs / Guard cache saves => success
    sccache: 16,151 requests / 15,503 hits / 604 misses (96.3 %)
    restores: sccache …-b2cad4ac…-43494827863, depcache …-f6bf3c45…-43494827863
    saves: depcache …-43530166879, sccache …-43530166879; L4 save skipped (has_new=0)

Artifact (downloaded and verified locally):

    chromium-sandboxed_157.0.8103.50_aarch64.deb
    sha256 cd0912903dc02d46f29859fe796d161099787c9fdc299b71d445ad53d79a7391
    160,452,964 bytes
    PACKAGE-IDENTITY-PASS: chromium-sandboxed, 486 private files

**This is the first GREEN 157 build on main** — RC=0, gates pass, 64.4 min inside
the 240-min guard, and the cold run's 33k-object archive was inherited exactly as
designed (15,503 hits).

## 13. Cold vs warm (157.0.8103.50, same pin, same port hash `8e2afc38…`)

| run | mode | build | target | sccache | RC | outcome |
|---|---|---|---|---|---|---|
| 43494827863 | cold | 240.0 min (guard) | 28,327 / 29,242 (96.9 %) | 0 hit / 15,254 miss | 124 | timeout, caches persisted |
| 43530166879 | warm | **64.4 min** | **29,242 / 29,242** | **15,503 hit / 604 miss (96.3 %)** | **0** | **GREEN, gates PASS** |

## 14. Verdict

| item | verdict |
|---|---|
| R8 upstream-157 anchor | **GO** (variant 157 applied in both real builds) |
| Maintenance upstream gate | **GO** (refuses lagging trees; ready pin builds) |
| 157 build on main | **GO** (RC=0, gates PASS, identity PASS) |
| Scheduled pipeline recovery | **CONDITIONAL** — next scheduled run repeats this build (warm) and registers the candidate; state (`maintenance-state`) was NOT written by these manual runs |
| R12 release | **NO-GO** — device matrix on 157 + release approval still missing |

Remaining open items: auto-build issues #29/#32-#36 stay open as the fail-closed
record until the scheduled pipeline registers a 157 candidate; `maintenance-state`
still records 156.0.8078.79-2 as the last successful build.
