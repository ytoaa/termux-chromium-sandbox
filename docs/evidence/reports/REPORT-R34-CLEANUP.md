# R34 — repository cleanup (executed) + post-cleanup state

Executed 2026-11-14 01:5x–02:0xZ on request ("나머지들도 정리"). Everything below
was actually performed; nothing is projected.

## 1. Before → after

| item | before | after |
|---|---|---|
| remote heads | 19 | **3** (`main`, `maintenance-state`, `r12-artifacts`) |
| tags | 2 | **18** (2 releases + **16 `r34-archive/*`** audit tags) |
| open PRs | 5 (#22/#24/#25/#26/#27) | **0** (all closed as superseded by #28) |
| open issues | 7 | **1** (#12 operational tracker; the 6 auto-build-blocked records closed) |
| caches | 11 entries / 11.96 GB | **3 entries / 3.84 GB** (list API; see §5) |
| releases | 2 pre-releases | unchanged |
| main | `9ddd3f6` | unchanged |
| maintenance-state / r12-artifacts | `4df8f7b` / `e70801a` | **unchanged (never touched)** |

## 2. Archive tags created (16, annotated, target = the exact deleted head)

    r34-archive/r12-bionic-set-tid-address      bae5316
    r34-archive/perf-ci-cache-layers            9ecb6e3
    r34-archive/perf-ci-source-cache            304faba
    r34-archive/audit-r12-full-verification     9570a3e
    r34-archive/fix-f6-side-by-side             3995f75
    r34-archive/diagnostics-r12-sccache         bae5316
    r34-archive/diag-r11-evidence-instrument-fixes 7b02fc6
    r34-archive/promotion-r11-r4-validated      a5d2977
    r34-archive/hotfix-chromium-side-by-side    1f7b612
    r34-archive/hotfix-publish-startup          d233096
    r34-archive/diag-ci-node24                  c8f9ff3
    r34-archive/integration-r12-main            feceb61
    r34-archive/fix-r12-profile-isolation       4130c00
    r34-archive/fix-c5-depcache-prune           a45f336
    r34-archive/fix-r33-upstream-157-r8         8e413c9
    r34-archive/fix-r33-maintenance-gate        5e5e10b

Verified with `git ls-remote --tags origin 'r34-archive/*'` (32 lines = 16 annotated
tags with peeled refs) and `git rev-parse <tag>^{commit}` for every tag.

## 3. PRs closed
#22, #24, #25, #26, #27 — comment points to PR #28 (integration) and the archive
tags; `gh pr reopen` remains possible.

## 4. Branches deleted (16)
r12-bionic-set-tid-address · perf/ci-cache-layers · perf/ci-source-cache ·
audit/r12-full-verification · fix/f6-side-by-side ·
diagnostics/r12-sccache-profile-20261028 · diag/r11-evidence-instrument-fixes ·
promotion/r11-r4-validated · hotfix/chromium-side-by-side-package-paths ·
hotfix/publish-startup · diag/ci-node24 · integration/r12-main ·
fix/r12-profile-isolation · fix/c5-depcache-prune · fix/r33-upstream-157-r8 ·
fix/r33-maintenance-upstream-gate

Recovery: `git push origin <sha>:refs/heads/<name>` for any archived SHA (all 16 are
reachable from tags), or from `refs/pull/*/head` for the five stacked PRs.

## 5. Caches (deleted by id, newest generation kept)
Deleted (all superseded generations + one 0-byte entry):

    10494089085 (L4 v2 88ecb5c7, 2,319 MB)   10398843740 (L4 v2 44c429b4, 2,113 MB)
    10504040588 (sccache b2cad4ac older, 1,262 MB)
    10494084781 (sccache c0c8922c, 780 MB)   10398840177 (sccache 2c945b15, 750 MB)
    10504030876 (depcache f6bf3c45 older, 432 MB)
    10494078081 (depcache 88ecb5c7, 455 MB)   9999514094 (0-byte zram)

Kept: `chromium-srccache-aarch64-v2-…-f6bf3c45…` (2,113 MB),
`chromium-sccache-aarch64-b2cad4ac…` (1,303 MB),
`termux-depcache-aarch64-…-f6bf3c45…` (432 MB) — the exact set the 157 GREEN run used.

Measured discrepancy (recorded, not resolved): `actions/cache/usage` still reports
**10 entries / 9.64 GB** while `actions/caches` lists **3 entries / 3.84 GB**. Branch
deletion and cache deletion are separate API surfaces and the usage endpoint is
eventually consistent; the authoritative inventory is the list endpoint. Re-check
before the next deletion round.

## 6. Issues closed
#29, #32, #33, #34, #35, #36 — fail-closed blocked records, superseded by the GREEN
157 build (43530166879). #12 (operational tracker) left open.

## 7. Not done (deliberately)
* `maintenance-state`: not modified, not merged (bot-owned state; still records
  156.0.8078.79-2).
* `r12-artifacts`: untouched (evidence container).
* Existing tags/releases: untouched.
* No release/publish/apt action; publisher workflow stays `disabled_manually`.
* Device matrix for the 157 deb: still **not executed**.

## 8. Post-cleanup risks
* The five stacked PRs are closed; their review trail survives only as archived
  tags + `refs/pull/*` (documented, not destructively tested).
* The 157 GREEN artifact (`cd091290…`) is **not** device-verified; R12 release
  remains blocked on that.
* Only three caches remain; the next producer run will recreate a DEB cache and a
  new sccache generation (each ~1 GB) — the 10 GB budget has ~6 GB headroom again.
