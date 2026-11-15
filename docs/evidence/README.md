# Evidence index (recent)

Full raw logs and device screenshots stay in the maintainer workspace
(`~/Project/chromium-evidence/`); the durable, reviewable parts are kept here so
the repository is self-explanatory without that workspace.

| file | content |
|---|---|
| [EVIDENCE-LEDGER.md](EVIDENCE-LEDGER.md) | round-by-round evidence ledger (R12 → R34) |
| [reports/REPORT-R32-DEVICE-MATRIX.md](reports/REPORT-R32-DEVICE-MATRIX.md) | 157 device matrix: root causes, fixes, testbed PASS with measurement limits |
| [reports/REPORT-R33-UPSTREAM157-R8.md](reports/REPORT-R33-UPSTREAM157-R8.md) | upstream-157 R8 shape fix, cold/warm measured builds, artifact identity |
| [reports/REPORT-R34-CLEANUP.md](reports/REPORT-R34-CLEANUP.md) | branch/PR/issue/cache cleanup execution |
| [reports/REPORT-R34-MAINTAINABILITY.md](reports/REPORT-R34-MAINTAINABILITY.md) | maintainability audit and P0 application |
| [reports/REPORT-R34-SOAK.md](reports/REPORT-R34-SOAK.md) | 60-minute device soak (stability, timers, canvas) |

## Latest state snapshot (as of Round 34)

* `main` = `76b0bda` (P0+P1 maintainability), branch protection requires `selftest`.
* Latest GREEN producer build: `43760242491` (157.0.8103.50, RC=0, gates PASS,
  artifact 160,998,876 B), run before the docs split.
* Cache pool: 3 layers kept (L4 + sccache + depcache), ~3.85 GB at last audit.
* Cache warm/budget workflow: `.github/workflows/cache-warm.yml` (probe + 8 GB guard).
* Open PR 0, open issue 1 (#12 operational tracker), remote branches 3.
* Known limits: testbed kernel hides `Seccomp_filters` (proxy criteria);
  `download-artifact` v7 validation pending the next daily run.
