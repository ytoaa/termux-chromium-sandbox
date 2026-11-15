# Design notes index

The design record was split in Round 35 so each part stays navigable.

| document | content |
|---|---|
| [docs/design/ARCHITECTURE.md](../docs/design/ARCHITECTURE.md) | target, device facts, seccomp-only decision, security posture, device-safety constraints, Phase 0/1b/2a/2b decisions, runner and test-device policy |
| [docs/design/ROUNDS.md](../docs/design/ROUNDS.md) | chronological round log (mysteries, device gates, R1–R34 fixes, CI/cache work, maintenance pipeline) |
| [docs/evidence/](../docs/evidence/) | recent evidence summaries + kept reports (full raw logs live in the maintainer workspace) |
| [port/REGRESSION.md](REGRESSION.md) | regression policy and historical failure modes |
| [README.md](../README.md) | usage, build and device-gate overview |

Invariants that never move are enumerated in the harness (`port/tests/`) and enforced
by the transformer's fail-closed rule set; treat the tests as the normative source.

Round 16 signature-schema v2 notes, Round 19 / Phase 0.3 decisions and every other
historical heading now live in the two documents above.
