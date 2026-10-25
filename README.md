# termux-chromium-sandbox

Revive Chromium's Linux sandbox on Termux/Android (aarch64) with the smallest
possible, **fail-closed** compatibility layer — the Chromium sibling of
[ytoaa/termux-firefox-sandbox](https://github.com/ytoaa/termux-firefox-sandbox).

Termux's `x11-packages/chromium` ships with the sandbox unusable; its own
maintainer note (build.sh) says the seccomp-bpf path needs "lots of patches"
and invites a PR. This project is that attempt.

## Status

- **Validated baseline (Round 13, 2026-10-24): run #31 / Chromium
  `156.0.8078.47`** (port `403274f`, termux-packages `64e02760`, deb sha256
  `29c4080d…9395b27c`) — fully-green gated build (CI self-test 42/42 + build
  + package gates incl. R9a grep), then A/B/C/D device gates on both devices
  and Round-12/12.1 soak: on kernel 6.1, 635 ACT-scoped rows
  `Seccomp_filters=2`+`NoNewPrivs=1` with zero violations; AudioServiceSandbox
  stream owner pid is the sandboxed utility (no browser-side fallback);
  60-min D + 10/10 relaunches; browser download manager A+D sha-match;
  zombie rows 0 with full reap; testbed dpkg install->purge residual 0.
  Network/Audio sandbox features remain **default-OFF** (enable via
  `--enable-features=NetworkServiceSandbox,AudioServiceSandbox`); default-on,
  apt/Release publishing are separate approvals. LMK observability is
  **NOT_VERIFIED** on non-root (not claimed absent). Prior baseline run #28
  (`155.0.8059.84`, sha256 `4e7dce52…dbe820a`, X11 DEVICE GATE PASS
  2026-10-22, 6 renderer activations, codecs 5/5, 7 children filters=2) is
  preserved in `port/port.toml gates.device_gate_history`.
- **Maintenance automation (Round 15, PR #1 — pending merge, currently
  inert):** daily probe (Chromium Stable vs Termux recipe pins) -> build
  decision engine (`port/maintenance.py`, offline/mock-tested) -> reuses the
  existing build workflow via `workflow_call` (all invariants preserved) ->
  candidate ledger on the `maintenance-state` branch (status
  BUILD_VERIFIED_CANDIDATE) -> fail-closed GitHub Issues with dedup and
  retry-gating. Automation NEVER widens policy, NEVER mutates validated,
  NEVER publishes. Schedule fires only after PR merge (default-branch
  cron) — merge and activation are separate approvals.

- **Maintenance automation (LIVE — AUTOMATED MAINTENANCE / AUTO PRE-RELEASE
  / MANUAL PROMOTION):** the daily workflow runs on schedule at **09:23 KST**
  (00:23 UTC; GitHub may delay — timing is an expectation, not a gate).
  Automated per run: upstream/recipe detection, validated/state compare,
  changed-input detection, build-signature computation (schema v2: the four
  raw port contract files by content fingerprint + `port.toml` SEMANTICALLY
  — human audit records `[port].last_validated_*` and
  `[gates].device_gate(_history)` are excluded as provably build-irrelevant;
  every other key, including new/unclassified ones, is hashed, so real
  contract edits always trigger rebuilds; v1 history is never rewritten —
  equivalence for the validated rev-2 baseline is re-proven every run from
  the audited `maintenance/signature-migrations.json`), duplicate skip,
  R1~R9b security gate, conditional CANDIDATE CI build, artifact capture,
  failure classification, deduplicated block Issues, candidate recording.
  NEVER automated: device installation/gates, validated promotion,
  port.toml writes, policy changes, STABLE releases, apt publishing,
  product-code merges.

- **Pre-release publishing (Round 17 — AUTO PRE-RELEASE):** a standalone
  `workflow_run`-triggered workflow (`Publish Pre-release`) watches
  SUCCESSFUL default-branch completions of the nightly maintenance run and
  direct manual build runs, re-executes the ledger gate from
  maintenance-state (only a `BUILD_VERIFIED_CANDIDATE` recorded for that
  exact run publishes; dry-run/skip/blocked/failed runs no-op), re-verifies
  the artifact fail-closed (provenance, exactly one DEB, SHA256,
  `dpkg-deb` identity, shield members, pins; signature required on the
  maintenance path, never fabricated on manual), then publishes a GitHub
  **Pre-release** `chromium-sandboxed-v<version>` (draft-first: DEB +
  `SHA256SUMS.txt` + `build-manifest.json` + secret-scanned logs; flipped
  public only after byte-level asset re-verification and a post-publish API
  re-read). Same version+sha = idempotent skip; same tag different sha =
  collision stop for human review; tags/releases/assets are NEVER
  clobbered. Publishing is SEPARATE from building: a publish failure never
  reclassifies the build or touches the ledger — recovery is
  `gh run rerun <publish-run>` (never a rebuild). Emergency stop of
  publishing only: `gh workflow disable publish-release.yml`. Releases
  state **CI VERIFIED — DEVICE NOT VERIFIED**: installing users verify on
  their own devices (Seccomp_filters/NoNewPrivs, GUI/X11, GPU/WebGL,
  downloads, audio, restart); a CI-green build is no device promise and
  `--no-sandbox` is never the fix. No back-publishing: builds completed
  before activation (incl. validated `156.0.8078.47-2`) are not released
  by this automation; stable conversion/apt remain separate human
  approvals.
  **Emergency stop:** `gh workflow disable daily-maintenance.yml` (runtime
  kill-switch) or revert the schedule trigger via PR. **Resume:**
  `gh workflow enable daily-maintenance.yml`. Blocked signatures retry
  only via human `retry-approved` label (consumed once) or
  `approve_retry=true` dispatch; recovery runs are idempotent (signature
  dedup + serial concurrency). Manual entry points remain:
  `gh workflow run daily-maintenance.yml -f dry_run=true|false`.
  **Manual dispatch is fail-closed:** omitting `dry_run` (or passing any
  value other than explicit `false`) runs DRY-ONLY; a real candidate build
  from dispatch requires the explicit `-f dry_run=false` go-ahead, and
  unsupported events can never reach the build path.
  Device-gate procedure and validated promotion policy: port/DESIGN.md.

- **Current validated baseline (2026-10-25):** `chromium-sandboxed
  156.0.8078.47-2` (upstream 156.0.8078.47 + packaging revision 2),
  DEB sha256 `cf2cb2a88e15ab42b1510140f4e41c34b751d4368b82f94172c06abd4151ba8d`,
  CI run 40104615699, termux pin `de1dd3d18e...`, build signature
  `ad5b0fdb8c7a9777`, port provenance `554da59a...`. Device-verified on
  Android 17/kernel 6.1 (BPF census filters=2/NNP=1 with P2b causality,
  broker inodes=80, official shield-wrapper launches only, GUI/X11 9/9 +
  cold starts 10/10, hardware WebGL2 via ANGLE zink Vulkan Turnip Adreno
  750, WS 20/20, downloads sha-verified incl. chrome://downloads pierced
  item proof, GTK file chooser, audio sink input, 540 concurrent-tab
  checks) and Android 13/kernel 4.19 testbed (install/purge/residual 0).
  First baseline run #31 (plain 156.0.8078.47) preserved as history.

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
