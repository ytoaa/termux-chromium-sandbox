# Pre-release publishing: historical build SHA authorization

## Why this exists

The `Build Termux Chromium Seccomp Sandbox Port` run [40254429486](https://github.com/ytoaa/termux-chromium-sandbox/actions/runs/40254429486) successfully produced `chromium-sandboxed_156.0.8078.47-3_aarch64.deb` (DEB SHA256 `627656dac77b35a2eee66dfd8c5b592289615ae1f529a40b3f0660dd77bfd363`). The recovery publisher run [40294779307](https://github.com/ytoaa/termux-chromium-sandbox/actions/runs/40294779307) downloaded and verified the DEB, but GitHub refused `gh release create ... --target 783efd63eeea89e2999e0408d55ea0de70fbed7c` with HTTP 403. The runner's token **already had Contents:write**.

GitHub documents a separate **Workflows:write** requirement when the release target points at a commit whose `.github/workflows` content differs from the default branch. The built-in Actions `GITHUB_TOKEN` cannot obtain this permission. References:

- https://docs.github.com/en/rest/releases/releases#create-a-release
- https://github.blog/changelog/2023-11-02-github-actions-enforcing-workflow-scope-when-creating-a-release/

## Correct privilege boundary

The publisher keeps the release target **the exact audited build commit SHA**. It never silently changes the target to the current `main`, and it never regenerates the Chromium build.

1. For builds whose audited source SHA is still the current default-branch HEAD, the existing `GITHUB_TOKEN` (Contents:write) is used.
2. For historical source SHAs, the preflight refuses a create/update operation unless a separate credential has been configured.
3. Only the final Execute step receives the optional `secrets.TCS_RELEASE_WORKFLOWS_TOKEN`. Earlier artifact discovery, SHA/ledger/integrity checks and planning still use the built-in token. No credentials are embedded in source code or output.
4. The dedicated token must be scoped **only to this repository** and have **Contents: Read and write** and **Workflows: Read and write**, because this is a known GitHub API authorization limitation. Prefer an organization-managed GitHub App issuing short-lived installation tokens if supported by your deployment; a repository-scoped, expiring fine-grained PAT is the practical initial option. Handle it as a powerful secret.
5. Missing/expired/incorrect token causes a red workflow status; it must never turn into an automatic no-op or a fabricated successful release.

## Owner setup (one-time)

Create an appropriately scoped, expiring GitHub fine-grained PAT with repository access restricted to `ytoaa/termux-chromium-sandbox`, **Contents: write** and **Workflows: write**.

Add it in GitHub repository **Settings → Secrets and variables → Actions → New repository secret**, name `TCS_RELEASE_WORKFLOWS_TOKEN`.

Alternatively, use an authenticated local terminal:

```bash
gh secret set TCS_RELEASE_WORKFLOWS_TOKEN -R ytoaa/termux-chromium-sandbox
```

The `gh` CLI accepts the secret via a secure prompt; do **not** paste the token into issue comments, logs, command arguments, or chat.

## Recovery after PR merge (no rebuild)

The old run predates the artifact-bound `publish-intent.json`. The publisher already has a tightly pinned, one-off, operator-confirmed recovery path for it. A failed old publishing run should **not** be blindly rerun: reruns use the original workflow revision, before this fix.

Dispatch a **fresh** `Publish Pre-release` workflow from updated `main` after configuring the secret:

```bash
gh workflow run publish-release.yml \
  -R ytoaa/termux-chromium-sandbox --ref main \
  -f recovery_run_id=40254429486 \
  -f recovery_expected_sha256=627656dac77b35a2eee66dfd8c5b592289615ae1f529a40b3f0660dd77bfd363 \
  -f recovery_ack=PUBLISH-LEGACY-BUILD-40254429486
```

Verify the new publisher run is successful **and** the GitHub Release exists, is `prerelease=true`, and contains a valid DEB, `SHA256SUMS.txt`, `build-manifest.json`, and accurate `CI VERIFIED — DEVICE NOT VERIFIED` notes. No `maintenance-state` or `validated` status promotion is part of this process.

If you do not want to grant Workflows:write to CI, leave the secret unset. Publishing historical commits stays safely blocked; a human with the proper GitHub authorization must handle those releases. Regular releases pinned to the current default-branch HEAD may still proceed using the built-in token.
