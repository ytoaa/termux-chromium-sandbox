#!/usr/bin/env python3
"""Round 15 maintenance pipeline decision engine.

Offline, deterministic, fully mock-tested: all GitHub/HTTP access happens
either in `fetch` (network probes) or in the workflow YAML (gh api). This
module never builds, never promotes validated, never widens policy.

Commands:
  fetch   --out probes.json                  (network: probes only)
  decide  --state S --probes P --out plan.json [--issues I] [--running R]
                                              [--port-sha SHA] [--now ISO]
                                              [--migrations FILE]
  port-input-hash --root REPO [--at REF]   (v2 port-input hash from a commit)
  apply   --state S --plan P --result RESULT --out S2 --issues-out OPS
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

RELEASES = ('https://chromiumdash.appspot.com/fetch_releases'
            '?channel=Stable&platform=Linux&num=10&offset=0')
TERMUX = 'termux/termux-packages'
HOST_PATH = 'x11-packages/chromium-host-tools/build.sh'
RECIPE_PATH = 'x11-packages/chromium/build.sh'
NUMERIC = re.compile(r'^[0-9]+(?:\.[0-9]+){3}$')
VERSION = re.compile(
    r"""^\s*TERMUX_PKG_VERSION\s*=\s*['"]?([0-9]+(?:\.[0-9]+){3})['"]?\s*(?:#.*)?$""",
    re.M)
REVISION = re.compile(r'^\s*TERMUX_PKG_REVISION\s*=\s*["\']?(\d+)', re.M)
DISTRO_VERSION = re.compile(
    r'^DISTRO_VERSION\s*=\s*["\']?([0-9]+(?:\.[0-9]+){3})', re.M)

BLOCKED_LABEL = 'auto-build-blocked'
TRANSIENT = ('timeout', 'temporarily unavailable', '502', '503', '504',
             'could not resolve host', 'connection reset', 'early eof',
             'the server aborted', 'rpc failed', 'http2 stream',
             'received fatal alert', 'exit code 137', 'out of memory',
             'no space left on device')


def version_parts(s: str):
    if not NUMERIC.fullmatch(s or ''):
        raise ValueError(f'Unexpected Chromium version: {s!r}')
    return tuple(int(x) for x in s.split('.'))


def blob_sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def build_signature(upstream: str, recipe_sha: str, host_sha: str,
                    port_sha: str, sig_version: int = 2) -> str:
    """Build-identity signature.

    v1 (legacy, frozen): sha256(json([upstream, recipe, host, port]))[:16].
      Existing ledger entries (candidates, validated, blocked) keep their
      original v1 signature FOREVER — history is never rewritten.
    v2: adds an explicit schema tag so a scheme switch can never be confused
      with a semantic input change (Round 16 safety hotfix). v2 equivalence
      against v1 history is granted ONLY through the audited migration file
      (maintenance/signature-migrations.json), never by re-hashing history.
    """
    if sig_version == 1:
        payload = [upstream, recipe_sha, host_sha, port_sha]
    elif sig_version == 2:
        payload = ['sigv2', upstream, recipe_sha, host_sha, port_sha]
    else:
        raise ValueError(f'unsupported signature schema {sig_version!r}')
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True).encode()).hexdigest()[:16]


# ------------------------------------------------ signature schema v2 ----
# Round 16 (Automated Maintenance Safety Hotfix), Stage B:
#
# port.toml carries BOTH build-contract ledgers ([port] version/phase/
# policy_mode, [termux], [sandbox], [rules] r1..r9b, [gates] *contracts*,
# [forbidden]) AND human audit records ([port].last_validated_* promotion
# evidence, [gates].device_gate / device_gate_history results). Hashing the
# raw blob made audit-only edits schedule spurious Chromium rebuilds.
#
# Proven zero-build-impact of the excluded keys: the ONLY consumer of
# port.toml inside the build chain is prepare_recipe.py's audit copy
# (shutil.copy2 -> recipe BUILDER_DIR); the port hook, the transformer and
# ci.sh never parse it, and BUILDER_DIR files are not packaged into the DEB.
#
# v2 therefore hashes the four RAW contract files by content fingerprint
# (sha256[:40] of the file bytes — every byte counts, any edit fails safe
# toward BUILD) and port.toml SEMANTICALLY:
# every key/value is included EXCEPT the explicit audit-record denylist
# below. NEW or unclassified keys are included by default (conservative):
# adding a contract field can never be silently ignored. If a future human
# adds a new audit-only key it will (fail-safe) count as a build input until
# it is proven build-irrelevant and added here under code review.
PORT_INPUTS_SCHEMA = 2
PORT_RAW_FILES = ('port/chromium_sandbox_port.py', 'port/prepare_recipe.py',
                  'port/gnp_shim.c', 'port/ci.sh')
PORT_TOML_FILE = 'port/port.toml'
TOML_METADATA_ONLY = {
    'port': frozenset(('last_validated_port',
                       'last_validated_chromium',
                       'last_validated_deb_version',
                       'last_validated_deb_sha256',
                       'last_validated_ci_run',
                       'last_validated_termux_sha',
                       'last_validated_build_signature',
                       'last_validated_port_commit',
                       'last_validated_promoted')),
    'gates': frozenset(('device_gate', 'device_gate_history')),
}
SIG16 = re.compile(r'^[0-9a-f]{16}$')


def port_toml_semantic_sha(toml_text: str) -> str:
    """Deterministic semantic hash over port.toml build-contract content.

    Canonicalization: parse TOML -> drop ONLY the exact audit-record keys in
    TOML_METADATA_ONLY -> json.dumps(sort_keys, compact separators, ASCII).
    Same meaningful inputs => same hash (byte layout / comments / key order /
    excluded audit text are irrelevant). Raises on invalid TOML (fail closed).
    """
    data = tomllib.loads(toml_text)
    filtered = {}
    for section, values in data.items():
        deny = TOML_METADATA_ONLY.get(section, frozenset())
        if isinstance(values, dict):
            keep = {k: v for k, v in values.items() if k not in deny}
            if keep:  # an all-metadata section contributes nothing
                filtered[section] = keep
        else:
            filtered[section] = values  # top-level scalars: always contract
    canon = json.dumps(filtered, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True)
    return hashlib.sha256(('port-toml-v2:' + canon).encode()).hexdigest()[:16]


def port_inputs_hash(blob_ids: dict, toml_text: str) -> str:
    """v2 port-input hash: content fingerprints for raw files + semantic TOML.

    Deterministic given the committed tree; MISSING entries are hashed as
    explicit MISSING:<path> sentinels so a deleted input still changes the
    signature (never silently collapses to the same digest).
    """
    parts = ['sigv2']
    for f in PORT_RAW_FILES:
        parts.append(blob_ids.get(f) or f'MISSING:{f}')
    parts.append('port.toml@semantic-v2:' + port_toml_semantic_sha(toml_text))
    return hashlib.sha256(("\n".join(parts) + "\n").encode()).hexdigest()[:16]


def cmd_port_input_hash(args) -> int:
    """CLI: compute the v2 port-input hash from a checked-out tree.

    Pure-filesystem (the engine keeps ZERO exec surface — s22 invariant):
    the ephemeral runner checked out exactly the commit being decided, so
    the worktree IS the tree. Raw fingerprint = sha256(file bytes)[:40].
    Fail closed: a missing input file or malformed TOML exits non-zero —
    the workflow then aborts BEFORE deciding, so a broken tree can never
    produce a silent build.
    """
    root = Path(args.root)
    raw = {}
    for f in PORT_RAW_FILES:
        p = root / f
        if not p.is_file():
            print(f'port-input-hash: missing build input {f}', file=sys.stderr)
            return 1
        raw[f] = hashlib.sha256(p.read_bytes()).hexdigest()[:40]
    toml_path = root / PORT_TOML_FILE
    if not toml_path.is_file():
        print(f'port-input-hash: missing {PORT_TOML_FILE}', file=sys.stderr)
        return 1
    try:
        print(port_inputs_hash(raw, toml_path.read_text(encoding='utf-8')))
    except Exception as exc:  # invalid TOML must not silently sign a build
        print(f'port-input-hash: port.toml parse failure — {exc}',
              file=sys.stderr)
        return 1
    return 0


# ------------------------------------------------ signature migrations ----
# v1 -> v2 equivalence is granted ONLY by this audited, human-reviewed file.
# Rules enforced here (fail closed):
#   * original history (v1 signature, ci_run, sha256, provenance) is NEVER
#     rewritten — equivalence is recomputed on EVERY run from CURRENT inputs;
#   * an entry activates only when status is 'approved' AND every pinned
#     semantic component (aligned version, recipe/host blobs, v2 port-input
#     hash) matches what this run actually measured;
#   * malformed JSON aborts the run; a malformed/unsigned entry is rejected
#     with a diagnostic (no equivalence => normal decide path => build),
#     never silently trusted.
def load_migrations(path: str | None):
    """-> (list, error). error non-None means fail-closed (caller aborts)."""
    if not path:
        return [], None
    p = Path(path)
    if not p.is_file():
        return [], None  # absent = no equivalence granted (safe: builds)
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError) as exc:
        return [], f'migration file unreadable/malformed: {exc}'
    if not isinstance(doc, dict) or not isinstance(doc.get('migrations'),
                                                   list):
        return [], 'migration file malformed: missing migrations list'
    ok = []
    for m in doc['migrations']:
        if not isinstance(m, dict):
            continue
        need_str = ('id', 'status', 'from_sig', 'aligned_version',
                    'recipe_sha', 'host_sha', 'port_inputs_hash_v2')
        if any(not isinstance(m.get(k), str) or not m.get(k)
               for k in need_str):
            continue
        if not (SIG16.fullmatch(m['from_sig'])
                and SIG16.fullmatch(m['recipe_sha'])
                and SIG16.fullmatch(m['host_sha'])
                and SIG16.fullmatch(m['port_inputs_hash_v2'])):
            continue
        if m.get('from_sig_version', 1) != 1 or \
                m.get('to_sig_version', 2) != PORT_INPUTS_SCHEMA:
            continue
        ok.append(m)
    return ok, None


def active_migrations(migrations: list, comps: dict) -> list:
    """Entries whose pinned semantic inputs match THIS run's measurements."""
    out = []
    for m in migrations:
        if m.get('status') != 'approved':
            continue
        if (m['aligned_version'] == comps['aligned_version']
                and m['recipe_sha'] == comps['recipe_sha']
                and m['host_sha'] == comps['host_sha']
                and m['port_inputs_hash_v2'] == comps['port_sha']):
            out.append(m)
    return out


def equivalent_v1_sigs(migrations: list, comps: dict) -> set:
    """v1 signatures that provably denote the SAME semantic build inputs."""
    return {m['from_sig'] for m in active_migrations(migrations, comps)}


# ---------------------------------------------------------------- fetch ----

def _get(url: str, token: str | None = None) -> bytes:
    headers = {'User-Agent': 'termux-chromium-sandbox-maintenance',
               'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                timeout=25) as r:
        return r.read()


def cmd_fetch(args) -> int:
    token = args.token or None
    probes = {'official_stable': None, 'termux_head': None,
              'recipe': None, 'pins_verified': False, 'fetch_errors': []}
    try:
        items = json.loads(_get(RELEASES, token))
        vs = [x.get('version', '') for x in items
              if isinstance(x, dict) and NUMERIC.fullmatch(x.get('version', ''))]
        probes['official_stable'] = max(vs, key=version_parts) if vs else None
        if not probes['official_stable']:
            probes['fetch_errors'].append('official stable: empty')
    except Exception as e:  # noqa: BLE001
        probes['fetch_errors'].append(f'official stable: {type(e).__name__}')
    try:
        head = json.loads(_get(
            f'https://api.github.com/repos/{TERMUX}/commits/master', token))
        probes['termux_head'] = head.get('sha')
    except Exception as e:  # noqa: BLE001
        probes['fetch_errors'].append(f'termux head: {type(e).__name__}')
    # Round 15.1 #3: BOTH recipe files are read AT THE PINNED HEAD SHA —
    # no 'master' fallback, so probe state is atomic and matches the build
    # checkout (which receives this exact sha as termux_ref).
    if probes['termux_head'] and not probes['fetch_errors']:
      try:
        sha = probes['termux_head']
        recipe = _get(
            f'https://raw.githubusercontent.com/{TERMUX}/{sha}/{RECIPE_PATH}',
            token).decode('utf-8', 'replace')
        host = _get(
            f'https://raw.githubusercontent.com/{TERMUX}/{sha}/{HOST_PATH}',
            token).decode('utf-8', 'replace')
        m = VERSION.search(recipe)
        mh = VERSION.search(host)
        distro = DISTRO_VERSION.search(recipe)
        rev = REVISION.search(recipe)
        if not m or not mh:
            probes['fetch_errors'].append('termux recipe: no literal version')
        else:
            probes['recipe'] = {
                'version': m.group(1),
                'host_version': mh.group(1),
                'recipe_sha': blob_sha(recipe),
                'host_sha': blob_sha(host),
                'revision': int(rev.group(1)) if rev else 0,
                'distro_version': distro.group(1) if distro else None,
            }
            # Round 15.1 #7: honest semantics — pins_verified means BOTH
            # build.sh files were read at the pinned sha AND their literal
            # version lines (+ the recipe distro/source pin when present)
            # parsed. Deep tarball hash verification remains inside the
            # build (prepare_recipe/termux contract); we never claim more.
            r = probes['recipe']
            probes['pins_verified'] = bool(
                r['version'] and r['host_version'] and r['recipe_sha'] and
                r['host_sha'])
      except Exception as e:  # noqa: BLE001
        probes['fetch_errors'].append(f'termux recipe: {type(e).__name__}')
    else:
        if probes['termux_head'] is None:
            probes['fetch_errors'].append('recipe read skipped: no pinned sha')
    Path(args.out).write_text(json.dumps(probes, indent=1) + '\n')
    return 0 if not probes['fetch_errors'] else 1


# --------------------------------------------------------------- decide ----

ALLOWED_STAGES = ('gate', 'build', 'verify', 'unknown', 'ok', 'cancelled',
                  'skipped-anomaly')


def classify_failure(stage: str, log_tail: str) -> str:
    # Round 15.3 #3: an unrecognized stage string from any producer is
    # treated as unknown (which BLOCKS) — never silently passed through.
    if stage not in ALLOWED_STAGES:
        stage = 'unknown'
    t = (log_tail or '').lower()
    if any(k in t for k in TRANSIENT):
        return 'infra'
    if stage in ('gate', 'verify'):
        return 'port'
    return 'unknown'


def issue_matches_sig(title: str, sig: str) -> bool:
    # Round 15.1 #6: ONE matcher everywhere (decide dedup, stamp, label).
    return f'sig {sig}' in (title or '')


def issue_sig_match(title: str, sig: str, eq_sigs=()) -> bool:
    """Round 16: match the current sig OR any migration-equivalent v1 sig."""
    if issue_matches_sig(title, sig):
        return True
    return any(issue_matches_sig(title, s) for s in eq_sigs)


def issue_title(target: dict, reason: str) -> str:
    return (f"[auto-build] Chromium {target['upstream_version']} "
            f"revision {target['revision']} blocked ({reason}, "
            f"sig {target['signature']})")


def render_issue(target: dict, probes: dict, last: dict, stage: str,
                 log_tail: str, run_url: str, failure_jobs: str = '') -> str:
    return '\n'.join([
        '## Auto-build blocked — manual investigation required',
        '',
        f"- Chromium (buildable Termux recipe): `{target['upstream_version']}`"
        f" (official Stable probe: `{probes.get('official_stable')}`)",
        f"- Package target: `chromium-sandboxed {target['package_version']}`"
        f" (revision {target['revision']})",
        f"- Port SHA: `{target['port_sha']}`  Termux pinned SHA: `{target['termux_ref']}`",
        f"- Build signature: `{target['signature']}`  Failure stage: `{stage}`"
        + (f"  Failed jobs: `{failure_jobs}`" if failure_jobs else ''),
        f"- Last successful build: `{last.get('upstream_version')}-r{last.get('revision')}`"
        f" (CI run {last.get('ci_run')}, deb sha256 `{str(last.get('deb_sha256'))[:16]}…`)",
        '- Validated baseline: untouched (port.toml [port] last_validated_*).',
        f"- CI run: {run_url}",
        '',
        '### Error log (core excerpt)',
        '```',
        (log_tail or '(unavailable)')[-3000:],
        '```',
        '',
        '### Repro / next actions',
        '1. Repro: workflow_dispatch Build-Termux-Chromium-Seccomp-Sandbox-Port'
        f" with termux_ref=`{target['termux_ref']}`.",
        '2. Inspect the failed step. Do NOT bypass R1~R9b transforms or widen'
        ' any allow-list from an automated context.',
        '3. Unblock paths: (a) change port/recipe inputs (signature changes),'
        ' (b) add label `retry-approved` to this issue, or (c) run Daily'
        '-Maintenance with approve_retry=true after review.',
        '',
        'Retry state: BLOCKED. Closing this issue alone does NOT re-enable'
        ' automatic attempts for the same signature.',
    ])


def decide(state: dict, probes: dict, port_sha: str, now: str,
           issues: list | None, running: dict | None,
           migrations: list | None = None) -> dict:
    diag = []
    plan = {'action': 'skip', 'reason': '', 'target': None,
            'issues_to_create': [], 'diagnostics': diag, 'now': now,
            'probes': probes}

    if probes.get('fetch_errors'):
        plan['reason'] = 'fetch-error-fail-closed'
        diag.append('probes incomplete: ' + '; '.join(probes['fetch_errors']))
        return plan
    recipe = probes.get('recipe') or {}
    if not probes.get('pins_verified') or not recipe.get('version') \
            or not recipe.get('host_version'):
        plan['reason'] = 'source-verification-failed'
        diag.append('recipe/host-tools pins unreadable at pinned sha — refusing')
        return plan
    # Round 15.1 #3: the version actually BUILT is the one prepare_recipe's
    # align_versions policy lands on: chromium/build.sh VERSION := host-tools
    # VERSION. Using it here keeps probe decisions consistent with the build.
    buildable = recipe['host_version']
    official = probes.get('official_stable')
    if official != buildable:
        diag.append(f'official Stable {official} != termux recipe {buildable};'
                    ' the recipe version is the buildable source (contract:')
        diag.append('  prepare_recipe aligns recipe/host-tools at build time)')
    if recipe.get('version') != recipe.get('host_version'):
        diag.append(f'recipe version {recipe["version"]} != host-tools '
                    f'{recipe["host_version"]}; building the ALIGNED value '
                    f'(prepare_recipe policy) = {buildable}')

    last = state.get('last_successful_build') or {}
    sig = build_signature(buildable, recipe['recipe_sha'],
                          recipe['host_sha'], port_sha)
    # Round 16: v1 history is honoured via audited migration entries ONLY
    # when their pinned semantic inputs match what THIS run measured — the
    # equivalence is recomputed every time, never asserted from history.
    comps = {'aligned_version': buildable,
             'recipe_sha': recipe['recipe_sha'],
             'host_sha': recipe['host_sha'], 'port_sha': port_sha}
    act = active_migrations(migrations or [], comps)
    eq_v1 = {m['from_sig'] for m in act}
    if act:
        diag.append('v1→v2 signature migration active: '
                    + ', '.join(m['id'] for m in act)
                    + ' (semantic inputs re-proven against current probes)')
    candidates = state.get('candidates') or []

    def sig_match(stored) -> bool:
        return stored == sig or (stored in eq_v1 if stored else False)

    def mk_target(rev):
        # Round 15.1 #7: revision 1 = PLAIN upstream version (no
        # TERMUX_PKG_REVISION), matching how run #31 really shipped as
        # '156.0.8078.47'. Only rev>=2 carries the '-N' suffix and passes
        # the revision env into the build.
        pv = buildable if rev <= 1 else f'{buildable}-{rev}'
        return {'upstream_version': buildable, 'revision': rev,
                'package_version': pv,
                'deb_version': pv,
                'pkg_revision_env': '' if rev <= 1 else str(rev),
                'termux_ref': probes['termux_head'],
                'port_sha': port_sha, 'signature': sig,
                'signature_schema': PORT_INPUTS_SCHEMA,
                'recipe_sha': recipe['recipe_sha'],
                'host_sha': recipe['host_sha'],
                'is_revision': (last.get('upstream_version') == buildable)}

    if not last.get('upstream_version'):
        target = mk_target(1)
        plan['reason'] = 'bootstrap-no-last-build'
    elif version_parts(buildable) > version_parts(last['upstream_version']):
        if any(c.get('upstream_version') == buildable and
               c.get('status') == 'BUILD_VERIFIED_CANDIDATE'
               for c in candidates):
            plan['reason'] = 'candidate-already-built'
            return plan
        target = mk_target(1)
        plan['reason'] = 'new-upstream-version'
    elif buildable == last['upstream_version']:
        if sig_match(last.get('signature')):
            plan['reason'] = 'identical-inputs-already-built'
            return plan
        if any(sig_match(c.get('signature')) and
               c.get('status') == 'BUILD_VERIFIED_CANDIDATE'
               for c in candidates):
            plan['reason'] = 'identical-candidate-already-built'
            return plan
        target = mk_target(int(last.get('revision', 1)) + 1)
        plan['reason'] = 'inputs-changed-revision-build'
    else:
        plan['reason'] = 'upstream-behind-last-success'
        return plan

    # Round 15.1 #6: issues list must be trustworthy; an API error marker
    # fails closed (we cannot verify dedup or retry labels).
    if isinstance(issues, dict) or (issues and isinstance(issues[0], dict)
                                    and issues[0].get('error')):
        plan['reason'] = 'issues-api-error-fail-closed'
        diag.append('issues API unavailable — refusing to build/issue to avoid'
                    ' duplicate issues and unverified retry state')
        return plan
    # Round 15.1 #4: honor a real `retry-approved` LABEL on the open issue
    # for this exact signature (in addition to state flag / dispatch).
    blocked_map = state.get('blocked') or {}
    blocked = blocked_map.get(sig)
    if blocked is None:
        # Round 16: a v1-keyed block that migration-equivalence proves to be
        # THIS same semantic build still blocks (fail-safe: honour it).
        for vs in sorted(eq_v1):
            if vs in blocked_map:
                blocked = blocked_map[vs]
                diag.append(f'blocked entry (v1 sig {vs}) applies via '
                            'migration equivalence — honoured')
                break
    consumed = set((blocked or {}).get('approval_consumed_issues') or [])
    if blocked and not blocked.get('retry_approved'):
        for i in (issues or []):
            if 'retry-approved' in (i.get('labels') or []) and \
                    issue_sig_match(i.get('title', ''), sig, eq_v1) and \
                    i.get('number') not in consumed:
                blocked['retry_approved'] = True
                # Round 15.3 #1: the approval ORIGIN must survive
                # serialization — outcome re-reads the ORIGINAL state.json,
                # so memory-only markers would never be consumed.
                plan['approval'] = {'issue': i.get('number'),
                                    'signature': sig}
                diag.append('retry-approved LABEL on issue '
                            f'{i.get("number")} — ONE attempt (will be consumed)')
                break
    if blocked:
        if blocked.get('retry_approved'):
            plan['approval_used'] = True
            plan.setdefault('approval', {'issue': 'dispatch',
                                         'signature': sig})
            diag.append('retry-approved observed — one attempt allowed '
                        '(consumed by the following apply)')
        elif blocked.get('classification') == 'infra' and \
                int(blocked.get('infra_failures', 0)) == 1:
            diag.append('infra flake (1/1) — the single automatic retry runs now')
        else:
            plan['action'] = 'skip'
            plan['reason'] = 'blocked-dedup'
            plan['target'] = target
            return plan

    # Round 15.2 #5: durable dedup for LOST state (issue created but state
    # push failed): an OPEN issue with this exact signature blocks even when
    # state.blocked is absent — and re-links the ledger to it. Approvals are
    # evaluated in the blocked branch above; with no state block, no approval
    # exists, so skipping here can never swallow a human-authorized retry.
    if blocked is None:
        for i in (issues or []):
            if BLOCKED_LABEL in (i.get('labels') or []) and \
                    issue_sig_match(i.get('title', ''), sig, eq_v1):
                stb = (state.setdefault('blocked', {})).setdefault(sig, {
                    'classification': 'port', 'at': now,
                    'inputs': {'recipe_sha': recipe['recipe_sha'],
                               'host_sha': recipe['host_sha'],
                               'port_sha': port_sha}})
                stb['issue'] = i.get('number')
                plan['relink'] = {'sig': sig, 'issue': i.get('number'),
                                  'classification': 'port',
                                  'inputs': stb['inputs']}
                diag.append(f're-linked blocked entry to existing issue '
                            f'{i.get("number")} (state.blocked was lost)')
                plan['action'] = 'skip'
                plan['reason'] = 'open-issue-exists'
                plan['target'] = target
                return plan

    if running and (running.get('signature') == sig or
                    running.get('signature') in ('RUNNING-ANY', 'API-ERROR')):
        plan['reason'] = 'build-workflow-busy'
        plan['target'] = target
        return plan

    plan['action'] = 'build'
    plan['target'] = target
    for i in (issues or []):
        if BLOCKED_LABEL in (i.get('labels') or []) and \
                issue_sig_match(i.get('title', ''), sig, eq_v1):
            plan['pending_issue'] = i.get('number')
            break
    return plan


# --------------------------------------------------------------- apply -----

def apply_result(state: dict, plan: dict, result: dict, now: str):
    st = json.loads(json.dumps(state))
    ops = {'create_issues': [], 'comment_issues': []}
    # Round 15.2 #5: persist re-links produced by decide (lost-state repair)
    if plan.get('relink'):
        rl = plan['relink']
        st.setdefault('blocked', {})
        cur = st['blocked'].get(rl['sig']) or {}
        if not cur.get('issue'):
            cur = {**{'classification': rl.get('classification', 'port'),
                      'inputs': rl.get('inputs', {}), 'at': now}, **cur}
            cur['issue'] = rl['issue']
            st['blocked'][rl['sig']] = cur
    if plan.get('action') != 'build' or not plan.get('target'):
        st.setdefault('history', []).append({'at': now,
                                             'skip': plan.get('reason')})
        return st, ops
    t = plan['target']
    stage = result.get('stage') or 'build'
    ok = bool(result.get('success'))
    st.setdefault('blocked', {})
    st.setdefault('candidates', [])
    st.setdefault('history', [])
    log_tail = result.get('log_tail') or ''
    if ok:
        # Round 15.2 #1: success is only recorded when EVERY field is
        # present with the expected shape; otherwise downgrade to a
        # 'verify' failure (blocked + issue) — a malformed success is a
        # failure, never a candidate.
        problems = []
        sha = str(result.get('deb_sha256') or '')
        ver = str(result.get('deb_version') or '')
        tsha = str(result.get('termux_sha') or '')
        run = result.get('ci_run')
        url = str(result.get('ci_url') or '')
        art = str(result.get('artifact') or '')
        if not re.fullmatch(r'[0-9a-f]{64}', sha):
            problems.append(f'deb_sha256 malformed: {sha[:20]!r}')
        expected = t['package_version']
        if ver != expected:
            problems.append(f'deb_version {ver!r} != expected {expected!r}')
        if not re.fullmatch(r'[0-9a-f]{40}', tsha):
            problems.append(f'termux_sha malformed: {tsha[:20]!r}')
        if not (isinstance(run, int) and run > 0):
            problems.append(f'ci_run invalid: {run!r}')
        if not url.startswith('https://'):
            problems.append(f'ci_url invalid: {url[:40]!r}')
        if not art:
            problems.append('artifact name missing')
        if problems:
            ok = False
            stage = 'verify'
            log_tail = ('success-shaped result failed validation:\n'
                        + '\n'.join(problems) + '\n' + (log_tail or ''))
            result = dict(result or {})
            result['log_tail'] = log_tail
    if ok and str(result.get('termux_sha') or '') != str(t.get('termux_ref') or ''):
        ok = False
        stage = 'verify'
        log_tail = ('termux_sha mismatch: result '
                    f'{result.get("termux_sha")!r} != pinned target '
                    f'{t.get("termux_ref")!r}\n' + (log_tail or ''))
    if ok:
        cand = dict(t)
        cand.update({'status': 'BUILD_VERIFIED_CANDIDATE',
                     'deb_sha256': result.get('deb_sha256'),
                     'deb_version': result.get('deb_version'),
                     'termux_sha': result.get('termux_sha'),
                     'ci_run': result.get('ci_run'),
                     'ci_url': result.get('ci_url'),
                     'artifact': result.get('artifact'),
                     # Round 15.3 #3: artifact existence is confirmed by the
                     # device-gate fetch step (human), never claimed here.
                     'artifact_verified': False,
                     'recorded_at': now,
                     'validated': False})
        st['candidates'] = (st['candidates'] + [cand])[-20:]
        st['last_successful_build'] = dict(cand)
        st['blocked'].pop(t['signature'], None)  # success clears block+approvals
        st['history'].append({'at': now, 'success':
                              f"{t['package_version']} sig={t['signature']}"})
        return st, ops
    # Round 15.1 #2: cancellations and orchestration skips are NOT build
    # failures — recorded in history only; no block, no issue (fail-closed
    # still applies to every other stage, including 'unknown').
    if stage in ('cancelled', 'skipped-anomaly'):
        st['history'].append({'at': now, stage: t['signature']})
        return st, ops
    cls = classify_failure(stage, log_tail)
    prev = st['blocked'].get(t['signature']) or {}
    # Round 15.2 #4: any attempt that ran under an approval consumes it.
    consumed_list = list(prev.get('approval_consumed_issues') or [])
    appr = plan.get('approval') or {}
    if plan.get('approval_used') or appr:
        src = appr.get('issue')
        if isinstance(src, int) and src not in consumed_list:
            consumed_list.append(src)
    if prev.get('retry_approved') or plan.get('approval_used'):
        prev = dict(prev)
        prev['retry_approved'] = False
        prev['approval_consumed_issues'] = consumed_list
        prev.pop('_approval_source_issue', None)
    n = int(prev.get('infra_failures', 0)) + 1
    if cls == 'infra' and n <= 1:
        st['blocked'][t['signature']] = {
            **prev,
            'classification': 'infra',
            'infra_failures': n,
            'inputs': {'recipe_sha': t['recipe_sha'],
                       'host_sha': t['host_sha'], 'port_sha': t['port_sha']},
            'stage': stage, 'at': now}
        st['history'].append({'at': now, 'infra-retry-pending': t['signature']})
        return st, ops
    st['blocked'][t['signature']] = {
        'classification': cls,
        'issue': prev.get('issue') or plan.get('pending_issue'),
        'retry_approved': bool(prev.get('retry_approved')),
        'approval_consumed_issues': consumed_list,
        'inputs': {'recipe_sha': t['recipe_sha'], 'host_sha': t['host_sha'],
                   'port_sha': t['port_sha']},
        'stage': stage, 'at': now,
        'infra_failures': n,
        'failure_jobs': (result or {}).get('failure_jobs', '')}
    if not prev.get('issue'):
        ops['create_issues'].append({
            'title': issue_title(t, stage),
            'labels': [BLOCKED_LABEL, f'classification/{cls}'],
            'body': render_issue(t, plan.get('probes') or {},
                                 state.get('last_successful_build') or {},
                                 stage, log_tail,
                                 result.get('ci_url') or '(link unavailable)',
                                 failure_jobs=str(result.get('failure_jobs') or ''))})
    else:
        ops['comment_issues'].append({
            'issue': prev['issue'],
            'body': f'Repeated failure at {now}: stage={stage} class={cls} '
                    f'run={result.get("ci_url")}'})
    st['history'].append({'at': now,
                          'blocked': f"{t['signature']} {stage}/{cls}"})
    return st, ops


# ---------------------------------------------------------------- CLI ------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='maintenance decision engine')
    sub = p.add_subparsers(dest='cmd', required=True)
    f = sub.add_parser('fetch')
    f.add_argument('--out', required=True)
    f.add_argument('--token', default='')
    d = sub.add_parser('decide')
    d.add_argument('--state', required=True)
    d.add_argument('--probes', required=True)
    d.add_argument('--out', required=True)
    d.add_argument('--issues', default=None)
    d.add_argument('--running', default=None)
    d.add_argument('--port-sha', required=True)
    d.add_argument('--now', default='(unset)')
    d.add_argument('--approve-retry', action='store_true')
    d.add_argument('--migrations', default=None,
                   help='audited v1->v2 signature-equivalence file '
                        '(malformed JSON fails the run closed)')
    h = sub.add_parser('port-input-hash')
    h.add_argument('--root', default='.')
    v = sub.add_parser('validate-state')
    v.add_argument('--state', required=True)
    st = sub.add_parser('stamp')
    st.add_argument('--state', required=True)
    st.add_argument('--ops', required=True)
    a = sub.add_parser('apply')
    a.add_argument('--state', required=True)
    a.add_argument('--plan', required=True)
    a.add_argument('--result', required=True)
    a.add_argument('--out', required=True)
    a.add_argument('--issues-out', required=True)
    args = p.parse_args(argv)
    if args.cmd == 'fetch':
        return cmd_fetch(args)
    if args.cmd == 'validate-state':
        d = json.loads(Path(args.state).read_text())
        assert 'validated' in d and 'last_successful_build' in d, 'state schema'
        print('STATE-VALID')
        return 0
    if args.cmd == 'stamp':
        ops = json.loads(Path(args.ops).read_text())
        stt = json.loads(Path(args.state).read_text())
        created = [(c['title'], c.get('issue'))
                   for c in ops.get('create_issues', []) if c.get('issue')]
        for sig, b in (stt.get('blocked') or {}).items():
            if not b.get('issue'):
                for title, num in created:
                    if issue_matches_sig(title, sig):
                        b['issue'] = num
        Path(args.state).write_text(json.dumps(stt, indent=1) + '\n')
        print('STAMPED', len(created))
        return 0
    if args.cmd == 'port-input-hash':
        return cmd_port_input_hash(args)
    if args.cmd == 'decide':
        def _load(path, what):
            try:
                return json.loads(Path(path).read_text())
            except (OSError, ValueError) as exc:
                # FAIL CLOSED with a clean report (non-zero rc aborts the
                # workflow step; never proceed on a half-read input).
                raise SystemExit(f'FATAL: {what} unreadable/malformed: {exc}')
        state = _load(args.state, 'state')
        if getattr(args, 'approve_retry', False):
            for v in (state.get('blocked') or {}).values():
                v['retry_approved'] = True
        probes = _load(args.probes, 'probes')
        issues = (_load(args.issues, 'issues') if args.issues else [])
        running = (_load(args.running, 'running') if args.running else None)
        migrations, mig_err = load_migrations(args.migrations)
        if mig_err:
            # FAIL CLOSED: a corrupt migration file must not silently grant
            # (or silently deny, in a re-run race) equivalence — abort.
            print(f'FATAL: signature migrations — {mig_err}', file=sys.stderr)
            return 1
        plan = decide(state, probes, args.port_sha, args.now, issues,
                      running, migrations)
        Path(args.out).write_text(json.dumps(plan, indent=1) + '\n')
        print(f"MAINTENANCE decide: action={plan['action']} "
              f"reason={plan['reason']}")
        return 0
    if args.cmd == 'apply':
        state = json.loads(Path(args.state).read_text())
        plan = json.loads(Path(args.plan).read_text())
        result = json.loads(Path(args.result).read_text())
        st, ops = apply_result(state, plan, result,
                               plan.get('now', '(unset)'))
        Path(args.out).write_text(json.dumps(st, indent=1) + '\n')
        Path(args.issues_out).write_text(json.dumps(ops, indent=1) + '\n')
        print(f"MAINTENANCE apply: create={len(ops['create_issues'])}"
              f" comment={len(ops['comment_issues'])}")
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
