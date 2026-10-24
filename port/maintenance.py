#!/usr/bin/env python3
"""Round 15 maintenance pipeline decision engine.

Offline, deterministic, fully mock-tested: all GitHub/HTTP access happens
either in `fetch` (network probes) or in the workflow YAML (gh api). This
module never builds, never promotes validated, never widens policy.

Commands:
  fetch   --out probes.json                  (network: probes only)
  decide  --state S --probes P --out plan.json [--issues I] [--running R]
                                              [--port-sha SHA] [--now ISO]
  apply   --state S --plan P --result RESULT --out S2 --issues-out OPS
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
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
                    port_sha: str) -> str:
    return hashlib.sha256(json.dumps(
        [upstream, recipe_sha, host_sha, port_sha],
        sort_keys=True).encode()).hexdigest()[:16]


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
              'recipe': None, 'checksum_ok': False, 'fetch_errors': []}
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
    try:
        recipe = _get(
            f'https://raw.githubusercontent.com/{TERMUX}/master/{RECIPE_PATH}',
            token).decode('utf-8', 'replace')
        host = _get(
            f'https://raw.githubusercontent.com/{TERMUX}/master/{HOST_PATH}',
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
            probes['checksum_ok'] = bool(probes['recipe']['version'])
    except Exception as e:  # noqa: BLE001
        probes['fetch_errors'].append(f'termux recipe: {type(e).__name__}')
    Path(args.out).write_text(json.dumps(probes, indent=1) + '\n')
    return 0 if not probes['fetch_errors'] else 1


# --------------------------------------------------------------- decide ----

def classify_failure(stage: str, log_tail: str) -> str:
    t = (log_tail or '').lower()
    if any(k in t for k in TRANSIENT):
        return 'infra'
    if stage in ('gate', 'verify'):
        return 'port'
    return 'unknown'


def issue_title(target: dict, reason: str) -> str:
    return (f"[auto-build] Chromium {target['upstream_version']} "
            f"revision {target['revision']} blocked ({reason}, "
            f"sig {target['signature'][:8]})")


def render_issue(target: dict, probes: dict, last: dict, stage: str,
                 log_tail: str, run_url: str) -> str:
    return '\n'.join([
        '## Auto-build blocked — manual investigation required',
        '',
        f"- Chromium (buildable Termux recipe): `{target['upstream_version']}`"
        f" (official Stable probe: `{probes.get('official_stable')}`)",
        f"- Package target: `chromium-sandboxed {target['package_version']}`"
        f" (revision {target['revision']})",
        f"- Port SHA: `{target['port_sha']}`  Termux pinned SHA: `{target['termux_ref']}`",
        f"- Build signature: `{target['signature']}`  Failure stage: `{stage}`",
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
           issues: list | None, running: dict | None) -> dict:
    diag = []
    plan = {'action': 'skip', 'reason': '', 'target': None,
            'issues_to_create': [], 'diagnostics': diag, 'now': now,
            'probes': probes}

    if probes.get('fetch_errors'):
        plan['reason'] = 'fetch-error-fail-closed'
        diag.append('probes incomplete: ' + '; '.join(probes['fetch_errors']))
        return plan
    recipe = probes.get('recipe') or {}
    if not probes.get('checksum_ok') or not recipe.get('version'):
        plan['reason'] = 'source-verification-failed'
        diag.append('recipe/distro pin unreadable — refusing to build')
        return plan
    buildable = recipe['version']
    official = probes.get('official_stable')
    if official != buildable:
        diag.append(f'official Stable {official} != termux recipe {buildable};'
                    ' the recipe version is the buildable source (contract:')
        diag.append('  prepare_recipe aligns recipe/host-tools at build time)')
    if recipe.get('host_version') and recipe['host_version'] != buildable:
        diag.append(f'recipe/host-tools differ ({buildable} vs '
                    f'{recipe["host_version"]}); alignment applies')

    last = state.get('last_successful_build') or {}
    sig = build_signature(buildable, recipe['recipe_sha'],
                          recipe['host_sha'], port_sha)
    candidates = state.get('candidates') or []

    def mk_target(rev):
        return {'upstream_version': buildable, 'revision': rev,
                'package_version': f'{buildable}-{rev}',
                'termux_ref': probes['termux_head'],
                'port_sha': port_sha, 'signature': sig,
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
        if sig == last.get('signature'):
            plan['reason'] = 'identical-inputs-already-built'
            return plan
        if any(c.get('signature') == sig and
               c.get('status') == 'BUILD_VERIFIED_CANDIDATE'
               for c in candidates):
            plan['reason'] = 'identical-candidate-already-built'
            return plan
        target = mk_target(int(last.get('revision', 1)) + 1)
        plan['reason'] = 'inputs-changed-revision-build'
    else:
        plan['reason'] = 'upstream-behind-last-success'
        return plan

    blocked = (state.get('blocked') or {}).get(sig)
    if blocked:
        if blocked.get('retry_approved'):
            diag.append('retry-approved observed — one attempt allowed')
        elif blocked.get('classification') == 'infra' and \
                int(blocked.get('infra_retries', 0)) < 1:
            diag.append('infra flake — one automatic retry allowed')
        else:
            plan['action'] = 'skip'
            plan['reason'] = 'blocked-dedup'
            plan['target'] = target
            return plan

    if running and (running.get('signature') == sig or
                    running.get('signature') == 'RUNNING-ANY'):
        plan['reason'] = 'build-workflow-busy'
        plan['target'] = target
        return plan

    plan['action'] = 'build'
    plan['target'] = target
    for i in (issues or []):
        if BLOCKED_LABEL in (i.get('labels') or []) and \
                sig in (i.get('title') or ''):
            plan['pending_issue'] = i.get('number')
            break
    return plan


# --------------------------------------------------------------- apply -----

def apply_result(state: dict, plan: dict, result: dict, now: str):
    st = json.loads(json.dumps(state))
    ops = {'create_issues': [], 'comment_issues': []}
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
    if ok:
        cand = dict(t)
        cand.update({'status': 'BUILD_VERIFIED_CANDIDATE',
                     'deb_sha256': result.get('deb_sha256'),
                     'ci_run': result.get('ci_run'),
                     'ci_url': result.get('ci_url'),
                     'artifact': result.get('artifact'),
                     'recorded_at': now,
                     'validated': False})
        st['candidates'] = (st['candidates'] + [cand])[-20:]
        st['last_successful_build'] = dict(cand)
        st['blocked'].pop(t['signature'], None)
        st['history'].append({'at': now, 'success':
                              f"{t['package_version']} sig={t['signature']}"})
        return st, ops
    log_tail = result.get('log_tail') or ''
    cls = classify_failure(stage, log_tail)
    prev = st['blocked'].get(t['signature']) or {}
    if cls == 'infra' and int(prev.get('infra_retries', 0)) < 1:
        st['blocked'][t['signature']] = {
            'classification': 'infra',
            'infra_retries': int(prev.get('infra_retries', 0)) + 1,
            'inputs': {'recipe_sha': t['recipe_sha'],
                       'host_sha': t['host_sha'], 'port_sha': t['port_sha']},
            'stage': stage, 'at': now}
        st['history'].append({'at': now, 'infra-retry': t['signature']})
        return st, ops
    st['blocked'][t['signature']] = {
        'classification': cls,
        'issue': prev.get('issue'),
        'retry_approved': bool(prev.get('retry_approved')),
        'inputs': {'recipe_sha': t['recipe_sha'], 'host_sha': t['host_sha'],
                   'port_sha': t['port_sha']},
        'stage': stage, 'at': now,
        'infra_retries': int(prev.get('infra_retries', 0))}
    if not prev.get('issue'):
        ops['create_issues'].append({
            'title': issue_title(t, stage),
            'labels': [BLOCKED_LABEL, f'classification/{cls}'],
            'body': render_issue(t, plan.get('probes') or {},
                                 state.get('last_successful_build') or {},
                                 stage, log_tail,
                                 result.get('ci_url') or '(link unavailable)')})
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
    a = sub.add_parser('apply')
    a.add_argument('--state', required=True)
    a.add_argument('--plan', required=True)
    a.add_argument('--result', required=True)
    a.add_argument('--out', required=True)
    a.add_argument('--issues-out', required=True)
    args = p.parse_args(argv)
    if args.cmd == 'fetch':
        return cmd_fetch(args)
    if args.cmd == 'decide':
        state = json.loads(Path(args.state).read_text())
        probes = json.loads(Path(args.probes).read_text())
        issues = (json.loads(Path(args.issues).read_text())
                  if args.issues else [])
        running = (json.loads(Path(args.running).read_text())
                   if args.running else None)
        plan = decide(state, probes, args.port_sha, args.now, issues, running)
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
