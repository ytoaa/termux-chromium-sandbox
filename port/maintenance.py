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

def classify_failure(stage: str, log_tail: str) -> str:
    t = (log_tail or '').lower()
    if any(k in t for k in TRANSIENT):
        return 'infra'
    if stage in ('gate', 'verify'):
        return 'port'
    return 'unknown'


def issue_matches_sig(title: str, sig: str) -> bool:
    # Round 15.1 #6: ONE matcher everywhere (decide dedup, stamp, label).
    return f'sig {sig}' in (title or '')


def issue_title(target: dict, reason: str) -> str:
    return (f"[auto-build] Chromium {target['upstream_version']} "
            f"revision {target['revision']} blocked ({reason}, "
            f"sig {target['signature']})")


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
        f"- Build signature: `{target['signature']}`  Failure stage: `{stage}`"
        + (f"  Failed jobs: `{(target.get('failure_jobs') or '')}`" if target.get('failure_jobs') else ''),
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
    candidates = state.get('candidates') or []

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
    blocked = (state.get('blocked') or {}).get(sig)
    consumed = set((blocked or {}).get('approval_consumed_issues') or [])
    if blocked and not blocked.get('retry_approved'):
        for i in (issues or []):
            if 'retry-approved' in (i.get('labels') or []) and \
                    issue_matches_sig(i.get('title', ''), sig) and \
                    i.get('number') not in consumed:
                blocked['retry_approved'] = True
                blocked['_approval_source_issue'] = i.get('number')
                diag.append('retry-approved LABEL on issue '
                            f'{i.get("number")} — ONE attempt (will be consumed)')
                break
    if blocked:
        if blocked.get('retry_approved'):
            plan['approval_used'] = True
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
    if not (state.get('blocked') or {}).get(sig):
        for i in (issues or []):
            if BLOCKED_LABEL in (i.get('labels') or []) and \
                    issue_matches_sig(i.get('title', ''), sig):
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
                issue_matches_sig(i.get('title', ''), sig):
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
    if ok:
        cand = dict(t)
        cand.update({'status': 'BUILD_VERIFIED_CANDIDATE',
                     'deb_sha256': result.get('deb_sha256'),
                     'deb_version': result.get('deb_version'),
                     'termux_sha': result.get('termux_sha'),
                     'ci_run': result.get('ci_run'),
                     'ci_url': result.get('ci_url'),
                     'artifact': result.get('artifact'),
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
    if plan.get('approval_used'):
        src = (prev.get('_approval_source_issue')
               or (state.get('blocked') or {}).get(t['signature'], {})
                   .get('_approval_source_issue'))
        if src is not None and src not in consumed_list:
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
    d.add_argument('--approve-retry', action='store_true')
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
    if args.cmd == 'decide':
        state = json.loads(Path(args.state).read_text())
        if getattr(args, 'approve_retry', False):
            for v in (state.get('blocked') or {}).values():
                v['retry_approved'] = True
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
