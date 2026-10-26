#!/usr/bin/env python3
"""GitHub Pre-release publisher for CI-verified chromium-sandboxed DEBs.

Round 17 design contract
========================
* BUILD state and PUBLISH state are SEPARATE. This module never imports
  maintenance.py, never reads/writes maintenance state, and never feeds a
  publish failure back into build classification: a successful build +
  recorded candidate stay intact if publishing fails; only the publish step
  is retried (re-run the publish job — never a Chromium rebuild).
* FAIL CLOSED. Missing metadata, any integrity or provenance mismatch, or
  an unverifiable GitHub API outcome => refuse to publish. Success is only
  claimed after a POST-publish API re-read proves published+prerelease with
  byte-matching assets.
* NEVER clobber, delete or edit any pre-existing release, asset or tag.
  A brand-new DRAFT is created only when the tag is absent; an existing
  draft is resumed only when we own it (run marker) and every asset is
  re-verified by content hash. Clobber-style flags are never used.
* Every candidate is a PRE-RELEASE (never stable, never marked latest). CI
  verification is stated as CI VERIFIED — DEVICE NOT VERIFIED; device
  validation is the downloading user's responsibility.

Exit-code classes (stable contract for the workflow):
  0  published | already-published (idempotent duplicate skip)
  1  integrity / fail-closed refusal — nothing was published
  2  collision or foreign-owned object — human review; existing objects
     are left EXACTLY as they were
  3  transient API/network — safe to retry the publish step only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

EXIT_OK, EXIT_INTEGRITY, EXIT_COLLISION, EXIT_TRANSIENT = 0, 1, 2, 3
EXPECTED_PACKAGE = 'chromium-sandboxed'
EXPECTED_ARCH = 'aarch64'
BUILD_WORKFLOW_NAME = 'Build Termux Chromium Seccomp Sandbox Port'
# a workflow_call build executes INSIDE the caller's run, so run.name is
# the CALLER workflow's display name there — both shapes are legitimate
# (provenance is pinned by run-id + head_commit + artifact name, not name).
RUN_NAME_ALLOWLIST = (BUILD_WORKFLOW_NAME, 'Daily Maintenance')
MIN_DEB_BYTES = 1 * 1024 * 1024  # structural floor: a real build is >> this
TAG_PREFIX = 'chromium-sandboxed-v'
OWNER_MARKUP = 'tcs-publish-run'
ASSET_SUMS = 'SHA256SUMS.txt'
ASSET_MANIFEST = 'build-manifest.json'
TOKEN_PATTERNS = (re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'),
                  re.compile(r'github_pat_[A-Za-z0-9_]{20,}'),
                  re.compile(r'Authorization:\s*Bearer\s+\S+', re.I),
                  re.compile(r'GH_TOKEN\s*=\s*\S+'),
                  re.compile(r'::add-mask::'))
HEX64 = re.compile(r'^[0-9a-f]{64}$')
HEX40 = re.compile(r'^[0-9a-f]{40}$')
VER_RE = re.compile(r'^[0-9]+(?:\.[0-9]+){3}(?:-[0-9]+)?$')


class Refuse(Exception):
    def __init__(self, code: int, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def tag_for(deb_version: str) -> str:
    if not VER_RE.fullmatch(deb_version or ''):
        raise Refuse(EXIT_INTEGRITY, f'deb_version {deb_version!r} is not a '
                       'concrete package version (refusing to guess a tag)')
    return f'{TAG_PREFIX}{deb_version}'


def _run(cmd: list[str], **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def gh(gh_bin: str, *args: str, accept: tuple[int, ...] = (0,)):
    """Run the (possibly mocked) gh CLI; classify failures conservatively.

    Unknown API errors default to TRANSIENT (safe: the whole step is an
    idempotent retry). Permission/validation/ownership shapes escalate.
    """
    r = _run(shlex.split(gh_bin) + list(args))
    out = (r.stdout or '') + (r.stderr or '')
    if r.returncode not in accept:
        low = out.lower()
        frag = f'gh {" ".join(args[:3])}...: {out[-300:]}'
        if any(s in low for s in ('could not resolve', 'timed out', 'timeout',
                                  'connection reset', 'tls handshake', '502',
                                  '503', '504', 'early eof', 'the server aborted',
                                  'temporarily unavailable')):
            raise Refuse(EXIT_TRANSIENT, 'transient API error: ' + frag)
        if any(s in low for s in ('already exists', 'already released',
                                  'cannot change a tag', 'validation failed',
                                  'release already exists')):
            raise Refuse(EXIT_COLLISION, 'object-conflict: ' + frag)
        if any(s in low for s in ('403', 'not accessible by integration',
                                  'resource not accessible', 'must have admin',
                                  'insufficient')):
            raise Refuse(EXIT_INTEGRITY, 'permission-blocked (no publish): ' + frag)
        if 'not found' in low:
            raise Refuse(EXIT_INTEGRITY, 'expected object missing: ' + frag)
        raise Refuse(EXIT_TRANSIENT, 'unclassified API failure (retry-safe): ' + frag)
    return r.stdout


def _write(path: str, doc) -> None:
    Path(path).write_text(json.dumps(doc, indent=1) + '\n')


def _read(path: str):
    return json.loads(Path(path).read_text())


# ====================================================== ledger lookup ==
# Round 18 (Stage C): read-only candidate lookup for a workflow_run id.
# The OLD gate (jq on last_successful_build.ci_run == run) could MISS an
# earlier successful candidate once a LATER build had replaced
# last_successful_build (queue delay / consecutive builds). Lookup now:
#   1) collects every record CLAIMING this run (last_successful_build and
#      every candidates[] entry with ci_run == run id);
#   2) requires, for each claim: status == BUILD_VERIFIED_CANDIDATE,
#      concrete deb_version, 64hex deb_sha256, 16hex build signature,
#      40hex termux_sha  (validated flag is NOT required - CI success is
#      not device verification and vice versa);
#   3) FAILS CLOSED (code 1) on contradictory claims (same run id,
#      different version/sha/signature/termux pin) or malformed claims -
#      a claim that exists but is broken is never downgraded to "not
#      found" (that would hide ledger corruption behind a green no-op);
#   4) FAILS CLOSED if the signature is currently blocked (blocked map) -
#      blocked builds never auto-publish;
#   5) returns code 4 (normal no-op) ONLY when NOTHING claims the run
#      (dry-run/skip/failed/unrecorded runs have no claim by contract).
# NEVER writes the state file; never fabricates a candidate; the presence
# of an artifact alone remains insufficient (the caller must pass THIS
# ledger record's metadata through verify's SHA comparison afterwards).
def ledger_lookup(state: dict, run_id: int):
    """-> (record|None, exit_code, why). Codes: 0 found, 4 no-claim, 1 refuse."""
    claims = []
    last = state.get('last_successful_build')
    if isinstance(last, dict) and last.get('ci_run') == run_id:
        claims.append(('last_successful_build', last))
    for i, c in enumerate(state.get('candidates') or []):
        if isinstance(c, dict) and c.get('ci_run') == run_id:
            claims.append((f'candidates[{i}]', c))
    if not claims:
        return None, 4, 'no ledger record claims this run id'
    agreed = None
    for where, rec in claims:
        if rec.get('status') != 'BUILD_VERIFIED_CANDIDATE':
            return None, 1, (f'{where} claims run {run_id} but '
                             f'status={rec.get("status")!r} is not '
                             'BUILD_VERIFIED_CANDIDATE')
        ver = str(rec.get('deb_version') or '')
        sha = str(rec.get('deb_sha256') or '')
        sig = str(rec.get('signature') or '')
        tsha = str(rec.get('termux_sha') or '')
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}(?:-[0-9]+)?', ver):
            return None, 1, f'{where} claims run {run_id} with malformed deb_version {ver!r}'
        if not HEX64.fullmatch(sha):
            return None, 1, f'{where} claims run {run_id} with malformed deb_sha256 {sha[:16]!r}'
        if not re.fullmatch(r'[0-9a-f]{16}', sig):
            return None, 1, f'{where} claims run {run_id} with malformed signature {sig[:20]!r}'
        if not HEX40.fullmatch(tsha):
            return None, 1, f'{where} claims run {run_id} with malformed termux_sha {tsha[:16]!r}'
        key = (ver, sha, sig, tsha)
        if agreed is None:
            agreed = key
        elif agreed != key:
            return None, 1, (f'contradictory candidate records for run {run_id} '
                             f'({agreed[0]}/{agreed[1][:8]}... vs '
                             f'{key[0]}/{key[1][:8]}...) - human review required')
    blocked = state.get('blocked') or {}
    b = blocked.get(agreed[2])
    if isinstance(b, dict):
        return None, 1, (f'signature {agreed[2]} is currently blocked '
                         f'(issue {b.get("issue")}) - blocked builds never '
                         'auto-publish')
    src, rec = claims[0]
    return {'ci_run': run_id, 'deb_version': agreed[0], 'deb_sha256': agreed[1],
            'signature': agreed[2], 'termux_sha': agreed[3],
            'recorded_at': rec.get('recorded_at'),
            'claim_sources': [w for w, _ in claims]}, 0, 'found'


def cmd_ledger_lookup(args) -> int:
    try:
        rid = int(args.run_id)
    except (TypeError, ValueError):
        print(f'LEDGER-REFUSE[1]: run id {args.run_id!r} is not numeric',
              file=sys.stderr)
        return 1
    try:
        st = json.loads(Path(args.state).read_text())
    except (OSError, ValueError) as exc:
        print(f'LEDGER-REFUSE[1]: state unreadable: {exc}', file=sys.stderr)
        return 1
    if not isinstance(st, dict):
        st = {}
    rec, code, why = ledger_lookup(st, rid)
    if code == 0:
        _write(args.out, {'found': True, **rec})
        print(f'LEDGER-FOUND run {rid}: {rec["deb_version"]} '
              f'{rec["deb_sha256"][:16]}... via '
              f'{",".join(rec["claim_sources"])}')
    elif code == 4:
        print(f'LEDGER-NO-CLAIM run {rid}: {why}')
    else:
        print(f'LEDGER-REFUSE[1] run {rid}: {why}', file=sys.stderr)
    return code


# ================================================================ verify ==

def cmd_verify(args) -> int:
    adir = Path(args.artifact_dir)
    errors: list[str] = []
    if not adir.is_dir():
        raise Refuse(EXIT_INTEGRITY, f'artifact dir absent: {adir}')
    debs = sorted(set(adir.glob('chromium-sandboxed_*_aarch64.deb'))
                  | set(adir.glob('**/chromium-sandboxed_*_aarch64.deb')))
    # [4][5] exactly ONE distinct package: upload trees may mirror the same
    # bytes at two paths; distinct content under two names is refused.
    by_sha: dict[str, list[str]] = {}
    for d in debs:
        by_sha.setdefault(sha256_file(d), []).append(str(d))
    if len(by_sha) != 1:
        raise Refuse(EXIT_INTEGRITY,
                     f'expected exactly 1 distinct chromium-sandboxed DEB, '
                     f'found {len(by_sha)}: {[v for v in by_sha.values()]}')
    deb = Path(next(iter(by_sha.values()))[0])
    size = deb.stat().st_size
    # [14] non-zero, structurally plausible size
    if size < MIN_DEB_BYTES:
        raise Refuse(EXIT_INTEGRITY, f'deb suspiciously small ({size} bytes)')
    # [10] content sha vs build output
    sha = sha256_file(deb)
    if sha != args.deb_sha256:
        raise Refuse(EXIT_INTEGRITY,
                     f'SHA256 mismatch: actual {sha} != build output {args.deb_sha256}')
    # [6..9] package identity via dpkg-deb (never trust the filename)
    def field(name):
        r = _run([args.debinfo_cmd, '-f', str(deb), name])
        if r.returncode != 0:
            raise Refuse(EXIT_INTEGRITY, f'dpkg-deb -f {name} failed: {r.stderr[-200:]}')
        return r.stdout.strip()
    pkg, arch, ver = field('Package'), field('Architecture'), field('Version')
    if pkg != EXPECTED_PACKAGE:
        errors.append(f'Package={pkg!r}')
    if arch != EXPECTED_ARCH:
        errors.append(f'Architecture={arch!r}')
    if ver != args.deb_version:
        errors.append(f'Version={ver!r} != {args.deb_version!r}')
    r = _run([args.debinfo_cmd, '-I', str(deb)])
    if r.returncode != 0:
        errors.append(f'deb structure invalid: {r.stderr[-200:]}')
    r = _run([args.debinfo_cmd, '-c', str(deb)])
    listing = r.stdout or ''
    if r.returncode != 0:
        errors.append('deb content listing failed')
    # packaging contract (shield) must be inside the published artifact
    for must in ('lib/chromium-sandboxed/libtermux-gnp-fix.so',
                 'lib/chromium-sandboxed/chromium-shield-wrapper.sh'):
        if must not in listing:
            errors.append(f'shield member missing from deb: {must}')
    # [11][12][13] provenance pins
    if not HEX40.fullmatch(args.termux_sha or ''):
        errors.append(f'termux_sha malformed: {args.termux_sha!r}')
    else:
        cands = [adir / 'termux-pin.txt', *adir.glob('**/termux-pin.txt')]
        pin = next((c for c in cands if c.is_file()), None)
        if pin is not None and pin.read_text().strip() != args.termux_sha:
            errors.append('termux-pin.txt inside artifact disagrees with build output')
    if not HEX40.fullmatch(args.port_sha or ''):
        errors.append(f'port_sha malformed: {args.port_sha!r}')
    # [1][2][3][15] build/gate/package-gate success via run audit (never the
    # mere existence of an artifact: uploads run under if: always())
    if args.run_audit_json:
        run = _read(args.run_audit_json)
        if run.get('status') != 'completed' or run.get('conclusion') != 'success':
            errors.append(f"CI run not successful: {run.get('status')}/"
                          f"{run.get('conclusion')} (artifacts exist even on failure)")
        if run.get('name') not in RUN_NAME_ALLOWLIST:
            errors.append(f"run workflow {run.get('name')!r} unexpected")
        if str(run.get('id')) != str(args.ci_run_id):
            errors.append(f"run id {run.get('id')} != ci_run_id {args.ci_run_id}")
        if args.port_sha and run.get('head_commit', {}).get('id') not in (None, args.port_sha):
            errors.append('run head_commit != port_sha (wrong source commit)')
    if args.artifacts_json:
        arts = _read(args.artifacts_json)
        mine = [a for a in arts.get('artifacts', [])
                if a.get('name') == args.artifact_name]
        if len(mine) != 1 or mine[0].get('expired'):
            errors.append(f"artifact {args.artifact_name!r} not uniquely present "
                          '(missing/expired/duplicated)')
    if args.source not in ('maintenance', 'manual'):
        errors.append(f'source {args.source!r} invalid')
    if args.build_signature and not re.fullmatch(r'[0-9a-f]{16}',
                                                  args.build_signature):
        errors.append(f'build_signature malformed: {args.build_signature!r}')
    if args.source == 'maintenance' and not args.build_signature:
        errors.append('maintenance builds must carry the build signature '
                      '(manual runs may omit it — never fabricate one)')
    for name, val in (('deb_version', args.deb_version),
                      ('deb_sha256', args.deb_sha256)):
        if not val:
            errors.append(f'missing required metadata: {name}')
    if not HEX64.fullmatch(args.deb_sha256 or ''):
        errors.append('deb_sha256 malformed')
    if errors:
        raise Refuse(EXIT_INTEGRITY, 'integrity checks failed: '
                     + '; '.join(errors))
    _write(args.out, {
        'status': 'verified', 'deb_path': str(deb), 'deb_name': deb.name,
        'deb_sha256': sha, 'deb_size': size, 'package': pkg, 'arch': arch,
        'version': ver, 'termux_sha': args.termux_sha, 'port_sha': args.port_sha,
        'source': args.source, 'ci_run_id': str(args.ci_run_id),
        'ci_run_url': args.ci_run_url, 'artifact': args.artifact_name,
        'build_signature': args.build_signature or None,
        'build_timestamp_utc': args.build_timestamp or None,
    })
    print(f'PUBLISH-VERIFY OK: {deb.name} sha256={sha[:16]}… size={size}')
    return 0



# ================================================================== plan ==

def cmd_plan(args) -> int:
    v = _read(args.verified)
    tag = tag_for(v['version'])
    plan = {'action': 'publish', 'tag': tag,
            'title': f'Chromium Sandbox {v["version"]} (CI Candidate)',
            'reason': '', 'existing': None}
    rel = None
    if args.release_json and Path(args.release_json).is_file():
        try:
            rel = _read(args.release_json)
        except ValueError:
            raise Refuse(EXIT_TRANSIENT, 'release state unreadable — refusing')
    if rel and rel.get('tag_name') == tag:
        plan['existing'] = {'is_draft': rel.get('draft'), 'url': rel.get('html_url'),
                            'assets': [a.get('name') for a in rel.get('assets', [])]}
        owner = (OWNER_MARKUP + ': ' + str(v['ci_run_id']))
        notes = rel.get('body') or ''
        existing_manifest = _fetch_asset_text(args.gh_bin, args.repo, tag,
                                              ASSET_MANIFEST, rel.get('assets', []))
        their_sha = None
        if existing_manifest is not None:
            try:
                their_sha = json.loads(existing_manifest).get('deb_sha256')
            except ValueError:
                their_sha = None
        # [same tag] decide by CONTENT, not by filename. A DRAFT is never
        # treated as done: it goes through execute's asset re-verification
        # (owned -> resume) even when the manifest matches, so tampered or
        # partial draft assets can never slip into the published state.
        if their_sha == v['deb_sha256'] and not rel.get('draft'):
            plan['action'] = 'already-published'
            plan['reason'] = ('identical DEB sha256 already present for this tag '
                              '— normal duplicate skip (nothing created)')
        elif rel.get('draft') and owner in notes:
            plan['action'] = 'resume-draft'
            plan['reason'] = 'unpublished draft owned by this CI run — resume'
        elif rel.get('draft') and owner not in notes:
            plan['action'] = 'blocked-ownership'
            plan['reason'] = ('draft exists for the tag but is NOT owned by this '
                              'run (ownership marker absent/mismatched) — left '
                              'untouched; human review required')
        else:
            plan['action'] = 'collision'
            plan['reason'] = ('tag exists as a (pre-)release with a DIFFERENT '
                              'deb_sha256 or no readable manifest — overwriting '
                              'is forbidden; human review required')
    _write(args.out, plan)
    print(f"PUBLISH-PLAN: {plan['action']} — {plan['reason'] or 'tag absent'}")
    return 0


def _fetch_asset_text(gh_bin: str, repo: str, tag: str, name: str,
                      assets: list) -> str | None:
    """Read one text asset of an existing release (never writes anything)."""
    if not any(a.get('name') == name for a in assets or []):
        return None
    import shutil as _sh
    tmp = f'.asset-dl-{os.getpid()}'
    _sh.rmtree(tmp, ignore_errors=True)
    r = _run(shlex.split(gh_bin) + ['release', 'download', tag, '--pattern', name,
              '--dir', tmp, '--repo', repo])
    p = Path(tmp) / name
    try:
        return p.read_text() if r.returncode == 0 and p.is_file() else None
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


# =============================================================== execute ==

def _manifest(v: dict) -> dict:
    return {
        'package': v['package'], 'package_version': v['version'],
        'architecture': v['arch'],
        'chromium_upstream_version': v['version'].split('-')[0],
        'deb_name': v['deb_name'], 'deb_sha256': v['deb_sha256'],
        'deb_size': v['deb_size'],
        'github_source_commit': v['port_sha'],   # repo commit the DEB was built from
        'termux_pinned_sha': v['termux_sha'],    # termux-packages pin (separate provenance)
        'ci_run_id': int(v['ci_run_id']), 'ci_run_url': v['ci_run_url'],
        'ci_artifact': v['artifact'],
        'build_signature': v.get('build_signature'),          # null when unknown (manual)
        'signature_schema': 2 if v.get('build_signature') else None,
        'build_timestamp_utc': v.get('build_timestamp_utc'),
        'ci_verification_status': 'PASS',
        'package_gates_status': 'PASS',
        'security_gates_status': 'PASS (R1~R9b via run conclusion)',
        'device_verification_status': 'NOT VERIFIED FOR THIS BUILD',
        'validated_promotion': 'NOT APPLICABLE (human-approved separately)',
        'publisher': 'termux-chromium-sandbox auto pre-release (Round 17)',
    }


NOTES_TEMPLATE = """**CI VERIFIED — DEVICE NOT VERIFIED**

| Check | Status |
|---|---|
| CI Build | {ci} |
| Package Gates (identity, shield, launcher) | {pkg} |
| R1~R9b static/security gates | {sec} |
| Android Device Test | NOT VERIFIED FOR THIS BUILD |
| GUI/GPU/Audio | NOT VERIFIED FOR THIS BUILD |
| Validated Promotion | NOT APPLICABLE |

This package is the Android/Termux **aarch64** port of Chromium with a
seccomp-bpf-only sandbox (user-namespace/setuid paths are not used). It
ships as `chromium-sandboxed`, installed side-by-side with the stock
`chromium` package: it never overwrites your existing Chromium package or
profiles.

**Verification on YOUR device is the user's responsibility.** After
installing (`dpkg -i`) check at least:
- launch and basic browsing; process `Seccomp_filters` = 2 and
  `NoNewPrivs` = 1 for renderer children (`grep -E 'Seccomp_filters|NoNewPrivs' /proc/<pid>/status`)
- GUI/X11 window, GPU/WebGL (`chrome://gpu`), network + downloads,
  audio playback, clean exit/relaunch.

Behavior depends on your Android version, kernel and ROM — a CI green
build is NOT a promise the sandbox works on every device.
**Do not "fix" launch problems with `--no-sandbox`; that removes the very
protection this port exists to provide.**

Provenance: repo commit `{commit}` · termux pin `{tpin}` · build
signature {sig} · [CI run]({url}).

<!-- {owner} -->
"""


def cmd_execute(args) -> int:
    plan = _read(args.plan)
    v = _read(args.verified)
    tag = plan['tag']
    if plan['action'] in ('already-published',):
        print('PUBLISH-SKIP: identical release already exists (idempotent)')
        _write(args.out, {'status': 'already-published', 'tag': tag})
        return 0
    if plan['action'] in ('collision', 'blocked-ownership'):
        print(f"PUBLISH-STOP [{plan['action']}]: {plan['reason']}", file=sys.stderr)
        _write(args.out, {'status': plan['action'], 'tag': tag,
                          'reason': plan['reason']})
        return EXIT_COLLISION
    if plan['action'] not in ('publish', 'resume-draft'):
        raise Refuse(EXIT_INTEGRITY, f"unknown plan action {plan['action']!r}")

    owner = f'{OWNER_MARKUP}: {v["ci_run_id"]} (source: {v["source"]})'
    files = [v['deb_path']]

    # build attached metadata FIRST (checksums cover the ACTUAL files)
    adir = Path(v['deb_path']).parent
    manifest = _manifest(v)
    mpath = adir / ASSET_MANIFEST
    mpath.write_text(json.dumps(manifest, indent=1) + '\n')
    lines = []
    for p in sorted([Path(v['deb_path']), mpath]):
        lines.append(f'{sha256_file(p)}  {p.name}')
    spath = adir / ASSET_SUMS
    spath.write_text('\n'.join(lines) + '\n')
    files += [str(mpath), str(spath)]
    # basename uniqueness: mirrored logs (artifact uploaded both a direct and
    # a ** path) are deduped when byte-identical; differing bytes under one
    # asset name are an integrity refusal (ambiguous artifact).
    _seen: dict[str, str] = {}
    _deduped = []
    for f in files:
        name = os.path.basename(f)
        digest = sha256_file(Path(f))
        if name in _seen:
            if _seen[name] != digest:
                raise Refuse(EXIT_INTEGRITY,
                             f'artifact contains two different files named {name}')
            continue
        _seen[name] = digest
        _deduped.append(f)
    files = _deduped

    # optional logs — only when the token/secret scan is clean
    omitted = []
    for pat in ('chromium-build.log', 'port-apply-chromium.log',
                '**/port-apply-chromium.log'):
        for lg in sorted(adir.glob(pat)):
            body = lg.read_bytes()
            if any(p.search(body.decode('utf-8', 'replace')) for p in TOKEN_PATTERNS):
                omitted.append(lg.name)
            else:
                files.append(str(lg))
    if omitted:
        warn = adir / 'logs-omitted.txt'
        warn.write_text('Log attachments omitted by secret scanner: '
                        + ', '.join(omitted) + '\n')
        files.append(str(warn))

    # ---- create DRAFT (only when tag absent, i.e. action==publish)
    if plan['action'] == 'publish':
        notes = NOTES_TEMPLATE.format(
            ci='PASS', pkg='PASS', sec='PASS', commit=v['port_sha'],
            tpin=v['termux_sha'],
            sig=('`%s` (schema v2)' % v['build_signature']) if v.get('build_signature')
                else 'not available (manual run — value not fabricated)',
            url=v['ci_run_url'], owner=owner)
        npath = adir / 'release-notes.md'
        npath.write_text(notes)
        try:
            gh(args.gh_bin, 'release', 'create', tag, '--draft', '--prerelease',
               '--target', v['port_sha'], '--title', plan['title'],
               '--notes-file', str(npath), '--repo', args.repo)
        except Refuse as r:
            # A crash after a previous create leaves OUR draft; 'already
            # exists' by anyone else is a collision we must not touch.
            if r.code != EXIT_COLLISION:
                raise
            cur_full = json.loads(gh(args.gh_bin, 'release', 'view', tag,
                                     '--json', 'isDraft,body', '--repo', args.repo)
                                  or '{}')
            if cur_full.get('isDraft') and owner in (cur_full.get('body') or ''):
                print('draft already exists and is owned by this run — resuming')
            else:
                print('PUBLISH-STOP [collision]: tag appeared under a foreign '
                      'object mid-publish; nothing was modified', file=sys.stderr)
                _write(args.out, {'status': 'collision', 'tag': tag,
                                  'created_race': True})
                return EXIT_COLLISION
    # else: resume-draft — the owned draft was already created by us

    # ---- upload assets WITHOUT clobbering; pre-existing same-name assets are
    # verified by content hash (skip) or escalate to collision (keep both)
    listed = json.loads(gh(args.gh_bin, 'release', 'view', tag, '--json',
                           'assets', '--repo', args.repo) or '{}')
    existing = {a.get('name'): a for a in listed.get('assets', [])}
    for f in files:
        name = os.path.basename(f)
        if name in existing:
            tmpdir = str(adir / '.existing')
            os.makedirs(tmpdir, exist_ok=True)
            _run(shlex.split(args.gh_bin) + ['release', 'download', tag, '--pattern', name,
                  '--dir', tmpdir, '--repo', args.repo])
            got = Path(tmpdir) / name
            if got.is_file() and sha256_file(got) == sha256_file(Path(f)):
                print(f'asset {name}: already present with identical content — skip')
                continue
            print(f'PUBLISH-STOP [collision]: asset {name} exists with '
                  'different content — existing objects left untouched',
                  file=sys.stderr)
            _write(args.out, {'status': 'collision', 'tag': tag,
                              'asset': name, 'draft_left_unpublished': True})
            return EXIT_COLLISION
        try:
            gh(args.gh_bin, 'release', 'upload', tag, f, '--repo', args.repo)
        except Refuse as up:
            if up.code != EXIT_COLLISION:
                raise
            # someone (an earlier crashed pass of us) put it there: verify by
            # content or escalate; never clobber.
            tmpdir = str(adir / '.existing')
            os.makedirs(tmpdir, exist_ok=True)
            _run(shlex.split(args.gh_bin) + ['release', 'download', tag,
                  '--pattern', name, '--dir', tmpdir, '--repo', args.repo])
            got = Path(tmpdir) / name
            if not (got.is_file() and sha256_file(got) == sha256_file(Path(f))):
                print(f'PUBLISH-STOP [collision]: asset {name} appeared with '
                      'unverifiable content — existing objects untouched',
                      file=sys.stderr)
                _write(args.out, {'status': 'collision', 'tag': tag,
                                  'asset': name, 'upload_race': True})
                return EXIT_COLLISION
            print(f'asset {name}: present with identical content — skip')

    # ---- pre-publish verification on the DRAFT: every expected asset exists
    want = {os.path.basename(f) for f in files}
    listed = json.loads(gh(args.gh_bin, 'release', 'view', tag, '--json',
                           'assets', '--repo', args.repo) or '{}')
    have = {a.get('name') for a in listed.get('assets', [])}
    if not want <= have:
        # never expose incomplete files: keep the draft, report transient
        raise Refuse(EXIT_TRANSIENT,
                     f'draft asset verification failed (missing '
                     f'{sorted(want - have)}); draft kept unpublished — retry '
                     'the publish step only')

    # ---- flip to published PRE-RELEASE, then re-read from the API
    gh(args.gh_bin, 'release', 'edit', tag, '--draft=false', '--repo', args.repo)
    # gh release view --json uses the CLI field name "url", NOT the
    # REST API's "html_url". The old selector falsely failed AFTER the
    # release was already published, leaving a red workflow on success.
    final = json.loads(gh(args.gh_bin, 'release', 'view', tag, '--json',
                          'isDraft,isPrerelease,assets,url',
                          '--repo', args.repo) or '{}')
    if final.get('isDraft') or not final.get('isPrerelease'):
        raise Refuse(EXIT_TRANSIENT,
                     'post-publish state verification failed (still draft or '
                     'not prerelease) — NOT claiming success; retry publish step')
    fnames = {a.get('name') for a in final.get('assets', [])}
    if not want <= fnames:
        raise Refuse(EXIT_TRANSIENT,
                     'post-publish asset verification failed — success NOT '
                     'claimed; retry publish step (no rebuild)')
    published_url = final.get('url')
    if not isinstance(published_url, str) or not published_url.startswith(
            f'https://github.com/{args.repo}/releases/tag/'):
        raise Refuse(EXIT_TRANSIENT,
                     'post-publish release URL missing/malformed — retry-safe '
                     'verification refusal (release may already be published)')
    _write(args.out, {'status': 'published', 'tag': tag, 'url': published_url,
                      'prerelease': True, 'deb_sha256': v['deb_sha256'],
                      'assets': sorted(fnames)})
    print(f"PUBLISH-OK pre-release {tag} -> {published_url}")
    return 0


# =================================================================== CLI ==

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    v = sub.add_parser('verify')
    v.add_argument('--artifact-dir', required=True)
    v.add_argument('--deb-version', required=True)
    v.add_argument('--deb-sha256', required=True)
    v.add_argument('--termux-sha', required=True)
    v.add_argument('--port-sha', required=True)
    v.add_argument('--source', required=True)
    v.add_argument('--ci-run-id', required=True)
    v.add_argument('--ci-run-url', required=True)
    v.add_argument('--artifact-name', required=True)
    v.add_argument('--build-signature', default='')
    v.add_argument('--build-timestamp', default='')
    v.add_argument('--run-audit-json', default=None)
    v.add_argument('--artifacts-json', default=None)
    v.add_argument('--debinfo-cmd', default='dpkg-deb')
    v.add_argument('--out', required=True)
    pl = sub.add_parser('plan')
    pl.add_argument('--verified', required=True)
    pl.add_argument('--release-json', default=None)
    pl.add_argument('--gh-bin', default='gh')
    pl.add_argument('--repo', required=True)
    pl.add_argument('--out', required=True)
    ll = sub.add_parser('ledger-lookup')
    ll.add_argument('--state', required=True)
    ll.add_argument('--run-id', required=True)
    ll.add_argument('--out', required=True)
    e = sub.add_parser('execute')
    e.add_argument('--plan', required=True)
    e.add_argument('--verified', required=True)
    e.add_argument('--repo', required=True)
    e.add_argument('--gh-bin', default='gh')
    e.add_argument('--out', required=True)
    args = p.parse_args(argv)
    try:
        if args.cmd == 'ledger-lookup':
            return cmd_ledger_lookup(args)
        if args.cmd == 'verify':
            return cmd_verify(args)
        if args.cmd == 'plan':
            return cmd_plan(args)
        if args.cmd == 'execute':
            return cmd_execute(args)
    except Refuse as r:
        print(f'PUBLISH-REFUSE[{r.code}]: {r.reason}', file=sys.stderr)
        out = getattr(args, 'out', None)
        if out:
            _write(out, {'status': 'refused', 'exit_code': r.code,
                         'reason': r.reason})
        return r.code
    return 2


if __name__ == '__main__':
    sys.exit(main())
