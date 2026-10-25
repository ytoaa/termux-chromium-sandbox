#!/usr/bin/env python3
"""Round 17 Stage I — publisher scenario suite (non-destructive, mocked).

Covers the required test table with the REAL publisher logic, a synthetic
but structurally real DEB (dpkg-deb built) and a stateful gh mock. No
Chromium is built; no real GitHub objects are touched.
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / 'port'))
import publish_release as P

PASS = fail = 0
def check(name, cond, extra=''):
    global PASS, fail
    if cond: PASS += 1; print(f'PASS  [{name}]')
    else: fail += 1; print(f'FAIL  [{name}] {extra}')

GH = f'{sys.executable} {HERE / "fixtures" / "gh_mock.py"}'
TSHA = 'd' * 40
PSHA = 'e' * 40
SIG = 'a' * 16
VERSION = '156.0.8078.47-3'

def make_artifact(tmp, *, name='chromium-sandboxed', version=VERSION,
                  arch='aarch64', shield=True, pad_mb=2, corrupt=False,
                  extra_files=True):
    """Build a structurally real DEB with dpkg-deb into an artifact dir."""
    adir = Path(tmp) / 'artifact'; adir.mkdir(parents=True, exist_ok=True)
    root = Path(tmp) / 'debroot'
    (root / 'DEBIAN').mkdir(parents=True, exist_ok=True)
    (root / 'DEBIAN' / 'control').write_text(
        f'Package: {name}\nVersion: {version}\nArchitecture: {arch}\n'
        'Maintainer: t <t@e.invalid>\nDescription: t\n')
    lib = root / 'data/data/com.termux/files/usr/lib/chromium-sandboxed'
    lib.mkdir(parents=True, exist_ok=True)
    (lib / 'chromium-launcher.sh').write_text('#!/bin/sh\nexec chromium-real\n')
    if shield:
        (lib / 'libtermux-gnp-fix.so').write_bytes(b'\x7fELF' + b'\0' * 64)
        (lib / 'chromium-shield-wrapper.sh').write_text(
            '#!/bin/sh\nexec .../chromium-launcher.sh "$@"\n')
    pad = adir / 'pad.bin'
    pad.write_bytes(os.urandom(pad_mb * 1024 * 1024))  # incompressible
    (root / 'data/data/com.termux/files/usr/share/doc/pad').mkdir(parents=True, exist_ok=True)
    shutil.move(str(pad), root / 'data/data/com.termux/files/usr/share/doc/pad/pad.bin')
    for dp, dns, fns in os.walk(root):
        for d in dns: os.chmod(os.path.join(dp, d), 0o755)
        for f in fns: os.chmod(os.path.join(dp, f), 0o644)
    os.chmod(root, 0o755)
    deb = adir / f'{name}_{version}_{arch}.deb'
    r = subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(root), str(deb)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    if corrupt:
        deb.write_bytes(deb.read_bytes()[:200])
    if extra_files:
        (adir / 'termux-pin.txt').write_text(TSHA + '\n')
        (adir / 'chromium-build.log').write_text('builder: ok (no secrets here)\n')
        (adir / 'port-apply-chromium.log').write_text('R1 APPLIED\nR9b APPLIED\n')
    return adir, deb

def audit(conclusion='success', status='completed', wf='Build Termux Chromium Seccomp Sandbox Port'):
    return {'status': status, 'conclusion': conclusion, 'name': wf, 'id': 999,
            'head_commit': {'id': PSHA}}
def arts(names=('build-999',), expired=False):
    return {'artifacts': [{'name': n, 'expired': expired} for n in names]}

def run_verify(tmp, adir, deb, *, rc_expect=None, **over):
    a = {'artifact_dir': str(adir), 'deb_version': VERSION,
         'deb_sha256': P.sha256_file(deb) if not over.pop('bad_sha', False) else '0' * 64,
         'termux_sha': TSHA, 'port_sha': PSHA, 'source': 'manual',
         'ci_run_id': '999', 'ci_run_url': 'https://example.invalid/run/999',
         'artifact_name': 'build-999', 'build_signature': '',
         'build_timestamp': '2026-10-26T00:00:00Z',
         'run_audit_json': None, 'artifacts_json': None,
         'debinfo_cmd': 'dpkg-deb', 'out': str(tmp / 'verified.json')}
    for k, v in over.items():
        if k in ('run_audit', 'artifacts'):
            continue
        if v is _DEL:
            a.pop(k, None)
        else:
            a[k] = v
    # map special keys
    if 'run_audit' in over:
        p = tmp / 'run.json'; p.write_text(json.dumps(over['run_audit'])); a['run_audit_json'] = str(p)
    if 'artifacts' in over:
        p = tmp / 'arts.json'; p.write_text(json.dumps(over['artifacts'])); a['artifacts_json'] = str(p)
    args = []
    for k, v in a.items():
        if v is None: continue
        args += [f'--{k.replace("_", "-")}', str(v)]
    rc = P.main(['verify', *args])
    return rc

_DEL = object()

def fresh():
    tmp = Path(tempfile.mkdtemp(prefix='pubtest.'))
    return tmp

# ---------- [row: CI success + valid DEB -> publishable]
tmp = fresh(); adir, deb = make_artifact(tmp)
rc = run_verify(tmp, adir, deb, run_audit=audit(), artifacts=arts(),
                termux_sha=TSHA, port_sha=PSHA)
check('[t1] valid CI-verified DEB -> verify PASS', rc == 0 and (tmp / 'verified.json').is_file())
# ---------- [row: CI run failed -> refuse]
rc = run_verify(tmp, adir, deb, run_audit=audit(conclusion='failure'), artifacts=arts())
check('[t2] CI run conclusion=failure -> refuse (artifact alone is NOT success)', rc == 1)
# ---------- [row: package gate failure (shield members missing)]
tmp2 = fresh(); adir2, deb2 = make_artifact(tmp2, shield=False)
rc = run_verify(tmp2, adir2, deb2, run_audit=audit(), artifacts=arts())
check('[t3] package-gate content missing (shield) -> refuse', rc == 1)
# ---------- [row: DEB absent]
tmp3 = fresh(); adir3, _ = make_artifact(tmp3); (adir3 / f'chromium-sandboxed_{VERSION}_aarch64.deb').unlink()
rc = P.main(['verify', '--artifact-dir', str(adir3), '--deb-version', VERSION,
             '--deb-sha256', '0' * 64, '--termux-sha', TSHA, '--port-sha', PSHA,
             '--source', 'manual', '--ci-run-id', '999', '--ci-run-url', 'u',
             '--artifact-name', 'build-999', '--out', str(tmp3 / 'v.json')])
check('[t4] no DEB present -> refuse', rc == 1)
# ---------- [row: multiple DISTINCT DEBs (nested real-artifact layout)]
tmp4 = fresh(); adir4, deb4 = make_artifact(tmp4)
sub = adir4 / 'termux-packages' / 'output'; sub.mkdir(parents=True, exist_ok=True)
d2 = make_artifact(tmp4 / 'alt', version='9.9.9.9-9')[1]
shutil.move(str(d2), sub / 'chromium-sandboxed_9.9.9.9-9_aarch64.deb')
rc = run_verify(tmp4, adir4, deb4, run_audit=audit(), artifacts=arts())
check('[t5] two DISTINCT DEBs (nested tree) -> refuse', rc == 1)
# ---------- mirrored identical bytes at two paths = ONE package
tmp4b = fresh(); adir4b, deb4b = make_artifact(tmp4b)
sub2 = adir4b / 'termux-packages' / 'output'; sub2.mkdir(parents=True, exist_ok=True)
shutil.move(str(deb4b), sub2 / deb4b.name)
(adir4b / 'termux-packages' / 'termux-pin.txt').write_text(TSHA + '\n')
(adir4b / 'termux-pin.txt').unlink()
rc = run_verify(tmp4b, adir4b, sub2 / deb4b.name, run_audit=audit(), artifacts=arts())
check('[t43] real artifact layout (deb nested under termux-packages/, pin moved) -> verify PASS',
      rc == 0)
# ---------- [row: package name mismatch]
tmp5 = fresh(); adir5, deb5 = make_artifact(tmp5, name='chromium-sandboxed-x')
rc = run_verify(tmp5, adir5, deb5, run_audit=audit(), artifacts=arts())
check('[t6] wrong Package name -> refuse', rc == 1)
# ---------- [row: arch mismatch]
tmp6 = fresh(); adir6, deb6 = make_artifact(tmp6, arch='arm64')
rc = run_verify(tmp6, adir6, deb6, run_audit=audit(), artifacts=arts())
check('[t7] wrong Architecture -> refuse', rc == 1)
# ---------- [row: SHA256 mismatch]
tmp7 = fresh(); adir7, deb7 = make_artifact(tmp7)
rc = run_verify(tmp7, adir7, deb7, bad_sha=True, run_audit=audit(), artifacts=arts())
check('[t8] deb sha256 != build output -> refuse', rc == 1)
# ---------- version mismatch + structural + tiny
tmp8 = fresh(); adir8, deb8 = make_artifact(tmp8, version='156.0.8078.47-4')
rc = run_verify(tmp8, adir8, deb8, run_audit=audit(), artifacts=arts())
check('[t9] dpkg Version != expected -> refuse', rc == 1)
tmp9 = fresh(); adir9, deb9 = make_artifact(tmp9, corrupt=True)
rc = run_verify(tmp9, adir9, deb9, run_audit=audit(), artifacts=arts())
check('[t10] corrupted/0-size-ish deb -> refuse (structure/size)', rc == 1)
tmp10 = fresh(); adir10, deb10 = make_artifact(tmp10, pad_mb=0)
rc = run_verify(tmp10, adir10, deb10, run_audit=audit(), artifacts=arts())
check('[t11] below structural size floor -> refuse', rc == 1)
# ---------- metadata failures
tmp11 = fresh(); adir11, deb11 = make_artifact(tmp11)
rc = run_verify(tmp11, adir11, deb11, termux_sha='short', run_audit=audit(), artifacts=arts())
check('[t12] malformed termux_sha -> refuse', rc == 1)
rc = run_verify(tmp11, adir11, deb11, source='maintenance', run_audit=audit(), artifacts=arts())
check('[t13] maintenance source WITHOUT signature -> refuse (no fabrication upstream)', rc == 1)
rc = run_verify(tmp11, adir11, deb11, run_audit=audit(), artifacts=arts(expired=True))
check('[t14] artifact missing/expired in owning run -> refuse', rc == 1)
try:
    P.tag_for('latest'); ok = False
except P.Refuse: ok = True
check('[t15] non-concrete version cannot yield a tag (refuse to guess)', ok)

# ================= execute / dedup / recovery (gh mock) ===================
def env_store():
    st = fresh() / 'store'; (st / 'files').mkdir(parents=True)
    os.environ['GH_MOCK_STORE'] = str(st)
    for k in ('GH_MOCK_FAIL_PHASE', 'GH_MOCK_FAIL_ASSET', 'GH_MOCK_TAMPER_ASSET',
              'GH_MOCK_FAIL_MSG'):
        os.environ.pop(k, None)
    return st
def store(st):
    f = st / 'releases.json'
    return json.loads(f.read_text()) if f.is_file() else {}
def seed_release(st, tag, *, draft=False, prerelease=True, body='', manifest_sha='0' * 64,
                 assets=('build-manifest.json',)):
    rels = store(st)
    alist = []
    for a in assets:
        p = st / 'files' / f'{tag}-{a}'
        if a == 'build-manifest.json':
            p.write_text(json.dumps({'deb_sha256': manifest_sha}))
        alist.append({'name': a, 'path': str(p), 'url': f'u/{a}'})
    rels[tag] = {'tag_name': tag, 'draft': draft, 'prerelease': prerelease,
                 'target': PSHA, 'title': 'x', 'body': body, 'assets': alist,
                 'html_url': f'https://example.invalid/{tag}'}
    (st / 'releases.json').write_text(json.dumps(rels))

def run_plan(tmp, tag_expected):
    tag = tag_expected or ('chromium-sandboxed-v' + VERSION)
    args = ['plan', '--verified', str(tmp / 'verified.json'),
            '--gh-bin', GH, '--repo', 'r/p', '--out', str(tmp / 'plan.json')]
    r = subprocess.run(GH.split() + ['release', 'view', tag, '--json',
                       'isDraft,isPrerelease,assets,html_url', '--repo', 'r/p'],
                       capture_output=True, text=True)
    if r.returncode == 0:
        rp = tmp / 'rel.json'; rp.write_text(r.stdout)
        args += ['--release-json', str(rp)]
    rc = P.main(args)
    return rc, json.loads((tmp / 'plan.json').read_text())

def run_execute(tmp):
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        rc = P.main(['execute', '--plan', str(tmp / 'plan.json'),
                     '--verified', str(tmp / 'verified.json'), '--repo', 'r/p',
                     '--gh-bin', GH, '--out', str(tmp / 'exec.json')])
    (tmp / 'exec.err').write_text(buf.getvalue())
    return rc

# [row: scheduled build success -> auto publish (maintenance path w/ signature)]
tmpm = fresh(); adirm, debm = make_artifact(tmpm)
rc = run_verify(tmpm, adirm, debm, source='maintenance', build_signature=SIG,
                run_audit=audit(), artifacts=arts())
check('[t16] maintenance-verified candidate (signature) -> verify PASS', rc == 0)
st = env_store()
rc, pl = run_plan(tmpm, None)
check('[t17] absent tag -> plan publish', rc == 0 and pl['action'] == 'publish'
      and pl['tag'] == 'chromium-sandboxed-v' + VERSION and pl['title'] == f'Chromium Sandbox {VERSION} (CI Candidate)')
rc = run_execute(tmpm)
rel = store(st).get('chromium-sandboxed-v' + VERSION, {})
ok_assets = {a['name'] for a in rel.get('assets', [])}
check('[t18] execute -> published PRE-RELEASE with deb+SHA256SUMS+manifest',
      rc == 0 and rel.get('draft') is False and rel.get('prerelease') is True
      and {'chromium-sandboxed_' + VERSION + '_aarch64.deb', 'SHA256SUMS.txt',
           'build-manifest.json'} <= ok_assets,
      'rc=%s %s || %s' % (rc, json.dumps(rel)[:160],
                         (tmpm / 'exec.err').read_text()[-400:]))
man = json.loads((Path(st / 'files' / ('chromium-sandboxed-v' + VERSION + '-build-manifest.json'))).read_text())
check('[t19] manifest carries full provenance + CI VERIFIED / DEVICE NOT VERIFIED',
      man['deb_sha256'] == P.sha256_file(debm) and man['termux_pinned_sha'] == TSHA
      and man['github_source_commit'] == PSHA and man['build_signature'] == SIG
      and man['signature_schema'] == 2 and man['ci_run_id'] == 999
      and man['device_verification_status'].startswith('NOT VERIFIED')
      and man['validated_promotion'].startswith('NOT APPLICABLE'), json.dumps(man)[:200])
notes = rel.get('body', '')
check('[t20] notes: CI VERIFIED — DEVICE NOT VERIFIED + no --no-sandbox advice + owner marker',
      'CI VERIFIED — DEVICE NOT VERIFIED' in notes and '--no-sandbox' in notes
      and 'Do not' in notes and 'tcs-publish-run: 999' in notes)
# [row: duplicate same tag same sha -> skip, no duplicate]
st_same = st  # same store already published
rc2, pl2 = run_plan(tmpm, None)
check('[t21] same tag + same sha -> plan already-published (normal dedup skip)',
      pl2['action'] == 'already-published')
before = json.dumps(store(st_same))
rc2 = run_execute(tmpm)
check('[t22] already-published execute -> rc0, store byte-unchanged (no duplicate)',
      rc2 == 0 and json.dumps(store(st_same)) == before)
# [row: same tag different sha -> collision, preserved]
tmpn = fresh(); adirn, dehn = make_artifact(tmpn)  # different bytes (pad same? new random)
(adirn / 'chromium-build.log').write_text('different build content ' + 'x' * 40)
# rebuild deb with different content: append a file
(root2 := (tmpn / 'debroot2'))
rcn = run_verify(tmpn, adirn, dehn, run_audit=audit(), artifacts=arts())
# seed a FOREIGN published release with different manifest sha under same tag
rc3, pl3 = run_plan(tmpn, None)  # store still has our release (same content as tmpm!) -> different sha than dehn
check('[t23] same tag + DIFFERENT sha -> plan collision',
      pl3['action'] == 'collision', json.dumps(pl3)[:150])
before = json.dumps(store(st))
rc3 = run_execute(tmpn)
check('[t24] collision execute -> exit2 and existing release UNTOUCHED (no clobber)',
      rc3 == 2 and json.dumps(store(st)) == before)
# [row: partial upload failure -> keep draft, recoverable]
st2 = env_store()
os.environ['GH_MOCK_FAIL_ASSET'] = 'SHA256SUMS.txt'
tmp4 = fresh(); adir4b, deb4b = make_artifact(tmp4)
rcv = run_verify(tmp4, adir4b, deb4b, run_audit=audit(), artifacts=arts())
# note: env_store switched store dir; re-plan against NEW empty store
import importlib
rc4, pl4 = run_plan(tmp4, None)
rc4 = run_execute(tmp4)
rel4 = store(st2).get('chromium-sandboxed-v' + VERSION, {})
check('[t25] upload failure -> transient rc!=0 and DRAFT stays unpublished (nothing exposed)',
      rc4 != 0 and rel4.get('draft') is True)
os.environ.pop('GH_MOCK_FAIL_ASSET')
rc5 = run_execute(tmp4)
rel5 = store(st2).get('chromium-sandboxed-v' + VERSION, {})
check('[t26] publish-step retry only -> completes from owned draft, NO rebuild',
      rc5 == 0 and rel5.get('draft') is False and rel5.get('prerelease') is True,
      (tmp4 / 'exec.err').read_text()[-400:])
# [row: tampered existing asset -> collision]
st3 = env_store()
tmp5 = fresh(); adir5b, deb5b = make_artifact(tmp5)
run_verify(tmp5, adir5b, deb5b, run_audit=audit(), artifacts=arts())
seed_release(st3, 'chromium-sandboxed-v' + VERSION, draft=True,
             body='tcs-publish-run: 999 (source: manual)', manifest_sha=P.sha256_file(deb5b),
             assets=('build-manifest.json', 'SHA256SUMS.txt'))
os.environ['GH_MOCK_TAMPER_ASSET'] = 'SHA256SUMS.txt'
rc6, pl6 = run_plan(tmp5, None)
rc6 = run_execute(tmp5)
check('[t27] pre-existing asset with DIFFERENT content -> collision exit2, draft kept',
      rc6 == 2 and store(st3)['chromium-sandboxed-v' + VERSION]['draft'] is True)
os.environ.pop('GH_MOCK_TAMPER_ASSET')
# [row: API error at publish flip -> transient, success NOT claimed]
st4 = env_store()
tmp6 = fresh(); adir6b, deb6b = make_artifact(tmp6)
run_verify(tmp6, adir6b, deb6b, run_audit=audit(), artifacts=arts())
rc7, pl7 = run_plan(tmp6, None)
os.environ['GH_MOCK_FAIL_PHASE'] = 'edit'
os.environ['GH_MOCK_FAIL_MSG'] = 'the server aborted the request'
rc7 = run_execute(tmp6)
rel7 = store(st4).get('chromium-sandboxed-v' + VERSION, {})
check('[t28] transient API error at publish flip -> rc3, NOT claimed success, draft kept',
      rc7 == 3 and rel7.get('draft') is True,
      (tmp6 / 'exec.err').read_text()[-400:])
os.environ.pop('GH_MOCK_FAIL_PHASE'); os.environ.pop('GH_MOCK_FAIL_MSG')
# [row: foreign draft ownership -> blocked]
rc8, pl8 = run_plan(tmp6, None)  # store st4 has OUR owned draft (marker 999) -> resume? marker matches our ci_run_id 999
check('[t29] our owned unpublished draft -> plan resume-draft', pl8['action'] == 'resume-draft')
st5 = env_store()
seed_release(st5, 'chromium-sandboxed-v' + VERSION, draft=True,
             body='someone else\u2019s draft', manifest_sha='1' * 64)
rc9, pl9 = run_plan(tmp6, None)
rc9 = run_execute(tmp6)
check('[t30] foreign-owned draft -> blocked-ownership exit2, untouched',
      pl9['action'] == 'blocked-ownership' and rc9 == 2
      and store(st5)['chromium-sandboxed-v' + VERSION]['draft'] is True)

# ============ workflow-level publish gates (dry-run/SKIP/blocked rows) =====
import yaml as _yaml
def _load_if(path, job):
    d = _yaml.safe_load(open(path))
    return d['jobs'][job]['if']
DAILY_IF = _load_if(ROOT / '.github/workflows/daily-maintenance.yml', 'publish')
BUILD_IF = _load_if(ROOT / '.github/workflows/build-chromium.yml', 'publish')
def _ghk(expr, ctx):
    e = expr.replace('&&', ' and ').replace('||', ' or ')
    paths = sorted(ctx, key=len, reverse=True)
    env = {}
    for i, p in enumerate(paths):
        tok = f'V{i}'
        e = e.replace(p, tok)
        env[tok] = ctx[p]
    return bool(eval(e, {'__builtins__': {}}, env))
def _daily_ctx(**over):
    c = {'needs.evaluate.result': 'success',
         'needs.evaluate.outputs.action': 'build',
         'needs.evaluate.outputs.dry': 'false',
         'needs.build.result': 'success',
         'needs.outcome.result': 'success',
         'needs.outcome.outputs.recorded': 'true',
         'needs.build.outputs.deb_sha256': 'a' * 64,
         'needs.outcome.outputs.deb_sha256': 'a' * 64,
         'needs.build.outputs.deb_version': '156.0.8078.47-3',
         'needs.outcome.outputs.deb_version': '156.0.8078.47-3'}
    c.update(over)
    return c
check('[g1] scheduled build success + recorded candidate -> publish gate OPEN',
      _ghk(DAILY_IF, _daily_ctx()))
check('[g2] dry-run -> publish gate CLOSED',
      not _ghk(DAILY_IF, _daily_ctx(**{'needs.evaluate.outputs.dry': 'true'})))
check('[g3] action=skip (identical inputs) -> CLOSED',
      not _ghk(DAILY_IF, _daily_ctx(**{'needs.evaluate.outputs.action': 'skip'})))
check('[g4] candidate NOT recorded (failure/blocked path) -> CLOSED',
      not _ghk(DAILY_IF, _daily_ctx(**{'needs.outcome.outputs.recorded': 'false'})))
check('[g5] build job failed -> CLOSED',
      not _ghk(DAILY_IF, _daily_ctx(**{'needs.build.result': 'failure'})))
check('[g6] outcome failed -> CLOSED',
      not _ghk(DAILY_IF, _daily_ctx(**{'needs.outcome.result': 'failure'})))
check('[g7] ledger sha != build output sha -> CLOSED (metadata must match)',
      not _ghk(DAILY_IF, _daily_ctx(**{'needs.outcome.outputs.deb_sha256': 'b' * 64})))
check('[g8] ledger version != build output version -> CLOSED',
      not _ghk(DAILY_IF, _daily_ctx(**{'needs.build.outputs.deb_version': 'x'})))
def _manual_ctx(**over):
    c = {'needs.build.result': 'success', 'inputs.source': '',
         'needs.build.outputs.deb_sha256': 'a' * 64,
         'needs.build.outputs.deb_version': '156.0.8078.47-3',
         'github.event.inputs.publish': 'true'}
    c.update(over)
    return c
check('[g9] direct manual build success -> build-chromium publish OPEN',
      _ghk(BUILD_IF, _manual_ctx()))
check('[g10] CALLED by maintenance (source=maintenance) -> build-chromium publish CLOSED (defer to ledger-gated job)',
      not _ghk(BUILD_IF, _manual_ctx(**{'inputs.source': 'maintenance'})))
check('[g11] manual publish=false opt-out -> CLOSED',
      not _ghk(BUILD_IF, _manual_ctx(**{'github.event.inputs.publish': 'false'})))
check('[g12] manual empty outputs -> CLOSED',
      not _ghk(BUILD_IF, _manual_ctx(**{'needs.build.outputs.deb_sha256': ''})))

print(f'PUBLISH-TESTS PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
