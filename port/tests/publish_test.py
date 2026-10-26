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

# ============ workflow_run publisher: classify + ledger gate + invariants =
import yaml as _yaml
_PR = _yaml.safe_load(open(ROOT / '.github/workflows/publish-release.yml'))
_STEPS = _PR['jobs']['publish']['steps']
_CLS = [st for st in _STEPS if st.get('id') == 'cls'][0]['run']
def _run_cls(**env_over):
    ghout = tempfile.mktemp(); summ = tempfile.mktemp(); ghenv = tempfile.mktemp()
    for f in (ghout, summ, ghenv): open(f, 'w').close()
    base = {'WF': '', 'RUN_EVENT': 'schedule', 'RUN_ID': '999',
            'RUN_HEAD': 'e' * 40, 'TRIGGER_KIND': 'workflow_run',
            'RECOVERY_RUN_ID': '', 'RECOVERY_SHA': '', 'RECOVERY_ACK': ''}
    base.update(env_over)
    r = subprocess.run(['bash', '-c', _CLS], capture_output=True, text=True,
                       env=dict(os.environ, GITHUB_OUTPUT=ghout,
                                GITHUB_STEP_SUMMARY=summ, GITHUB_ENV=ghenv, **base))
    kv = dict(l.split('=', 1) for l in open(ghout).read().splitlines() if '=' in l)
    for f in (ghout, summ, ghenv):
        try: os.unlink(f)
        except OSError: pass
    return kv, r.returncode
kv, rc = _run_cls(WF='Daily Maintenance')
check('[g1] nightly maintenance run -> source=maintenance (ledger-gated publish)',
      rc == 0 and kv.get('skip') == 'false' and kv.get('source') == 'maintenance'
      and kv.get('artifact') == 'build-999', str(kv))
kv, rc = _run_cls(WF='Build Termux Chromium Seccomp Sandbox Port',
                  RUN_EVENT='workflow_dispatch')
check('[g2] direct manual build success -> source=manual (auto publish)',
      rc == 0 and kv.get('skip') == 'false' and kv.get('source') == 'manual')
kv, rc = _run_cls(WF='Build Termux Chromium Seccomp Sandbox Port')
check('[g3] workflow_run missing inputs must NOT imply consent: defer to artifact gate',
      rc == 0 and kv.get('source') == 'manual' and kv.get('skip') == 'false')
kv, rc = _run_cls(WF='Build Termux Chromium Seccomp Sandbox Port',
                  RUN_EVENT='schedule')
check('[g4] direct build with unexpected source event fails closed', rc != 0)
kv, rc = _run_cls(WF='Some Other Workflow')
check('[g5] unhandled workflow -> no-op skip', rc == 0 and kv.get('skip') == 'true')
kv, rc = _run_cls(WF='Daily Maintenance', RUN_ID='1;rm')
check('[g6] malformed run id -> step fails (fail closed)', rc != 0)
kv, rc = _run_cls(WF='Daily Maintenance', RUN_HEAD='zzz')
check('[g7] malformed head sha -> step fails', rc != 0)

# ---- Artifact-bound manual publish consent + one-time legacy recovery.
_BW = _yaml.safe_load(open(ROOT / '.github/workflows/build-chromium.yml'))
_RECORD = [x for x in _BW['jobs']['build']['steps']
           if x.get('name', '').startswith('Record manual publish intent')][0]['run']
_CONSENT = [x for x in _STEPS
            if x.get('name', '').startswith('Verify manual publish consent')][0]['run']
def _emit_intent(event, requested):
    import tempfile as _tmp
    with _tmp.TemporaryDirectory(prefix='consent-src.') as d:
        env = dict(os.environ, SOURCE_EVENT=event, SOURCE_RUN_ID='999',
                   SOURCE_HEAD_SHA='e'*40, REQUESTED_PUBLISH=requested)
        r = subprocess.run(['bash', '-c', 'set -euo pipefail\\n'+_RECORD],
                           cwd=d, capture_output=True, text=True, env=env)
        f = Path(d) / 'publish-intent.json'
        return r.returncode, json.loads(f.read_text()) if f.exists() else None
rc, doc = _emit_intent('workflow_dispatch', 'true')
check('[c1] manual publish=true produces artifact-bound explicit consent',
      rc==0 and doc and doc['publish'] is True and doc['run_id']=='999')
rc, doc = _emit_intent('workflow_dispatch', 'false')
check('[c2] manual publish=false remains false (no release authorized)',
      rc==0 and doc and doc['publish'] is False)
rc, doc = _emit_intent('workflow_dispatch', '')
check('[c3] missing publish input is false, never default allow',
      rc==0 and doc and doc['publish'] is False)
rc, doc = _emit_intent('workflow_call', 'true')
check('[c4] workflow_call cannot impersonate direct manual release',
      rc==0 and doc and doc['publish'] is False)
rc, doc = _emit_intent('workflow_dispatch', 'ambiguous')
check('[c5] malformed consent input fails closed', rc!=0 and doc is None)
def _check_consent(record):
    import tempfile as _tmp
    with _tmp.TemporaryDirectory(prefix='consent-pub.') as d:
        d=Path(d); art=d/'artifact'; art.mkdir()
        if record is not None: (art/'publish-intent.json').write_text(json.dumps(record))
        (d/'env').touch(); (d/'summary').touch()
        env=dict(os.environ, EXPECTED_RUN_ID='999', EXPECTED_HEAD_SHA='e'*40,
                 GITHUB_ENV=str(d/'env'), GITHUB_STEP_SUMMARY=str(d/'summary'))
        r=subprocess.run(['bash','-c',_CONSENT],cwd=d,capture_output=True,text=True,env=env)
        return r.returncode,(d/'env').read_text(),r.stdout+r.stderr
okdoc={'schema':1,'event':'workflow_dispatch','run_id':'999',
       'head_sha':'e'*40,'publish':True}
rc,env,log=_check_consent(okdoc)
check('[c6] consent=true passes manual publish gate',rc==0 and 'SKIP_REMAIN=true' not in env)
rc,env,log=_check_consent(dict(okdoc,publish=False))
check('[c7] consent=false yields explicit normal no-op',rc==0 and 'SKIP_REMAIN=true' in env)
rc,env,log=_check_consent(None)
check('[c8] legacy missing consent is RED, never auto-published',rc!=0)
for k,bad in (('run_id',dict(okdoc,run_id='1000')),
              ('head_sha',dict(okdoc,head_sha='f'*40)),
              ('schema',dict(okdoc,schema=2)),
              ('publish',dict(okdoc,publish='true'))):
    rc,env,log=_check_consent(bad)
    check(f'[c9] invalid {k} marker refuses publish',rc!=0)
kv,rc=_run_cls(TRIGGER_KIND='workflow_dispatch',RECOVERY_RUN_ID='40254429486',
               RECOVERY_SHA='a'*64,RECOVERY_ACK='PUBLISH-LEGACY-BUILD-40254429486')
check('[c10] legacy recovery requires pinned run, SHA, exact ack',
      rc==0 and kv.get('recovery')=='true' and kv.get('run_id')=='40254429486'
      and kv.get('run_head')=='783efd63eeea89e2999e0408d55ea0de70fbed7c')
for k,opts in (('run',{'RECOVERY_RUN_ID':'123'}),
               ('ack',{'RECOVERY_ACK':'not-authorized'}),
               ('sha',{'RECOVERY_SHA':'abc'})):
    vals={'TRIGGER_KIND':'workflow_dispatch','RECOVERY_RUN_ID':'40254429486',
          'RECOVERY_SHA':'a'*64,'RECOVERY_ACK':'PUBLISH-LEGACY-BUILD-40254429486'}
    vals.update(opts)
    kv,rc=_run_cls(**vals)
    check(f'[c11] legacy recovery malformed {k} refuses',rc!=0)

# ---- ledger lookup (engine CLI; covers defect B: candidates[] scan)
def _lk(state_doc, run_id):
    p = ROOT / '._lk_state.json'; p.write_text(json.dumps(state_doc))
    o = ROOT / '._lk_out.json'
    if o.exists(): o.unlink()
    rc = P.main(['ledger-lookup', '--state', str(p), '--run-id', str(run_id),
                 '--out', str(o)])
    p.unlink()
    rec = json.loads(o.read_text()) if o.exists() else None
    if o.exists(): o.unlink()
    return rc, rec
TSHA_OK = 'd' * 40
def _cand(ci, ver, sha_c, sig_c, **over):
    r = {'ci_run': ci, 'status': 'BUILD_VERIFIED_CANDIDATE', 'deb_version': ver,
         'deb_sha256': sha_c * 64, 'signature': sig_c * 16, 'termux_sha': TSHA_OK}
    r.update(over); return r
A = _cand(101, '156.0.8078.47-3', 'a', '1')
B = _cand(102, '156.0.8078.47-4', 'b', '2')
st_ab = {'last_successful_build': dict(B), 'candidates': [dict(A), dict(B)], 'blocked': {}}
rc, rec = _lk(st_ab, 101)
check('[l1] Run A still publishable when last_successful_build already moved to B (defect B)',
      rc == 0 and rec and rec['deb_sha256'] == 'a' * 64
      and 'candidates[0]' in rec['claim_sources'], f'rc={rc} {rec}')
rc, rec = _lk(st_ab, 102)
check('[l2] Run B (current) found via last+candidates', rc == 0 and rec['deb_version'] == '156.0.8078.47-4')
rc, rec = _lk(st_ab, 999)
check('[l3] unclaimed run id -> code 4 (normal no-op, NEVER fabricate)', rc == 4 and rec is None)
st_dup = {'last_successful_build': dict(B), 'candidates': [dict(A), dict(A), dict(B)], 'blocked': {}}
rc, _ = _lk(st_dup, 101)
check('[l4] duplicate IDENTICAL records -> tolerated (found once)', rc == 0)
st_con = {'last_successful_build': dict(B), 'candidates': [dict(A), dict(A, deb_sha256='f' * 64)], 'blocked': {}}
rc, _ = _lk(st_con, 101)
check('[l5] same run id, contradicting records -> FAIL-CLOSED rc1 (never silent pick)', rc == 1)
st_bad = {'last_successful_build': dict(A, status='BUILD_FAILED'), 'candidates': [], 'blocked': {}}
rc, _ = _lk(st_bad, 101)
check('[l6] claim with non-VERIFIED status -> refused rc1 (CI-failure records never pass)', rc == 1)
st_mal = {'last_successful_build': dict(A, signature='seed-manual'), 'candidates': [], 'blocked': {}}
rc, _ = _lk(st_mal, 101)
check('[l7] claim with malformed signature -> refused rc1 (not downgraded to no-op)', rc == 1)
st_blk = json.loads(json.dumps(st_ab)); st_blk['blocked'] = {'1' * 16: {'issue': 2, 'classification': 'port'}}
rc, _ = _lk(st_blk, 101)
check('[l8] claim whose signature is currently blocked -> refused rc1 (blocked never auto-publishes)', rc == 1)
st_noval = {'last_successful_build': dict(A, validated=False), 'candidates': [], 'blocked': {}}
rc, _ = _lk(st_noval, 101)
check('[l9] validated flag NOT required for CI-candidate publishing', rc == 0)
st_nt = {'last_successful_build': {k: v for k, v in A.items() if k != 'termux_sha'}, 'candidates': [], 'blocked': {}}
rc, _ = _lk(st_nt, 101)
check('[l10] claim without 40hex termux_sha -> refused rc1', rc == 1)
rc, _ = _lk({}, 101)
check('[l11] empty state -> code 4 no-claim (no crash)', rc == 4)

# ---- ledger-vs-artifact cross-check (derive step; closes defect-B loop:
# a candidates[] hit must still byte-match the audited run's artifact)
_der=[st for st in _STEPS if st.get('name','').startswith('Integrity verification')][0]['run']
_der_head=_der[:_der.index('python3 port/publish_release.py verify')]
w = Path(tempfile.mkdtemp(prefix='dmatch.'))
adir, deb = make_artifact(w)
def _derive_body():
    d=_der.split('python3 port/publish_release.py verify')[0]
    return d
def _derive_run(exp_ver,exp_sha,srcdir):
    env=dict(os.environ,GITHUB_OUTPUT=str(srcdir/'o'),GITHUB_ENV=str(srcdir/'e'),
             EXPECT_VERSION=exp_ver,EXPECT_SHA=exp_sha,EXPECT_TERMUX='',EXPECT_SIG='',EXPECT_TS='')
    (srcdir/'o').write_text(''); (srcdir/'e').write_text('')
    os.environ['PWD']=str(srcdir)
    cwd=os.getcwd(); os.chdir(srcdir)
    r=subprocess.run(['bash','-c','set -euo pipefail\n'+_derive_body()],capture_output=True,text=True,env=env)
    os.chdir(cwd)
    return r.returncode,(r.stdout+r.stderr)
wsub=w/'sub'; (wsub/'artifact').mkdir(parents=True)
import shutil as _sh
_sh.copy2(deb, wsub/'artifact'/deb.name)
(wsub/'artifact'/'termux-pin.txt').write_text('d'*40+'\n')
rc,out=_derive_run(VERSION, P.sha256_file(deb), wsub)
check('[x1] ledger-matching artifact passes the derive cross-check (maintenance path)', rc==0 and f'deb_version={VERSION}' in open(wsub/'o').read(), f'rc={rc} {out[-160:]}')
rc,out=_derive_run(VERSION, 'f'*64, wsub)
check('[x2] ledger SHA != artifact SHA -> refuse (never publish a run whose bytes disagree with its record)', rc!=0 and 'refusing' in out.lower())
rc,out=_derive_run('9.9.9.9-1', P.sha256_file(deb), wsub)
check('[x3] ledger VERSION != artifact VERSION -> refuse', rc!=0)

# ---- e-series: EXECUTE STEP bash exit-code fidelity (defect A)
_exec = [st for st in _STEPS if st.get('name', '').startswith('Execute (draft')][0]['run']
def _run_exec(rc_inject, legacy_negated=False):
    stub = str(ROOT / 'port/tests/fixtures/rc_stub.py')
    body = _exec.replace("${{ github.repository }}", 'r/p').replace('${{ github.run_id }}', '999')
    body = body.replace("python3 port/publish_release.py execute",
                        f"python3 {stub}")
    if legacy_negated:
        # reconstruct the PRE-fix shape to PROVE it masked failures
        NL = chr(10)
        body = ('set -euo pipefail' + NL + 'if ! python3 ' + stub
                + ' --plan x --out ./_exec_result.json; then rc=$?; exit "$rc"; fi' + NL)
    summ = tempfile.mktemp(); open(summ, 'w').close()
    argf = tempfile.mktemp()
    env = dict(os.environ, STUB_RC=str(rc_inject), STUB_ARGS=argf,
               STUB_OUT_FILE='._exec_result.json', GITHUB_STEP_SUMMARY=summ)
    for junk in ('._exec_result.json',):
        if os.path.exists(junk): os.unlink(junk)
    r = subprocess.run(['bash', '-c', body], capture_output=True, text=True, env=env)
    called = os.path.exists(argf) and 'ledger' not in open(argf).read()
    for f in (summ, argf):
        try: os.unlink(f)
        except OSError: pass
    if os.path.exists('._exec_result.json'): os.unlink('._exec_result.json')
    return r.returncode, (r.stdout + r.stderr), called
rc_out, out, called = _run_exec(0)
check('[e1] publisher rc0 -> step SUCCESS (positive-if, publisher invoked)',
      rc_out == 0 and called and 'Pre-release publisher completed' in out, f'rc={rc_out}')
for _rc in (1, 2, 3):
    rc_out, out, called = _run_exec(_rc)
    check(f'[e2-e4] publisher rc{_rc} -> step FAILURE with EXACT code (defect A fix)',
          rc_out == _rc and called and '::error::' in out and f'rc={_rc}' in out,
          f'observed rc={rc_out}')
rc_out, out, _ = _run_exec(3, legacy_negated=True)
check('[e5] LEGACY `if ! cmd` shape PROVEN to mask rc3 as success (regression anchor)',
      rc_out == 0, f'legacy form returned {rc_out} (must be 0 to document the defect)')
rc_out, out, _ = _run_exec(2)
check('[e6] failed publish leaves NO success summary, points to rerun-only recovery',
      rc_out == 2 and 'Pre-release publisher completed' not in out
      and 'rerun' in out.lower() and 'never rebuild' in out.lower())

# ---- instance invariants (startup_failure bisection learnings, revert PR #8)
_WFS = {'daily-maintenance.yml': _yaml.safe_load(open(ROOT / '.github/workflows/daily-maintenance.yml')),
        'build-chromium.yml': _yaml.safe_load(open(ROOT / '.github/workflows/build-chromium.yml')),
        'publish-release.yml': _PR}
for _n, _d in _WFS.items():
    _bad = [j for j, sp in _d['jobs'].items() if 'uses' in sp and 'permissions' in sp]
    check(f'[g13] {_n}: no caller-side permissions on uses: jobs (instance invariant)',
          not _bad, str(_bad))
_all_src = ''.join(open(ROOT / ('.github/workflows/' + n)).read() for n in _WFS)
check('[g14] no actions:write anywhere; contents:write ONLY at publish-release top level',
      'actions: write' not in _all_src.replace('actions: read', '')
      and _PR['permissions'] == {'contents': 'write', 'actions': 'read'}
      and all('permissions' not in sp for sp in _PR['jobs'].values())
      and _WFS['daily-maintenance.yml']['permissions'] == {'contents': 'read'})
check('[g15] workflow_run restricted to the two build workflows, completed-only, default-branch-only',
      set(_PR[True if True in _PR else 'on']['workflow_run']['workflows'])
      == {'Daily Maintenance', 'Build Termux Chromium Seccomp Sandbox Port'}
      and _PR[True if True in _PR else 'on']['workflow_run']['types'] == ['completed']
      and 'github.event.workflow_run.conclusion == \'success\'' in _PR['jobs']['publish']['if']
      and "head_branch == github.event.repository.default_branch" in _PR['jobs']['publish']['if'])
_src = open(ROOT / '.github/workflows/publish-release.yml').read()
check('[g16] publisher pinned to default-branch code (supply-chain) + artifact by audited run-id',
      'ref: ${{ github.event.repository.default_branch }}' in _src
      and 'run-id: ${{ steps.cls.outputs.run_id }}' in _src
      and 'github-token: ${{ github.token }}' in _src)
check('[g17] direct manual publish opt-out enforced from source artifact, not workflow_run.inputs',
      'workflow_run.inputs.publish' not in _src.replace('# The workflow_run.inputs.publish field is absent in real','')
      and 'publish-intent.json' in _src and 'publish-intent.json' in open(ROOT/'.github/workflows/build-chromium.yml').read()
      and _PR['permissions'].get('actions') == 'read')

print(f'PUBLISH-TESTS PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
