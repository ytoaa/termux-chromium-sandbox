#!/usr/bin/env python3
"""Round 16 Stage C — REQUIRED simulation matrix for signature schema v2.

Runs the REAL engine against REAL repo inputs + the REAL audited migration
file (maintenance/signature-migrations.json) + a state fixture cloned from
the actual maintenance-state rev-2 baseline. Thirteen scenarios from the
safety-hotfix spec; SKIP may only ever come from re-proven equivalence,
never from weakening change detection.
"""
import hashlib, json, os, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
os.chdir(ROOT)
sys.path.insert(0, os.path.join(ROOT, 'port'))
import maintenance as M

PASS = fail = 0
def check(name, cond, extra=''):
    global PASS, fail
    if cond: PASS += 1; print(f'PASS  [{name}]')
    else: fail += 1; print(f'FAIL  [{name}] {extra}')

RAW = {f: hashlib.sha256(open(f, 'rb').read()).hexdigest()[:40]
       for f in M.PORT_RAW_FILES}
TOML = open('port/port.toml', encoding='utf-8').read()
def ph(raw=None, toml=None):
    return M.port_inputs_hash(raw or RAW, toml if toml is not None else TOML)

MIGS, ERR = M.load_migrations('maintenance/signature-migrations.json')
check('[sim0] real migration file loads (schema valid)', ERR is None and len(MIGS) == 1,
      str(ERR))

REV2_SIG = 'ad5b0fdb8c7a9777'
RECIPE, HOST, VER = '7c5c20eb1182e197', '34b799517be2a99a', '156.0.8078.47'
def state(blocked=None, last_sig=REV2_SIG):
    return {'validated': {'upstream_version': VER, 'deb_version': VER + '-2'},
            'last_successful_build': {'upstream_version': VER, 'revision': 2,
                                      'package_version': VER + '-2',
                                      'signature': last_sig, 'status': 'BUILD_VERIFIED_CANDIDATE',
                                      'validated': True, 'ci_run': 40104615699,
                                      'deb_sha256': 'cf2cb2a8' + '0' * 56},
            'candidates': [], 'blocked': blocked or {}, 'history': []}
def probes(version=VER, recipe_sha=RECIPE, host_sha=HOST, errs=None):
    return {'official_stable': version, 'termux_head': 'd' * 40,
            'pins_verified': not errs, 'fetch_errors': errs or [],
            'recipe': {'version': version, 'host_version': version,
                       'recipe_sha': recipe_sha, 'host_sha': host_sha,
                       'revision': 2, 'distro_version': version}}

def run(**kw):
    p = probes(**{k: kw[k] for k in ('version', 'recipe_sha', 'host_sha', 'errs') if k in kw})
    return M.decide(state(kw.get('blocked')), p, kw.get('port_sha', ph()),
                    't', kw.get('issues', []), None, MIGS)

# [sim1] fully identical build inputs -> SKIP (via re-proven v1->v2 equivalence)
pl = run()
check('[sim1] identical build inputs -> skip (no build)',
      pl['action'] == 'skip' and pl['reason'] == 'identical-inputs-already-built', pl['reason'])
# [sim2] only a validated-promotion DATE/record edit -> SKIP
t2 = TOML.replace('last_validated_promoted = "2026-10-25 manual human-approved promotion (Phase B CI + C/C.1/C.2 device gates)"',
                  'last_validated_promoted = "2027-01-01 some future human promotion"')
check('[sim2] promotion-record-only edit -> same hash -> skip',
      M.port_toml_semantic_sha(t2) == M.port_toml_semantic_sha(TOML)
      and run(port_sha=ph(toml=t2))['action'] == 'skip')
# [sim3] only device-gate HISTORY edit -> SKIP
t3 = TOML.replace('device_gate_history = [',
                  'device_gate_history = [\n  "synthetic future gate record for simulation",')
check('[sim3] device_gate_history-only edit -> same hash -> skip',
      M.port_toml_semantic_sha(t3) != '' and
      M.port_toml_semantic_sha(t3) == M.port_toml_semantic_sha(TOML)
      and run(port_sha=ph(toml=t3))['action'] == 'skip')
# [sim4] docs-only commit (no port input touched) -> SKIP
check('[sim4] docs-only change -> skip (inputs untouched)',
      run()['action'] == 'skip')
# [sim5] BPF policy contract edit -> BUILD (revision 3 detection intact)
t5 = TOML.replace('require_bpf_policy = true', 'require_bpf_policy = false')
pl = run(port_sha=ph(toml=t5))
check('[sim5] BPF policy contract edit -> BUILD rev3',
      pl['action'] == 'build' and pl['target']['revision'] == 3, pl['reason'])
# [sim6] patch-transformer code byte edit -> BUILD
r6 = dict(RAW); r6['port/chromium_sandbox_port.py'] = hashlib.sha256(b'tampered').hexdigest()[:40]
pl = run(port_sha=ph(raw=r6))
check('[sim6] chromium_sandbox_port.py byte edit -> BUILD', pl['action'] == 'build', pl['reason'])
# [sim7] gnp shim edit -> BUILD
r7 = dict(RAW); r7['port/gnp_shim.c'] = hashlib.sha256(b'x').hexdigest()[:40]
pl = run(port_sha=ph(raw=r7))
check('[sim7] gnp_shim.c edit -> BUILD', pl['action'] == 'build', pl['reason'])
# [sim8] build recipe change -> BUILD
pl = run(recipe_sha='aaaaaaaaaaaaaaaa')
check('[sim8] recipe change -> BUILD (equivalence invalidated by pin mismatch)',
      pl['action'] == 'build', pl['reason'])
# [sim9] Termux pinned host-tools input change -> BUILD
pl = run(host_sha='bbbbbbbbbbbbbbbb')
check('[sim9] host-tools pin change -> BUILD', pl['action'] == 'build', pl['reason'])
# [sim10] new Chromium upstream -> BUILD (rev1 plain)
pl = run(version='157.0.7277.99', recipe_sha='cccccccccccccccc', host_sha='dddddddddddddddd')
check('[sim10] new upstream -> BUILD rev1', pl['action'] == 'build'
      and pl['reason'] == 'new-upstream-version' and pl['target']['revision'] == 1, pl['reason'])
# [sim11] existing blocked signature -> stays BLOCKED (skip, no auto-retry, no new issue)
# (last-success is NOT equivalent here so the block gate is the deciding path)
cur_sig = M.build_signature(VER, RECIPE, HOST, ph())
st = state(blocked={cur_sig: {'classification': 'port', 'issue': 2,
                              'retry_approved': False}},
           last_sig='ffffffffffffffff')
pl = M.decide(st, probes(), ph(), 't', [], None, MIGS)
check('[sim11] blocked current sig -> skip blocked-dedup (no retry, no issue)',
      pl['action'] == 'skip' and pl['reason'] == 'blocked-dedup', pl['reason'])
st2, ops = M.apply_result(state({'x': 1}), pl, {'success': False}, 't')
check('[sim11b] blocked skip creates nothing', not ops['create_issues'] and not ops['comment_issues'])
# [sim12] input probe failure -> FAIL-CLOSED; missing port input -> CLI aborts
pl = run(errs=['termux recipe: HTTP 500'])
check('[sim12a] probe fetch error -> fail-closed skip',
      pl['action'] == 'skip' and pl['reason'] == 'fetch-error-fail-closed', pl['reason'])
tmp = tempfile.mkdtemp()
for f in list(M.PORT_RAW_FILES) + ['port/port.toml']:
    d = os.path.join(tmp, os.path.dirname(f)); os.makedirs(d, exist_ok=True)
    shutil.copy(f, os.path.join(tmp, f))
os.remove(os.path.join(tmp, 'port/gnp_shim.c'))
check('[sim12b] missing raw input -> CLI rc=1 (no silent signature)',
      M.main(['port-input-hash', '--root', tmp]) == 1)
open(os.path.join(tmp, 'port/gnp_shim.c'), 'w').write('int main(){}')
open(os.path.join(tmp, 'port/port.toml'), 'w').write('[[broken\n')
check('[sim12c] malformed port.toml -> CLI rc=1 (fail closed)',
      M.main(['port-input-hash', '--root', tmp]) == 1)
shutil.rmtree(tmp)
# [sim13] unclear migration (pinned hash stale) -> NO auto-execution of SKIP;
#         malformed migration JSON -> run aborts (report, do not act)
bad = [dict(MIGS[0], port_inputs_hash_v2='0000000000000000')]
pl = M.decide(state(), probes(), ph(), 't', [], None, bad)
check('[sim13a] stale/mismatched migration pin -> equivalence denied (no false skip)',
      pl['action'] == 'build', pl['reason'])
with open('._badmig.json', 'w') as f:
    f.write('{"migrations": [{"id": x}')
with open('._probes_ok.json', 'w') as f:
    json.dump(probes(), f)
with open('._state_ok.json', 'w') as f:
    json.dump(state(), f)
rc = M.main(['decide', '--state', '._state_ok.json', '--probes', '._probes_ok.json',
             '--out', '._out.json', '--port-sha', ph(), '--migrations', '._badmig.json'])
os.unlink('._badmig.json'); os.unlink('._probes_ok.json'); os.unlink('._state_ok.json')
check('[sim13b] malformed migration JSON -> abort rc=1, no plan emitted',
      rc == 1 and not os.path.exists('._out.json'))
print(f'MAINTENANCE-SIGNATURE PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
