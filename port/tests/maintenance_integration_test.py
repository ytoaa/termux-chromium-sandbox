#!/usr/bin/env python3
"""Round 15.3 integration simulation: identical dataflow to Actions jobs —
evaluate writes state.json/plan.json FILES; outcome RE-READS them from disk
(original state, never decide's mutated memory) plus result.json; apply
writes state2.json/ops.json; the NEXT day's decide re-reads state2.json.
All transitions go through the real CLI (subprocess), no in-memory reuse."""
import json, os, subprocess, sys, tempfile
ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)
import maintenance as M

PASS = fail = 0
def check(name, cond, extra=''):
    global PASS, fail
    if cond: PASS += 1; print(f'PASS  [{name}]')
    else: fail += 1; print(f'FAIL  [{name}] {extra}')

T40 = 'ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12'
TMP = tempfile.mkdtemp(prefix='r153-')
def W(n, o): open(os.path.join(TMP, n), 'w').write(json.dumps(o))
def R(n): return json.loads(open(os.path.join(TMP, n)).read())
def cli(*a):
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'maintenance.py')] + list(a),
                       capture_output=True, text=True, cwd=TMP)
    assert r.returncode == 0, r.stderr
    return r.stdout

def probes(v='157.0.100.5', rs='R2', hs='H2'):
    return {'official_stable': v, 'termux_head': T40, 'pins_verified': True,
            'fetch_errors': [], 'recipe': {'version': v, 'host_version': v,
            'recipe_sha': rs, 'host_sha': hs, 'revision': 0, 'distro_version': v}}

def base():
    return {'validated': {'upstream_version': '156.0.8078.47'},
            'last_successful_build': {'upstream_version': '156.0.8078.47',
              'revision': 1, 'package_version': '156.0.8078.47',
              'termux_ref': T40, 'port_sha': 'P0', 'signature': 'seed-manual',
              'deb_sha256': '2'*64, 'deb_version': '156.0.8078.47',
              'ci_run': 31, 'ci_url': 'https://x/31', 'artifact': 'build-31',
              'status': 'BUILD_VERIFIED_CANDIDATE', 'validated': True},
            'candidates': [], 'blocked': {}, 'history': []}

def decide(state, iss, running=None, approve=False, port='P1'):
    W('state.json', state); W('probes.json', probes())
    W('issues.json', iss)
    W('running.json', running if running is not None else None)
    a = ['decide', '--state', 'state.json', '--probes', 'probes.json',
         '--out', 'plan.json', '--issues', 'issues.json',
         '--running', 'running.json', '--port-sha', port, '--now', 'T1']
    if approve: a.append('--approve-retry')
    cli(*a)
    return R('plan.json')            # reloaded from DISK like the job does

def apply(state_on_disk, result):
    W('result.json', result)
    cli('apply', '--state', 'state.json', '--plan', 'plan.json',
        '--result', 'result.json', '--out', 'state2.json',
        '--issues-out', 'ops.json')
    return R('state2.json'), R('ops.json')   # both reloaded from disk

def sig(): return M.build_signature('157.0.100.5', 'R2', 'H2', 'P1')

# --- scenario A: approved retry consumed ACROSS serialized days ---
st = base()
t1 = M.issue_title({'upstream_version':'157.0.100.5','revision':1,'signature':sig()}, 'gate')
st['blocked'][sig()] = {'classification':'port','issue':11,'retry_approved':False,
    'inputs':{'recipe_sha':'R2','host_sha':'H2','port_sha':'P1'}}
iss = [{'number':11,'title':t1,'labels':['auto-build-blocked','retry-approved']}]
p1 = decide(st, iss)
check('[iA1] day1 approval grants build (plan on disk carries origin)',
      p1['action']=='build' and p1.get('approval',{}).get('issue')==11)
st2, ops2 = apply(st, {'success':False,'stage':'gate',
    'log_tail':'PORT ERROR still','failure_jobs':'gate',
    'ci_url':'https://x/2','ci_run':2})
ent = st2['blocked'][sig()]
check('[iA2] apply consumed approval from ORIGINAL state + serialized plan',
      ent['retry_approved'] is False and 11 in (ent.get('approval_consumed_issues') or []))
check('[iA3] failure kept issue link, no duplicate', ent.get('issue')==11 and len(ops2['create_issues'])==0 and len(ops2['comment_issues'])==1)
p2 = decide(st2, iss)
check('[iA4] day3 blocked despite surviving label', p2['action']=='skip' and p2['reason']=='blocked-dedup', p2['reason'])

# --- scenario B: state-push loss -> relink path, ZERO builds ---
st3 = base()                      # blocked entry lost (push failed)
p3 = decide(st3, [{'number':11,'title':t1,'labels':['auto-build-blocked']}])
check('[iB1] durable skip + relink plan (no build)', p3['action']=='skip' and p3['reason']=='open-issue-exists' and p3.get('relink',{}).get('issue')==11)
st4, ops4 = apply(st3, {'success':False,'stage':'skipped-anomaly','log_tail':'relink run',
                        'failure_jobs':'','ci_url':'https://x/3','ci_run':3})
check('[iB2] relink persisted to state (issue 11 attached)', st4['blocked'].get(sig(),{}).get('issue')==11)
check('[iB3] relink run creates NO issues and NO candidates',
      len(ops4['create_issues'])==0 and not st4['candidates'])

# --- scenario C: failed job names appear in created issue body ---
st5 = base()
p5 = decide(st5, [])
check('[iC0] new version decides build', p5['action']=='build')
st6, ops6 = apply(st5, {'success':False,'stage':'build',
    'log_tail':'linker exploded','failure_jobs':'build,build (call)',
    'ci_url':'https://x/5','ci_run':5})
body = ops6['create_issues'][0]['body'] if ops6['create_issues'] else ''
check('[iC1] failure_jobs in issue body', 'Failed jobs:' in body and 'build,build (call)' in body)

# --- scenario D: success with FOREIGN termux sha never becomes candidate ---
st7 = base(); p7 = decide(st7, [])
st8, ops8 = apply(st7, {'success':True,'stage':'ok','deb_sha256':'9'*64,
    'deb_version':'157.0.100.5','termux_sha':'0'*40,
    'ci_url':'https://x/9','ci_run':9,'artifact':'build-9'})
check('[iD1] foreign termux_sha -> verify block, no candidate',
      not st8['candidates'] and list(st8['blocked'].values())[0]['stage']=='verify'
      and len(ops8['create_issues'])==1)
st9, ops9 = apply(st7, {'success':True,'stage':'ok','deb_sha256':'9'*64,
    'deb_version':'157.0.100.5','termux_sha':T40,
    'ci_url':'https://x/9','ci_run':9,'artifact':'build-9'})
check('[iD2] matching sha -> candidate full + artifact_verified flag',
      st9['candidates'][-1]['termux_sha']==T40 and st9['candidates'][-1]['artifact_verified'] is False
      and st9['last_successful_build']['upstream_version']=='157.0.100.5')

# --- scenario E: busy/dry regression ---
pE = decide(base(), [], running={'signature':'RUNNING-ANY'})
check('[iE1] busy skip regression', pE['action']=='skip' and pE['reason']=='build-workflow-busy')
pE2 = decide(base(), [{'error':True}])
check('[iE2] issues-api fail-closed regression', pE2['action']=='skip' and pE2['reason']=='issues-api-error-fail-closed')

print(f'MAINTENANCE-INTEGRATION PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
