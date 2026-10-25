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

# --- Round 15.4: boundary & operational scenarios (file-based) ---
VAL0 = base()['validated']

def validated_intact(st):
    return st.get('validated') == VAL0

# [iF1] approved retry FAILS + state-push LOST + label consumed on GitHub
#       -> next run cannot re-use the approval (the 15.4 boundary fix)
stf = base()
sigf = M.build_signature('157.0.100.5','R2','H2','P1')
stf['blocked'][sigf] = {'classification':'port','issue':21,'retry_approved':False,
    'inputs':{'recipe_sha':'R2','host_sha':'H2','port_sha':'P1'}}
title_f = M.issue_title({'upstream_version':'157.0.100.5','revision':1,'signature':sigf},'gate')
iss_f = [{'number':21,'title':title_f,'labels':['auto-build-blocked','retry-approved']}]
pf1 = decide(stf, iss_f)
check('[iF1a] approval authorizes attempt', pf1['action']=='build' and pf1.get('approval',{}).get('issue')==21)
stf2, _ = apply(stf, {'success':False,'stage':'gate','log_tail':'still broken',
                      'failure_jobs':'gate','ci_url':'https://x/7','ci_run':7})
# SIMULATE STATE-PUSH FAILURE: outcome state2 never lands on the branch;
# but the label WAS removed on GitHub (workflow's consume step).
iss_after = [{'number':21,'title':title_f,'labels':['auto-build-blocked']}]  # label gone
pf2 = decide(stf, iss_after)   # OLD state again (push lost!)
check('[iF1b] push-lost + label-consumed -> NO re-attempt', pf2['action']=='skip'
      and pf2['reason']=='blocked-dedup', pf2['reason'])
# and BOTH failing (label still there, push lost) = documented bounded case:
pf2b = decide(stf, iss_f)
check('[iF1c] label-still-present re-attempt is the only bounded fallback',
      pf2b['action']=='build' and pf2b.get('approval',{}).get('issue')==21)

# [iF2] infra flake sequence via files: fail1(no issue)->retry allowed->fail2 block+issue
sti = base()
pi1 = decide(sti, [])
sti2, opi1 = apply(sti, {'success':False,'stage':'build','log_tail':'502 from mirror',
                         'failure_jobs':'build','ci_url':'https://x/1','ci_run':1})
check('[iF2a] infra#1 no issue', len(opi1['create_issues'])==0)
pi2 = decide(sti2, [])
check('[iF2b] retry runs', pi2['action']=='build')
sti3, opi2 = apply(sti2, {'success':False,'stage':'build','log_tail':'502 again',
                          'failure_jobs':'build','ci_url':'https://x/2','ci_run':2})
check('[iF2c] infra#2 blocks+issue', len(opi2['create_issues'])==1 and list(sti3['blocked'].values())[0]['infra_failures']==2)
pi3 = decide(sti3, [])
check('[iF2d] then permanently skipped', pi3['action']=='skip' and pi3['reason']=='blocked-dedup')

# [iF3] same version + port-input change -> revision build via CLI
stg = json.loads(json.dumps(base()))
sg = M.build_signature('156.0.8078.47','R1','H1','P0')
stg['last_successful_build']['signature']=sg
stg['last_successful_build']['termux_ref']=T40
def probes_r(v='156.0.8078.47', rs='R1', hs='H1'):
    return {'official_stable':v,'termux_head':T40,'pins_verified':True,'fetch_errors':[],
            'recipe':{'version':v,'host_version':v,'recipe_sha':rs,'host_sha':hs,'revision':0,'distro_version':v}}
W('state.json',stg); W('probes.json',probes_r()); W('issues.json',[]); W('running.json',None)
cli('decide','--state','state.json','--probes','probes.json','--out','plan.json',
    '--issues','issues.json','--running','running.json','--port-sha','P9','--now','T')
pg=R('plan.json')
check('[iF3] port-change -> revision 2 via files', pg['action']=='build' and pg['target']['package_version']=='156.0.8078.47-2')

# [iF4] identical inputs -> skip (no rebuild) via files
W('state.json',stg); W('probes.json',probes_r()); W('issues.json',[]); W('running.json',None)
cli('decide','--state','state.json','--probes','probes.json','--out','plan.json',
    '--issues','issues.json','--running','running.json','--port-sha','P0','--now','T')
check('[iF4] identical inputs skip', R('plan.json')['action']=='skip')

# [iF5] deb_version mismatch -> verify block via files
pv = decide(base(), [])
st5f, ops5f = apply(base(), {'success':True,'stage':'ok','deb_sha256':'1'*64,
    'deb_version':'9.9.9.9','termux_sha':T40,'ci_url':'https://x/1','ci_run':1,'artifact':'build-1'})
check('[iF5] wrong deb_version never a candidate',
      not st5f['candidates'] and list(st5f['blocked'].values())[0]['stage']=='verify')

# [iF6] issue created then state lost -> next run creates NO duplicate
st6 = base()
p6 = decide(st6, [])
st6b, ops6 = apply(st6, {'success':False,'stage':'gate','log_tail':'boom','failure_jobs':'gate',
                         'ci_url':'https://x/1','ci_run':1})
title6 = ops6['create_issues'][0]['title']
# issue appears on GitHub, state push lost -> next decide sees OLD state + open issue
p6c = decide(st6, [{'number':31,'title':title6,'labels':['auto-build-blocked']}])
st6c, ops6c = apply(st6, {'success':False,'stage':'skipped-anomaly','log_tail':'relink',
                          'failure_jobs':'','ci_url':'','ci_run':0})
check('[iF6] no duplicate issue after lost push', p6c['action']=='skip'
      and p6c['reason']=='open-issue-exists' and len(ops6c['create_issues'])==0)

check('[iF7] validated block NEVER mutated across all scenarios',
      validated_intact(sti3) and validated_intact(st5f) and validated_intact(st6c))

print(f'MAINTENANCE-INTEGRATION PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
