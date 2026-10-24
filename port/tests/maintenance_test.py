#!/usr/bin/env python3
"""Round 15 offline scenario tests for the maintenance engine (mocked)."""
import json, os, sys, copy, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import maintenance as M

PASS=fail=0
def check(name, cond, extra=''):
    global PASS, fail
    if cond: PASS+=1; print(f'PASS  [{name}]')
    else: fail+=1; print(f'FAIL  [{name}] {extra}')

def base_state():
    return {
      'validated': {'upstream_version':'156.0.8078.47','port_sha':'403274f','deb_sha256':'29c4080d','ci_run':39976822670},
      'last_successful_build': {'upstream_version':'156.0.8078.47','revision':1,'package_version':'156.0.8078.47-1',
        'termux_ref':'64e02760','port_sha':'PORT-A','signature':'SIG-LAST','deb_sha256':'29c4080d','ci_run':39976822670,
        'status':'BUILD_VERIFIED_CANDIDATE','validated':True},
      'candidates': [], 'blocked': {}, 'history': []}

def probes(version='156.0.8078.47', recipe_sha='R1', host_sha='H1', head='64e02760', errs=None, cksum=True):
    return {'official_stable':version,'termux_head':head,'checksum_ok':cksum,'fetch_errors':errs or [],
            'recipe':{'version':version,'host_version':version,'recipe_sha':recipe_sha,'host_sha':host_sha,'revision':0,'distro_version':version}}

SIG = M.build_signature('156.0.8078.47','R1','H1','PORT-A')

# [1] no new version, identical inputs -> skip
p=probes(); s=base_state(); s['last_successful_build']['signature']=SIG
pl=M.decide(s,p,'PORT-A','t',[],None)
check('[m1] identical-inputs skip', pl['action']=='skip' and pl['reason']=='identical-inputs-already-built', pl['reason'])

# [2] new version -> build
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[m2] new-upstream build', pl['action']=='build' and pl['target']['upstream_version']=='157.0.100.5' and pl['target']['revision']==1 and pl['target']['package_version']=='157.0.100.5-1', json.dumps(pl)[:120])

# [3] same successful version (candidate) -> no rebuild
st=copy.deepcopy(s); st['candidates']=[{'upstream_version':'157.0.100.5','status':'BUILD_VERIFIED_CANDIDATE','signature':M.build_signature('157.0.100.5','R2','H2','PORT-A')}]
pl=M.decide(st,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[m3] candidate-already-built skip', pl['action']=='skip' and pl['reason']=='candidate-already-built', pl['reason'])

# [4] same chromium, port changed -> revision build
pl=M.decide(s,probes(),'PORT-B','t',[],None)
check('[m4] revision build', pl['action']=='build' and pl['target']['revision']==2 and pl['target']['package_version']=='156.0.8078.47-2', pl['reason'])

# [5] patch failure -> blocked + issue creation
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
st2,ops=M.apply_result(s,pl,{'success':False,'stage':'gate','log_tail':'PORT ERROR: R9a anchor not found','ci_url':'u'},'t')
check('[5] gate-failure blocked+issue', len(ops['create_issues'])==1 and ops['create_issues'][0]['labels'][0]=='auto-build-blocked' and 'sig' in ops['create_issues'][0]['title'] and st2['blocked'], json.dumps(ops)[:150])
check('[5b] classification=port', list(st2['blocked'].values())[0]['classification']=='port')

# [6] existing failure issue -> no duplicate, blocked-dedup, no infinite retry
st2['blocked'][list(st2['blocked'])[0]]['issue']=42
pl2=M.decide(st2,probes('157.0.100.5','R2','H2'),'PORT-A','t',[{'number':42,'title':ops['create_issues'][0]['title'],'labels':['auto-build-blocked']}],None)
check('[6a] blocked-dedup skip', pl2['action']=='skip' and pl2['reason']=='blocked-dedup', pl2['reason'])
st3,ops2=M.apply_result(st2,pl2,{'success':False,'stage':'gate','log_tail':'PORT ERROR again'},'t')
check('[6b] skip-plan no new issue', len(ops2['create_issues'])==0)
# repeated real failure with same sig -> comment not new issue
plf=M.decide(copy.deepcopy(s),probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
stf,opsf=M.apply_result(s,plf,{'success':False,'stage':'gate','log_tail':'PORT ERROR first'},'t')
stf['blocked'][list(stf['blocked'])[0]]['issue']=7
stf2,opsf2=M.apply_result(stf,plf,{'success':False,'stage':'gate','log_tail':'PORT ERROR second'},'t')
check('[6c] second failure -> comment only', len(opsf2['create_issues'])==0 and len(opsf2['comment_issues'])==1)

# [6d] closing issue alone must not retry: decide consults state.blocked regardless of issues list
pl3=M.decide(stf2,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)  # issues=[] as if closed
check('[6d] closed-issue-still-blocked', pl3['action']=='skip' and pl3['reason']=='blocked-dedup', pl3['reason'])
# retry_approved opens exactly one attempt
st4=copy.deepcopy(stf2)
for v in st4['blocked'].values(): v['retry_approved']=True
pl4=M.decide(st4,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[6e] retry-approved builds once', pl4['action']=='build', pl4['reason'])

# [7] source verification failed -> fail-closed
pl=M.decide(s,probes(cksum=False),'PORT-A','t',[],None)
check('[m7] checksum-fail-closed', pl['action']=='skip' and pl['reason']=='source-verification-failed', pl['reason'])

# [8] success -> candidate recorded, validated untouched
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
st5,ops5=M.apply_result(s,pl,{'success':True,'stage':'ok','deb_sha256':'DEB2','ci_url':'u','ci_run':99,'artifact':'build-99'},'t')
check('[8a] candidate recorded', st5['candidates'][-1]['deb_sha256']=='DEB2' and st5['candidates'][-1]['status']=='BUILD_VERIFIED_CANDIDATE')
check('[8b] last_successful updated', st5['last_successful_build']['upstream_version']=='157.0.100.5')
check('[8c] validated untouched', st5['validated']==s['validated'])
check('[8d] never claims validated', st5['candidates'][-1]['validated'] is False)

# [9] upstream behind -> skip
st6=copy.deepcopy(s); st6['last_successful_build']['upstream_version']='158.0.0.0'
pl=M.decide(st6,probes(),'PORT-A','t',[],None)
check('[m9] behind skip', pl['action']=='skip' and pl['reason']=='upstream-behind-last-success', pl['reason'])

# [10] fetch/API errors -> fail-closed; running -> skip
pl=M.decide(s,probes(errs=['termux recipe: URLError']),'PORT-A','t',[],None)
check('[m10a] fetch-error skip', pl['action']=='skip' and pl['reason']=='fetch-error-fail-closed', pl['reason'])
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],{'signature':'RUNNING-ANY'})
check('[m10b] busy skip', pl['action']=='skip' and pl['reason']=='build-workflow-busy' or pl['reason']=='same-target-running', pl['reason'])

# infra classification: transient gets ONE automatic retry, then blocks
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
sti,opsi=M.apply_result(s,pl,{'success':False,'stage':'build','log_tail':'error: 502 Bad Gateway from sccache','ci_url':'u'},'t')
check('[11a] infra transient -> one retry, no issue', len(opsi['create_issues'])==0 and list(sti['blocked'].values())[0]['classification']=='infra')
sti2,opsi2=M.apply_result(sti,pl,{'success':False,'stage':'build','log_tail':'502 again','ci_url':'u'},'t')
check('[11b] infra second time -> block+issue', len(opsi2['create_issues'])==1)
pl=M.decide(sti2,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[11c] blocked after infra exhaust', pl['action']=='skip' and pl['reason']=='blocked-dedup', pl['reason'])

# official vs recipe divergence is informational, not failure
pl=M.decide(s,{'official_stable':'158.0.0.1','termux_head':'T','checksum_ok':True,'fetch_errors':[],'recipe':{'version':'156.0.8078.47','host_version':'156.0.8078.47','recipe_sha':'R1','host_sha':'H1','revision':0,'distro_version':'156.0.8078.47'}},'PORT-A','t',[],None)
check('[12] divergence informational', pl['action']=='skip' and 'differs' not in pl['reason'] and any('official Stable' in d for d in pl['diagnostics']), pl['reason'])

print(f'MAINTENANCE-TESTS PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
