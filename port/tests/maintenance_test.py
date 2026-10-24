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

def probes(version='156.0.8078.47', recipe_sha='R1', host_sha='H1', head='64e02760', errs=None, cksum=True, host_version=None):
    hv = host_version or version
    return {'official_stable':version,'termux_head':head,'pins_verified':cksum and bool(version and hv),'fetch_errors':errs or [],
            'recipe':{'version':version,'host_version':hv,'recipe_sha':recipe_sha,'host_sha':host_sha,'revision':0,'distro_version':version}}

SIG = M.build_signature('156.0.8078.47','R1','H1','PORT-A')

# [1] no new version, identical inputs -> skip
p=probes(); s=base_state(); s['last_successful_build']['signature']=SIG
pl=M.decide(s,p,'PORT-A','t',[],None)
check('[m1] identical-inputs skip', pl['action']=='skip' and pl['reason']=='identical-inputs-already-built', pl['reason'])

# [2] new version -> build
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[m2] new-upstream build rev1=PLAIN version', pl['action']=='build' and pl['target']['upstream_version']=='157.0.100.5' and pl['target']['revision']==1 and pl['target']['package_version']=='157.0.100.5' and pl['target']['pkg_revision_env']=='', json.dumps(pl)[:120])

# [3] same successful version (candidate) -> no rebuild
st=copy.deepcopy(s); st['candidates']=[{'upstream_version':'157.0.100.5','status':'BUILD_VERIFIED_CANDIDATE','signature':M.build_signature('157.0.100.5','R2','H2','PORT-A')}]
pl=M.decide(st,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[m3] candidate-already-built skip', pl['action']=='skip' and pl['reason']=='candidate-already-built', pl['reason'])

# [4] same chromium, port changed -> revision build
pl=M.decide(s,probes(),'PORT-B','t',[],None)
check('[m4] revision build rev2 suffix+env', pl['action']=='build' and pl['target']['revision']==2 and pl['target']['package_version']=='156.0.8078.47-2' and pl['target']['pkg_revision_env']=='2', pl['reason'])

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
GOOD_OK={'success':True,'stage':'ok','deb_sha256':'a'*64,
         'deb_version':'157.0.100.5','termux_sha':'b'*40,
         'ci_url':'https://github.com/o/r/actions/runs/99','ci_run':99,'artifact':'build-99'}
st5,ops5=M.apply_result(s,pl,dict(GOOD_OK),'t')
check('[8a] candidate recorded (full fields)', st5['candidates'][-1]['deb_sha256']=='a'*64 and st5['candidates'][-1]['status']=='BUILD_VERIFIED_CANDIDATE' and st5['candidates'][-1]['ci_run']==99 and st5['candidates'][-1]['artifact']=='build-99' and st5['candidates'][-1]['termux_sha']=='b'*40)
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
check('[11a] infra first -> no issue, failures=1', len(opsi['create_issues'])==0 and list(sti['blocked'].values())[0]['classification']=='infra' and list(sti['blocked'].values())[0]['infra_failures']==1)
plR=M.decide(sti,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[11a2] decide ALLOWS the single automatic retry', plR['action']=='build', plR['reason'])
sti2,opsi2=M.apply_result(sti,pl,{'success':False,'stage':'build','log_tail':'502 again','ci_url':'u'},'t')
check('[11b] infra second time -> block+issue', len(opsi2['create_issues'])==1)
pl=M.decide(sti2,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
check('[11c] blocked after infra exhaust', pl['action']=='skip' and pl['reason']=='blocked-dedup', pl['reason'])

# official vs recipe divergence is informational, not failure
pl=M.decide(s,{'official_stable':'158.0.0.1','termux_head':'T','pins_verified':True,'fetch_errors':[],'recipe':{'version':'156.0.8078.47','host_version':'156.0.8078.47','recipe_sha':'R1','host_sha':'H1','revision':0,'distro_version':'156.0.8078.47'}},'PORT-A','t',[],None)
check('[12] divergence informational', pl['action']=='skip' and 'differs' not in pl['reason'] and any('official Stable' in d for d in pl['diagnostics']), pl['reason'])

# --- Round 15.1 additions ---
# [13] issues API error marker -> fail-closed skip
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[{'error':True}],None)
check('[13] issues-api-error fail-closed', pl['action']=='skip' and pl['reason']=='issues-api-error-fail-closed', pl['reason'])

# [14] retry-approved LABEL on matching open issue unblocks one attempt
stl=copy.deepcopy(s)
sigL=M.build_signature('157.0.100.5','R2','H2','PORT-A')
stl['blocked'][sigL]={'classification':'port','issue':5,'retry_approved':False,
    'inputs':{'recipe_sha':'R2','host_sha':'H2','port_sha':'PORT-A'}}
tL=M.issue_title({'upstream_version':'157.0.100.5','revision':1,'signature':sigL},'gate')
pl=M.decide(stl,probes('157.0.100.5','R2','H2'),'PORT-A','t',[{'number':5,'title':tL,'labels':['auto-build-blocked','retry-approved']}],None)
check('[14] retry-approved label honored', pl['action']=='build', pl['reason'])
stl2=copy.deepcopy(s)
stl2['blocked'][sigL]={'classification':'port','issue':5,'retry_approved':False,
    'inputs':{'recipe_sha':'R2','host_sha':'H2','port_sha':'PORT-A'}}
pl=M.decide(stl2,probes('157.0.100.5','R2','H2'),'PORT-A','t',[{'number':5,'title':tL,'labels':['auto-build-blocked']}],None)
check('[14b] without label stays blocked', pl['action']=='skip' and pl['reason']=='blocked-dedup', pl['reason'])

# [15] full-sig title matching is consistent (dedup==stamp==label)
check('[15] full-sig matcher', M.issue_matches_sig(tL, sigL) and not M.issue_matches_sig(tL.replace(sigL, sigL[:8]), sigL))

# [16] buildable follows host-tools alignment (prepare_recipe policy)
pl=M.decide(s,probes('157.0.100.5','R2','H2',host_version='157.0.100.7'),'PORT-A','t',[],None)
check('[16] aligned host version built', pl['action']=='build' and pl['target']['upstream_version']=='157.0.100.7', json.dumps(pl)[:100])

# [17] actions API error marker -> busy skip
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],{'signature':'API-ERROR'})
check('[17] actions api-error busy skip', pl['action']=='skip' and pl['reason']=='build-workflow-busy', pl['reason'])

# [18] cancelled outcome is recorded, never blocks/issues
pl=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
stc,opsc=M.apply_result(s,pl,{'success':False,'stage':'cancelled','log_tail':'run cancelled','ci_url':'u'},'t')
check('[18] cancelled -> no block no issue', len(opsc['create_issues'])==0 and not stc.get('blocked'), json.dumps(opsc)[:120])
# skipped-anomaly likewise non-blocking
stx,opsx=M.apply_result(s,pl,{'success':False,'stage':'skipped-anomaly','log_tail':'orchestration skip','ci_url':'u'},'t')
check('[18b] skipped-anomaly -> no block no issue', len(opsx['create_issues'])==0 and not stx.get('blocked'), json.dumps(opsx)[:120])

# --- Round 15.2 cases ---
GOOD={'success':True,'stage':'ok','deb_sha256':'c'*64,'deb_version':'157.0.100.5',
      'termux_sha':'d'*40,'ci_url':'https://x/runs/9','ci_run':9,'artifact':'build-9'}
plG=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
stb,opsb=M.apply_result(s,plG,{**GOOD,'deb_sha256':'not-a-sha'},'t')
check('[19a] bad sha -> verify block + issue', (list(stb['blocked'].values())[0]['stage']=='verify' or 'verify' in str(stb['blocked'])) and len(opsb['create_issues'])==1 and not stb['candidates'])
stb2,_=M.apply_result(s,plG,{**GOOD,'deb_version':'157.0.100.9'},'t')
check('[19b] version mismatch -> verify', list(stb2['blocked'].values())[0]['stage']=='verify')
stb3,_=M.apply_result(s,plG,{**GOOD,'ci_run':0},'t')
check('[19c] ci_run invalid -> verify', list(stb3['blocked'].values())[0]['stage']=='verify')
stok,opsok=M.apply_result(s,plG,dict(GOOD),'t')
check('[19d] good shape -> candidate full', stb3 and stok['candidates'][-1]['deb_sha256']=='c'*64 and stok['candidates'][-1]['ci_url']=='https://x/runs/9' and len(opsok['create_issues'])==0)

# [20] failure result with failed job names preserved into issue body
plF=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
stf2,opsf2b=M.apply_result(s,plF,{'success':False,'stage':'gate','log_tail':'PORT ERROR R3 anchor',
    'failure_jobs':'gate','ci_url':'https://x/runs/8','ci_run':8},'t')
body=opsf2b['create_issues'][0]['body']
check('[20] failed job names in issue', 'gate' in body and 'PORT ERROR' in body and stf2['blocked'][list(stf2['blocked'])[0]]['failure_jobs']=='gate')

# [22] label approval consumed exactly once
st22=copy.deepcopy(s)
sig22=M.build_signature('157.0.100.5','R2','H2','PORT-A')
st22['blocked'][sig22]={'classification':'port','issue':5,'retry_approved':False,
    'inputs':{'recipe_sha':'R2','host_sha':'H2','port_sha':'PORT-A'}}
t22=M.issue_title({'upstream_version':'157.0.100.5','revision':1,'signature':sig22},'gate')
iss22=[{'number':5,'title':t22,'labels':['auto-build-blocked','retry-approved']}]
pl22=M.decide(st22,probes('157.0.100.5','R2','H2'),'PORT-A','t',iss22,None)
check('[22a] approval first attempt builds', pl22['action']=='build' and pl22.get('approval_used'))
st22b,ops22=M.apply_result(st22,pl22,{'success':False,'stage':'gate','log_tail':'still broken','ci_url':'u','ci_run':1},'t')
ent=st22b['blocked'][sig22]
check('[22b] approval consumed', ent['retry_approved'] is False and 5 in (ent.get('approval_consumed_issues') or []))
pl22c=M.decide(st22b,probes('157.0.100.5','R2','H2'),'PORT-A','t',iss22,None)
check('[22c] label remains but NO second retry', pl22c['action']=='skip' and pl22c['reason']=='blocked-dedup', pl22c['reason'])

# [23] lost state + open issue -> skip + re-link persisted via apply
st23=copy.deepcopy(s)  # NO blocked entry (state push was lost)
t23=M.issue_title({'upstream_version':'157.0.100.5','revision':1,'signature':M.build_signature('157.0.100.5','R2','H2','PORT-A')},'gate')
pl23=M.decide(st23,probes('157.0.100.5','R2','H2'),'PORT-A','t',[{'number':9,'title':t23,'labels':['auto-build-blocked']}],None)
check('[23a] open-issue-exists durable skip', pl23['action']=='skip' and pl23['reason']=='open-issue-exists', pl23['reason'])
st23b,_=M.apply_result(st23,pl23,{'success':False,'stage':'build','log_tail':'x','ci_run':0,'ci_url':''},'t')
sig23=M.build_signature('157.0.100.5','R2','H2','PORT-A')
check('[23b] re-link persisted', st23b['blocked'].get(sig23,{}).get('issue')==9)

print(f'MAINTENANCE-TESTS PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
