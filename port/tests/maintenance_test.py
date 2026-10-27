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

T40='ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12'
def probes(version='156.0.8078.47', recipe_sha='R1', host_sha='H1', head=T40, errs=None, cksum=True, host_version=None):
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
         'deb_version':'157.0.100.5','termux_sha':T40,
         'ci_url':'https://github.com/o/r/actions/runs/99','ci_run':99,'artifact':'build-99'}
st5,ops5=M.apply_result(s,pl,dict(GOOD_OK),'t')
check('[8a] candidate recorded (full fields)', st5['candidates'][-1]['deb_sha256']=='a'*64 and st5['candidates'][-1]['status']=='BUILD_VERIFIED_CANDIDATE' and st5['candidates'][-1]['ci_run']==99 and st5['candidates'][-1]['artifact']=='build-99' and st5['candidates'][-1]['termux_sha']==T40)
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
      'termux_sha':T40,'ci_url':'https://x/runs/9','ci_run':9,'artifact':'build-9'}
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

# [24] success with FOREIGN termux sha -> verify (never a candidate)
plX=M.decide(s,probes('157.0.100.5','R2','H2'),'PORT-A','t',[],None)
stX,opsX=M.apply_result(s,plX,{**GOOD,'termux_sha':'0'*40},'t')
check('[24] foreign termux sha blocked', (not stX['candidates'] or stX['candidates'][-1].get('deb_sha256')!='c'*64) and list(stX['blocked'].values())[0]['stage']=='verify')
# [25] unrecognized stage string -> unknown -> blocks (fail closed)
stY,opsY=M.apply_result(s,plX,{'success':False,'stage':'banana','log_tail':'x','ci_run':1,'ci_url':'https://x'},'t')
check('[25] bad stage -> unknown blocks+issue', list(stY['blocked'].values())[0]['classification']=='unknown' and len(opsY['create_issues'])==1)
# [26] serialized approval survives JSON round-trip and is consumed
import tempfile, os as _os
stB=copy.deepcopy(s); sigB=M.build_signature('157.0.100.5','R2','H2','PORT-A')
stB['blocked'][sigB]={'classification':'port','issue':11,'retry_approved':False,
    'inputs':{'recipe_sha':'R2','host_sha':'H2','port_sha':'PORT-A'}}
planA=M.decide(stB,probes('157.0.100.5','R2','H2'),'PORT-A','t',
               [{'number':11,'title':M.issue_title({'upstream_version':'157.0.100.5','revision':1,'signature':M.build_signature('157.0.100.5','R2','H2','PORT-A')},'gate'),'labels':['auto-build-blocked','retry-approved']}],None)
ser=json.loads(json.dumps(planA))
check('[26] approval origin in serialized plan', ser.get('approval',{}).get('issue')==11)
stA,_=M.apply_result(stB,ser,{'success':False,'stage':'gate','log_tail':'x','ci_run':1,'ci_url':'https://x'},'t')
entA=list(stA['blocked'].values())[0]
check('[26b] consumed via serialized plan only', entA['retry_approved'] is False and 11 in (entA.get('approval_consumed_issues') or []))

# ================= Round 16 — signature schema v2 (Stage B/C) ==============
REAL_TOML = open(os.path.join(os.path.dirname(__file__), '..', 'port.toml')).read()
_blob = {f: 'b'*40 for f in M.PORT_RAW_FILES}
_h0 = M.port_toml_semantic_sha(REAL_TOML)
def _swap(text, key, newval):
    import re as _r2
    return _r2.sub(r'(?m)^%s = .*$$' % key, '%s = %s' % (key, newval), text, count=1)
# [R1] audit-record (promotion) edits do NOT move the semantic hash
_r1 = _swap(REAL_TOML, 'last_validated_promoted', '"changed by a robot tomorrow"')
check('[R1] metadata-only (last_validated_*) edit -> same semantic hash',
      M.port_toml_semantic_sha(_r1) == _h0)
# [R2] device-gate record edits do NOT move the semantic hash
_r2 = REAL_TOML.replace('device_gate = "PASS', 'device_gate = "PASS (hypothetical future record)')
check('[R2] device_gate record edit -> same semantic hash',
      M.port_toml_semantic_sha(_r2) == _h0)
# [R3] a security-contract edit MUST move the hash
_r3 = REAL_TOML.replace('setuid_sandbox', 'setuid_sandbox_X')
check('[R3] contract key rename ([sandbox]) -> hash changes',
      M.port_toml_semantic_sha(_r3) != _h0)
_r3b = REAL_TOML.replace('require_bpf_policy = true', 'require_bpf_policy = false')
check('[R3b] require_bpf_policy true->false -> hash changes',
      M.port_toml_semantic_sha(_r3b) != _h0 and _r3b != REAL_TOML)
# [R4] NEW/unclassified keys are hashed by DEFAULT (conservative inclusion)
_r4 = REAL_TOML.replace('[forbidden]', 'newly_observed_contract = "x"\n[forbidden]')
check('[R4] new unclassified contract key -> hash changes (never silently ignored)',
      M.port_toml_semantic_sha(_r4) != _h0)
# [R5] determinism + canonicalization insensitivity (layout/comments/order)
check('[R5] same text twice -> same hash (determinism)',
      _h0 == M.port_toml_semantic_sha(REAL_TOML))
_r5c = REAL_TOML.replace('[sandbox]', '# an added comment does not sign\n[sandbox]')
check('[R5b] comment-only edit -> same semantic hash',
      M.port_toml_semantic_sha(_r5c) == _h0)
check('[R5c] port_inputs_hash deterministic',
      M.port_inputs_hash(_blob, REAL_TOML) == M.port_inputs_hash(dict(_blob), REAL_TOML))
# [R6] a missing raw input is a sentinel, not a silent collision
_b2 = dict(_blob); _b2.pop('port/ci.sh')
check('[R6] missing raw file -> distinct hash (MISSING sentinel)',
      M.port_inputs_hash(_b2, REAL_TOML) != M.port_inputs_hash(_blob, REAL_TOML))
# [R7] v1 frozen reproduction of the rev-2 baseline; v1 != v2 for same inputs
check('[R7] legacy v1 sig reproduces bit-exact (rev-2 baseline)',
      M.build_signature('156.0.8078.47', '7c5c20eb1182e197', '34b799517be2a99a',
                        'd98814c2a3feee8a', sig_version=1) == 'ad5b0fdb8c7a9777')
_v2 = M.build_signature('156.0.8078.47', '7c5c20eb1182e197', '34b799517be2a99a', '7f86b30313338792')
check('[R7b] v2 schema-tagged and distinct from v1', _v2 == '35af420388ac5a5f'
      and _v2 != M.build_signature('156.0.8078.47', '7c5c20eb1182e197',
                                   '34b799517be2a99a', '7f86b30313338792', sig_version=1))
try:
    M.build_signature('1', '2', '3', '4', sig_version=99); _r8 = False
except ValueError:
    _r8 = True
check('[R8] unsupported sig_version rejected', _r8)
# [R9] decide + migration: v1 last_success is SKIPPED only with fresh proof
def _mig_entry(**over):
    e = {'id': 't-rev2', 'status': 'approved', 'from_sig': 'ad5b0fdb8c7a9777',
         'from_sig_version': 1, 'to_sig_version': 2,
         'aligned_version': '156.0.8078.47', 'recipe_sha': 'R1', 'host_sha': 'H1',
         'port_inputs_hash_v2': 'PORT-V2'}
    e.update(over); return e
sM = base_state()
sM['last_successful_build']['signature'] = 'ad5b0fdb8c7a9777'
plM = M.decide(sM, probes(), 'PORT-V2', 't', [], None, [_mig_entry()])
check('[R9] migration-equivalent identical inputs -> skip (never a build)',
      plM['action'] == 'skip' and plM['reason'] == 'identical-inputs-already-built'
      and any('migration active' in d for d in plM['diagnostics']), plM['reason'])
# [R10] recipe drift invalidates equivalence -> real build (detection intact)
plM2 = M.decide(sM, probes(recipe_sha='R2'), 'PORT-V2', 't', [], None, [_mig_entry()])
check('[R10] pinned component differs -> NO equivalence -> build',
      plM2['action'] == 'build' and plM2['reason'] == 'inputs-changed-revision-build', plM2['reason'])
# [R11] revoked entry grants nothing
plM3 = M.decide(sM, probes(), 'PORT-V2', 't', [], None, [_mig_entry(status='revoked')])
check('[R11] revoked migration -> build (equivalence withdrawn)',
      plM3['action'] == 'build')
# [R12] malformed entry is rejected (no crash, no equivalence)
plM4 = M.decide(sM, probes(), 'PORT-V2', 't', [], None,
                [_mig_entry(from_sig='ZZZZ')])
check('[R12] malformed from_sig in-memory entry ignored',
      plM4['action'] == 'build')
# [R13] candidate list honours equivalence too (last is NOT equivalent here)
sC = copy.deepcopy(sM)
sC['last_successful_build']['signature'] = 'ffffffffffffffff'
sC['candidates'] = [{'upstream_version': '156.0.8078.47',
                     'status': 'BUILD_VERIFIED_CANDIDATE',
                     'signature': 'ad5b0fdb8c7a9777'}]
plC = M.decide(sC, probes(), 'PORT-V2', 't', [], None, [_mig_entry()])
check('[R13] equivalent candidate signature -> identical-candidate skip',
      plC['reason'] == 'identical-candidate-already-built', plC['reason'])
# [R14] a v1-keyed BLOCK still blocks the equivalent v2 inputs (fail-safe)
sBl = copy.deepcopy(sM)
sBl['last_successful_build']['signature'] = 'ffffffffffffffff'
sBl['blocked'] = {'ad5b0fdb8c7a9777': {'classification': 'port',
                                       'issue': 7, 'retry_approved': False}}
plB = M.decide(sBl, probes(), 'PORT-V2', 't', [], None, [_mig_entry()])
check('[R14] v1 block honoured via equivalence (blocked-dedup)',
      plB['action'] == 'skip' and plB['reason'] == 'blocked-dedup', plB['reason'])
# [R15] open issue titled with v1 sig still dedups (lost-state repair)
sIs = base_state()
sIs['last_successful_build']['signature'] = 'ffffffffffffffff'
plI = M.decide(sIs, probes(), 'PORT-V2', 't', [{'number': 9,
      'title': '[auto-build] Chromium 156.0.8078.47 revision 2 blocked (gate, sig ad5b0fdb8c7a9777)',
      'labels': ['auto-build-blocked']}], None, [_mig_entry()])
check('[R15] open issue with v1 sig dedups via equivalence',
      plI['action'] == 'skip' and plI['reason'] == 'open-issue-exists', plI['reason'])
# [R16] load_migrations fail-closed on malformed JSON; absent file is safe
with open('._mig_bad.json', 'w') as _f: _f.write('{"migrations": [oops')
_, _err = M.load_migrations('._mig_bad.json')
os.unlink('._mig_bad.json')
check('[R16] malformed migrations JSON -> error (caller aborts)', _err is not None)
_, _err2 = M.load_migrations('does-not-exist.json')
check('[R16b] absent migrations file -> no error, no equivalence (safe: builds)',
      _err2 is None)
# [R17] CLI end-to-end fail-closed on bad migrations file
with open('._mig_bad2.json', 'w') as _f: _f.write('not json at all')
_stf = _os.path.join(_os.getcwd(), '._st.json')
json.dump(base_state(), open(_stf, 'w')); json.dump(probes(), open('._pr.json', 'w'))
rc_cli = M.main(['decide', '--state', _stf, '--probes', '._pr.json',
                 '--out', '._out.json', '--port-sha', 'x',
                 '--migrations', '._mig_bad2.json'])
os.unlink('._mig_bad2.json'); os.unlink(_stf); os.unlink('._pr.json')
check('[R17] CLI decide with corrupt migrations -> rc!=0 (no plan, no build)',
      rc_cli == 1)
# [R18] keep the old approved rev-2 provenance canary IMMUTABLE.
# The new R10 rule is a new security contract; its semantic hash must
# differ. Do NOT edit maintenance/signature-migrations.json to claim the
# R10 candidate has the original rev-2 content.
_r10start = REAL_TOML.index('[rules.r10]\n')
_r10end = REAL_TOML.index('[rules.r9b]\n', _r10start)
# R12 (Issue #12 fix candidate) is likewise NEW contract content: splice it
# out for the historical reconstruction; the full-content assertion below
# (_h0 != canary) still proves the branch diverges from rev-2 semantics.
_r12start = REAL_TOML.index('[rules.r12]\n')
_r12end = REAL_TOML.index('[gates]', _r12start)
_historical_toml = (REAL_TOML[:_r10start] + REAL_TOML[_r10end:_r12start]
                    + REAL_TOML[_r12end:])
check('[R18] frozen rev-2 hash preserved and new R10/R12 contracts differ',
      M.port_toml_semantic_sha(_historical_toml) == 'fbf559c15b61e310'
      and _h0 != 'fbf559c15b61e310', _h0)
_rc = M.main(['port-input-hash', '--root', os.path.join(os.path.dirname(__file__), '..', '..')])
check('[R18b] golden v2 port-input hash via CLI (repo tree)', _rc == 0)
print(f'MAINTENANCE-TESTS PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
