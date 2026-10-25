#!/usr/bin/env python3
"""Round 15 static verification: workflows + seed cross-check + invariants."""
import json, os, sys, tomllib
import yaml
ROOT=os.path.join(os.path.dirname(__file__),'..')
PASS=fail=0
def check(name,cond,extra=''):
    global PASS,fail
    if cond: PASS+=1; print(f'PASS  [{name}]')
    else: fail+=1; print(f'FAIL  [{name}] {extra}')

bw=yaml.safe_load(open(os.path.join(ROOT,'..','.github/workflows/build-chromium.yml')))
on=bw[True] if True in bw else bw['on']
check('[s1] build keeps workflow_dispatch (manual build intact)', 'workflow_dispatch' in on)
check('[s2] build gained workflow_call', 'workflow_call' in on)
check('[s3] build concurrency serializes', bw.get('concurrency',{}).get('group')=='build-chromium-serial' and bw['concurrency']['cancel-in-progress'] is False)
bo=bw['jobs']['build'].get('outputs',{})
check('[s4] build exposes artifact outputs', set(bo)== {'deb_sha256','deb_version','termux_sha','port_sha'}, str(bo))
check('[s5] revision env plumbed', 'TERMUX_SANDBOXED_REVISION' in json.dumps(bw['jobs']['build'].get('env',{})))
check('[s6] build permissions stayed minimal', bw.get('permissions')=={'contents':'read'}, str(bw.get('permissions')))
# gate still fail-closed on selftest
steps=json.dumps(bw['jobs']['gate']['steps'])
check('[s7] gate self-test intact', 'port/ci.sh selftest' in steps)

dw=yaml.safe_load(open(os.path.join(ROOT,'..','.github/workflows/daily-maintenance.yml')))
don=dw[True] if True in dw else dw['on']
check('[s8] ACTIVATION: schedule cron 23 0 * * * + dispatch with dry_run+approve_retry',
      don.get('schedule',[{}])[0].get('cron')=='23 0 * * *'
      and 'workflow_dispatch' in don
      and set(don['workflow_dispatch']['inputs'])=={'dry_run','approve_retry'},
      str(list(don.keys())))
check('[s9] daily dispatch inputs (dry_run/approve_retry)', set(don['workflow_dispatch']['inputs'])=={'dry_run','approve_retry'})
check('[s10] daily top-level perms minimal (read); writes only per-job', dw['permissions']=={'contents':'read'}, str(dw['permissions']))
check('[s11] daily concurrency no-cancel', dw['concurrency']=={'group':'daily-maintenance','cancel-in-progress':False})
dj=json.dumps(dw['jobs'])
_dwj = dw['jobs']
check('[s13] normalized dry gate on build+outcome (explicit string compare, no implicit coercion)',
      "needs.evaluate.outputs.dry == 'false'" in _dwj['build']['if'] and "needs.evaluate.outputs.dry == 'false'" in _dwj['outcome']['if'])
check('[s12] build invoked via reusable call only (no dispatch API)',
      'actions/workflows/' not in dj.lower() or 'POST' not in dj)
check('[s14] state path locked to maintenance-state', dj.count('maintenance-state')>=6 and 'maintenance/state.json' in dj)
check('[s15] issue label dedup used', 'auto-build-blocked' in dj)
check('[s16] no apt/release/publish verbs', not any(k in dj.lower() for k in ('apt','gh release','deploy-pages','package publish')))
check('[s17] validated never written by workflow', 'last_validated' not in dj)

seed=json.load(open(os.path.join(ROOT,'..','maintenance/state.seed.json')))
with open(os.path.join(ROOT,'port.toml'),'rb') as f: t=tomllib.load(f)
p=t['port']
check('[s18] seed agrees with validated ledger (promoted -2 baseline)', seed['validated']['upstream_version']==p['last_validated_chromium'] and seed['validated']['port_sha']==p['last_validated_port_commit'] and seed['validated'].get('deb_version')==p['last_validated_deb_version'] and seed['validated']['termux_sha']==p['last_validated_termux_sha'] and p['phase']=='validated' and p['last_validated_port']=='0.1.0')
check('[s18b] seed: #31 plain preserved as history; last_successful + validated == promoted -2 baseline',
      seed['candidates'][0]['package_version']=='156.0.8078.47'
      and seed['last_successful_build']['package_version']=='156.0.8078.47-2'
      and seed['validated'].get('deb_version')=='156.0.8078.47-2'
      and seed['validated']['deb_sha256']=='cf2cb2a88e15ab42b1510140f4e41c34b751d4368b82f94172c06abd4151ba8d'
      and seed['validated']['ci_run']==40104615699
      and seed['last_successful_build'].get('artifact_verified') is True)
check('[s19] seed deb sha == promoted baseline AND #31 preserved as history', seed['validated']['deb_sha256']==p['last_validated_deb_sha256'] and seed['last_successful_build']['deb_sha256']==seed['validated']['deb_sha256'] and seed['candidates'][0]['deb_sha256'].startswith('29c4080d'))
check('[s20] seed records #31 in history AND last_success == promoted baseline', seed['candidates'][0]['ci_run']==39976822670 and seed['last_successful_build']['ci_run']==40104615699 and seed['last_successful_build']['status']=='BUILD_VERIFIED_CANDIDATE' and seed['last_successful_build'].get('validated') is True)

check('[s21] maintenance.py never imports subprocess/os.system', True)  # structural: reviewed by test below
src=open(os.path.join(ROOT,'maintenance.py')).read()
check('[s22] engine has no build/exec surface', 'subprocess' not in src and 'os.system' not in src)
check('[s23] engine never touches validated block', 'validated' in src and 'st[' not in src.split('validated')[0][-40:])
import ast
ast.parse(src)
check('[s24] engine compiles', True)
# renovate non-collision
rv=json.load(open(os.path.join(ROOT,'..','renovate.json')))
check('[s25] renovate confined to ledger file (no build trigger)', rv.get('autodiscover') is False and rv['enabledManagers']==['custom.regex'])
import re as _re
_dwt=open(os.path.join(ROOT,'..','.github/workflows/daily-maintenance.yml')).read()
check('[s26] no inline python heredocs (engine subcommands only)', "<<'PY'" not in _dwt)
_allowed={'fromJson','toJSON','tojson','contains','startsWith','endsWith','format','join','split','success','failure','always','cancelled','hashFiles'}
_bad=[fn for e in _re.findall(r'\$\{\{(.*?)\}\}', _dwt, _re.S) for fn in _re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', e) if fn not in _allowed]
check('[s27] GH expression functions whitelisted (no string())', not _bad, str(_bad))
# --- Round 15.1 job-structure grammar ---
_dwj = dw['jobs']
check('[s28] reusable call at JOBS level (no steps[].uses ./)',
      'uses' in _dwj['build'] and _dwj['build']['uses'].startswith('./')
      and 'steps' not in _dwj['build']
      and all(not any(str(st.get('uses','')).startswith('./') for st in j.get('steps',[]))
              for j in _dwj.values() if 'steps' in j))
check('[s29] outcome needs evaluate+build and runs on always()',
      set(_dwj['outcome']['needs'])=={'evaluate','build'}
      and 'always()' in _dwj['outcome']['if']
      and "needs.evaluate.outputs.dry == 'false'" in _dwj['outcome']['if'])
check('[s30] data handoff via artifact (upload==download name)',
      _dwj['evaluate']['steps'][-1]['with']['name'].replace('${{ github.run_id }}','R')
      == next(s['with']['name'].replace('${{ github.run_id }}','R')
              for s in _dwj['outcome']['steps'] if 'download-artifact' in str(s.get('uses'))))
check('[s31] build call passes pinned sha + pkg_revision_env',
      'termux_ref' in _dwj['build']['with'] and 'pkg_revision_env' in str(_dwj['build']['with']))
check('[s32] per-job permissions least-privilege',
      _dwj['evaluate'].get('permissions',{}).get('issues')=='read'
      and 'issues' not in str(_dwj['evaluate'].get('permissions',{}).get('contents',''))
      and _dwj['outcome']['permissions']['contents']=='write'
      and _dwj['build'].get('permissions') is None)
# s34: every run: block in daily-maintenance passes bash -n
# (expressions substituted with placeholder literals)
import subprocess as _sp, tempfile as _tf
_ok=True; _bad=[]
for _jn,_j in dw['jobs'].items():
    for _i,_st in enumerate(_j.get('steps',[]) or []):
        _r=_st.get('run')
        if not _r: continue
        _x=_re.sub(r'\$\{\{[^}]*\}\}','PLACEHOLDER',_r)
        with _tf.NamedTemporaryFile('w',suffix='.sh',delete=False) as _f:
            _f.write('#!/usr/bin/env bash\n'+_x); _p=_f.name
        _c=_sp.run(['bash','-n',_p],capture_output=True,text=True)
        if _c.returncode!=0:
            _ok=False; _bad.append(f'{_jn}#{_i}:{_c.stderr.strip()[:80]}')
        os.unlink(_p)
check('[s34] all run-blocks pass bash -n (expressions substituted)', _ok, str(_bad))
check('[s35] relink-only repair path wired (evaluate output + outcome if)',
      'relink' in _dwj['evaluate']['outputs'] and 'relink' in _dwj['outcome']['if']
      and "relink == 'true'" in _dwj['outcome']['if'])
check('[s36] failed job names prefix-normalized (split at space)',
      _dwt.count('split') > 0 and ('" ")[0]' in _dwt))
_steps_out={st.get('name',''):st.get('run','') for st in _dwj['outcome']['steps']}
_steps_ev={st.get('name',''):st.get('run','') for st in _dwj['evaluate']['steps']}
_cl=[v for k,v in _steps_out.items() if 'Classify' in k]
check('[s37] state-load fail-closed semantics (non-404 aborts)',
      any('::error::state API failure' in v and 'exit 1' in v and
          'No commit found for the ref' in v for v in _steps_ev.values()))
check('[s38] classify covers all result branches + guarantees result.json',
      _cl and all(k in _cl[0] for k in ('success)','cancelled)','failure|timed_out)','skipped)','*)'))
      and 'test -s result.json' in _cl[0])
check('[s39] durable label-consume step present before classify',
      any('Consume retry-approved label' in k for k in _steps_out)
      and list(_steps_out).index(next(k for k in _steps_out if 'Consume retry-approved' in k))
          < list(_steps_out).index(next(k for k in _steps_out if 'Classify' in k)))
_ps=[st.get('run','') for st in _dwj['outcome']['steps'] if 'Push state' in str(st.get('name',''))]
_ps=_ps[0] if _ps else ''
check('[s40] state push bootstrap: DEFAULT BRANCH sha feeds POST; no || true; verify; split',
      'POST' in _ps and 'git/refs' in _ps and '-f ref="refs/heads/maintenance-state"' in _ps
      and '--jq .default_branch' in _ps
      and 'base=$(gh api "repos/${{ github.repository }}/git/ref/heads/$default_branch" --jq .object.sha)' in _ps
      and '-f sha="$base" > ref-create.json' in _ps
      and 'github.ref_name' not in _ps
      and 'creating maintenance-state' in _ps and 'updating existing state file' in _ps
      and 'creating initial state file' in _ps
      and 'git/ref/heads/maintenance-state' in _ps
      and '-f sha="$base" > ref-create.json 2>/dev/null || true' not in _ps)
check('[s41] issues.json typed guard (array vs error object)',
      'if type=="object" then (.error // false) else false end' in _dwt)
check('[s42] called-job name parsing splits on last slash',
      'split("/") | last' in _dwt)
check('[s43] log download errors surfaced not hidden',
      'log download failed (job id' in _dwt)
_mode=[st for st in _dwj['evaluate']['steps'] if st.get('id')=='mode']
_mstep=_mode[0] if _mode else {}
_mtxt=_mstep.get('run','')
_menv=_mstep.get('env') or {}
def _run_mode(event, dry_val, appr_val):
    # Faithful simulation: GHK resolves the step-level env expressions to
    # STRINGS before bash ever sees them; the body only reads shell vars.
    gh_out=_tf.mktemp()
    open(gh_out,'w').close()
    resolved={}
    for k,v in _menv.items():
        v=str(v)
        v=v.replace('${{ github.event_name }}',event)
        v=v.replace('${{ inputs.dry_run }}',dry_val)
        v=v.replace('${{ inputs.approve_retry }}',appr_val)
        resolved[k]=v
    out=_sp.run(['bash','-c',_mtxt],capture_output=True,text=True,
                env=dict(os.environ,GITHUB_OUTPUT=gh_out,**resolved))
    kv=dict(l.split('=',1) for l in open(gh_out).read().splitlines() if '=' in l)
    try: os.unlink(gh_out)
    except OSError: pass
    return kv, out.returncode
check('[s44-sig] mode step reads inputs ONLY via env (no inline ${{ }) in body',
      '${{' not in _mtxt and set(_menv)>= {'EVENT_NAME','IN_DRY_RUN','IN_APPROVE_RETRY'})
kv,rc=_run_mode('schedule','','');   check('[s44a] schedule -> dry=false approve=false rc0', rc==0 and kv.get('dry')=='false' and kv.get('approve')=='false', str(kv))
kv,rc=_run_mode('workflow_dispatch','true','false'); check('[s44b] dispatch dry_run=true -> dry=true', rc==0 and kv.get('dry')=='true' and kv.get('approve')=='false', str(kv))
kv,rc=_run_mode('workflow_dispatch','',''); check('[s44c] dispatch dry_run MISSING -> dry=true (fail-closed)', rc==0 and kv.get('dry')=='true', str(kv))
kv,rc=_run_mode('workflow_dispatch','false','true'); check('[s44d] explicit dry_run=false -> build allowed; approve only via dispatch', rc==0 and kv.get('approve')=='true' and kv.get('dry')=='false', str(kv))
kv,rc=_run_mode('schedule','true','true'); check('[s44e] schedule IGNORES stray inputs (approve forced false)', rc==0 and kv.get('approve')=='false' and kv.get('dry')=='false', str(kv))
kv,rc=_run_mode('workflow_dispatch','yes','true'); check('[s44f] dispatch INVALID dry_run value -> build forbidden', rc==0 and kv.get('dry')=='true', str(kv))
kv,rc=_run_mode('workflow_dispatch','null','true'); check('[s44g] dispatch dry_run=null-string -> build forbidden', rc==0 and kv.get('dry')=='true', str(kv))
kv,rc=_run_mode('workflow_dispatch','False',''); check('[s44h] dispatch False (capitalized) explicit -> build allowed; approve missing -> false', rc==0 and kv.get('dry')=='false' and kv.get('approve')=='false', str(kv))
kv,rc=_run_mode('repository_dispatch','false','true'); check('[s44i] UNSUPPORTED event -> build forbidden regardless of inputs', rc==0 and kv.get('dry')=='true' and kv.get('approve')=='false', str(kv))
kv,rc=_run_mode('schedule','false','true'); check('[s44j] schedule stray dry_run=false ignored (still auto)', rc==0 and kv.get('dry')=='false' and kv.get('approve')=='false', str(kv))
_first_dry=[l.strip() for l in _mtxt.splitlines() if l.strip().startswith('DRY=')]
check('[s47] mode step initialises FAIL-CLOSED (first DRY assignment is true)',
      bool(_first_dry) and _first_dry[0]=='DRY=true', str(_first_dry[:1]))
check('[s45] no implicit GHK boolean coercion patterns remain',
      'inputs.dry_run !=' not in _dwt and 'inputs.approve_retry }}" = ' not in _dwt)
# s46: YAML duplicate-key guard (GHK/GitHub rejects duplicates; pyyaml
# silently last-wins — this exact defect escaped review once at activation)
def _no_dup_loader():
    import yaml as _y
    class L(_y.SafeLoader): pass
    def _ctor(loader, node, deep=False):
        mapping=set()
        for k,_n in node.value:
            key=loader.construct_object(k, deep=deep)
            if key in mapping:
                raise _y.constructor.ConstructorError('mapping','duplicate key %r'%(key,),node.start_mark)
            mapping.add(key)
        return _y.SafeLoader.construct_mapping(loader,node,deep)
    L.add_constructor(_y.resolver.BaseResolver.DEFAULT_MAPPING_TAG,_ctor)
    return L
try:
    import subprocess as _sp2
    _wfs=(ROOT+'/../.github/workflows/daily-maintenance.yml',
          ROOT+'/../.github/workflows/build-chromium.yml',
          ROOT+'/../.github/workflows/publish-release.yml')
    _allok=True; _last=''
    for _src in _wfs:
        _r=_sp2.run([sys.executable,'-c',
            'import yaml,sys\n'
            'class L(yaml.SafeLoader):\n    pass\n'
            'def c(l,n,d=False):\n    m=set()\n    for k,_ in n.value:\n        key=l.construct_object(k,deep=d)\n        if key in m: raise yaml.constructor.ConstructorError("mapping","duplicate key %r"%(key,),n.start_mark)\n        m.add(key)\n    return yaml.SafeLoader.construct_mapping(l,n,d)\n'
            'L.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,c)\n'
            'yaml.load(open(sys.argv[1]),Loader=L)\nprint("NODUP-OK")', _src],
            capture_output=True,text=True)
        _allok=_allok and _r.returncode==0 and 'NODUP-OK' in _r.stdout
        _last=(_r.stdout+_r.stderr)[:150]
    check('[s46] ALL workflows contain no duplicate YAML keys (activation dup-key regression)',
          _allok, _last)
except Exception as _ex:
    check('[s46] workflows contain no duplicate YAML keys', False, repr(_ex))
# s48 (Round 16): signature-schema v2 wiring — semantic port-input hash +
# audited v1→v2 migration file, with the legacy raw-5-blob loop retired.
_migf=ROOT+'/../maintenance/signature-migrations.json'
try:
    _mig=json.load(open(_migf))
    _ms=_mig.get('migrations') or []
    _m0=_ms[0] if _ms else {}
    _prov=_m0.get('provenance') or {}
    check('[s48] migrations file: approved v1->v2 entry pinning rev-2 baseline (from_sig ad5b0fdb8c7a9777, ci 40104615699), never rewriting history',
          _mig.get('schema')==1 and len(_ms)==1 and _m0.get('status')=='approved'
          and _m0.get('from_sig')=='ad5b0fdb8c7a9777'
          and _m0.get('from_sig_version')==1 and _m0.get('to_sig_version')==2
          and _m0.get('aligned_version')=='156.0.8078.47'
          and _m0.get('recipe_sha')=='7c5c20eb1182e197'
          and _m0.get('host_sha')=='34b799517be2a99a'
          and all(_re.fullmatch(r'[0-9a-f]{16}',_m0.get(k) or '')
                  for k in ('port_inputs_hash_v2',))
          and _prov.get('build_ci_run')==40104615699
          and _prov.get('deb_sha256','').startswith('cf2cb2a8')
          and _prov.get('build_commit')=='554da59a8f021bc65f9c3aab4c25841a0768f373',
          json.dumps(_m0)[:120])
except Exception as _mx:
    check('[s48] migrations file: approved v1->v2 entry pinning rev-2 baseline', False, repr(_mx))
_decstep=[st for st in _dwj['evaluate']['steps'] if st.get('id')=='decide']
_dtxt=_decstep[0]['run'] if _decstep else ''
check('[s48b] decide uses v2 port-input-hash + migrations; legacy raw-5-blob loop removed',
      'maintenance.py port-input-hash' in _dtxt
      and '--migrations maintenance/signature-migrations.json' in _dtxt
      and 'for f in port/chromium_sandbox_port.py' not in _dwt)
_msrc=open(ROOT+'/maintenance.py').read()
check('[s48c] engine denylist is EXACT (new keys hash by default) and documented in DESIGN',
      "'last_validated_promoted'" in _msrc and "'device_gate_history'" in _msrc
      and 'TOML_METADATA_ONLY' in _msrc
      and 'Signature schema v2' in open(ROOT+'/DESIGN.md').read())
check('[s48d] engine keeps v1 frozen (sig_version=1 path) and tags v2 payload',
      "if sig_version == 1" in _msrc and "'sigv2'" in _msrc
      and "unsupported signature schema" in _msrc)
# ---- s50..s54 (Round 17): pre-release publishing — boundaries, permissions,
# separation from build/state classification.
_pw=(ROOT+'/../.github/workflows/publish-release.yml')
_psrc=open(_pw).read()
_pj=yaml.safe_load(open(_pw))
_pub=open(ROOT+'/publish_release.py').read()
_both=_psrc+_pub
check('[s50] publisher is a SELF-CONTAINED workflow_run job: contents:write only at top level, NO job-level permissions',
      _pj['permissions']=={'contents':'write'}
      and all('permissions' not in sp for sp in _pj['jobs'].values())
      and 'issues:' not in _psrc and 'admin:' not in _psrc
      and 'workflow_run' in (_pj[True] if True in _pj else _pj['on']))
check('[s50b] no clobber-style flag, no latest marker, no delete anywhere in publisher',
      '--clobber' not in _both and '--latest' not in _both
      and 'release delete' not in _both and 'git tag -d' not in _both
      and '--draft=false' in _both and "'release', 'create'" in _both
      and '--draft' in _both and '--prerelease' in _both)
check('[s50c] provenance audit BEFORE publish: run success + artifact uniqueness + download pinned to audited run id',
      'conclusion=="success"' in _psrc and 'length == 1' in _psrc
      and 'run-id: ${{ steps.cls.outputs.run_id }}' in _psrc
      and 'workflow_run.conclusion == ' in str(_pj['jobs']['publish']['if']))
check('[s50d] step order: classify -> ledger gate -> download -> verify -> plan -> execute',
      _psrc.index('Classify trigger event') < _psrc.index('ledger gate')
      < _psrc.index('Download candidate artifact') < _psrc.index('Integrity verification')
      < _psrc.index('+ plan (dedup') < _psrc.index('Execute (draft'))
_li=_psrc.index('ok=$(jq -r --argjson id'); _ai=_psrc.index('actions/runs/$RUN_ID/artifacts')
check('[s50g] ORDER: ledger no-op check precedes artifact-existence (dry/skip runs have no build-<id> artifact -> must be green no-op, never red)',
      _li < _ai and 'SKIP_REMAIN=true' in _psrc[_li:_ai] and 'exit 0' in _psrc[_li:_ai])
check('[s50e] ledger gate re-executed in publisher (BUILD_VERIFIED_CANDIDATE + 64hex sha + 16hex sig for THIS run)',
      'BUILD_VERIFIED_CANDIDATE' in _psrc and 'test("^' in _psrc
      and '[0-9a-f]{64}' in _psrc and '[0-9a-f]{16}' in _psrc and 'SKIP_REMAIN' in _psrc)
check('[s50f] dry-run/skip/blocked/unrecorded => no-op (SKIP_REMAIN=true, never publish)',
      'no-op' in _psrc and 'SKIP_REMAIN=true' in _psrc)
# s51/s52: caller workflows must NOT have gained any publisher wiring or elevated perms (Round 17 keeps them at Round-16 baseline; only build-chromium gained a dispatch opt-out input)
check('[s51] daily-maintenance publisher-free at caller level: no permissions: on any uses: job, actions:write nowhere, no gh workflow run publish',
      all(not ('uses' in sp and 'permissions' in sp) for sp in _dwj.values())
      and 'actions: write' not in _dwt.replace('actions: read','')
      and 'publish-release.yml' not in _dwt)
_bfull=yaml.safe_load(open(ROOT+'/../.github/workflows/build-chromium.yml'))
_bwt=open(ROOT+'/../.github/workflows/build-chromium.yml').read()
check('[s52] build-chromium gained ONLY a publish dispatch opt-out input; no caller publisher wiring / elevated perms',
      'publish-release.yml' not in _bwt
      and all(not ('uses' in sp and 'permissions' in sp) for sp in _bfull['jobs'].values())
      and 'actions: write' not in _bwt.replace('actions: read','')
      and _bfull[True if True in _bfull else 'on']['workflow_dispatch']['inputs']['publish']['default'] is True
      and _bfull['permissions']=={'contents':'read'})
check('[s53] publisher is ISOLATED from build/state classification (no maintenance import/state writes)',
      'import maintenance' not in _pub and 'maintenance-state' not in _pub
      and 'state.json' not in _pub and 'state2' not in _pub
      and 'apply_result' not in _pub and 'retry_approved' not in _pub
      and 'BLOCKED_LABEL' not in _pub and 'blocked-dedup' not in _pub)
check('[s54] notes/manifest: CI VERIFIED — DEVICE NOT VERIFIED, device never claimed, signature never fabricated, secret scanner present',
      'CI VERIFIED — DEVICE NOT VERIFIED' in _pub
      and 'NOT VERIFIED FOR THIS BUILD' in _pub
      and "v.get('build_signature')" in _pub
      and "if v.get('build_signature')" in _pub
      and 'not fabricated' in _pub
      and 'TOKEN_PATTERNS' in _pub and 'add-mask' in _pub)
print(f'MAINTENANCE-STATIC PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
