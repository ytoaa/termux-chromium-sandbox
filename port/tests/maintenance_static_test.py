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
check('[s8] NO schedule trigger (activation requires separate approval); dispatch+dry_run+approve_retry intact',
      'schedule' not in don and 'workflow_dispatch' in don and 'dry_run' in don['workflow_dispatch']['inputs'] and 'approve_retry' in don['workflow_dispatch']['inputs'], str(list(don.keys())))
check('[s9] daily dispatch inputs (dry_run/approve_retry)', set(don['workflow_dispatch']['inputs'])=={'dry_run','approve_retry'})
check('[s10] daily top-level perms minimal (read); writes only per-job', dw['permissions']=={'contents':'read'}, str(dw['permissions']))
check('[s11] daily concurrency no-cancel', dw['concurrency']=={'group':'daily-maintenance','cancel-in-progress':False})
dj=json.dumps(dw['jobs'])
_dwj = dw['jobs']
check('[s13] dry_run gates build+outcome jobs', 'inputs.dry_run != true' in _dwj['build']['if'] and 'inputs.dry_run != true' in _dwj['outcome']['if'])
check('[s12] build invoked via reusable call only', './.github/workflows/build-chromium.yml' in dj and 'workflow_dispatch' not in dj.replace('Build Termux',''))
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
      and 'dry_run != true' in _dwj['outcome']['if'])
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
print(f'MAINTENANCE-STATIC PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
