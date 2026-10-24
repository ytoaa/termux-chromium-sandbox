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
check('[s8] daily cron 00:23 UTC (09:23 KST)', don['schedule'][0]['cron']=='23 0 * * *', str(don.get('schedule')))
check('[s9] daily dispatch inputs (dry_run/approve_retry)', set(don['workflow_dispatch']['inputs'])=={'dry_run','approve_retry'})
check('[s10] daily permissions exact set', dw['permissions']=={'actions':'read','issues':'write','contents':'write'}, str(dw['permissions']))
check('[s11] daily concurrency no-cancel', dw['concurrency']=={'group':'daily-maintenance','cancel-in-progress':False})
dj=json.dumps(dw['jobs']['maintenance'])
check('[s12] build invoked via reusable call only', './.github/workflows/build-chromium.yml' in dj and 'workflow_dispatch' not in dj.replace('Build Termux',''))
check('[s13] dry_run guards every mutation step', dj.count('inputs.dry_run != true')>=5)
check('[s14] state path locked to maintenance-state', dj.count('maintenance-state')>=6 and 'maintenance/state.json' in dj)
check('[s15] issue label dedup used', 'auto-build-blocked' in dj)
check('[s16] no apt/release/publish verbs', not any(k in dj.lower() for k in ('apt','gh release','deploy-pages','package publish')))
check('[s17] validated never written by workflow', 'last_validated' not in dj)

seed=json.load(open(os.path.join(ROOT,'..','maintenance/state.seed.json')))
with open(os.path.join(ROOT,'port.toml'),'rb') as f: t=tomllib.load(f)
p=t['port']
check('[s18] seed agrees with validated ledger', seed['validated']['upstream_version']==p['last_validated_chromium'] and seed['validated']['port_sha'].startswith('403274f') and p['phase']=='validated' and p['last_validated_port']=='0.1.0')
check('[s19] seed deb sha matches #31', seed['validated']['deb_sha256'].startswith('29c4080d') and seed['last_successful_build']['deb_sha256']==seed['validated']['deb_sha256'])
check('[s20] seed records #31 as first success', seed['last_successful_build']['ci_run']==39976822670 and seed['last_successful_build']['status']=='BUILD_VERIFIED_CANDIDATE')

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
print(f'MAINTENANCE-STATIC PASS={PASS} FAIL={fail}')
sys.exit(1 if fail else 0)
