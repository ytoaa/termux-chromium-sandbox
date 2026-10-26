#!/usr/bin/env python3
"""Offline regression for exact historical-SHA publish authorization.

NO GitHub writes, no real tokens, no builds. Exercises the actual step body.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]
p = yaml.safe_load((ROOT / '.github/workflows/publish-release.yml').read_text())
steps = p['jobs']['publish']['steps']
matches = [s for s in steps if s.get('name', '').startswith('Authorize exact build-commit')]
assert len(matches) == 1
auth_step = matches[0]
script = auth_step['run'].replace('${{ github.repository }}', 'test/repo').replace(
    '${{ github.event.repository.default_branch }}', 'main')
execute = next(s for s in steps if s.get('name','').startswith('Execute (draft'))
summary = next(s for s in steps if s.get('name') == 'Summary')
PASS = 0
FAIL = 0
A = 'a'*40
B = 'b'*40
def check(name, success):
    global PASS, FAIL
    if success:
        PASS += 1
        print('PASS  ' + name)
    else:
        FAIL += 1
        print('FAIL  ' + name)

def run(source=A, main=A, auth='false', plan='publish', api_fail=False):
    with tempfile.TemporaryDirectory(prefix='pub-auth.') as td:
        wd = Path(td)
        (wd / 'publish-plan.json').write_text(json.dumps({'action': plan}))
        tool = wd / 'gh'
        tool.write_text('#!/bin/sh\n'
                        'if [ "$1" != api ]; then exit 14; fi\n'
                        'if [ "$MOCK_API_FAIL" = yes ]; then exit 15; fi\n'
                        'printf "%s\\n" "$MOCK_MAIN_SHA"\n')
        tool.chmod(0o755)
        env = dict(os.environ, PATH=str(wd)+os.pathsep+os.environ.get('PATH',''),
                   SOURCE_SHA=source, ELEVATED_TOKEN_CONFIGURED=auth,
                   MOCK_MAIN_SHA=main, MOCK_API_FAIL='yes' if api_fail else 'no',
                   GH_TOKEN='dummy-only-for-offline-test')
        r = subprocess.run(['bash','-c',script],cwd=wd,env=env,capture_output=True,text=True)
        return r.returncode,r.stdout+r.stderr

rc,out=run(source=A,main=A,auth='false')
check('[a1] head-pinned candidate with builtin token -> allowed',rc==0 and 'builtin token permitted' in out)
rc,out=run(source=A,main=B,auth='false')
check('[a2] historical SHA without secret -> FAIL CLOSED',rc!=0 and 'TCS_RELEASE_WORKFLOWS_TOKEN' in out)
rc,out=run(source=A,main=B,auth='true')
check('[a3] historical SHA with separate credential -> allowed',rc==0 and 'dedicated release token' in out)
rc,out=run(source='bad',main=A,auth='true')
check('[a4] malformed build SHA rejected EVEN with dedicated secret',rc!=0)
rc,out=run(source=A,main=A,auth='maybe')
check('[a5] unknown token flag rejected',rc!=0)
rc,out=run(source=A,main=A,auth='false',api_fail=True)
check('[a6] current HEAD API failure is fail-closed',rc!=0)
rc,out=run(source=A,main=B,auth='false',plan='already-published')
check('[a7] already-published idempotence needs no write token',rc==0)
rc,out=run(source=A,main=B,auth='false',plan='collision')
check('[a8] collision stays in publisher collision handler',rc==0)
rc,out=run(source=A,main=B,auth='false',plan='blocked-ownership')
check('[a9] foreign-draft case stays in publisher ownership handler',rc==0)
check('[a10] exact build SHA stays release target (no silent retarget)',
      "'--target', v['port_sha']" in (ROOT/'port/publish_release.py').read_text()
      and '--target main' not in (ROOT/'.github/workflows/publish-release.yml').read_text())
check('[a11] elevated secret isolated to execute env; publisher never requests actions:write',
      execute.get('env',{}).get('GH_TOKEN') ==
           "${{ secrets.TCS_RELEASE_WORKFLOWS_TOKEN || github.token }}"
      and auth_step.get('env',{}).get('GH_TOKEN') == '${{ github.token }}'
      and p['permissions'] == {'contents':'write','actions':'read'})
check('[a12] summary renders JSON with explicit jq identity filter',
      'jq -c . publish-result.json' in summary['run']
      and 'jq -c publish-result.json' not in summary['run'])
print(f'RELEASE-AUTH-TESTS PASS={PASS} FAIL={FAIL}')
raise SystemExit(1 if FAIL else 0)
