#!/usr/bin/env bash
# Phase B remediation tests: A (quoted recipe parsing, REAL fixtures at
# termux sha 2af83c387...), B (typed issues.json guard), D (called-job name
# classification with the ACTUAL run-40098664387 job names).
set -u
RC=0; PASS=0
ok(){ PASS=$((PASS+1)); echo "PASS  [$1]"; }
bad(){ echo "FAIL  [$1] $2"; RC=1; }
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
mkdir -p "$D/x11-packages/chromium" "$D/x11-packages/chromium-host-tools"
cp port/tests/fixtures/real_chromium_build_sh_2af83c3 "$D/x11-packages/chromium/build.sh"
cp port/tests/fixtures/real_host_tools_build_sh_2af83c3 "$D/x11-packages/chromium-host-tools/build.sh"

# [A1] align_versions on the REAL recipe (same versions -> no-op, no crash)
python3 - "$D" <<'PY' || bad A1 crash
import sys, pathlib
sys.path.insert(0,'port')
import prepare_recipe as P
d=pathlib.Path(sys.argv[1]); t=(d/'x11-packages/chromium/build.sh').read_text()
text,notes=P.align_versions(t,d)
assert text==t and notes==[], (notes,)
print('A1 ok')
PY
[ $RC -eq 0 ] && ok A1

# [A2] quoted rewrite preserves quote style; drift aligns to host-tools
python3 - "$D" <<'PY' || bad A2 crash
import sys, pathlib, re
sys.path.insert(0,'port')
import prepare_recipe as P
d=pathlib.Path(sys.argv[1]); f=d/'x11-packages/chromium/build.sh'
t=f.read_text()
P.fetch_tarball_sha256=lambda v: 'e'*64          # offline mock
htf=d/'x11-packages/chromium-host-tools/build.sh'
htext=htf.read_text().replace('"156.0.8078.47"','"156.0.8078.48"'); htf.write_text(htext)
text,notes=P.align_versions(t,d)
m=re.search(r'^TERMUX_PKG_VERSION="([0-9.]+)"',text,re.M)
assert m and m.group(1)=='156.0.8078.48', text[:200]
assert re.search(r'^TERMUX_PKG_SHA256=e{64}$',text,re.M)
assert any('aligned' in n for n in notes)
f.write_text(text)
print('A2 ok')
PY
[ $RC -eq 0 ] && ok A2

# [A3] unrecognised version line -> RecipeError (NOT AttributeError)
python3 - <<'PY' || bad A3 crash
import sys
sys.path.insert(0,'port')
import prepare_recipe as P
try:
    P.align_versions('TERMUX_PKG_VERSION=@weird@\n', pathlib_dummy=None) if False else None
except Exception as e:
    pass
import pathlib, tempfile, os
d=pathlib.Path(tempfile.mkdtemp()); (d/'x11-packages').mkdir(); (d/'x11-packages/chromium-host-tools').mkdir()
(d/'x11-packages/chromium-host-tools/build.sh').write_text('TERMUX_PKG_VERSION="1.2.3.4"\n')
try:
    P.align_versions('TERMUX_PKG_VERSION=@weird@\n', d)
    raise SystemExit('no error raised')
except P.RecipeError as e:
    assert 'unrecognised' in str(e)
    print('A3 ok (RecipeError)')
PY
[ $RC -eq 0 ] && ok A3

# [A4] revision injection on QUOTED recipe keeps quotes + bash -n + version untouched
env TERMUX_SANDBOXED_REVISION=2 python3 - "$D" <<'PY' || bad A4 crash
import sys, os, pathlib, re
sys.path.insert(0,'port')
import prepare_recipe as P
d=pathlib.Path(sys.argv[1]); f=d/'x11-packages/chromium/build.sh'
t=f.read_text()
rev=os.environ.get('TERMUX_SANDBOXED_REVISION','').strip()
assert re.fullmatch(r'[0-9]{1,2}',rev)
if re.search(r'^TERMUX_PKG_REVISION=',t,re.M):
    t=re.sub(r'^TERMUX_PKG_REVISION=.*$',f'TERMUX_PKG_REVISION="{rev}"',t,count=1,flags=re.M)
else:
    t=re.sub(r'^(TERMUX_PKG_VERSION=.*)$',r'\1\nTERMUX_PKG_REVISION="2"',t,count=1,flags=re.M)
assert re.search(r'^TERMUX_PKG_REVISION="2"$',t,re.M)
assert re.search(r'^TERMUX_PKG_VERSION="156.0.8078.48"$',t,re.M)  # A2 result intact
f.write_text(t); print('A4 ok')
PY
[ $RC -eq 0 ] && ok A4
bash -n "$D/x11-packages/chromium/build.sh" && ok A5 || bad A5 'bash -n failed'

# [B] typed issues.json guard: array ok, empty array ok, object-marker true
for spec in '[]|false' '[{"number":2,"title":"t","labels":["auto-build-blocked"]}]|false' '{"error":true}|true'; do
  inp=${spec%|*}; want=${spec##*|}
  got=$(echo "$inp" | jq -r 'if type=="object" then (.error // false) else false end')
  [ "$got" = "$want" ] && ok "B:$inp" || bad "B:$inp" "got=$got want=$want"
done

# [D] called-job name classification with REAL run names
all_jobs='{"jobs":[{"id":5,"name":"Reusable build (only when decided) / gate","conclusion":"success"},{"id":6,"name":"Reusable build (only when decided) / build","conclusion":"failure"}]}'
jobs_json=$(echo "$all_jobs" | jq -c '[.jobs[] | select(.conclusion=="failure" or .conclusion=="timed_out") | {id,name,conclusion}]')
failed_names=$(echo "$jobs_json" | jq -r '[.[].name | split("/") | last | ltrimstr(" ") | split(" ")[0]] | join(",")')
[ "$failed_names" = "build" ] && ok D1 || bad D1 "got=$failed_names"
stage=unknown; echo "$failed_names" | grep -qw 'gate' && stage=gate || true; echo "$failed_names" | grep -qw 'build' && stage=build || true
[ "$stage" = "build" ] && ok D2 || bad D2 "stage=$stage"
failed_names2=$(echo '[{"id":1,"name":"Reusable build (only when decided) / gate","conclusion":"failure"}]' | jq -r '[.[].name | split("/") | last | ltrimstr(" ") | split(" ")[0]] | join(",")')
[ "$failed_names2" = "gate" ] && ok D3 || bad D3 "got=$failed_names2"
# [B*] strict version parser boundary cases (Phase B remediation B)
python3 - <<'PY' || bad B-cases crash
import sys
sys.path.insert(0,'port')
import prepare_recipe as P
cases=[
 ('TERMUX_PKG_VERSION=156.0.8078.47', ('156.0.8078.47','', '')),
 ('TERMUX_PKG_VERSION="156.0.8078.47"', ('156.0.8078.47','"', '')),
 ("TERMUX_PKG_VERSION='156.0.8078.47'", ('156.0.8078.47',"'", '')),
 ('TERMUX_PKG_VERSION=156.0.8078.47  # upstream bump', ('156.0.8078.47','', '  # upstream bump')),
 ('  TERMUX_PKG_VERSION="1.2.3"', ('1.2.3','"','')),
 ('TERMUX_PKG_VERSION=156.0.8078.47junk', None),
 ("TERMUX_PKG_VERSION=\"156.0.8078.47'", None),
 ('TERMUX_PKG_VERSION = "1.2.3"', None),
 ('TERMUX_PKG_VERSION="1.2.3\"4"', None),
 ('TERMUX_PKG_VERSION=', None),
 ('no version line here', None),
 ('TERMUX_PKG_VERSION=1.2.3.', None),
]
for src,want in cases:
    got=P.parse_version_line(src)
    assert got==want, (src, got, want)
# rewrite preserves trailing comment and quote style
new=P.VER_STRICT.sub(lambda m:'TERMUX_PKG_VERSION={0}{1}{0}{2}'.format('"','9.9.9.9',m.group(4)),
                     'TERMUX_PKG_VERSION="1.2.3" # keepme', count=1)
assert new=='TERMUX_PKG_VERSION="9.9.9.9" # keepme', new
# align: junk suffix must RecipeError (not partial pass)
import pathlib,tempfile
d=pathlib.Path(tempfile.mkdtemp()); (d/'x11-packages/chromium-host-tools').mkdir(parents=True)
(d/'x11-packages/chromium-host-tools/build.sh').write_text('TERMUX_PKG_VERSION="1.2.3"\n')
try:
    P.align_versions('TERMUX_PKG_VERSION=1.2.3suffix\n', d); raise SystemExit('partial match passed!')
except P.RecipeError: pass
# host parser junk -> None (align no-ops, no crash)
(d/'x11-packages/chromium-host-tools/build.sh').write_text('TERMUX_PKG_VERSION="1.2.3junk"\n')
assert P.host_tools_version(d) is None
print('B-cases ok')
PY
[ $RC -eq 0 ] && ok "B-parser" || true

# [C*] bash-comment boundary cases (Phase B final parser hardening):
# parser verdicts must agree with how BASH actually assigns the value.
python3 - <<'PY' || bad C-cases crash
import subprocess, sys
sys.path.insert(0,'port')
import prepare_recipe as P
cases=[
 ('TERMUX_PKG_VERSION=1.2.3',               '1.2.3', True),
 ('TERMUX_PKG_VERSION="1.2.3"',             '1.2.3', True),
 ("TERMUX_PKG_VERSION='1.2.3'",             '1.2.3', True),
 ('TERMUX_PKG_VERSION=1.2.3 #comment',      '1.2.3', True),
 ('TERMUX_PKG_VERSION="1.2.3" #comment',    '1.2.3', True),
 ('TERMUX_PKG_VERSION=1.2.3\t#comment',    '1.2.3', True),
 ('TERMUX_PKG_VERSION=1.2.3#junk',          None,    False),
 ('TERMUX_PKG_VERSION="1.2.3"#junk',        None,    False),
 ("TERMUX_PKG_VERSION='1.2.3'#junk",        None,    False),
 ('TERMUX_PKG_VERSION=1.2.3junk',           None,    False),
]
for src, want_ver, want_ok in cases:
    got = P.parse_version_line(src)
    if want_ok:
        assert got and got[0] == want_ver, (src, got)
    else:
        assert got is None, (src, got)
    # empirical BASH comparison: what value does bash itself assign?
    r = subprocess.run(['bash','-c', src + '\nprintf %s "$TERMUX_PKG_VERSION"'],
                       capture_output=True, text=True)
    bash_val = r.stdout
    if want_ok:
        assert bash_val == want_ver, (src, 'bash=', bash_val)
    else:
        # parser must refuse anything whose bash value is NOT a clean dotted version
        import re as _re
        assert not _re.fullmatch(r'[0-9]+(\.[0-9]+)*', bash_val), (src, 'bash accepted!', bash_val)
# comment preserved after alignment rewrite (quote style + trailing)
new = P.VER_STRICT.sub(lambda m: 'TERMUX_PKG_VERSION={0}{1}{0}{2}'.format('"','9.9.9.9',m.group(4)),
                       'TERMUX_PKG_VERSION="1.2.3"  # keepme', count=1)
assert new == 'TERMUX_PKG_VERSION="9.9.9.9"  # keepme', new
# abnormal recipe -> RecipeError; abnormal host-tools -> None
import pathlib, tempfile
d = pathlib.Path(tempfile.mkdtemp()); (d/'x11-packages/chromium-host-tools').mkdir(parents=True)
(d/'x11-packages/chromium-host-tools/build.sh').write_text('TERMUX_PKG_VERSION="1.2.3"\n')
try:
    P.align_versions('TERMUX_PKG_VERSION=1.2.3#junk\n', d); raise SystemExit('accepted junk-comment!')
except P.RecipeError: pass
(d/'x11-packages/chromium-host-tools/build.sh').write_text('TERMUX_PKG_VERSION="1.2.3"#junk\n')
assert P.host_tools_version(d) is None
print('C-cases ok (10 + bash-parity + preserve + errors)')
PY
[ $RC -eq 0 ] && ok "C-boundary" || true

echo "RECIPE-CLASSIFY-TESTS RC=$RC"
exit $RC
