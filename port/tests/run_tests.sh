#!/usr/bin/env bash
# Self-test harness for chromium_sandbox_port.py against vendored fixtures.
set -u
cd "$(dirname "$0")/../.."   # repo root
PORT=port/chromium_sandbox_port.py
FIX=port/tests/fixtures
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
rc=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; rc=1; }

fresh() { rm -rf "$WORK/src"; mkdir -p "$WORK/src"; cp -r "$FIX/." "$WORK/src/"; }

# [1] apply: both rules APPLIED
fresh
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
[ $got -eq 0 ] && echo "$out" | grep -q 'APPLIED.*R1' && echo "$out" | grep -q 'APPLIED.*R2' \
  && pass "[1] apply -> R1,R2 APPLIED" || { fail "[1] apply"; echo "$out"; }

# [2] idempotent: ALREADY_PRESENT
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
[ $got -eq 0 ] && echo "$out" | grep -q 'ALREADY_PRESENT.*R1' && echo "$out" | grep -q 'ALREADY_PRESENT.*R2' \
  && pass "[2] re-apply -> ALREADY_PRESENT" || { fail "[2] idempotence"; echo "$out"; }

# [3] verify passes after apply
python3 $PORT check --src "$WORK/src" >/dev/null 2>&1 && pass "[3] verify after apply" || fail "[3] verify"

# [4] drift on anchor -> PORT ERROR (fail closed)
fresh
sed -i 's/LOG(FATAL)$/LOG(FATAL_TOAST)/' "$WORK/src/content/browser/zygote_host/zygote_host_impl_linux.cc"
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
[ $got -ne 0 ] && echo "$out" | grep -q 'PORT ERROR' && pass "[4] anchor drift -> PORT ERROR" || { fail "[4] drift detection"; echo "$out"; }

# [5] missing file -> PORT ERROR
fresh; rm "$WORK/src/sandbox/policy/linux/sandbox_linux.cc"
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
[ $got -ne 0 ] && echo "$out" | grep -q 'missing' && pass "[5] missing file -> PORT ERROR" || fail "[5] missing-file detection"

# [6] anti-injection gate: rogue appender detected
fresh
python3 $PORT apply --src "$WORK/src" >/dev/null 2>&1
mkdir -p "$WORK/src/chrome/browser/evil"; cat > "$WORK/src/chrome/browser/evil/rogue.cc" <<'CC'
void Inject() { command_line->AppendSwitch(switches::kNoSandbox); }
CC
out=$(python3 $PORT check --src "$WORK/src" --scan chrome 2>&1); got=$?
[ $got -ne 0 ] && echo "$out" | grep -q 'anti-injection' && pass "[6] anti-injection gate" || { fail "[6] anti-injection"; echo "$out"; }

# [7] patched binary markers present for future deb gate
grep -qF 'Termux seccomp-only sandbox:' "$WORK/../$(basename $WORK)" 2>/dev/null
fresh; python3 $PORT apply --src "$WORK/src" >/dev/null 2>&1
grep -qF 'Termux seccomp-only sandbox:' "$WORK/src/content/browser/zygote_host/zygote_host_impl_linux.cc" \
  && grep -qF 'Termux seccomp-only port:' "$WORK/src/sandbox/policy/linux/sandbox_linux.cc" \
  && pass "[7] marker strings present" || fail "[7] markers"

exit $rc
