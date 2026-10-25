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

# [8] recipe prepare/audit on vendored build.sh (side-by-side identity + hook)
TREP="$WORK/termux"; mkdir -p "$TREP/x11-packages/chromium"
cp "$FIX/termux-build.sh" "$TREP/x11-packages/chromium/build.sh"
touch "$TREP/build-package.sh"; chmod +x "$TREP/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$TREP" >/dev/null 2>&1 \
  && python3 port/prepare_recipe.py audit --termux-dir "$TREP" >/dev/null 2>&1 \
  && pass "[8] recipe prepare+audit" || fail "[8] recipe"

# [10] generated recipe must be bash-parseable
fresh; TREP2="$WORK/termux2"; mkdir -p "$TREP2/x11-packages/chromium"
cp "$FIX/termux-build.sh" "$TREP2/x11-packages/chromium/build.sh"
touch "$TREP2/build-package.sh"; chmod +x "$TREP2/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$TREP2" >/dev/null 2>&1
bash -n "$TREP2/x11-packages/chromium-sandboxed/build.sh" \
  && pass "[10] generated recipe parses" || fail "[10] recipe syntax broken"

# [11] regression (run #7): generated recipe must KEEP upstream post_get_source
# body (cr-patches loop) — chaining, never shadowing.
fresh; TREP3="$WORK/termux3"; mkdir -p "$TREP3/x11-packages/chromium"
cp "$FIX/termux-build.sh" "$TREP3/x11-packages/chromium/build.sh"
touch "$TREP3/build-package.sh"; chmod +x "$TREP3/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$TREP3" >/dev/null 2>&1
g="$TREP3/x11-packages/chromium-sandboxed/build.sh"
grep -q 'termux_step_post_get_source_upstream()' "$g" \
  && grep -q 'cr-patches' "$g" \
  && [ "$(grep -c '^termux_step_post_get_source() {' "$g")" = "1" ] \
  && pass "[11] upstream post_get_source chained, not shadowed" \
  || fail "[11] clobber regression (upstream body lost or duplicate def)"

# [12] sandbox-disable patches must be excluded from the cr-patches loop
fresh2="$WORK/t12"; mkdir -p "$fresh2/x11-packages/chromium"
cp "$FIX/termux-build.sh" "$fresh2/x11-packages/chromium/build.sh"
touch "$fresh2/build-package.sh"; chmod +x "$fresh2/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$fresh2" >/dev/null 2>&1
grep -q "grep -v -e '1001-chromium-disable-sandbox' -e '1004-chromium-headless-disable-sandbox-by-default'" "$fresh2/x11-packages/chromium-sandboxed/build.sh" \
  && pass "[12] sandbox-disable patches excluded" || fail "[12] exclusion missing"

# [9] tampered recipe (hook removed) -> audit must fail
sed -i '/port hook (generated/,/port hook <<</d' "$TREP/x11-packages/chromium-sandboxed/build.sh"
python3 port/prepare_recipe.py audit --termux-dir "$TREP" >/dev/null 2>&1 \
  && fail "[9] tamper undetected" || pass "[9] recipe tamper detected"

# [13] Phase 2/3 gate: bpf_evidence.sh selftest (fake /proc fixtures)
out=$(bash port/bpf_evidence.sh selftest 2>&1); got=$?
[ $got -eq 0 ] && echo "$out" | grep -q '\[selftest\] PASS' \
  && pass "[13] bpf_evidence selftest" || { fail "[13] bpf_evidence selftest"; echo "$out"; }

# [14] bpf_evidence content contract: Phase 2/3 requirements must be encoded
be=port/bpf_evidence.sh
grep -q -- '--disable-seccomp-filter-sandbox' $be \
  && grep -q 'broker' $be \
  && grep -q 'No usable sandbox' $be \
  && grep -q -- '--no-sandbox' $be \
  && grep -q 'gpu-process' $be && grep -q 'utility' $be \
  && pass "[14] bpf_evidence encodes P2/P3 checks" || fail "[14] bpf_evidence contract"

# [15] marathon: generated recipe must wire cc_wrapper=sccache (run #10 post-mortem)
fresh; T15="$WORK/t15"; mkdir -p "$T15/x11-packages/chromium"
cp "$FIX/termux-build.sh" "$T15/x11-packages/chromium/build.sh"
touch "$T15/build-package.sh"; chmod +x "$T15/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$T15" >/dev/null 2>&1
g15="$T15/x11-packages/chromium-sandboxed/build.sh"
[ "$(grep -c 'cc_wrapper="sccache"' "$g15")" = "1" ]   && grep -q 'echo .cc_wrapper="sccache". >> $TERMUX_PKG_BUILDDIR/out/Release/args.gn' "$g15"   && python3 port/prepare_recipe.py audit --termux-dir "$T15" >/dev/null 2>&1   && pass "[15] cc_wrapper wired into args.gn (and audit enforces it)"   || fail "[15] sccache cc_wrapper wiring missing"

# [16] ci.sh build must (re)export the sccache volume IN-STEP + early evidence gate
grep -q 'TERMUX_DOCKER_RUN_EXTRA_ARGS="--volume $d/.sccache:/home/builder/.cache/sccache"' port/ci.sh   && grep -q 'SCCACHE DEAD' port/ci.sh   && grep -q 'sleep 1800' port/ci.sh   && grep -q 'SCCACHE ALIVE' port/ci.sh   && pass "[16] in-step volume export + 30min evidence watchdog" || fail "[16] ci.sh marathon contract"

# [17] run #11 false-failure regression: reaped-watchdog kill/wait must be || true
grep -q 'kill "$wpid" 2>/dev/null || true' port/ci.sh \
  && grep -q 'wait "$wpid" 2>/dev/null || true' port/ci.sh \
  && grep -q 'kill -KILL -"$bpid" 2>/dev/null || true' port/ci.sh \
  && pass "[17] set -e false-failure guarded" || fail "[17] unguarded kill/wait under set -e"

# [18] R3 bionic prctl allowlist (device-gate round-1 postmortem)
fresh
out=$(python3 $PORT apply --src "$WORK/src" 2>&1)
echo "$out" | grep -q 'APPLIED.*R3' \
  && out=$(python3 $PORT apply --src "$WORK/src" 2>&1) \
  && echo "$out" | grep -q 'ALREADY_PRESENT.*R3' \
  && grep -q 'PR_PAC_RESET_KEYS' "$WORK/src/sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.cc" \
  && grep -q '#if defined(__BIONIC__)' "$WORK/src/sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.cc" \
  && pass "[18] R3 bionic prctl applied+idempotent+guarded" || fail "[18] R3 bionic prctl"

# [19] R4 zygote passthrough (device-gate round-2: set_tid_address SYS_SECCOMP kill)
fresh
out=$(python3 $PORT apply --src "$W/src" 2>/dev/null); out=$(python3 $PORT apply --src "$WORK/src" 2>&1)
echo "$out" | grep -q 'APPLIED.*R4' \
  && grep -q 'kZygote' "$WORK/src/sandbox/policy/linux/sandbox_linux.cc" \
  && grep -q '#if defined(__BIONIC__)' "$WORK/src/sandbox/policy/linux/sandbox_linux.cc" \
  && python3 $PORT check --src "$WORK/src" >/dev/null 2>&1 \
  && pass "[19] R4 zygote passthrough applied+verified" || fail "[19] R4 zygote passthrough"

# [20] R5 stack-top prewarm (round-3 abort forensics: bionic pthread_getattr_np FATAL post-filter)
fresh
out=$(python3 $PORT apply --src "$WORK/src" 2>&1)
echo "$out" | grep -q 'APPLIED.*R5' \
  && grep -q 'GetStackEnd()' "$WORK/src/sandbox/policy/linux/sandbox_linux.cc" \
  && python3 $PORT check --src "$WORK/src" >/dev/null 2>&1 \
  && pass "[20] R5/R6 GetStackEnd prewarm applied+verified" || fail "[20] R5/R6 prewarm"

# [21] R7 bionic stack cache (round-5: IS_ANDROID-gated cache absent on os=linux)
fresh
out=$(python3 $PORT apply --src "$WORK/src" 2>&1)
echo "$out" | grep -q 'APPLIED.*R7 bionic stack cache (base)' \
  && grep -q '#if BUILDFLAG(IS_ANDROID) || defined(__BIONIC__)' "$WORK/src/base/debug/stack_trace.cc" \
  && grep -q '#if PA_BUILDFLAG(IS_ANDROID) || defined(__BIONIC__)' "$WORK/src/base/allocator/partition_allocator/src/partition_alloc/partition_alloc_base/debug/stack_trace.cc" \
  && python3 $PORT check --src "$WORK/src" >/dev/null 2>&1 \
  && pass "[21] R7 bionic stack cache applied+verified" || fail "[21] R7 bionic stack cache"

# [22] optional-file tolerance: PA copy absent must SKIP, not fail
fresh; rm -f "$WORK/src/base/allocator/partition_allocator/src/partition_alloc/partition_alloc_base/debug/stack_trace.cc"
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
[ $got -eq 0 ] && echo "$out" | grep -q 'SKIPPED.*PA copy' \
  && pass "[22] missing vendored PA file -> SKIPPED (not fatal)" || { fail "[22] optional-file handling"; echo "$out" | tail -3; }

# [23] R8 bionic stack-top cache + prewarm export (round-6: 3rd gnp site)
fresh
out=$(python3 $PORT apply --src "$WORK/src" 2>&1)
ST="$WORK/src/base/allocator/partition_allocator/src/partition_alloc/stack/stack.cc"
echo "$out" | grep -q 'APPLIED.*R8 bionic stack-top cache' \
  && grep -q 'g_termux_main_thread' "$ST" \
  && grep -q 'void\* TermuxPrewarmStackTop()' "$ST" \
  && grep -q 'TermuxPrewarmStackTop' "$WORK/src/sandbox/policy/linux/sandbox_linux.cc" \
  && python3 $PORT check --src "$WORK/src" >/dev/null 2>&1 \
  && pass "[23] R8 stack-top cache + prewarm wired" || fail "[23] R8 stack-top cache"

# [24] R8 must fail closed if the PA stack.cc is present but unpatched
fresh; ST2="$WORK/src/base/allocator/partition_allocator/src/partition_alloc/stack/stack.cc"
python3 - <<'PY' >/dev/null 2>&1
import pathlib,re
p=pathlib.Path("$ST2")
p.write_text(re.sub(r"#if defined\(__BIONIC__\)\n  // Termux seccomp-only bionic stack-top:.*?#endif\n", "", p.read_text(), flags=re.S))
PY
python3 $PORT check --src "$WORK/src" >/dev/null 2>&1 \
  && fail "[24] unpatched PA stack.cc passed verify" || pass "[24] unpatched PA stack.cc rejected"

# [25] bionic shield: recipe must chain post_make_install, build+install the shim,
#      and route bin/chromium-sandboxed through LD_PRELOAD (round-7 breakthrough)
fresh; T25="$WORK/t25"; mkdir -p "$T25/x11-packages/chromium"
cp "$FIX/termux-build.sh" "$T25/x11-packages/chromium/build.sh"
touch "$T25/build-package.sh"; chmod +x "$T25/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$T25" >/dev/null 2>&1
g25="$T25/x11-packages/chromium-sandboxed/build.sh"
[ "$(grep -c '^termux_step_post_make_install() {' "$g25")" = "1" ] \
  && grep -q 'termux_step_post_make_install_upstream' "$g25" \
  && grep -q 'libtermux-gnp-fix.so' "$g25" \
  && grep -q 'gnp_shim.c' "$g25" \
  && grep -q 'LD_PRELOAD' "$g25" \
  && [ -f "$T25/x11-packages/chromium-sandboxed/gnp_shim.c" ] \
  && bash -n "$g25" \
  && python3 port/prepare_recipe.py audit --termux-dir "$T25" >/dev/null 2>&1 \
  && pass "[25] bionic shield chained+shipped" || fail "[25] bionic shield"

# [26] shield regression: clobbering post_make_install (no upstream call) must be caught
sed -i 's/^\tterux_step_post_make_install_upstream$/\t:/; s/^\tterux_step_post_make_install_upstream$/\t:/' "$g25" 2>/dev/null
sed -i '/termux_step_post_make_install_upstream/d' "$g25"
python3 port/prepare_recipe.py audit --termux-dir "$T25" >/dev/null 2>&1 \
  && fail "[26] shield clobber undetected" || pass "[26] shield clobber detected"

# [27] run #25 regression: wrapper must live in its own file and bin/ must be
#      repointed at it; the real launcher must never receive the shield line
fresh; T27="$WORK/t27"; mkdir -p "$T27/x11-packages/chromium"
cp "$FIX/termux-build.sh" "$T27/x11-packages/chromium/build.sh"
touch "$T27/build-package.sh"; chmod +x "$T27/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$T27" >/dev/null 2>&1
g27="$T27/x11-packages/chromium-sandboxed/build.sh"
grep -q 'local _wrap="\$_p/chromium-shield-wrapper.sh"' "$g27" \
  && grep -q 'rm -f "\$TERMUX_PREFIX/bin/chromium-sandboxed"' "$g27" \
  && grep -q 'ln -sfr "\$_wrap"' "$g27" \
  && grep -q 'clobbered' "$g27" \
  && pass "[27] wrapper is a separate file, bin repointed, recursion guard" \
  || fail "[27] launcher clobber regression"

# [28] R9a network-policy rule: APPLIED + marker + idempotence + verify gate
fresh
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
F="$WORK/src/sandbox/policy/linux/bpf_network_policy_linux.cc"
[ $got -eq 0 ] && echo "$out" | grep -q 'APPLIED.*R9a' \
  && grep -qF 'Termux seccomp-only net-sockopt:' "$F" \
  || { fail "[28] R9a apply/marker"; echo "$out"; }
out=$(python3 $PORT apply --src "$WORK/src" 2>&1)
echo "$out" | grep -q 'ALREADY_PRESENT.*R9a' \
  && python3 $PORT check --src "$WORK/src" >/dev/null 2>&1 \
  && pass "[28] R9a applied+verified+idempotent" || fail "[28] R9a (idempotence/verify)"

# [29] R9a anchor drift -> PORT ERROR (fail closed: candidate must not ship unpatched)
fresh
sed -i 's/Case(SO_ERROR, Allow())/Case(SO_ERRORTAMP, Allow())/' "$WORK/src/sandbox/policy/linux/bpf_network_policy_linux.cc"
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
[ $got -ne 0 ] && echo "$out" | grep -q 'R9a' && pass "[29] R9a anchor drift -> PORT ERROR" || { fail "[29] R9a drift"; echo "$out"; }

# [29b] R9a missing file -> PORT ERROR (network policy is REQUIRED, not optional)
fresh; rm "$WORK/src/sandbox/policy/linux/bpf_network_policy_linux.cc"
out=$(python3 $PORT apply --src "$WORK/src" 2>&1); got=$?
[ $got -ne 0 ] && echo "$out" | grep -qi 'missing\|R9a' && pass "[29b] R9a missing file -> PORT ERROR" || { fail "[29b] R9a missing"; echo "$out"; }

# [30] R9a scope guard: exactly one SO_DOMAIN pair, bionic block get-side only
fresh; python3 $PORT apply --src "$WORK/src" >/dev/null 2>&1
F="$WORK/src/sandbox/policy/linux/bpf_network_policy_linux.cc"
n_dom=$(grep -c 'Case(SO_DOMAIN, Allow())' "$F")
n_mark=$(grep -c 'Termux seccomp-only net-sockopt:' "$F")
setfn=$(awk '/RestrictSetSockoptForNetworkService\(\)/,/^}/' "$F" | grep -c '__BIONIC__')
[ "$n_dom" -eq 1 ] && [ "$n_mark" -eq 1 ] && [ "$setfn" -eq 0 ] \
  && ! grep -q 'SO_PROTOCOL, Allow()' "$F" \
  && pass "[30] R9a scope: 1 pair, get-side only, no SO_PROTOCOL/set drift" \
  || fail "[30] R9a scope drift (dom=$n_dom mark=$n_mark set-bionic=$setfn)"

# [31] ledger contract: port.toml must be valid TOML (parser verification)
python3 -c "import tomllib,sys; d=tomllib.load(open('port/port.toml','rb')); sys.exit(0 if all(k in d.get('rules',{}) for k in ('r1','r2','r3','r4','r5','r7','r8','r9a','r9b')) and 'items' in d.get('forbidden',{}) else 1)" \
  && pass "[31] port.toml parses (tomllib) + rules r1-r9a + forbidden.items present" \
  || fail "[31] port.toml invalid TOML / contract keys missing"

# [32] R9b wrapper rule: generated shield wrapper carries the guarded
# PULSE_SERVER export (user-set incl. empty respected; -S socket checks;
# unix: form; exec line & LD_PRELOAD path preserved; single wrapper).
T32=$WORK/t32; rm -rf "$T32"; mkdir -p "$T32/x11-packages/chromium" "$T32/x11-packages/chromium-sandboxed"
cp "$FIX/termux-build.sh" "$T32/x11-packages/chromium/build.sh"
touch "$T32/build-package.sh"; chmod +x "$T32/build-package.sh"
python3 port/prepare_recipe.py prepare --termux-dir "$T32" >/dev/null 2>&1
G32="$T32/x11-packages/chromium-sandboxed/build.sh"
grep -q 'Termux seccomp-only audio-pulse-server:' "$G32" \
  && grep -q '\[ -z "${PULSE_SERVER+x}" \]' "$G32" \
  && grep -q 'case "${XDG_RUNTIME_DIR:-}" in' "$G32" \
  && grep -q '\[ -S "$XDG_RUNTIME_DIR/pulse/native" \]' "$G32" \
  && grep -q 'tmp/pulse/native' "$G32" \
  && grep -q 'export PULSE_SERVER="unix:$_pas"' "$G32" \
  && [ "$(grep -c 'exec "$_p/chromium-launcher.sh" "$@"' "$G32")" -eq 1 ] \
  && grep -q 'export LD_PRELOAD="$_p/libtermux-gnp-fix.so' "$G32" \
  && pass "[32] R9b wrapper: guarded export + unix: + exec/LD_PRELOAD intact" \
  || fail "[32] R9b wrapper markers"

# [33] R9b behavioural: run the generated wrapper against a stub tree.
mksock() { python3 -c "import socket,sys;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1])" "$1"; }
STUB=$WORK/stub; rm -rf "$STUB"
SB="$STUB/files/usr/lib/chromium-sandboxed"; mkdir -p "$SB"
# extract the wrapper body from the generated recipe heredoc
sed -n '/cat > "\$_wrap" <<.SHIMWRAP./,/^SHIMWRAP$/p' "$G32" | sed '1d;$d' > "$SB/chromium-shield-wrapper.sh"
chmod +x "$SB/chromium-shield-wrapper.sh"
printf '#!/usr/bin/env bash\necho "PULSE=[$PULSE_SERVER] LD=[${LD_PRELOAD%%:*}]"\n' > "$SB/chromium-launcher.sh"
chmod +x "$SB/chromium-launcher.sh"
printf "void _termux_stub(void){}\n" | clang -shared -x c - -o "$SB/libtermux-gnp-fix.so" 2>/dev/null || cp "$(command -v bash)" "$SB/libtermux-gnp-fix.so"
W="$SB/chromium-shield-wrapper.sh"; XP="${PREFIX:-/data/data/com.termux/files/usr}"
o=$(PREFIX=$STUB/files/usr env -u PULSE_SERVER -u XDG_RUNTIME_DIR bash "$W" 2>&1)
[ "$o" = "PULSE=[] LD=[$SB/libtermux-gnp-fix.so]" ] && pass "[33a] no socket -> no-op, LD_PRELOAD kept" || fail "[33a] $o"
mkdir -p "$STUB/xdg/pulse" "$STUB/files/usr/tmp/pulse"
mksock "$STUB/xdg/pulse/native"; mksock "$STUB/files/usr/tmp/pulse/native"
o=$(PREFIX=$STUB/files/usr XDG_RUNTIME_DIR=$STUB/xdg env -u PULSE_SERVER bash "$W" 2>&1)
[ "$o" = "PULSE=[unix:$STUB/xdg/pulse/native] LD=[$SB/libtermux-gnp-fix.so]" ] && pass "[33b] XDG socket preferred" || fail "[33b] $o"
rm -f "$STUB/xdg/pulse/native"
o=$(PREFIX=$STUB/files/usr XDG_RUNTIME_DIR=$STUB/xdg env -u PULSE_SERVER bash "$W" 2>&1)
[ "$o" = "PULSE=[unix:$STUB/files/usr/tmp/pulse/native] LD=[$SB/libtermux-gnp-fix.so]" ] && pass "[33c] PREFIX tmp fallback" || fail "[33c] $o"
o=$(PREFIX=$STUB/files/usr env -u PULSE_SERVER XDG_RUNTIME_DIR=$STUB/nonexistent bash "$W" 2>&1)
[ "$o" = "PULSE=[unix:$STUB/files/usr/tmp/pulse/native] LD=[$SB/libtermux-gnp-fix.so]" ] && pass "[33d] missing XDG dir -> fallback" || fail "[33d] $o"
o=$(PREFIX=$STUB/files/usr env PULSE_SERVER= XDG_RUNTIME_DIR=$STUB/xdg bash "$W" 2>&1)
[ "$o" = "PULSE=[] LD=[$SB/libtermux-gnp-fix.so]" ] && pass "[33e] user empty PULSE_SERVER respected" || fail "[33e] $o"
o=$(PREFIX=$STUB/files/usr env "PULSE_SERVER=tcp:1.2.3.4" bash "$W" 2>&1)
[ "$o" = "PULSE=[tcp:1.2.3.4] LD=[$SB/libtermux-gnp-fix.so]" ] && pass "[33f] user PULSE_SERVER kept" || fail "[33f] $o"
SP="$STUB/sp ace/pulse"; mkdir -p "$SP"; mksock "$SP/native"
o=$(PREFIX=$STUB/files/usr env -u PULSE_SERVER XDG_RUNTIME_DIR="$STUB/sp ace" bash "$W" 2>&1)
[ "$o" = "PULSE=[unix:$SP/native] LD=[$SB/libtermux-gnp-fix.so]" ] && pass "[33g] spaces in path (quoting)" || fail "[33g] $o"
XDG_RUNTIME_DIR=$STUB/xdg PREFIX=$STUB/files/usr bash "$W" >/dev/null 2>&1 && [ -x "$SB/chromium-launcher.sh" ] \
  && ! grep -q 'libtermux-gnp-fix.so' "$SB/chromium-launcher.sh" \
  && pass "[33h] wrapper!=launcher (no recursion clobber)" || fail "[33h]"

# [34] R9b security guard: wrapper block must never contain widening tokens.
BODY=$(sed -n '/cat > "\$_wrap" <<.SHIMWRAP./,/^SHIMWRAP$/p' "$G32")
! echo "$BODY" | grep -qE -- '--no-sandbox|--disable-seccomp-filter-sandbox|fchmod|ReadWriteCreateRecursive|setuid' \
  && pass "[34] R9b wrapper: no forbidden widening tokens" \
  || fail "[34] R9b forbidden token in wrapper"

# [35] Round 15/16 maintenance engine scenario tests (offline, mocked).
python3 "port/tests/maintenance_test.py" 2>&1 | grep -q '^MAINTENANCE-TESTS PASS=70 FAIL=0$' \
  && pass "[35] maintenance engine 70/70 scenarios" \
  || fail "[35] maintenance engine scenarios"

# [36] Round 15/16 static verification (mode fail-closed matrix + migrations).
python3 "port/tests/maintenance_static_test.py" 2>&1 | grep -q '^MAINTENANCE-STATIC PASS=71 FAIL=0$' \
  && pass "[36] maintenance static workflow+seed 71/71" \
  || fail "[36] maintenance static checks"

# [37] TERMUX_PKG_REVISION injection behavior (default-off reproducibility).
if bash "port/tests/maintenance_revision_test.sh" 2>&1 | grep -c '^PASS  \[37' | grep -qx 4; then
  pass "[37] revision injection default/inject/reject"
else
  fail "[37] revision injection suite"
fi

# [38] Round 15.3 Actions-equivalent integration simulation (file round-trips).
python3 "port/tests/maintenance_integration_test.py" 2>&1 | grep -q '^MAINTENANCE-INTEGRATION PASS=25 FAIL=0$' \
  && pass "[38] maintenance integration simulation 25/25" \
  || fail "[38] maintenance integration simulation"

# [39] Phase B remediation: real-recipe fixtures + typed issues guard + called-job classification.
bash "port/tests/maintenance_recipe_test.sh" 2>&1 | tail -1 | grep -q '^RECIPE-CLASSIFY-TESTS RC=0$' \
  && pass "[39] recipe/fixtures/classify suite (A/B/D)" \
  || fail "[39] recipe/fixtures/classify suite"

# [40] C.2-A verdict gate matrix (fails must produce nonzero rc; optionals never flip).
python3 "port/tests/phase_c/gui_extra_verdict_test.py" 2>&1 | tail -1 | grep -q '^VERDICT-TESTS-RC=0$' \
  && pass "[40] gui_extra verdict matrix 11/11" \
  || fail "[40] gui_extra verdict matrix"

# [41] Round 16 Stage C REQUIRED simulation matrix (13 scenarios: identical/metadata
# edits SKIP, real edits BUILD, blocked BLOCK, fetch fail + unclear migration fail-closed).
python3 "port/tests/maintenance_signature_test.py" 2>&1 | grep -q '^MAINTENANCE-SIGNATURE PASS=18 FAIL=0$' \
  && pass "[41] build-signature v2 + migration simulation (13 scenarios, 18 checks)" \
  || fail "[41] build-signature simulation matrix"

# [42] Round 17 pre-release publisher (required 19-row scenario table: publish
# gating, integrity refusals, dedup/collision, draft-safe recovery, gates).
python3 "port/tests/publish_test.py" 2>&1 | grep -q '^PUBLISH-TESTS PASS=43 FAIL=0$' \
  && pass "[42] pre-release publisher scenarios (19-row table, 43 checks)" \
  || fail "[42] pre-release publisher scenarios"

exit $rc
