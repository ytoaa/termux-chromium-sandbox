#!/usr/bin/env bash
# Phase 2/3 BPF evidence gate for the Termux Chromium seccomp-only port.
#
# Phase 2 (Renderer BPF 활성화 입증):
#   - per-process census: Seccomp / Seccomp_filters / NoNewPrivs / PPid, exe-verified
#   - broker channel proof: socket inode shared between zygote fds and renderer fds
#   - causality control: --disable-seccomp-filter-sandbox must drop renderer
#     filter count (proves the 2nd filter is Chromium's own BPF, not the OS)
#   - marker proof: "Termux seccomp-only" string present in binary (R1/R2 linked)
#   - injection tripwire: runtime --no-sandbox in the browser cmdline = FAIL
#     (this is exactly what termux cr-patches 1001/1004 used to inject)
# Phase 3 (GPU·Utility·Network 확대):
#   - gpu-process / utility filter census (recommended >=2, non-fatal WARN)
#   - network: informational (Linux network sandbox is opt-in upstream)
# Failure diagnostics follow the DESIGN.md priority:
#   R1 marker -> R2 marker -> zygote presence -> No usable sandbox / SIGSYS log.
#
# NEVER dpkg-install. Run against a deb EXTRACTED by device_gate.sh.
# PROC_ROOT env lets the harness fake /proc for offline testing.
set -uo pipefail
PROC_ROOT=${PROC_ROOT:-/proc}

usage() { echo "usage: bpf_evidence.sh <chrome-bin> [--ws DIR] | bpf_evidence.sh selftest"; exit 2; }

census() { # $1=bin(exe-verified) $2=out-file
  # Phase C measurement fix: Linux zygote children fork WITHOUT execv, so
  # sandboxed renderer children keep --type=zygote in cmdline. Two-pass:
  # collect rows + zygote pid set, then reclassify rows whose PPid is a
  # zygote as renderer (the sandboxed spawn class). Real zygotes (parent =
  # browser) stay zygote. Pure classification; no policy involvement.
  local bin=$1 out=$2
  local pid exe t f s n pp cmd
  local -a rows=()
  # Instrumentation fix (2026-10-27 R11 audit): census APPENDS. A reused ws
  # would silently accumulate stale rows and inflate max_field/presence
  # verdicts (false-PASS risk). Truncate: one census call = one snapshot.
  : > "$out"
  local zypids=" "
  for pid in $(ls "$PROC_ROOT" 2>/dev/null | grep -E '^[0-9]+$'); do
    exe=$(readlink "$PROC_ROOT/$pid/exe" 2>/dev/null) || continue
    [ "$exe" = "$bin" ] || continue
    cmd=$(tr '\0' '\n' < "$PROC_ROOT/$pid/cmdline" 2>/dev/null)
    t=$(printf '%s\n' "$cmd" | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
    f=$(awk '/^Seccomp_filters:/{print $2}' "$PROC_ROOT/$pid/status" 2>/dev/null)
    s=$(awk '/^Seccomp:/{print $2}' "$PROC_ROOT/$pid/status" 2>/dev/null)
    n=$(awk '/^NoNewPrivs:/{print $2}' "$PROC_ROOT/$pid/status" 2>/dev/null)
    pp=$(awk '/^PPid:/{print $2}' "$PROC_ROOT/$pid/status" 2>/dev/null)
    rows+=("$pid|${t:-browser}|${f:-0}|${s:-0}|${n:-0}|${pp:-0}|$(printf '%s\n' "$cmd" | grep -c -- '--no-sandbox')")
    [ "${t:-}" = zygote ] && zypids="$zypids$pid "
  done
  local r rp rt rf rs rn rpp rnsb
  for r in "${rows[@]}"; do
    IFS='|' read -r rp rt rf rs rn rpp rnsb <<<"$r"
    if [ "$rt" = zygote ] && [ "$rp" != "$rpp" ] && case "$zypids" in *" $rpp "*) true;; *) false;; esac; then
      rt=renderer
    fi
    echo "$rt $rf $rs $rn $rpp $rnsb" >> "$out"
  done
}

broker_channel() { # $1=census-file $2=zygote-pids-list (unused; re-scan fds)
  # A live sandboxed renderer holds a socketpair fd whose inode also appears
  # in the zygote (broker) fd table. Shared inode > 0 => broker IPC wired.
  local rp zpid ino common=0
  for rp in $(pids_of "$CHROME" renderer); do
    for zpid in $(pids_of "$CHROME" zygote); do
      while read -r ino; do
        [ -n "$ino" ] || continue
        if ls -l "$PROC_ROOT/$zpid/fd" 2>/dev/null | grep -q "socket:\[$ino\]"; then
          common=$((common+1)); break
        fi
      done < <(ls -l "$PROC_ROOT/$rp/fd" 2>/dev/null | sed -n 's/.*socket:\[\([0-9]*\)\].*/\1/p')
    done
  done
  echo "$common"
}

pids_of() { # $1=bin $2=type → pids
  local pid exe cmd
  for pid in $(ls "$PROC_ROOT" 2>/dev/null | grep -E '^[0-9]+$'); do
    exe=$(readlink "$PROC_ROOT/$pid/exe" 2>/dev/null) || continue
    [ "$exe" = "$1" ] || continue
    cmd=$(tr '\0' '\n' < "$PROC_ROOT/$pid/cmdline" 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
    if [ "$cmd" = "$2" ]; then echo "$pid"; continue; fi
    if [ "$2" = renderer ] && [ "$cmd" = zygote ]; then
      ppid=$(awk '/^PPid:/{print $2}' "$PROC_ROOT/$pid/status" 2>/dev/null)
      for z in $(pids_of "$1" zygote); do [ "$ppid" = "$z" ] && { echo "$pid"; break; }; done
    fi
  done
}

spawn_probe() { # $1=bin $2=label $3=ws $4..=extra chrome flags
  local bin=$1 label=$2 ws=$3; shift 3
  local udd="$ws/udd-ev-$label"
  rm -rf "$udd"
  setsid "$bin" --headless=new --user-data-dir="$udd" --no-first-run \
      --disable-dev-shm-usage "$@" >"$ws/ev-$label.log" 2>&1 &
  EV_GPID=$!
  ( sleep 75; kill -KILL -"$EV_GPID" 2>/dev/null ) & EV_WPID=$!
  sleep 14
}
stop_probe() { kill -TERM -"$EV_GPID" 2>/dev/null; sleep 2; kill -KILL -"$EV_GPID" 2>/dev/null; kill "$EV_WPID" 2>/dev/null; wait "$EV_WPID" 2>/dev/null; }


TCS_PREFIX=${TCS_PREFIX:-/data/data/com.termux/files/usr}
wrapper_guard() { # $1=launch-path — REFUSE extracted DEB shield wrappers
  # The deb's chromium-shield-wrapper.sh resolves its launcher via
  # ${PREFIX:-/data/data/com.termux/files/usr} — running an EXTRACTED copy
  # silently execs the INSTALLED package (identity contamination; observed
  # 2026-10-27 R11 audit). Installed-mode launches (under $TCS_PREFIX) are
  # the supported official path and stay allowed.
  case "$(basename "$1")" in
    chromium-shield-wrapper.sh)
      case "$1" in
        "$TCS_PREFIX"/*) return 0 ;;
        *) echo "[FAIL] extracted DEB shield-wrapper refuses: it would exec the INSTALLED launcher (hardcoded \${PREFIX}); run the extracted chromium-launcher.sh with LD_PRELOAD=<extract>/libtermux-gnp-fix.so instead"; return 1 ;;
      esac ;;
  esac
  return 0
}

max_field() { # $1=file $2=type $3=field(2..6)
  awk -v t="$2" -v c="$3" '$1==t{if($c>m)m=$c}END{print m+0}' "$1"
}

run_gate() { # $1=chrome bin, $2=ws
  local bin=$1 ws=$2 rc=0
  # Phase C adaptation (R9b packaged form): the SUPPORTED launch path is the
  # shield wrapper; census identity must match the REAL chrome exe. When bin
  # resolves to a script, target <dir-of-wrapper>/chrome. Spawn still uses
  # the given bin (never bypass the wrapper); marker check uses the exe.
  wrapper_guard "$bin" || { echo "BPF EVIDENCE GATE: FAIL"; return 1; }
  local match=$bin
  local realbin; realbin=$(readlink -f "$bin")
  case "$realbin" in
    *.sh) match="$(dirname "$realbin")/chrome" ;;
  esac
  mkdir -p "$ws"
  echo "=== P0 marker/tripwire ==="
  if grep -aq 'Termux seccomp-only' "$match"; then echo "[ok] R1/R2 marker string in binary"; else echo "[FAIL] no port marker in binary (built without port?)"; rc=1; fi

  echo "=== P2 renderer census ==="
  spawn_probe "$bin" ported "$ws"
  census "$match" "$ws/census-ported.txt"; stop_probe
  local ren ren_s ren_n zyg bro inj
  ren=$(max_field "$ws/census-ported.txt" renderer 2)
  ren_s=$(max_field "$ws/census-ported.txt" renderer 3)
  ren_n=$(max_field "$ws/census-ported.txt" renderer 4)
  zyg=$(max_field "$ws/census-ported.txt" zygote 2)
  inj=$(max_field "$ws/census-ported.txt" browser 6)
  # broker proof is only meaningful while the measured processes are alive:
  # it runs BEFORE stop_probe, on a NON-EMPTY fresh census. Empty census =
  # measurement error, never a silent pass.
  if [ ! -s "$ws/census-ported.txt" ]; then
    echo "[FAIL] census empty — measurement error (browser never spawned?); refusing broker proof"; rc=1; bro=0
  else
    bro=$(broker_channel "$ws/census-ported.txt")
  fi
  awk '{print "  ["$1"] filters="$2" seccomp="$3" nnp="$4" ppid="$5}' "$ws/census-ported.txt" | sort -u
  echo "  renderer: filters=$ren seccomp=$ren_s nnp=$ren_n | zygote filters=$zyg | broker-inodes=$bro | runtime --no-sandbox=$inj"
  [ "$inj" -eq 0 ] || { echo "[FAIL] runtime --no-sandbox injected (1001/1004 regression?)"; rc=1; }
  ren_present=$(awk '$1=="renderer"{c++}END{print c+0}' "$ws/census-ported.txt")
  crash_now=$(grep -c 'CRASHING' "$ws/ev-ported.log" 2>/dev/null || true)
  if [ "$ren" -ge 2 ]; then :
  elif [ "$ren_present" -gt 0 ] && [ "${crash_now:-0}" -eq 0 ]; then
    echo "[WARN] kernel lacks Seccomp_filters export — renderer x$ren_present alive, 0 CRASHING (presence proxy; authoritative census on main device)"
  else echo "[FAIL] renderer filters<2 — Chromium BPF absent (present=$ren_present crashing=$crash_now)"; rc=1; fi
  [ "$ren_s" -eq 2 ] || { echo "[FAIL] renderer not in seccomp filter mode"; rc=1; }
  [ "$ren_n" -eq 1 ] || echo "[WARN] renderer NoNewPrivs=$ren_n"
  [ "$bro" -gt 0 ] || echo "[WARN] no shared zygote↔renderer socket inode (broker unproven)"
  [ "$zyg" -ge 1 ] || { echo "[FAIL] no zygote process — R1 path not reached?"; rc=1; }

  echo "=== P2b causality control (--disable-seccomp-filter-sandbox) ==="
  spawn_probe "$bin" noflt "$ws" --disable-seccomp-filter-sandbox
  census "$match" "$ws/census-noflt.txt"; stop_probe
  local ren_off; ren_off=$(max_field "$ws/census-noflt.txt" renderer 2)
  echo "  renderer filters with switch OFF: $ren_off (expect < $ren)"
  [ "$ren_off" -lt "$ren" ] || echo "[WARN] filter count did not drop — 2nd filter may not be Chromium's (or switch inert)"
  grep -iE 'No usable sandbox|SIGSYS|SeccompBPF' "$ws/ev-noflt.log" | head -3

  echo "=== P3 gpu/utility/network ==="
  local gpu uti
  gpu=$(max_field "$ws/census-ported.txt" gpu-process 2)
  uti=$(max_field "$ws/census-ported.txt" utility 2)
  [ "$gpu" -ge 2 ] && echo "[ok] gpu-process filters=$gpu" || echo "[WARN] gpu-process filters=$gpu (recommended >=2; swiftshader path)"
  [ "$uti" -ge 2 ] && echo "[ok] utility filters=$uti" || echo "[WARN] utility filters=$uti (network sandbox is opt-in upstream — informational)"

  echo "=== DIAGNOSTIC PRIORITY (on FAIL) ==="
  [ $rc -eq 0 ] || {
    echo "  1. grep port-apply.log for 'R1'/'R2' APPLIED markers (build side)"
    echo "  2. strings check: 'Termux seccomp-only' → P0 above"
    echo "  3. zygote absent + --no-zygote in browser cmdline → shell_main_delegate PreSandboxStartup"
    echo "  4. browser 'No usable sandbox' in ev-ported.log → ZygoteHostImpl::Init R1 not compiled"
    echo "  5. renderer filters=1 with marker present → EngageNamespaceSandbox still fatal? check R2 + sandbox_linux.cc"
    echo "  6. SIGSYS boot-loop → EnableSandbox self-check vs missing BPF (sandbox_linux EngageLayerZero)"
  }
  echo "BPF EVIDENCE GATE: $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
  return $rc
}

selftest() {
  local t=$PWD/.bpf-selftest.$$ ; rm -rf "$t"; mkdir -p "$t"
  local P="$t/proc" ; mkdir -p "$P"
  local real=$(command -v bash)   # any executable works as fake chrome exe target
  mk() { # pid type filters seccomp nnp nosbx ppid
    mkdir -p "$P/$1/fd"
    ln -sf "$real" "$P/$1/exe"
    printf -- '--type=%s\0--flag\0' "$2" > "$P/$1/cmdline"
    [ "$6" = x ] && printf -- '--no-sandbox\0' >> "$P/$1/cmdline"
    printf 'Name: chrome\nSeccomp:\t%s\nSeccomp_filters:\t%s\nNoNewPrivs:\t%s\nPPid:\t%s\n' "$4" "$3" "$5" "$7" > "$P/$1/status"
    # fake socketpair inode between zygote and renderer
    [ "$2" = zygote ] || [ "$2" = renderer ] && ln -sf "socket:[4242]" "$P/$1/fd/9" 2>/dev/null
  }
  mk 100 browser 1 0 0 "" 1   ; mk 101 zygote  2 2 1 "" 100
  mk 102 renderer 2 2 1 "" 101; mk 103 gpu-process 2 2 1 "" 100
  mk 104 utility 1 0 0 "" 100
  local rc=0
  PROC_ROOT=$P CHROME_FAKE=1 bash -c "
    set -e
    CHROME=$real
    source $0 --noop 2>/dev/null || true
  " 2>/dev/null
  # direct invocation path
  if CHROME_BIN=$real PROC_ROOT=$P bash "$0" _internal_census "$real" "$t/c.txt" && \
     grep -q '^renderer 2 2 1 101 0$' "$t/c.txt"; then echo "[selftest] census ok"; else echo "[selftest] census FAIL"; rc=1; fi
  # verdict logic unit: max_field + expected shape
  awk '$1=="renderer"&&$2==2&&$3==2&&$4==1&&$5==101{f=1}END{exit !f}' "$t/c.txt" || { echo "[selftest] verdict FAIL"; rc=1; }
  # negative fixture: renderer 1 filter → should be detected
  printf 'Name: x\nSeccomp:\t0\nSeccomp_filters:\t1\nNoNewPrivs:\t0\nPPid:\t101\n' > "$P/102/status"
  PROC_ROOT=$P bash "$0" _internal_census "$real" "$t/c2.txt"
  awk '$1=="renderer"&&$2==1{f=1}END{exit !f}' "$t/c2.txt" || { echo "[selftest] negative-fixture FAIL"; rc=1; }
  # tripwire fixture: browser cmdline carrying --no-sandbox must set flag col=1
  printf -- '--no-sandbox\0--type=browser\0' > "$P/100/cmdline"
  PROC_ROOT=$P bash "$0" _internal_census "$real" "$t/c3.txt"
  awk '$1=="browser"&&$6==1{f=1}END{exit !f}' "$t/c3.txt" || { echo "[selftest] no-sandbox-tripwire FAIL"; rc=1; }
  # idempotence: a second census on the SAME output file must not accumulate
  : > "$t/c4.txt"; printf 'Name: chrome\nSeccomp:\t2\nSeccomp_filters:\t2\nNoNewPrivs:\t1\nPPid:\t101\n' > "$P/102/status"
  PROC_ROOT=$P bash "$0" _internal_census "$real" "$t/c4.txt"; n1=$(wc -l < "$t/c4.txt")
  PROC_ROOT=$P bash "$0" _internal_census "$real" "$t/c4.txt"; n2=$(wc -l < "$t/c4.txt")
  [ "$n1" = "$n2" ] && [ "$n1" -gt 0 ] && echo "[selftest] census idempotent ok" \
    || { echo "[selftest] census idempotence FAIL ($n1 vs $n2)"; rc=1; }
  # wrapper guard: extracted path refused, prefix-under path allowed
  mkdir -p "$t/extract" "$t/pfx/usr/lib/chromium-sandboxed"
  touch "$t/extract/chromium-shield-wrapper.sh" "$t/pfx/usr/lib/chromium-sandboxed/chromium-shield-wrapper.sh"
  if TCS_PREFIX=$t/pfx bash "$0" _internal_guard "$t/extract/chromium-shield-wrapper.sh"; then
    echo "[selftest] wrapper guard FAIL (extracted not refused)"; rc=1
  else echo "[selftest] wrapper guard refuses extracted ok"; fi
  if TCS_PREFIX=$t/pfx bash "$0" _internal_guard "$t/pfx/usr/lib/chromium-sandboxed/chromium-shield-wrapper.sh"; then
    echo "[selftest] wrapper guard allows installed-mode ok"
  else echo "[selftest] wrapper guard FAIL (installed-mode refused)"; rc=1; fi
  rm -rf "$t"
  echo "[selftest] $([ $rc -eq 0 ] && echo PASS || echo FAIL)"
  return $rc
}

case ${1:-} in
  selftest) selftest ;;
  _internal_census) census "$2" "$3" ;;
  _internal_guard) wrapper_guard "${2:-}" ;;
  --noop) exit 0 ;;
  "") usage ;;
  *) CHROME=$1; LAUNCH=$1; shift; WS=. ; [ "${1:-}" = --ws ] && { WS=$2; shift 2; }
     [ -x "$LAUNCH" ] || { echo "no exec at $LAUNCH"; exit 1; }
     _rb=$(readlink -f "$LAUNCH"); case "$_rb" in *.sh) CHROME="$(dirname "$_rb")/chrome" ;; esac
     run_gate "$LAUNCH" "$WS" ;;
esac
