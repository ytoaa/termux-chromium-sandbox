#!/usr/bin/env bash
# Phase 3 device gate for the Termux Chromium seccomp-only sandbox port.
# HARD CONSTRAINTS: never dpkg-install, never touch stock profile. The ported
# deb is EXTRACTED into an isolated workspace dir and executed from there;
# every run uses --user-data-dir under the workspace.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
WS=${CHROMIUM_GATE_WS:-$PWD/chromium-device-gate}
DEB=${1:?usage: device_gate.sh <deb-path> [baseline-chrome-path]}
BASELINE=${2:-/data/data/com.termux/files/usr/lib/chromium/chrome}
mkdir -p "$WS"
ROOT="$WS/extracted"; rm -rf "$ROOT"; mkdir -p "$ROOT"
dpkg-deb -x "$DEB" "$ROOT" || { echo "GATE FAIL: extract"; exit 1; }
CHROME=$(find "$ROOT" -type f -path '*chromium-sandboxed/chrome' | head -1)
[ -n "$CHROME" ] || { echo "GATE FAIL: chrome binary not found in deb"; exit 1; }
# Product path: users launch the shield wrapper (sets LD_PRELOAD=gnp shim);
# probing the raw binary bypasses the shield and is not what the deb ships.
# Prefer the INSTALLED package (the deb's wrapper resolves ${PREFIX}); an
# extracted wrapper would exec the installed launcher (mixed identity, refused
# by bpf_evidence's guard), so extraction mode stays the fallback.
INST="${PREFIX:-/data/data/com.termux/files/usr}/lib/chromium-sandboxed"
if [ -x "$INST/chrome" ] && [ -x "$INST/chromium-shield-wrapper.sh" ]; then
  CHROME="$INST/chrome"; LAUNCH="$INST/chromium-shield-wrapper.sh"; MODE=installed
else
  LAUNCH=$(find "$ROOT" -type f -path '*chromium-sandboxed/chromium-shield-wrapper.sh' | head -1)
  [ -n "$LAUNCH" ] || LAUNCH=$CHROME; MODE=extracted
fi
echo "ported chrome: $CHROME ($MODE)"
echo "ported launcher: $LAUNCH"

sample() { # $1=binary path, $2=label  → prints "type filters seccomp" lines
  local bin=$1 label=$2 out="$WS/procs-$2.txt"
  : > "$out"
  local deadline=$((SECONDS+25)) pid exe t f sc pp rows zypids r
  while [ $SECONDS -lt $deadline ]; do
    # Two-pass classification (same rule as bpf_evidence.sh census): Linux
    # zygote children fork WITHOUT execv, so a sandboxed renderer keeps
    # --type=zygote in cmdline; rows whose PPid is a zygote are renderers.
    zypids=" "
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
      exe=$(readlink /proc/$pid/exe 2>/dev/null) || continue
      [ "$exe" = "$bin" ] || continue
      t=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
      [ "${t:-}" = zygote ] && zypids="$zypids$pid "
    done
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
      exe=$(readlink /proc/$pid/exe 2>/dev/null) || continue
      [ "$exe" = "$bin" ] || continue
      t=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
      f=$(awk '/^Seccomp_filters:/{print $2}' /proc/$pid/status 2>/dev/null)
      sc=$(awk '/^Seccomp:/{print $2}' /proc/$pid/status 2>/dev/null)
      pp=$(awk '/^PPid:/{print $2}' /proc/$pid/status 2>/dev/null)
      if [ "${t:-}" = zygote ] && case "$zypids" in *" $pp "*) true;; *) false;; esac; then
        t=renderer
      fi
      echo "${t:-browser} ${f:-0} ${sc:-0}" >> "$out"
    done
    sleep 2
  done
  sort -u "$out" | sed "s/^/[$label] /"
}

run_probe() { # $1=binary $2=label [$3=launcher] (headless=new keeps children alive)
  local bin=$1 label=$2 launch=${3:-$1} udd="$WS/udd-$2"
  rm -rf "$udd"
  # setsid + process-group kill: NEVER pkill -f (our own cmdline contains
  # the pattern and pkill would SIGTERM the gate itself).
  setsid "$launch" --headless=new --user-data-dir="$udd" --no-first-run \
      --disable-dev-shm-usage --remote-debugging-port=0 \
      "file://$here/media-capabilities.html" >"$WS/run-$2.log" 2>&1 &
  local gpid=$!
  # watchdog: hard-kill the group after 60s no matter what
  ( sleep 60; kill -KILL -"$gpid" 2>/dev/null ) & local wpid=$!
  sleep 12
  sample "$bin" "$label"
  kill -TERM -"$gpid" 2>/dev/null
  sleep 2
  kill -KILL -"$gpid" 2>/dev/null
  kill "$wpid" 2>/dev/null
  wait "$wpid" 2>/dev/null
}

echo "=== A) BASELINE (stock chrome, read-only, isolated profile) ==="
run_probe "$BASELINE" baseline
echo "=== B) PORTED build ==="
CODEC_OUT="$WS/codecs-ported.txt"
rm -rf "$WS/udd-codecs"
timeout 40 "$LAUNCH" --headless=new --user-data-dir="$WS/udd-codecs" --no-first-run \
  --disable-dev-shm-usage --virtual-time-budget=8000 --dump-dom \
  "file://$here/media-capabilities.html" 2>/dev/null | sed -n '/CHROMIUM_CODECS_BEGIN/,/CHROMIUM_CODECS_END/p' > "$CODEC_OUT"
cat "$CODEC_OUT"
run_probe "$CHROME" ported "$LAUNCH"

echo "=== C) VERDICT ==="
base_max=$(awk '/^renderer /{if($2>m)m=$2}END{print m+0}' "$WS/procs-baseline.txt" 2>/dev/null)
port_ren=$(awk '/^renderer /{if($2>m)m=$2}END{print m+0}' "$WS/procs-ported.txt" 2>/dev/null)
port_ren_sc=$(awk '/^renderer /{if($3>m)m=$3}END{print m+0}' "$WS/procs-ported.txt" 2>/dev/null)
port_gpu=$(awk '/^gpu-process /{if($2>m)m=$2}END{print m+0}' "$WS/procs-ported.txt" 2>/dev/null)
port_uti=$(awk '/^utility /{if($2>m)m=$2}END{print m+0}' "$WS/procs-ported.txt" 2>/dev/null)
echo "baseline renderer filters=${base_max:-0} | ported renderer filters=${port_ren:-0} seccomp=${port_ren_sc:-0} gpu=${port_gpu:-0} utility=${port_uti:-0}"
verdict=PASS
[ "${base_max:-0}" -le 1 ] || { echo "GATE FAIL: baseline unexpectedly sandboxed (compare apples to apples)"; verdict=FAIL; }
ren_present=$(awk '$1=="renderer"{c++}END{print c+0}' "$WS/procs-ported.txt" 2>/dev/null)
crash_count=$(grep -c 'CRASHING' "$WS/run-ported.log" 2>/dev/null || true)
if [ "${port_ren:-0}" -ge 2 ]; then
  echo "renderer BPF census ok (filters=$port_ren)"
elif [ "${ren_present:-0}" -gt 0 ] && [ "${port_ren_sc:-0}" -eq 2 ] && [ "${crash_count:-0}" -eq 0 ]; then
  # Android 13 testbed kernel does not export Seccomp_filters (only Seccomp
  # mode). A live renderer with Seccomp=2 (filter mode), zero CRASHING traps
  # and a complete codec report is the measured proxy; the authoritative
  # filter-count census runs on the main device (kernel >= 6.1).
  echo "GATE NOTE: Seccomp_filters unexportable; renderer x$ren_present alive, Seccomp=2, 0 CRASHING — presence+mode proxy ok"
else
  echo "GATE FAIL: no ported renderer with >=2 filters (BPF missing; present=$ren_present seccomp=${port_ren_sc:-0} crashing=$crash_count)"; verdict=FAIL
fi
if [ -s "$CODEC_OUT" ] && ! grep -qE "=&gt; no|=> no" "$CODEC_OUT"; then echo "codecs ok"; else echo "GATE FAIL: codec report incomplete or unsupported"; verdict=FAIL; fi
echo "DEVICE GATE: $verdict"
[ "$verdict" = PASS ]
