#!/usr/bin/env bash
# Phase 3 device gate for the Termux Chromium seccomp-only sandbox port.
# HARD CONSTRAINTS: never dpkg-install, never touch stock profile. The ported
# deb is EXTRACTED into an isolated workspace dir and executed from there;
# every run uses --user-data-dir under the workspace.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=gate_lib.sh
. "$here/gate_lib.sh" || { echo "GATE FAIL: gate_lib.sh missing next to device_gate.sh"; exit 1; }
PROC_ROOT=${PROC_ROOT:-/proc}
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

sample() { # $1=binary path, $2=label  → prints "[label] type filters seccomp" rows
  local bin=$1 label=$2 out="$WS/procs-$2.txt"
  gate_classify "$PROC_ROOT" "$bin" "$out"
  sed "s/^/[$label] /" "$out"
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
verdict=PASS
base_max=$(gate_field "$WS/procs-baseline.txt" renderer 2)
base_present=$(gate_present "$WS/procs-baseline.txt" renderer)
[ "${base_max:-0}" -le 1 ] || { echo "GATE FAIL: baseline unexpectedly sandboxed"; verdict=FAIL; }
crash_count=$(grep -c 'CRASHING' "$WS/run-ported.log" 2>/dev/null || true)
if [ -s "$CODEC_OUT" ] && ! grep -qE "=&gt; no|=> no" "$CODEC_OUT"; then codecs=1; else codecs=0; fi
decided=$(gate_decide "$WS/procs-ported.txt" "${crash_count:-0}" "$codecs" ported)
echo "$decided" | head -n -1
[ "$(echo "$decided" | tail -1)" = PASS ] || verdict=FAIL
echo "DEVICE GATE: $verdict"
[ "$verdict" = PASS ]
