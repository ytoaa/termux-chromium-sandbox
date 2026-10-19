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
echo "ported chrome: $CHROME"

sample() { # $1=binary path, $2=label  → prints "type filters" lines
  local bin=$1 label=$2 out="$WS/procs-$2.txt"
  : > "$out"
  local deadline=$((SECONDS+25))
  while [ $SECONDS -lt $deadline ]; do
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
      exe=$(readlink /proc/$pid/exe 2>/dev/null) || continue
      [ "$exe" = "$bin" ] || continue
      t=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
      f=$(awk '/^Seccomp_filters:/{print $2}' /proc/$pid/status 2>/dev/null)
      echo "${t:-browser} ${f:-?}" >> "$out"
    done
    sleep 2
  done
  sort -u "$out" | sed "s/^/[$label] /"
}

run_probe() { # $1=binary $2=label  (headless=new keeps gpu/utility/renderer alive)
  local bin=$1 label=$2 udd="$WS/udd-$2"
  rm -rf "$udd"
  (timeout 30 "$bin" --headless=new --user-data-dir="$udd" --no-first-run \
      --disable-dev-shm-usage --remote-debugging-port=0 \
      "file://$here/media-capabilities.html" >"$WS/run-$2.log" 2>&1 &)
  sleep 12
  sample "$bin" "$label"
  pkill -f "user-data-dir=$udd" 2>/dev/null
}

echo "=== A) BASELINE (stock chrome, read-only, isolated profile) ==="
run_probe "$BASELINE" baseline
echo "=== B) PORTED build ==="
CODEC_OUT="$WS/codecs-ported.txt"
rm -rf "$WS/udd-codecs"
timeout 40 "$CHROME" --headless=new --user-data-dir="$WS/udd-codecs" --no-first-run \
  --disable-dev-shm-usage --virtual-time-budget=8000 --dump-dom \
  "file://$here/media-capabilities.html" 2>/dev/null | sed -n '/CHROMIUM_CODECS_BEGIN/,/CHROMIUM_CODECS_END/p' > "$CODEC_OUT"
cat "$CODEC_OUT"
run_probe "$CHROME" ported

echo "=== C) VERDICT ==="
base_max=$(sed -n 's/^\[baseline\] renderer \([0-9]*\)$/\1/p' "$WS/procs-baseline.txt" 2>/dev/null | sort -n | tail -1)
port_ren=$(sed -n 's/^\[ported\] renderer \([0-9]*\)$/\1/p'   "$WS/procs-ported.txt"  2>/dev/null | sort -n | tail -1)
port_gpu=$(sed -n 's/^\[ported\] gpu-process \([0-9]*\)$/\1/p' "$WS/procs-ported.txt"  2>/dev/null | sort -n | tail -1)
port_uti=$(sed -n 's/^\[ported\] utility \([0-9]*\)$/\1/p'     "$WS/procs-ported.txt"  2>/dev/null | sort -n | tail -1)
echo "baseline renderer filters=${base_max:-none} | ported renderer=${port_ren:-none} gpu=${port_gpu:-none} utility=${port_uti:-none}"
verdict=PASS
[ "${base_max:-0}" -le 1 ] || { echo "GATE FAIL: baseline unexpectedly sandboxed (compare apples to apples)"; verdict=FAIL; }
[ "${port_ren:-0}" -ge 2 ] || { echo "GATE FAIL: no ported renderer with >=2 filters (BPF missing)"; verdict=FAIL; }
if [ -s "$CODEC_OUT" ] && ! grep -qE "=&gt; no|=> no" "$CODEC_OUT"; then echo "codecs ok"; else echo "GATE FAIL: codec report incomplete or unsupported"; verdict=FAIL; fi
echo "DEVICE GATE: $verdict"
[ "$verdict" = PASS ]
