#!/usr/bin/env bash
# Orchestrate the device gate on the dedicated remote test Termux device.
# MAIN-device rule stands (extract-only, never dpkg). The REMOTE device is a
# clean testbed (no chromium ever installed) so we also validate the real
# apt/dpkg install path there.
#
# usage: remote_gate.sh <run-id> [run-id ...]
# env:   RG_HOST RG_PORT RG_USER RG_KEY   (defaults filled from ~/.ssh config)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$here/..
RG_HOST=${RG_HOST:-100.64.1.44}; RG_PORT=${RG_PORT:-8022}
RG_USER=${RG_USER:-u0_a356}; RG_KEY=${RG_KEY:-$root/../.remote-test/rk}
SSH="ssh -p $RG_PORT -o BatchMode=yes -o ConnectTimeout=10 -i $RG_KEY $RG_USER@$RG_HOST"
RCP="scp -q -P $RG_PORT -i $RG_KEY"
export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=/data/data/com.termux/files/usr/tmp/dbus-CUeiMF9cgm,guid=b12d808478a303cda4bfa6b16ad5cd79}
[ -f "$RG_KEY" ] || { echo "no key at $RG_KEY"; exit 2; }
$SSH true || { echo "remote unreachable"; exit 2; }

snapshot() { # on-demand Termux-internal (X11) screen grab, e.g. live chromium GUI
  local tag=${1:-now}
  local out=$root/../gate-out/snap-$(date -u +%Y%m%dT%H%M%S)-$tag.png
  mkdir -p "$root/../gate-out"
  $SSH 'export DISPLAY=:0; import -window root ~/chromium-gate/snap.png 2>/dev/null'     && $RCP $RG_USER@$RG_HOST:~/chromium-gate/snap.png "$out" && echo "SNAPSHOT $out" || { echo "snapshot failed (X11 session down?)"; return 1; }
}
[ "${1:-}" = snapshot ] && { shift; snapshot "${1:-now}"; exit $?; }

for run in "$@"; do
  echo "===== RUN $run ====="
  OUT=$root/../gate-out/$run; rm -rf "$OUT"; mkdir -p "$OUT"
  gh run download "$run" -R ytoaa/termux-chromium-sandbox -D "$OUT/artifacts" >/dev/null 2>&1 \
    || { echo "[skip] run $run has no artifacts yet"; continue; }
  DEB=$(find "$OUT/artifacts" -name '*.deb' | head -1)
  [ -n "$DEB" ] || { echo "[skip] no deb in run $run (build died before packaging?)"; continue; }
  echo "deb: $DEB ($(stat -c %s "$DEB") bytes)"
  sha256sum "$DEB" | tee "$OUT/deb.sha256"
  # fresh remote dir per run
  $SSH 'rm -rf ~/chromium-gate/run; mkdir -p ~/chromium-gate/run'
  $RCP "$DEB" $RG_USER@$RG_HOST:~/chromium-gate/run/
  DEBN=$(basename "$DEB")
  echo "--- real install validation (clean testbed only) ---"
  $SSH "cd ~/chromium-gate/run && dpkg -i $DEBN 2>&1 | tail -3; apt-get -f install -y 2>&1 | tail -2; dpkg -l chromium-sandboxed 2>/dev/null | tail -1" | tee "$OUT/install.log"
  echo "--- device_gate (extract-run census + codecs) ---"
  $SSH "cd ~/chromium-gate && ./device_gate.sh run/$DEBN /data/data/com.termux/files/usr/bin/dpkg 2>&1" | tee "$OUT/device_gate.log"
  dg=$?
  CHROME=$(find "$OUT" -path '*chromium-sandboxed/chrome' 2>/dev/null | head -1) # local copy not kept; use remote path
  echo "--- bpf_evidence (P0/P2/P2b/P3) ---"
  $SSH "cd ~/chromium-gate && B=\$(find extracted -path '*chromium-sandboxed/chrome' | head -1) && ./bpf_evidence.sh \"\$B\" --ws ." | tee "$OUT/bpf_evidence.log"
  bg=$?
  # cleanup installed deb state so next run starts clean
  $SSH "dpkg -r chromium-sandboxed >/dev/null 2>&1; true"
  echo "===== VERDICT run $run: device_gate=$dg bpf_evidence=$bg ====="
done
