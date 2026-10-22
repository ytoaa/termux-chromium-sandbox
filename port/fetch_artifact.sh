#!/usr/bin/env bash
# Fetch the chromium-sandboxed deb (+logs) from a build run into an evidence
# dir, record sha256. Usage: fetch_artifact.sh <run-id> [out-dir]
set -euo pipefail
run=${1:?usage: fetch_artifact.sh <run-id> [out-dir]}
out=${2:-../chromium-evidence/run-$run}
mkdir -p "$out"
# absolutize: subshells cd under $out later (run #28 postmortem: a relative
# out-dir made 'cd artifacts && ... > $out/deb.sha256' resolve from the wrong cwd)
out=$(cd "$out" && pwd)
command -v gh >/dev/null || { echo "gh required" >&2; exit 2; }
: "${DBUS_SESSION_BUS_ADDRESS:?gh keyring needs the desktop session dbus (export DBUS_SESSION_BUS_ADDRESS=...)}"
# verify run is a COMPLETED SUCCESS first (fail closed)
concl=$(gh run view "$run" --json status,conclusion --jq '"\(.status)/\(.conclusion)"')
case "$concl" in
  completed/success) ;;
  *) echo "run $run is '$concl' — refusing to harvest" >&2; exit 1;;
esac
gh run download "$run" -D "$out/artifacts"
deb=$(find "$out/artifacts" -name 'chromium-sandboxed_*_aarch64.deb' | head -1)
[ -n "$deb" ] || { echo "no deb in artifacts (did Package gates pass?)" >&2; exit 1; }
( cd "$out/artifacts" && sha256sum "$(basename "$deb")" > "$out/deb.sha256" )
dpkg-deb -f "$deb" Package Version Architecture > "$out/deb-fields.txt"
echo "harvested:"; sed 's/^/  /' "$out/deb-fields.txt"; echo "  sha256: $(cut -d' ' -f1 "$out/deb-fields.txt" 2>/dev/null || true)"
echo "next: bash port/x11_gate.sh '$deb' /data/data/com.termux/files/usr/lib/chromium/chrome"
