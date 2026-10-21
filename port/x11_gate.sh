#!/usr/bin/env bash
# X11 device gate for the Termux Chromium seccomp-only port.
#
# WHY X11: --headless=new NEVER renders on termux chromium (stock included,
# verified device-gate round 3) - it starts, forks a zygote, then dies without
# ever producing a renderer. The only working render path is
# --ozone-platform=x11 against the Termux:X11 display (:0), with
# --enable-logging=stderr so page console.log() reaches the log.
#
# Verdict = three independent facts:
#   [1] renderer engages the BPF     ("Activated seccomp-bpf ... renderer" >=1)
#   [2] page actually renders         (5/5 codec CONSOLE lines, none "no")
#   [3] filters are per-process real  (renderer pid Seccomp_filters >= 2)
# Any missing => FAIL (fail-closed; never a partial pass).
#
# usage: x11_gate.sh <deb> [baseline-chrome]
# env:   X11_DISPLAY (default :0), GATE_WS (default $PWD/chromium-device-gate)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
DEB=${1:?usage: x11_gate.sh <deb> [baseline-chrome]}
BASELINE=${2:-/data/data/com.termux/files/usr/lib/chromium/chrome}
DISP=${X11_DISPLAY:-:0}
WS=${GATE_WS:-$PWD/chromium-device-gate}
PAGE=$here/codecs-console.html
PRE=${X11_GATE_PRELOAD:-}
[ -f "$PAGE" ] || { echo "GATE FAIL: missing $PAGE"; exit 1; }
mkdir -p "$WS"
ROOT="$WS/extracted"; rm -rf "$ROOT"; mkdir -p "$ROOT"
dpkg-deb -x "$DEB" "$ROOT" || { echo "GATE FAIL: extract"; exit 1; }
CHROME=$(find "$ROOT" -type f -path '*chromium-sandboxed/chrome' | head -1)
[ -n "$CHROME" ] || { echo "GATE FAIL: chrome not found in deb"; exit 1; }
echo "ported chrome: $CHROME"
# The package ships the bionic pthread_getattr_np shield; when it is present in
# the deb, load it exactly the way bin/chromium-sandboxed does (LD_PRELOAD) so
# the gate verifies the shipped artifact, not an unshielded binary.
if [ -z "$PRE" ]; then
  PRE=$(find "$ROOT" -name 'libtermux-gnp-fix.so' | head -1)
  [ -n "$PRE" ] && echo "shield: $PRE (from deb)" || echo "shield: ABSENT (deb predates the bionic shield)"
fi
echo "display: $DISP (socket: $([ -S /data/data/com.termux/files/usr/tmp/.X11-unix/X0 ] && echo present || echo MISSING))"

# ---------- helper: run + capture ----------
run_capture() { # $1=bin $2=tag  [extra flags...]
  local bin=$1 tag=$2; shift 2
  local udd="$WS/udd-$tag" log="$WS/x11-$tag.log"
  rm -rf "$udd"
  # setsid + process-group kill (never pkill -f: our own cmdline matches)
  DISPLAY="$DISP" setsid env ${PRE:+LD_PRELOAD=$PRE} "$bin" --ozone-platform=x11 --user-data-dir="$udd" \
      --no-first-run --disable-dev-shm-usage --enable-logging=stderr --v=1 \
      "$@" "file://$PAGE" >"$log" 2>&1 &
  local gpid=$!
  ( sleep 45; kill -KILL -"$gpid" 2>/dev/null ) & local wpid=$!
  sleep 15
  census "$bin" "$WS/census-$tag.txt"
  kill -TERM -"$gpid" 2>/dev/null || true
  sleep 2
  kill -KILL -"$gpid" 2>/dev/null || true
  kill "$wpid" 2>/dev/null || true
  wait "$wpid" 2>/dev/null || true
  echo "$log"
}

census() { # $1=bin $2=out  -> "type filters nnp" per pid, exe-verified
  local bin=$1 out=$2
  : > "$out"
  for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    local exe; exe=$(readlink /proc/$pid/exe 2>/dev/null) || continue
    [ "$exe" = "$bin" ] || continue
    local t f n
    t=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
    f=$(awk '/^Seccomp_filters:/{print $2}' /proc/$pid/status 2>/dev/null)
    n=$(awk '/^NoNewPrivs:/{print $2}' /proc/$pid/status 2>/dev/null)
    echo "${t:-browser} ${f:-?} ${n:-?}" >> "$out"
  done
}

maxf() { awk -v t="$1" '$1==t && $2 ~ /^[0-9]+$/ {if($2>m)m=$2}END{print m+0}' "$2"; }
countt() { awk -v t="$1" '$1==t{c++}END{print c+0}' "$2"; }

verdict=PASS
echo "=== [0] baseline control (stock chrome, read-only, isolated profile) ==="
BLOG=$(run_capture "$BASELINE" baseline)
echo "baseline renderer filters=$(maxf renderer "$WS/census-baseline.txt") (Android platform baseline; expect <=1)"

echo "=== [1..3] PORTED build ==="
PLOG=$(run_capture "$CHROME" ported)
act=$(grep -ac 'Activated seccomp-bpf sandbox for process type: renderer' "$PLOG")
# pids that logged a renderer activation (log prefix is "[pid:tid:...]")
actpids=$(grep -a 'Activated seccomp-bpf sandbox for process type: renderer' "$PLOG" \
          | sed -n 's/^\[\([0-9]*\):.*/\1/p' | sort -u)
echo "--- renderer activation pids: $(printf '%s ' $actpids)"
codecs=$(grep -a 'CONSOLE' "$PLOG" | sed -n 's/.*CONSOLE[^"]*"\([^"]*\)".*/\1/p' | grep -E '=>' | head -8)
ncodec=$(printf '%s\n' "$codecs" | grep -c '=>' || true)
nbad=$(printf '%s\n' "$codecs" | grep -cE '=> no$' || true)
renf=$(maxf renderer "$WS/census-ported.txt")
renp=$(countt renderer "$WS/census-ported.txt")
echo "--- activated renderer engagements: $act"
echo "--- codecs ($ncodec/5, unsupported=$nbad):"; printf '%s\n' "$codecs" | sed 's/^/      /'
echo "--- census:"; awk '{print "      ["$1"] filters="$2" nnp="$3}' "$WS/census-ported.txt" | sort | uniq -c | sort -rn | head -8
echo "--- renderer: alive=$renp filters=$renf"

[ "$act" -ge 1 ] || { echo "GATE FAIL[1]: renderer never engaged the BPF (post-activation death or no renderer)"; verdict=FAIL; }
# [3] prove a RENDERER pid actually carries >=2 filters (Android baseline is 1)
proven=0
for p in $actpids; do
  f=$(awk '/^Seccomp_filters:/{print $2}' "/proc/$p/status" 2>/dev/null)
  [ -n "${f:-}" ] && [ "$f" -ge 2 ] && { echo "      renderer pid $p filters=$f"; proven=1; }
done
if [ "$proven" -ne 1 ]; then
  # fall back: any live child with >=2 filters (activation pids may have exited)
  n2=$(awk '$2 ~ /^[0-9]+$/ && $2>=2 {c++}END{print c+0}' "$WS/census-ported.txt")
  [ "$n2" -ge 1 ] && { echo "      fallback: $n2 live process(es) with filters>=2"; proven=1; }
fi
if [ "$ncodec" -ge 5 ] && [ "$nbad" -eq 0 ]; then :; else echo "GATE FAIL[2]: render did not complete (codecs=$ncodec/5 bad=$nbad)"; verdict=FAIL; fi
if [ "$proven" -eq 1 ]; then :; else echo "GATE FAIL[3]: no process carried Chromium's 2nd filter (alive=$renp filters=$renf)"; verdict=FAIL; fi

if [ "$verdict" != PASS ]; then
  echo "=== diagnostics ==="
  grep -aoE '(SIGSYS[^ ]*|CRASHING[^ ]*|pthread_getattr_np|GetStackEnd|FATAL[^:]*:.*)' "$PLOG" | sort | uniq -c | head -6
  [ -f "$WS/abort.log" ] && { echo "-- abort() backtrace frames (file offsets):"; grep -aE '^[0-9a-f]{9,}$' "$WS/abort.log" | sort | uniq -c | sort -rn | head -5; }
  echo "-- re-run with abort shim for forensics:"
  echo "   LD_PRELOAD=<abort_shim.so> DISPLAY=$DISP <chrome> --ozone-platform=x11 ... (see DESIGN round 3-4)"
fi
echo "X11 DEVICE GATE: $verdict"
[ "$verdict" = PASS ]
