#!/data/data/com.termux/files/usr/bin/bash
# Phase C.1-F: 10 GUI cold starts via the supported wrapper under X11.
# Each: fresh profile -> window with unique title -> graceful CDP close.
BIN=${PHC_WRAPPER:-/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed}
HERE=$(cd "$(dirname "$0")" && pwd)
export DISPLAY=${DISPLAY:-:0}
OK=0; FAILS=""
CH=$(readlink -f "$(dirname "$(readlink -f "$BIN")")/chrome")
for i in $(seq 1 10); do
  UDD=$(mktemp -d /data/data/com.termux/files/home/Project/.phc-cs-XXXXXX)
  TAG="PHCCS$i"
  PORT=$((9500+i))
  printf '<html><head><title>%s</title></head><body><h1>CS</h1></body></html>' "$TAG" > "$UDD/p.html"
  setsid "$BIN" --user-data-dir="$UDD" --no-first-run --remote-debugging-port=$PORT "file://$UDD/p.html" >/dev/null 2>&1 &
  GP=$!
  W=""
  for t in $(seq 1 30); do W=$(xdotool search --name "$TAG" 2>/dev/null | head -1); [ -n "$W" ] && break; sleep 1; done
  if [ -z "$W" ]; then FAILS="$FAILS no-window-$i"; kill -KILL -$GP 2>/dev/null; rm -rf "$UDD"; continue; fi
  if python3 - "$PORT" "$HERE" <<'PYQ'
import sys,os
sys.path.insert(0,sys.argv[2])
from cdp_client import CDP
cdp=CDP(port=int(sys.argv[1]),timeout=10)
cdp.call('Browser.close',timeout=10)
PYQ
  then
    # window must vanish
    LEFT=1
    for t in 1 2 3 4 5 6; do sleep 1; C=$(xdotool search --name "$TAG" 2>/dev/null | wc -l); [ "$C" = "0" ] && { LEFT=0; break; }; done
    [ "$LEFT" = "0" ] && OK=$((OK+1)) || FAILS="$FAILS window-stuck-$i"
  else
    FAILS="$FAILS cdp-quit-fail-$i"
  fi
  kill -KILL -$GP 2>/dev/null; sleep 1; rm -rf "$UDD"
done
sleep 2
RES=0
for p in $(ls /proc | grep -E '^[0-9]+$'); do e=$(readlink /proc/$p/exe 2>/dev/null); [ "$e" = "$CH" ] && RES=$((RES+1)); done
echo "GUI-COLDSTARTS=$OK/10 residual=$RES fails:[$FAILS]"
[ "$OK" = "10" ] && [ "$RES" = "0" ] && [ -z "$FAILS" ] && exit 0 || exit 1
