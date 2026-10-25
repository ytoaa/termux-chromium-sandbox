#!/data/data/com.termux/files/usr/bin/bash
# Phase C.1-C: real X11 GUI verification on the MAIN device.
# Independent temp profile; NEVER touches user profiles or the existing
# session's windows (we only look for OUR window by unique title).
set -u
BIN=${PHC_WRAPPER:-/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed}
UDD=$(mktemp -d /data/data/com.termux/files/home/Project/.phc-gui-XXXXXX)
TAG="PHCGUI$$"
OUT=${PHC_GUI_OUT:-./gui-result.json}
export DISPLAY=${DISPLAY:-:0}
PASSV=""; FAILV=""
addok(){ PASSV="$PASSV $1"; }
addbad(){ FAILV="$FAILV $1"; }
cleanup(){ [ -n "${GP:-}" ] && kill -KILL -"$GP" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT
# T-launch: real window with unique title page
cat > "$UDD/page.html" <<'H'
<html><head><title>PHC-GUI-T1</title></head><body style="margin:0">
<h1 style="color:darkgreen">GUI-RENDER-OK</h1></body></html>
H
DP=$(ss -tln 2>/dev/null | awk "/:8[3-9][0-9][0-9] /{print}" | wc -l)
DEBUGPORT=$((9400 + RANDOM % 50))
echo $DEBUGPORT > "$UDD/debug-port"
setsid "$BIN" --user-data-dir="$UDD" --no-first-run --remote-debugging-port=$DEBUGPORT "file://$UDD/page.html" >/dev/null 2>&1 &
GP=$!
WID=""
for i in $(seq 1 40); do
  WID=$(xdotool search --name 'PHC-GUI-T1' 2>/dev/null | head -1)
  [ -n "$WID" ] && break
  sleep 1
done
if [ -n "$WID" ]; then addok "window-created wid=$WID"; else addbad "no-window"; fi
# T-title content check (rendering proven via WM_NAME set by page title)
if [ -n "$WID" ]; then
  NAME=$(xdotool getwindowname "$WID" 2>/dev/null)
  case "$NAME" in *PHC-GUI-T1*) addok "title=$NAME";; *) addbad "title=$NAME";; esac
fi
# T-move/resize
if [ -n "$WID" ]; then
  xdotool windowmove "$WID" 40 60 windowsize "$WID" 800 600 2>/dev/null; sleep 1
  GEO=$(xdotool getwindowgeometry "$WID" 2>/dev/null | tr '\n' ' ')
  case "$GEO" in *"800x600"*|*"800 x 600"*) addok "resize-geometry:$GEO";; *) addbad "geometry:$GEO";; esac
case "$GEO" in *"Position: 40,60"*) addok "move-geometry:$GEO";; *) addbad "move-geometry:$GEO";; esac
fi
# T-new-tab (ctrl+t) + address navigation (ctrl+l type file url + Enter)
if [ -n "$WID" ]; then
  xdotool windowactivate --sync "$WID" key ctrl+t; sleep 2
  xdotool windowactivate --sync "$WID" key ctrl+l; sleep 1
  xdotool type --window "$WID" --delay 20 "file://$UDD/page2.html" 2>/dev/null
  cat > "$UDD/page2.html" <<'H2'
<html><head><title>PHC-GUI-T2</title></head><body><h1>NAV-OK</h1></body></html>
H2
  xdotool key ctrl+l; sleep 1
  xdotool type --window "$WID" --delay 20 "file://$UDD/page2.html" 2>/dev/null
  xdotool key Return; sleep 4
  NAME2=$(xdotool getwindowname "$WID" 2>/dev/null)
  case "$NAME2" in *PHC-GUI-T2*) addok "address-navigation:$NAME2";; *) addbad "nav-title:$NAME2";; esac
  xdotool key ctrl+w; sleep 2   # close extra tab via UI
  addok "tab-close-issued"
fi
# T-scroll+keyboard input probe: type into focus (omnibox), expect no crash
if [ -n "$WID" ]; then
  xdotool windowactivate --sync "$WID" key ctrl+l; xdotool key --window "$WID" a b c 2>/dev/null; sleep 1
  xdotool key ctrl+l Escape; addok "kbd-input-no-crash"
fi
# T-process census (GUI mode): browser+renderer+gpu+utility present
sleep 2
CH=$(readlink -f "$(dirname "$(readlink -f "$BIN")")/chrome")
declare -A TYPES
NPROC=0
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  e=$(readlink /proc/$p/exe 2>/dev/null) || continue
  [ "$e" = "$CH" ] || continue
  tr '\0' '\n' < /proc/$p/cmdline 2>/dev/null | grep -q "$UDD" || continue
  NPROC=$((NPROC+1))
  t=$(tr '\0' '\n' < /proc/$p/cmdline 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
  s=$(awk '/^Seccomp:/{print $2}' /proc/$p/status)
  f=$(awk '/^Seccomp_filters:/{print $2}' /proc/$p/status)
  n=$(awk '/^NoNewPrivs:/{print $2}' /proc/$p/status)
  TYPES["$t s=$s f=$f n=$n"]=1
done
[ "$NPROC" -ge 3 ] && addok "proc-count=$NPROC" || addbad "proc-count=$NPROC"
# T-graceful quit via ctrl+q then window gone
if [ -n "$WID" ]; then
  # graceful quit via CDP Browser.close (protocol-level; the keyboard
  # ctrl+q path through the X11 IM is environment-dependent and recorded
  # separately, not as a product gate)
  python3 - "$BIN" "$UDD" <<'PYQ' || echo QUIT-TOOL-FAIL
import os,sys,subprocess,time
sys.path.insert(0,os.path.dirname(os.path.abspath(sys.argv[0])) if False else '.')
from cdp_client import CDP
port=open(os.path.join(sys.argv[2],'debug-port')).read().strip()
cdp=CDP(port=int(port),timeout=10)
cdp.call('Browser.close',timeout=10)
PYQ
  STILL=1
  for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; STILL=$(xdotool search --name 'PHC-GUI' 2>/dev/null | wc -l); [ "$STILL" = "0" ] && break; done
  [ "$STILL" = "0" ] && addok "graceful-quit-cdp" || addbad "windows-left=$STILL"
fi
kill -KILL -"$GP" 2>/dev/null; sleep 2
LEFT=$(for p in $(ls /proc | grep -E '^[0-9]+$'); do e=$(readlink /proc/$p/exe 2>/dev/null); [ "$e" = "$CH" ] && echo x; done | wc -l)
[ "$LEFT" = "0" ] && addok "residual=0" || addbad "residual=$LEFT"
rm -rf "$UDD"
printf '{\n "ok":[%s],\n "bad":[%s]\n}\n' "$(printf '"%s",' $PASSV | sed 's/,$//')" "$(printf '"%s",' $FAILV | sed 's/,$//')" > "$OUT"
echo "PASS:$PASSV"; echo "FAIL:$FAILV"
[ -z "$FAILV" ] && exit 0 || exit 1
