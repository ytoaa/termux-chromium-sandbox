#!/data/data/com.termux/files/usr/bin/bash
# Phase C functional battery on testbed (wrapper = supported launch path)
BIN=/data/data/com.termux/files/usr/bin/chromium-sandboxed
OUT=$HOME/phc-results; mkdir -p $OUT
echo '{"started":"'$(date -u +%FT%TZ)'"}' > $OUT/battery-start.json
# T1 dump-dom JS/CSS
cat > $OUT/t1.html <<'H'
<html><head><style>#c{color:green;font-size:20px}</style></head><body>
<div id=c>init</div><canvas id=cv width=8 height=8></canvas>
<script>
document.getElementById('c').textContent='JS:'+getComputedStyle(document.getElementById('c')).fontSize;
const g=document.getElementById('cv').getContext('2d');g.fillStyle='#0f0';g.fillRect(0,0,8,8);
document.title='CANVAS:'+(g.getImageData(0,0,1,1).data[1]===255?'OK':'FAIL');
</script></body></html>
H
timeout 180 $BIN --headless=new --user-data-dir=$OUT/udd-t1 --no-first-run --dump-dom file://$OUT/t1.html > $OUT/t1-dom.out 2>$OUT/t1.err
echo "T1-RC=$?" >> $OUT/battery.txt
grep -o 'JS:[0-9a-z]*px' $OUT/t1-dom.out | head -1 >> $OUT/battery.txt
grep -o '<div id="c">[^<]*' $OUT/t1-dom.out | head -1 >> $OUT/battery.txt
# T2 WebGL
timeout 180 $BIN --headless=new --user-data-dir=$OUT/udd-t2 --no-first-run --enable-unsafe-swiftshader --virtual-time-budget=8000 --dump-dom 'data:text/html,<canvas id=c></canvas><script>const gl=document.getElementById("c").getContext("webgl");document.title=gl?("WEBGL:"+(gl.getParameter(gl.VERSION)||"null")):"WEBGL:NULL";</script>' > $OUT/t2.out 2>/dev/null; echo "T2-RC=$?" >> $OUT/battery.txt
grep -ao 'WEBGL:[^"]*' $OUT/t2.out | head -1 >> $OUT/battery.txt
grep -a 'WEBGL' $OUT/t2.out | grep -ao '<title>[^<]*' | head -1 >> $OUT/battery.txt
# T3 audio element
timeout 180 $BIN --headless=new --user-data-dir=$OUT/udd-t3 --no-first-run --virtual-time-budget=6000 --dump-dom 'data:text/html,<audio id=a src=data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA=></audio><script>const a=document.getElementById("a");a.play().then(()=>document.title="AUDIO:PLAYING").catch(e=>document.title="AUDIO:ERR-"+e.name);</script>' > $OUT/t3.out 2>/dev/null
grep -ao 'AUDIO:[A-Z-]*' $OUT/t3.out | head -1 >> $OUT/battery.txt
# T4 local HTTP server + download
python3 -c "
import http.server,threading,socketserver,os
os.chdir('$OUT')
h=http.server.SimpleHTTPRequestHandler
h.log_file=open('$OUT/httpd.log','a')
srv=socketserver.TCPServer(('127.0.0.1',8099),h)
threading.Thread(target=srv.serve_forever,daemon=True).start()
import subprocess,time
r=subprocess.run(['timeout','120','$BIN','--headless=new','--user-data-dir=$OUT/udd-t4','--no-first-run','--dump-dom','http://127.0.0.1:8099/t1.html'],capture_output=True,text=True)
open('$OUT/t4.out','w').write('HTTP-RC=%s\nHTTP-HIT=%s' % (r.returncode, 'JS:' in r.stdout))
srv.shutdown()
"
cat $OUT/t4.out >> $OUT/battery.txt 2>/dev/null
# T5 HTTPS/TLS
timeout 120 $BIN --headless=new --user-data-dir=$OUT/udd-t5 --no-first-run --dump-dom https://example.com/ > $OUT/t5.out 2>/dev/null; grep -aoc 'example' $OUT/t5.out | head -1 >> $OUT/battery.txt; echo "T5-RC=$?" >> $OUT/battery.txt
# process census snapshot mid-run (proxy: filters NA on 4.19, existence matters)
timeout 60 $BIN --headless=new --user-data-dir=$OUT/udd-t6 --no-first-run about:blank >/dev/null 2>&1 &
GP=$!; sleep 12
{ echo "=== testbed census proxy (kernel 4.19) ==="; for pid in $(ls /proc | grep -E '^[0-9]+$'); do e=$(readlink /proc/$pid/exe 2>/dev/null)||continue; [ "$e" = /data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome ] ||continue; tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | grep -q udd-t6 || continue; t=$(tr '\0' '\n' < /proc/$pid/cmdline|sed -n 's/^--type=\(.*\)/\1/p'|head -1); s=$(awk '/^Seccomp:/{print $2}' /proc/$pid/status); n=$(awk '/^NoNewPrivs:/{print $2}' /proc/$pid/status); echo "type=${t:-browser} seccomp=$s nnp=$n"; done | sort | uniq -c; } >> $OUT/battery.txt
kill -KILL -$GP 2>/dev/null
tail -1 $OUT/battery.txt >/dev/null; echo "BATTERY-TB-DONE $(date -u +%FT%TZ)" >> $OUT/battery.txt
cat $OUT/battery.txt
