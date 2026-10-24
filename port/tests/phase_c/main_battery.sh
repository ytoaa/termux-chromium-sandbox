#!/data/data/com.termux/files/usr/bin/bash
BIN=/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed
OUT=/data/data/com.termux/files/home/Project/phase-c/main-batt; mkdir -p $OUT
# WS test (local server)
python3 - <<'PY' > $OUT/ws-result.txt 2>&1
import asyncio, socket, threading, subprocess, time
# minimal RFC6455 echo server (stdlib only)
import hashlib, base64
def accept_conn(c):
    data=b''
    while b'\r\n\r\n' not in data:
        d=c.recv(4096)
        if not d: return
        data+=d
    key=[l.split(b': ')[1].strip() for l in data.split(b'\r\n') if l.lower().startswith(b'sec-websocket-key')][0]
    acc=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
    c.send(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+acc+b'\r\n\r\n')
    n=0
    while n<40:
        h=c.recv(2)
        if len(h)<2: break
        ln=h[1]&0x7f
        if ln==126: ln=int.from_bytes(c.recv(2),'big')
        elif ln==127: ln=int.from_bytes(c.recv(8),'big')
        mask=c.recv(4); payload=bytearray(); 
        while len(payload)<ln: payload+=c.recv(ln-len(payload))
        dec=bytes(b^mask[i%4] for i,b in enumerate(payload))
        n+=1
        msg=bytes([0x82,ln])+mask+bytes(payload)
        c.send(msg)
    c.close()
    return n
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(('127.0.0.1',8098)); srv.listen(3)
print('WS-SERVER-UP',flush=True)
import concurrent.futures as cf
page='''<html><body><div id=r>init</div><script>
const ws=new WebSocket('ws://127.0.0.1:8098/');let n=0;
ws.onopen=()=>{for(let i=0;i<40;i++)ws.send('m'+i);};
ws.onmessage=e=>{n++;document.getElementById('r').textContent='WS:'+n;if(n>=40)document.title='WSOK-'+n;};
ws.onerror=()=>{document.title='WSERR';};
</script></body></html>'''
open('/data/data/com.termux/files/home/Project/.phc-ws.html','w').write(page)
with cf.ThreadPoolExecutor(2) as ex:
    c,_=srv.accept(); ex.submit(accept_conn,c)
    r=subprocess.run(['timeout','120','/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed','--headless=new','--user-data-dir=/data/data/com.termux/files/home/.phc-ws-udd','--no-first-run','--virtual-time-budget=15000','--dump-dom','file:///data/data/com.termux/files/home/Project/.phc-ws.html'],capture_output=True,text=True)
print('WS-DOM-MARKERS:',r.stdout.count('WS:40'), 'TITLE-WSOK' if 'WSOK-40' in r.stdout else 'NO-TITLE')
PY
# download sha-match
ddir=$HOME/phc-downloads; rm -rf $ddir; mkdir -p $ddir
python3 -c "import hashlib;open('$OUT/big.bin','wb').write(bytes(range(256))*4096)"  # 1MiB
EXPECTED=$(sha256sum $OUT/big.bin | cut -d' ' -f1)
timeout 180 $BIN --headless=new --user-data-dir=$OUT/udd-dl --no-first-run --enable-features=DownloadSummary --disable-gpu "data:text/html,<a id=a download=big.bin href='file://$OUT/big.bin'>dl</a><script>document.getElementById('a').click()</script>" >/dev/null 2>&1
# downloads go to default dir under user-data; find the file
DL=$(find $OUT/udd-dl -name 'big.bin*' -size +100k 2>/dev/null | head -1)
GOT=$( [ -n "$DL" ] && sha256sum "$DL" | cut -d' ' -f1 )
echo "DL-EXPECTED=$EXPECTED" > $OUT/dl-result.txt
echo "DL-GOT=${GOT:-NONE}" >> $OUT/dl-result.txt
echo "DL-MATCH=$([ "$EXPECTED" = "$GOT" ] && echo YES || echo NO)" >> $OUT/dl-result.txt
# audio with PA socket if available
PA=${PREFIX:-/data/data/com.termux/files/usr}/tmp/pulse/native
[ -S "$XDG_RUNTIME_DIR/pulse/native" ] && PA=$XDG_RUNTIME_DIR/pulse/native
echo "PA-SOCKET=$([ -S "$PA" ] && echo PRESENT || echo ABSENT)" > $OUT/audio-result.txt
timeout 120 $BIN --headless=new --user-data-dir=$OUT/udd-aud --no-first-run --autoplay-policy=no-user-gesture-required --virtual-time-budget=8000 --dump-dom 'data:text/html,<audio id=a src=data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA=></audio><script>const a=document.getElementById("a");a.play().then(()=>document.title="AUDIO:PLAYING").catch(e=>document.title="AUDIO:ERR-"+e.name);</script>' > $OUT/aud.out 2>/dev/null
grep -ao 'AUDIO:[A-Za-z-]*' $OUT/aud.out | head -1 >> $OUT/audio-result.txt
grep -ao '<title>[^<]*' $OUT/aud.out | head -1 >> $OUT/audio-result.txt
# stability: 10 cold starts
OKS=0; TOTAL_T0=$(date +%s)
for i in $(seq 1 10); do
  rm -rf $HOME/.phc-st-$i
  if timeout 90 $BIN --headless=new --user-data-dir=$HOME/.phc-st-$i --no-first-run --dump-dom 'data:text/html,<p>OK' 2>/dev/null | grep -q '>OK<'; then OKS=$((OKS+1)); fi
  rm -rf $HOME/.phc-st-$i
done
echo "STABILITY: relaunches=$OKS/10 elapsed=$(( $(date +%s)-TOTAL_T0 ))s" > $OUT/stability-result.txt
LEFT=$(for p in $(ls /proc | grep -E '^[0-9]+$'); do e=$(readlink /proc/$p/exe 2>/dev/null)||continue; [ "$e" = "$(readlink -f /data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome)" ] && echo x; done | wc -l)
echo "residual-chrome-procs-after-all=$LEFT" >> $OUT/stability-result.txt
cat $OUT/ws-result.txt $OUT/dl-result.txt $OUT/audio-result.txt $OUT/stability-result.txt
