import socket, threading, hashlib, base64, subprocess, time, sys, http.server, re
OUT='/data/data/com.termux/files/home/Project/phase-c/main-batt'
proof={'msgs':0,'http':''}
def ws_handle(c):
    try:
        c.settimeout(45); data=b''
        while b'\r\n\r\n' not in data:
            d=c.recv(4096)
            if not d: return
            data+=d
        key=[l.split(b': ')[1].strip() for l in data.split(b'\r\n') if l.lower().startswith(b'sec-websocket-key')][0]
        acc=base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        c.send(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+acc+b'\r\n\r\n')
        while proof["msgs"]<20:
            h=c.recv(2)
            if len(h)<2: break
            ln=h[1]&0x7f
            if ln==126: ln=int.from_bytes(c.recv(2),'big')
            mask=c.recv(4); payload=bytearray()
            while len(payload)<ln: payload+=c.recv(ln-len(payload))
            proof['msgs']+=1
            if ln<126: c.send(bytes([0x82,ln])+bytes(payload))
            else: c.send(bytes([0x82,126])+ln.to_bytes(2,'big')+bytes(payload))
    except Exception as ex:
        sys.stderr.write('WS-ERR %r\n'%(ex,))
    finally:
        try: c.close()
        except Exception: pass
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/PROOF'):
            proof['http']=self.path
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self,*a): pass
hs=http.server.HTTPServer(('127.0.0.1',8196),H)
threading.Thread(target=hs.serve_forever,daemon=True).start()
srv=socket.socket(); srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
srv.bind(('127.0.0.1',8197)); srv.listen(4); srv.settimeout(60)
page='''<html><body><div id=r>init</div><script>
const ws=new WebSocket('ws://127.0.0.1:8197/');let n=0;
ws.onopen=()=>{for(let i=0;i<20;i++)ws.send('m'+i);};
ws.onmessage=e=>{n++;document.getElementById('r').textContent='WS:'+n;
 if(n>=20){fetch('http://127.0.0.1:8196/PROOF-'+n);}
};
ws.onerror=()=>{fetch('http://127.0.0.1:8196/WSERR');};
</script></body></html>'''
open('/data/data/com.termux/files/home/Project/.phc-ws3.html','w').write(page)
acc_t=threading.Thread(target=lambda: (lambda c: ws_handle(c))(srv.accept()[0]) , daemon=True)
acc_t.start()
subprocess.Popen(['/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed','--headless=new','--user-data-dir='+OUT+'/udd-ws3','--no-first-run','file:///data/data/com.termux/files/home/Project/.phc-ws3.html'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
t0=time.time()
while time.time()-t0<50 and (proof["msgs"]<20 or not proof['http']): time.sleep(1)
open(OUT+'/ws-result.txt','w').write('WS-SERVER-MSGS=%d\nWS-HTTP-PROOF=%s\nRESULT=%s\n'%(proof['msgs'],proof['http'] or 'NONE','PASS' if proof['msgs']>=40 and proof['http'].startswith('/PROOF-20') else 'CHECK'))
print(open(OUT+'/ws-result.txt').read())
