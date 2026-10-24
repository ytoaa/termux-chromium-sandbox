import http.server, threading, hashlib, subprocess, os, shutil, time, sys
OUT='/data/data/com.termux/files/home/Project/phase-c/main-batt'
DLDIR=OUT+'/dl-served'
os.makedirs(DLDIR,exist_ok=True)
body=bytes(range(256))*4096
H=lambda: None
class H2(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','application/octet-stream')
        self.send_header('Content-Disposition','attachment; filename="big.bin"')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass
srv=http.server.HTTPServer(('127.0.0.1',8198),H2)
threading.Thread(target=srv.serve_forever,daemon=True).start()
udd=OUT+'/udd-dl2'; shutil.rmtree(udd,ignore_errors=True)
subprocess.Popen(['/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed','--headless=new','--user-data-dir='+udd,'--no-first-run','--default-download-directory='+DLDIR,'--disable-background-networking','http://127.0.0.1:8198/big.bin'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
exp=hashlib.sha256(body).hexdigest()
got=None; t0=time.time()
while time.time()-t0<45:
    for fn in os.listdir(DLDIR) if os.path.isdir(DLDIR) else []:
        p=os.path.join(DLDIR,fn)
        if os.path.isfile(p) and os.path.getsize(p)>100000:
            got=hashlib.sha256(open(p,'rb').read()).hexdigest(); break
    if got: break
    time.sleep(2)
open(OUT+'/dl-result.txt','w').write('DL-EXPECTED=%s\nDL-GOT=%s\nDL-MATCH=%s\n'%(exp,got or 'NONE','YES' if got==exp else 'NO'))
print(open(OUT+'/dl-result.txt').read())
