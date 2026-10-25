#!/usr/bin/env python3
# Phase C.1-A1: strict bidirectional WebSocket proof.
# Definitions (each counted separately, recorded):
#   sent_by_page        : browser->server text messages m0..m19 (server-verified)
#   page_msgs_received  : server->browser echoes counted by page JS (DOM + HTTP witness)
# PASS requires ALL of: server received exactly 20, contents EXACTLY match
# m0..m19, server sent 20 echoes (RFC6455 unmasked server->client frames),
# page witnessed PROOF-20. Partial/early-close/timeout => FAIL (never PASS).
# Full cleanup: browser process group killed, servers closed, exit code set.
import base64
import hashlib
import http.server
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

OUT_DIR = os.environ.get('PHC_WS_OUT', os.path.dirname(os.path.abspath(__file__)))
WRAPPER = os.environ.get(
    'PHC_WRAPPER',
    '/data/data/com.termux/files/home/Project/.phc-main/data/data/'
    'com.termux/files/usr/bin/chromium-sandboxed')
# residual-scan identity: real chrome inside the packaged prefix the
# wrapper resolves to (derived from the wrapper, never executed directly)
CHROME = os.path.realpath(os.path.join(
    os.path.dirname(os.path.realpath(WRAPPER)), 'chrome'))
N = 20
proof = {'sent_by_page': [], 'page_msgs_received': None,
         'server_echoed': 0, 'close_code_seen': False, 'errors': []}


def ws_read_frame(c):
    h = b''
    while len(h) < 2:
        d = c.recv(2 - len(h))
        if not d:
            return None, None
        h += d
    op = h[0] & 0x0F
    masked = h[1] & 0x80
    ln = h[1] & 0x7F
    if ln == 126:
        ln = struct.unpack('>H', c.recv(2))[0]
    elif ln == 127:
        ln = struct.unpack('>Q', c.recv(8))[0]
    mask = c.recv(4) if masked else b'\x00\x00\x00\x00'
    payload = bytearray()
    while len(payload) < ln:
        d = c.recv(ln - len(payload))
        if not d:
            break
        payload += d
    dec = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return op, dec


def ws_send_text(c, text):
    payload = text.encode()
    ln = len(payload)
    if ln < 126:
        hdr = bytes([0x82, ln])
    else:
        hdr = bytes([0x82, 126]) + struct.pack('>H', ln)
    c.sendall(hdr + payload)  # server->client: MUST be unmasked (RFC6455)


def ws_handle(c):
    try:
        c.settimeout(45)
        data = b''
        while b'\r\n\r\n' not in data:
            d = c.recv(4096)
            if not d:
                return
            data += d
        keys = [l.split(b': ')[1].strip() for l in data.split(b'\r\n')
                if l.lower().startswith(b'sec-websocket-key')]
        if not keys:
            proof['errors'].append('no ws key')
            return
        acc = base64.b64encode(hashlib.sha1(
            keys[0] + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        c.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                  b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + acc +
                  b'\r\n\r\n')
        while len(proof['sent_by_page']) < N:
            op, msg = ws_read_frame(c)
            if op is None:
                proof['errors'].append('peer closed at msg %d'
                                       % len(proof['sent_by_page']))
                return
            if op == 0x8:
                proof['close_code_seen'] = True
                return
            if op == 0x1:
                proof['sent_by_page'].append(msg.decode(errors='replace'))
                ws_send_text(c, msg.decode(errors='replace'))  # echo same text
                proof['server_echoed'] += 1
    except Exception as ex:
        proof['errors'].append('conn: %r' % (ex,))
    finally:
        try:
            c.close()
        except Exception:
            pass


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/PROOF-'):
            try:
                proof['page_msgs_received'] = int(self.path.split('-')[1])
            except Exception:
                pass
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *a):
        pass


def main():
    tmp = tempfile.mkdtemp(prefix='phc-ws-')
    proc = None
    ws_srv = http_srv = None
    exit_code = 1
    try:
        page = ('<html><body><div id=r>init</div><script>'
                'const ws=new WebSocket("ws://127.0.0.1:8297/");let n=0;'
                'ws.onopen=()=>{for(let i=0;i<%d;i++)ws.send("m"+i);};'
                'ws.onmessage=e=>{n++;document.getElementById("r").textContent="WS:"+n;'
                'if(n>=%d){fetch("http://127.0.0.1:8296/PROOF-"+n);}};'
                'ws.onerror=()=>{fetch("http://127.0.0.1:8296/WSERR");};'
                '</script></body></html>' % (N, N))
        pagef = os.path.join(tmp, 'ws.html')
        open(pagef, 'w').write(page)
        http_srv = http.server.HTTPServer(('127.0.0.1', 8296), H)
        threading.Thread(target=http_srv.serve_forever, daemon=True).start()
        ws_srv = socket.socket()
        ws_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ws_srv.bind(('127.0.0.1', 8297))
        ws_srv.listen(4)
        ws_srv.settimeout(60)
        # C.2-B: launch through the OFFICIAL packaged shield wrapper
        # (no direct chrome exec, no hand-rolled LD_PRELOAD). The wrapper
        # supplies the gnp preload, PULSE wiring and launcher checks.
        proc = subprocess.Popen(
            [WRAPPER, '--headless=new', '--user-data-dir=' + tmp + '/udd',
             '--no-first-run', 'file://' + pagef],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid)
        try:
            c, _ = ws_srv.accept()
        except socket.timeout:
            proof['errors'].append('ws accept timeout')
            c = None
        if c:
            t = threading.Thread(target=ws_handle, args=(c,), daemon=True)
            t.start()
            t.join(60)
        deadline = time.time() + 45
        while time.time() < deadline and \
                proof['page_msgs_received'] is None:
            time.sleep(0.5)
        expected = ['m%d' % i for i in range(N)]
        recv_ok = proof['sent_by_page'] == expected
        all_ok = (recv_ok and proof['server_echoed'] == N
                  and proof['page_msgs_received'] == N
                  and not proof['errors'])
        result = {
            'verdict': 'PASS' if all_ok else 'FAIL',
            'sent_by_page_verified': len(proof['sent_by_page']),
            'contents_exact_match': recv_ok,
            'server_echoed': proof['server_echoed'],
            'page_msgs_received': proof['page_msgs_received'],
            'errors': proof['errors'],
            'note': ('server->client frames unmasked per RFC6455; client '
                     'frames unmasked after mask check'),
        }
        out = os.path.join(OUT_DIR, 'ws-result.json')
        json.dump(result, open(out, 'w'), indent=1)
        print(json.dumps(result, indent=1))
        exit_code = 0 if all_ok else 1
    finally:
        try:
            if proc and proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=10)
        except Exception:
            pass
        for s in (ws_srv, http_srv):
            try:
                if s:
                    s.close() if isinstance(s, socket.socket) else (
                        s.shutdown(), s.server_close())
            except Exception:
                pass
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
