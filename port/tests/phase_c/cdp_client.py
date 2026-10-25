# Minimal Chrome DevTools Protocol client over raw sockets (stdlib only).
# Phase C.1 test tooling: no third-party deps (Termux-safe).
# RFC6455: client->server frames MUST be masked; server->client unmasked;
# handles 7-bit, 16-bit (126) and 64-bit (127) payload lengths and
# continuation frames. Explicit timeouts; never blocks forever.
import json
import os
import socket
import struct
import time
import urllib.request
import base64


class CDPError(RuntimeError):
    pass


def http_json(url, timeout=10, method='GET'):
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


class WS:
    def __init__(self, ws_url, timeout=30.0):
        assert ws_url.startswith('ws://'), ws_url
        hostport, path = ws_url[5:].split('/', 1)
        self.path = '/' + path
        host, _, port = hostport.partition(':')
        self.s = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.s.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = ('GET %s HTTP/1.1\r\nHost: %s\r\n'
               'Upgrade: websocket\r\nConnection: Upgrade\r\n'
               'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n'
               % (self.path, host, key))
        self.s.sendall(req.encode())
        resp = b''
        while b'\r\n\r\n' not in resp:
            d = self.s.recv(4096)
            if not d:
                raise CDPError('ws handshake closed')
            resp += d
        if b'101' not in resp.split(b'\r\n')[0]:
            raise CDPError('ws handshake refused: %r' % resp[:120])
        self._buf = resp.split(b'\r\n\r\n', 1)[1]
        self._id = 0

    def _recv_exact(self, n):
        while len(self._buf) < n:
            d = self.s.recv(65536)
            if not d:
                raise CDPError('ws closed')
            self._buf += d
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send_text(self, text):
        payload = text.encode()
        hdr = bytearray([0x81])
        ln = len(payload)
        if ln < 126:
            hdr.append(0x80 | ln)
        elif ln < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack('>H', ln)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack('>Q', ln)
        mask = os.urandom(4)
        hdr += mask
        hdr += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.s.sendall(bytes(hdr))

    def recv_frame(self):
        fin_op = self._recv_exact(1)[0]
        ln_b = self._recv_exact(1)[0]
        if ln_b & 0x80:
            raise CDPError('server frames must be unmasked')
        ln = ln_b & 0x7F
        if ln == 126:
            ln = struct.unpack('>H', self._recv_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack('>Q', self._recv_exact(8))[0]
        data = self._recv_exact(ln)
        op = fin_op & 0x0F
        if op == 0x0:  # continuation of previous
            data = getattr(self, '_last', b'') + data
        self._last = data
        return (0x1 if op == 0x0 else op), data

    def call(self, method, params=None, session_id=None, timeout=30):
        self._id += 1
        mid = self._id
        msg = {'id': mid, 'method': method}
        if params:
            msg['params'] = params
        if session_id:
            msg['sessionId'] = session_id
        self.send_text(json.dumps(msg))
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.s.settimeout(max(0.5, deadline - time.time()))
            try:
                op, data = self.recv_frame()
            except (socket.timeout, CDPError):
                break
            if op != 0x1:
                continue
            try:
                m = json.loads(data)
            except Exception:
                continue
            if m.get('id') == mid:
                if 'error' in m:
                    raise CDPError('%s -> %s' % (method, m['error']))
                return m.get('result', {})
            elif 'method' in m:
                self.on_event(m)
        raise CDPError('timeout waiting for %s reply (id=%d)' % (method, mid))

    def drain_events(self, wanted, seconds=5.0):
        """wanted: list of method names; returns dict name->last params."""
        got = {}
        deadline = time.time() + seconds
        while time.time() < deadline and not all(w in got for w in wanted):
            try:
                self.s.settimeout(max(0.3, deadline - time.time()))
                op, data = self.recv_frame()
            except (socket.timeout, CDPError):
                return got
            if op != 0x1:
                continue
            try:
                m = json.loads(data)
            except Exception:
                continue
            if 'method' in m:
                self.on_event(m)
                if m['method'] in wanted:
                    got[m['method']] = m.get('params', {})
        return got

    def on_event(self, m):
        pass

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


class CDP(WS):
    def __init__(self, port=9333, timeout=30.0):
        info = http_json('http://127.0.0.1:%d/json/version' % port, timeout=timeout)
        super().__init__(info['webSocketDebuggerUrl'], timeout=timeout)
        self.targets = {}

    def new_tab(self, url='about:blank'):
        r = self.call('Target.createTarget', {'url': url})
        tid = r['targetId']
        att = self.call('Target.attachToTarget', {'targetId': tid, 'flatten': True})
        self.targets[tid] = att['sessionId']
        return tid

    def eval(self, tid, expression, timeout=20):
        r = self.call('Runtime.evaluate',
                      {'expression': expression, 'returnByValue': True},
                      session_id=self.targets[tid], timeout=timeout)
        return r.get('result', {}).get('value')

    def list_targets(self):
        return self.call('Target.getTargets')['targetInfos']

    def close_tab(self, tid):
        try:
            self.call('Target.closeTarget', {'targetId': tid})
            self.targets.pop(tid, None)
        except CDPError:
            pass
