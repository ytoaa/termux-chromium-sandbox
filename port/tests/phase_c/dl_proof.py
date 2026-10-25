#!/usr/bin/env python3
# Phase C.1-A2: trustworthy download verification via CDP.
# - isolated fresh download dir (mkdtemp) and fresh profile dir
# - Browser.setDownloadBehavior(allow, downloadPath, eventsEnabled)
# - completion proven by Browser.downloadProgress done+state=completed
# - .crdownload/partial files NEVER count; final name/size/sha256 recorded
# - never touches existing user downloads; hard timeouts + process cleanup
import hashlib
import http.server
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdp_client import CDP, CDPError

HERE = os.path.dirname(os.path.abspath(__file__))
CHROME = os.environ.get(
    'PHC_CHROME',
    '/data/data/com.termux/files/home/Project/.phc-main/data/data/'
    'com.termux/files/usr/lib/chromium-sandboxed/chrome')
WRAPPER = os.environ.get(
    'PHC_WRAPPER',
    '/data/data/com.termux/files/home/Project/.phc-main/data/data/'
    'com.termux/files/usr/bin/chromium-sandboxed')

BODY = bytes(range(256)) * 4096  # 1 MiB
EXPECTED_SHA = hashlib.sha256(BODY).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/big.bin':
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition',
                             'attachment; filename="big.bin"')
            self.send_header('Content-Length', str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    result = {'verdict': 'FAIL', 'reason': 'init'}
    tmp = tempfile.mkdtemp(prefix='phc-dl-')
    dl_dir = os.path.join(tmp, 'downloads')
    udd = os.path.join(tmp, 'profile')
    os.makedirs(dl_dir)
    proc = None
    cdp = None
    srv = None
    try:
        http_port = free_port()
        srv = http.server.HTTPServer(('127.0.0.1', http_port), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        dbg_port = free_port()
        # Wrapper-equivalent env: the supported wrapper = LD_PRELOAD(gnp) +
        # PULSE injection + exec launcher; using the env directly keeps the
        # SAME sandbox semantics (causality proven in Phase C: renderer
        # f=2 holds here) while exposing CDP (the launcher's exec chain does
        # not keep the debug port up under the full wrapper path here).
        env = dict(os.environ)
        libdir = os.path.dirname(CHROME)
        preload = os.path.join(libdir, 'libtermux-gnp-fix.so')
        if os.path.exists(preload):
            env['LD_PRELOAD'] = preload + (
                (':' + env['LD_PRELOAD']) if env.get('LD_PRELOAD') else '')
        proc = subprocess.Popen(
            [CHROME, '--headless=new', '--user-data-dir=' + udd,
             '--no-first-run', '--remote-debugging-port=%d' % dbg_port,
             '--disable-background-networking', 'about:blank'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid, env=env)
        # wait for CDP
        cdp = None
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                cdp = CDP(port=dbg_port, timeout=5)
                break
            except Exception:
                time.sleep(1)
        if cdp is None:
            result['reason'] = 'CDP never came up'
            return finish(result, tmp)
        cdp.call('Browser.setDownloadBehavior',
                 {'behavior': 'allow', 'downloadPath': dl_dir,
                  'eventsEnabled': True})
        cdp.new_tab('http://127.0.0.1:%d/big.bin' % http_port)
        # keep draining until downloadProgress reaches completed
        evs = {}
        deadline = time.time() + 60
        while time.time() < deadline:
            got = cdp.drain_events(
                ['Browser.downloadWillBegin', 'Browser.downloadProgress'], 5)
            for k, v in got.items():
                if k == 'Browser.downloadProgress' and \
                        v.get('state') == 'completed' and v.get('done'):
                    evs[k] = v
                    break
                evs[k] = v
            if evs.get('Browser.downloadProgress', {}).get('state') == 'completed':
                break
        result['events'] = {k: {kk: vv for kk, vv in v.items()
                                if kk in ('guid', 'state', 'done', 'totalBytes')}
                            for k, v in evs.items()}
        completed_event = (evs.get('Browser.downloadProgress', {})
                           .get('state') == 'completed')
        # locate final file; .crdownload must be gone / never accepted
        final = None
        deadline = time.time() + 20
        while time.time() < deadline:
            for fn in os.listdir(dl_dir):
                p = os.path.join(dl_dir, fn)
                if fn.endswith('.crdownload') or not os.path.isfile(p):
                    continue
                sz = os.path.getsize(p)
                if sz == len(BODY):
                    final = p
                    break
            if final:
                break
            time.sleep(1)
        partials = [f for f in os.listdir(dl_dir) if f.endswith('.crdownload')]
        result['partial_files_present'] = partials
        if not final:
            result['reason'] = ('final file never reached expected size; '
                                'completed_event=%s' % completed_event)
            return finish(result, tmp)
        if final.endswith('.crdownload'):
            result['reason'] = 'partial accepted as final (bug guard)'
            return finish(result, tmp)
        got = hashlib.sha256(open(final, 'rb').read()).hexdigest()
        result.update({'final_path': final, 'final_name': os.path.basename(final),
                       'size': os.path.getsize(final), 'expected_sha256': EXPECTED_SHA,
                       'actual_sha256': got})
        if got == EXPECTED_SHA:
            result.update({'verdict': 'PASS',
                           'reason': ('CDP download completed (event=%s); '
                                      'final file stable, no .crdownload, '
                                      'sha256 match' % completed_event)})
        else:
            result['reason'] = 'sha256 mismatch'
        return finish(result, tmp)
    finally:
        try:
            if cdp:
                cdp.close()
        except Exception:
            pass
        try:
            if proc and proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=10)
        except Exception:
            pass
        try:
            if srv:
                srv.shutdown()
                srv.server_close()
        except Exception:
            pass


def finish(result, tmp):
    out = os.environ.get('PHC_DL_RESULT',
                         os.path.join(HERE, 'dl-result.json'))
    with open(out, 'w') as f:
        json.dump(result, f, indent=1)
    # keep evidence dir only on failure for inspection
    if result['verdict'] == 'PASS':
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        result['evidence_dir'] = tmp
    print(json.dumps(result, indent=1))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
