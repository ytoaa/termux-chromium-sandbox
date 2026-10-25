#!/usr/bin/env python3
# Phase C.1-A3/F: REAL concurrent-tab stability battery.
# One browser process; 2/4/6 tabs alive SIMULTANEOUSLY (distinct origins +
# --site-per-process => one renderer per tab, provable via process census).
# Per tab: CDP Target.getTargets presence + Runtime.evaluate render marker.
# Per census: type/PPid/Seccomp/Seccomp_filters/NoNewPrivs/VmRSS/CPU jiffies.
# Failures counted per round; full cleanup verified (0 residual). Exit code
# non-zero on any unmet condition. No string-only PASS checks.
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import http.server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdp_client import CDP, CDPError, http_json

HERE = os.path.dirname(os.path.abspath(__file__))
CHROME = os.environ.get(
    'PHC_CHROME',
    '/data/data/com.termux/files/home/Project/.phc-main/data/data/'
    'com.termux/files/usr/lib/chromium-sandboxed/chrome')
MINUTES = float(os.environ.get('PHC_SOAK_MINUTES', '15'))
ROUNDS_PLAN = [2, 4, 6]


def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]
    s.close(); return p


def make_server(port, marker):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = ('<html><head><title>%s</title></head><body>'
                    '<h1>%s</h1><script>document.title="%s-R"</script>'
                    '</body></html>' % (marker, marker, marker)).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(('127.0.0.1', port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def census(udd):
    rows = []
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink('/proc/%s/exe' % pid)
        except OSError:
            continue
        if exe != os.path.realpath(CHROME):
            continue
        try:
            cmd = open('/proc/%s/cmdline' % pid, 'rb').read().decode(
                errors='replace')
            if udd not in cmd:
                continue
            st = open('/proc/%s/status' % pid).read()
            stat = open('/proc/%s/stat' % pid).read().rsplit(') ', 1)
            fields = stat[-1].split()
            t = None
            for part in cmd.split('\0'):
                if part.startswith('--type='):
                    t = part[7:]
                    break
            def g(key):
                for line in st.splitlines():
                    if line.startswith(key):
                        return line.split()[1]
                return None
            pp = g('PPid:'); se = g('Seccomp:'); fi = g('Seccomp_filters:')
            nn = g('NoNewPrivs:')
            # reclassify zygote children (no execv keeps --type=zygote)
            rows.append({'pid': int(pid), 'type': t or 'browser', 'ppid': int(pp or 0),
                         'seccomp': se, 'filters': fi, 'nnp': nn,
                         'rss_kb': int((g('VmRSS:') or '0')),
                         'cpu_jiffies': int(fields[11]) + int(fields[12])})
        except (OSError, IndexError, ValueError):
            continue
    # mark renderer class: parent is a zygote process
    zyg = {r['pid'] for r in rows if r['type'] == 'zygote'}
    for r in rows:
        if r['type'] == 'zygote' and r['ppid'] in zyg:
            r['type'] = 'renderer(or zyg-spawn)'
    return rows


def main():
    tmp = tempfile.mkdtemp(prefix='phc-soak-')
    udd = os.path.join(tmp, 'profile')
    result = {'verdict': 'FAIL', 'rounds': 0, 'failures': [], 'tabs_ok': 0}
    proc = cdp = None
    servers = []
    ports = [8310 + i for i in range(6)]
    try:
        for i, p in enumerate(ports):
            servers.append(make_server(p, 'T%d' % i))
        dbg = free_port()
        env = dict(os.environ)
        preload = os.path.join(os.path.dirname(CHROME), 'libtermux-gnp-fix.so')
        if os.path.exists(preload):
            env['LD_PRELOAD'] = preload
        proc = subprocess.Popen(
            [CHROME, '--headless=new', '--user-data-dir=' + udd,
             '--no-first-run', '--remote-debugging-port=%d' % dbg,
             '--site-per-process', '--disable-background-networking',
             'about:blank'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid, env=env)
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                cdp = CDP(port=dbg, timeout=5); break
            except Exception:
                time.sleep(1)
        if cdp is None:
            result['failures'].append('CDP never up')
            return finish(result, tmp, proc, cdp, servers)
        t_start = time.time()
        round_no = 0
        max_rss = 0
        census_seccomp_bad = 0
        renderer_seen = set()
        while time.time() - t_start < MINUTES * 60:
            round_no += 1
            result['rounds'] = round_no
            for n in ROUNDS_PLAN:
                tids = []
                try:
                    for i in range(n):
                        tids.append(cdp.new_tab('http://127.0.0.1:%d/%d' %
                                                (ports[i], round_no)))
                    time.sleep(2.5)
                    pages = [x for x in cdp.list_targets()
                             if x.get('type') == 'page' and
                             str(x.get('url', '')).startswith(
                                 'http://127.0.0.1:83')]
                    if len(pages) != n:
                        result['failures'].append(
                            'r%d n%d concurrent-pages=%d' % (round_no, n, len(pages)))
                        continue
                    ok = 0
                    for tid in tids:
                        try:
                            title = cdp.eval(tid, 'document.title', timeout=15)
                            if title and title.endswith('-R'):
                                ok += 1
                        except CDPError:
                            pass
                    if ok != n:
                        result['failures'].append(
                            'r%d n%d rendered=%d' % (round_no, n, ok))
                        continue
                    rows = census(udd)
                    rends = [r for r in rows if str(r['type']).startswith('renderer')]
                    renderer_seen |= {r['pid'] for r in rends}
                    if len(rends) < n:
                        result['failures'].append(
                            'r%d n%d renderer-procs=%d' % (round_no, n, len(rends)))
                    for r in rows:
                        max_rss = max(max_rss, r['rss_kb'])
                        if r['seccomp'] != '2':
                            census_seccomp_bad += 1
                        if str(r['type']).startswith('renderer') and \
                                r['nnp'] != '1':
                            result['failures'].append(
                                'r%d renderer pid=%d nnp=%s' % (round_no, r['pid'], r['nnp']))
                    result['tabs_ok'] += n
                    time.sleep(3)
                finally:
                    for tid in tids:
                        cdp.close_tab(tid)
            time.sleep(2)
        result['distinct_renderer_pids'] = len(renderer_seen)
        result['max_rss_kb'] = max_rss
        result['seccomp_mode2_violations'] = census_seccomp_bad
        if (result['rounds'] >= 3 and not result['failures']
                and len(renderer_seen) >= 6 and census_seccomp_bad == 0):
            result['verdict'] = 'PASS'
        return finish(result, tmp, proc, cdp, servers)
    except Exception as ex:
        result['failures'].append('fatal: %r' % (ex,))
        return finish(result, tmp, proc, cdp, servers)


def finish(result, tmp, proc, cdp, servers):
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
    time.sleep(2)
    left = []
    try:
        real = os.path.realpath(CHROME)
        for p in os.listdir('/proc'):
            if not p.isdigit():
                continue
            try:
                if os.readlink('/proc/%s/exe' % p) == real:
                    left.append(int(p))
            except OSError:
                pass
    except OSError:
        pass
    result['residual_procs'] = left
    if left:
        result['failures'].append('residual %s' % left)
    for s in servers:
        try:
            s.shutdown(); s.server_close()
        except Exception:
            pass
    out = os.path.join(HERE, 'soak-result.json')
    json.dump(result, open(out, 'w'), indent=1)
    print(json.dumps({k: v for k, v in result.items() if k != 'note'}, indent=1))
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
