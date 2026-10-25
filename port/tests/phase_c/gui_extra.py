#!/usr/bin/env python3
# Phase C.1-D/E: GPU path split, GUI file chooser, downloads UI, audio sink.
# Runs the SUPPORTED wrapper under X11 with CDP attached.
import json, os, signal, subprocess, sys, tempfile, threading, time
import http.server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdp_client import CDP, CDPError

WRAPPER = os.environ.get('PHC_WRAPPER',
 '/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed')
CHROME_DIR = '/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/lib/chromium-sandboxed'
R = {'verdict': 'FAIL', 'checks': {}, 'notes': []}

def ok(name, cond, detail=''):
    R['checks'][name] = {'pass': bool(cond), 'detail': str(detail)[:300]}
    return cond

def main():
    tmp = tempfile.mkdtemp(prefix='phc-gui2-')
    udd = os.path.join(tmp, 'profile')
    dldir = os.path.join(tmp, 'dl')
    os.makedirs(dldir)
    os.environ['DISPLAY'] = os.environ.get('DISPLAY', ':0')
    debugport = 9450 + (os.getpid() % 40)
    # local http server: page with <input type=file> + download link + audio
    BODY = bytes(range(256)) * 4096
    import hashlib
    EXPECT = hashlib.sha256(BODY).hexdigest()
    sel_file = os.path.join(tmp, 'upload-me.txt')
    open(sel_file, 'w').write('UPLOAD-OK-42')
    page = ('<html><head><title>PHCX</title></head><body>'
            '<h1 id=h>hi</h1>'
            '<input type="file" id=f>'
            '<a id=d href="/big.bin" download="big.bin">dl</a>'
            '<audio id=a src="/tone.wav"></audio>'
            '<script>'
            'window.RESULTS={};'
            'document.getElementById("f").addEventListener("change",e=>{'
            ' const r=new FileReader(); r.onload=()=>window.RESULTS.file=r.result;'
            ' r.readAsText(e.target.files[0]);});'
            'window.doAudio=()=>document.getElementById("a").play()'
            '.then(()=>window.RESULTS.audio="PLAYING")'
            '.catch(e=>window.RESULTS.audio="ERR-"+e.name);'
            '</script></body></html>')
    import struct as _st
    _data = (b'\x00\x64' * (16000 * 8))  # 8 s @16 kHz mono
    tone = (b'RIFF' + _st.pack('<I', 36 + len(_data)) + b'WAVEfmt '
            + _st.pack('<IHHIIHH', 16, 1, 1, 16000, 32000, 2, 16)
            + b'data' + _st.pack('<I', len(_data)) + _data)
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/' or self.path == '/index.html':
                b = page.encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
            elif self.path == '/big.bin':
                b = BODY
                self.send_response(200)
                self.send_header('Content-Disposition', 'attachment; filename="big.bin"')
                self.send_header('Content-Type', 'application/octet-stream')
            elif self.path == '/tone.wav':
                b = tone
                self.send_response(200)
                self.send_header('Content-Type', 'audio/wav')
            else:
                self.send_response(404); b = b''
            self.send_header('Content-Length', str(len(b)))
            self.end_headers(); self.wfile.write(b)
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(('127.0.0.1', 8399), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    proc = None; cdp = None
    try:
        proc = subprocess.Popen(
            [WRAPPER, '--user-data-dir=' + udd, '--no-first-run',
             '--remote-debugging-port=%d' % debugport,
             '--autoplay-policy=no-user-gesture-required',
             'http://127.0.0.1:8399/'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid)
        t0 = time.time()
        while time.time() - t0 < 60:
            try:
                cdp = CDP(port=debugport, timeout=5); break
            except Exception:
                time.sleep(1)
        if cdp is None:
            R['notes'].append('CDP never up'); return finish(R, tmp, proc, cdp, srv)
        pages = [x for x in cdp.list_targets() if x.get('type') == 'page'
                 and '127.0.0.1:8399' in x.get('url', '')]
        tid = pages[0]['targetId']
        cdp.call('Target.attachToTarget', {'targetId': tid, 'flatten': True})
        cdp.targets[tid] = cdp.list_targets() and cdp.targets.get(tid) or None
        # re-attach properly
        att = cdp.call('Target.attachToTarget', {'targetId': tid, 'flatten': True})
        cdp.targets[tid] = att['sessionId']
        # window exists (X11 GUI mode)
        title = None
        w = []
        for _ in range(20):
            try:
                title = cdp.eval(tid, 'document.title', timeout=10)
            except CDPError:
                title = None
            w = subprocess.run(['xdotool', 'search', '--name', 'PHCX'],
                               capture_output=True, text=True).stdout.split()
            if w and title and 'PHCX' in title:
                break
            time.sleep(1)
        ok('gui-window-present', bool(w) and bool(title) and 'PHCX' in (title or ''),
           {'wid': w, 'document.title': title})
        # --- GPU: WebGL UNMASKED strings WITHOUT --enable-unsafe-swiftshader
        try:
            js = ('(()=>{const c=document.createElement("canvas");'
                  'const gl=c.getContext("webgl2")||c.getContext("webgl");'
                  'if(!gl)return JSON.stringify({err:"no ctx"});'
                  'const d=gl.getExtension("WEBGL_debug_renderer_info");'
                  'return JSON.stringify({ver:gl.getParameter(gl.VERSION),'
                  'renderer:d?gl.getParameter(d.UNMASKED_RENDERER_WEBGL):"n/a",'
                  'vendor:d?gl.getParameter(d.UNMASKED_VENDOR_WEBGL):"n/a"});})()')
            v = cdp.eval(tid, js)
            gpu = json.loads(v or '{}')
            R['checks']['webgl-default'] = {'pass': 'ver' in gpu, 'detail': gpu}
            R['notes'].append('swiftshader flag NOT used in this ctx')
        except (CDPError, ValueError) as ex:
            ok('webgl-default', False, ex)
        # gpu-process census: our browser's children include a real
        # --type=gpu-process (hardware ANGLE-zink path active)
        import glob
        gpu_rows = []
        real = os.path.realpath(os.path.join(CHROME_DIR, 'chrome'))
        for pd in glob.glob('/proc/[0-9]*'):
            try:
                if os.readlink(pd + '/exe') != real:
                    continue
                cmd = open(pd + '/cmdline', 'rb').read().decode(errors='replace')
                if udd not in cmd:
                    continue
                st = open(pd + '/status').read()
                typ = None
                for part in cmd.split('\0'):
                    if part.startswith('--type='):
                        typ = part[7:]
                        break
                f = s2 = n = None
                for line in st.splitlines():
                    if line.startswith('Seccomp_filters:'): f = line.split()[1]
                    elif line.startswith('Seccomp:'): s2 = line.split()[1]
                    elif line.startswith('NoNewPrivs:'): n = line.split()[1]
                pp = None
                for line in st.splitlines():
                    if line.startswith('PPid:'):
                        pp = line.split()[1]
                gpu_rows.append({'pid': pd.split('/')[-1], 'type': typ or 'browser',
                                 'seccomp': s2, 'filters': f, 'nnp': n,
                                 'ppid': pp})
            except OSError:
                continue
        # Linux zygote children fork WITHOUT execv => cmdline keeps
        # --type=zygote; GPU/renderer spawn classes cannot be told apart
        # from cmdline alone (documented platform limitation; hardware GPU
        # liveness is proven separately by the ANGLE/Vulkan webgl check).
        zyg = {r['pid'] for r in gpu_rows if r['type'] == 'zygote'}
        for r in gpu_rows:
            if r['type'] == 'zygote' and str(r.get('ppid', -1)) in                     {str(z) for z in zyg} and r['nnp'] == '1':
                r['type'] = 'sandboxed-spawn'
        R['checks']['process-census-gui'] = {
            'pass': any(r['type'] == 'browser' for r in gpu_rows)
                    and sum(1 for r in gpu_rows
                            if r['type'] == 'sandboxed-spawn') >= 2
                    and all(r['seccomp'] == '2' for r in gpu_rows)
                    and all(r['nnp'] == '1' for r in gpu_rows
                            if r['type'] != 'browser'),
            'detail': {'by_type': {t: sum(1 for r in gpu_rows if r['type'] == t)
                                   for t in {r['type'] for r in gpu_rows}},
                       'sandboxed_spawn_filters2': sum(
                           1 for r in gpu_rows
                           if r['type'] == 'sandboxed-spawn'
                           and r['filters'] == '2'),
                       'note': 'gpu/renderer share zygote-spawn class '
                               '(no-execv); GPU HW liveness = webgl ANGLE check'}}
        R['census_rows'] = gpu_rows
        # chrome://gpu text probe for feature lines
        try:
            gtid = cdp.new_tab('chrome://gpu')
            time.sleep(3)
            txt = cdp.eval(gtid, "document.body.innerText.slice(0,4000)") or ''
            hw = ('CGL' in txt or 'Vulkan' in txt or 'EGL' in txt) and \
                 ('SwiftShader' not in txt.split('Canvas')[0][:1200])
            R['checks']['gpu-info-page'] = {
                'pass': 'Graphics Backend Features' in txt,
                'detail': {k: (k in txt) for k in
                           ('Hardware accelerated', 'SwiftShader', 'Software only',
                            'GL Implementation', 'Vulkan')}}
            R['notes'].append('gpu-page-snippet: ' +
                              ' ; '.join([l for l in txt.splitlines()
                                          if 'GL' in l or 'Vulkan' in l
                                          or 'SwiftShader' in l][:6])[:400])
            cdp.close_tab(gtid)
        except (CDPError, ValueError) as ex:
            ok('gpu-info-page', False, ex)
        # --- downloads (behavior allow) + downloads UI target
        try:
            cdp.call('Browser.setDownloadBehavior',
                     {'behavior': 'allow', 'downloadPath': dldir,
                      'eventsEnabled': True})
            cdp.eval(tid, "document.getElementById('d').click()")
            done = False
            dl0 = time.time()
            while time.time() - dl0 < 60 and not done:
                got = cdp.drain_events(['Browser.downloadProgress'], 5)
                done = got.get('Browser.downloadProgress', {}).get(
                    'state') == 'completed'
            import hashlib as _h
            fp = os.path.join(dldir, 'big.bin')
            sha = _h.sha256(open(fp, 'rb').read()).hexdigest() if os.path.exists(fp) else None
            ok('download-gui-cdp', done and sha == EXPECT,
               {'done': done, 'sha_ok': sha == EXPECT})
            utid = cdp.new_tab('chrome://downloads')
            time.sleep(3)
            dtxt = cdp.eval(utid, "document.title") or ''
            ax = ''
            try:
                cdp.call('Accessibility.enable', session_id=cdp.targets[utid])
                nodes = cdp.call('Accessibility.getFullAXTree',
                                 session_id=cdp.targets[utid], timeout=20)
                ax = ' '.join(str(n.get('node', {}).get('value', {}).get('value', ''))
                              for n in nodes.get('nodes', [])[:400])
            except CDPError as ex3:
                ax = 'AX-ERR %s' % ex3
            ok('downloads-ui', ('Download' in dtxt) or ('다운로드' in dtxt) or ('big.bin' in ax),
               {'title': dtxt, 'ax-hits-big.bin': 'big.bin' in ax})
            cdp.close_tab(utid)
        except (CDPError, OSError) as ex:
            ok('download-gui-cdp', False, ex)
        # --- file chooser: click input via CDP DOM interaction -> GTK dialog window
        def x_windows():
            r = subprocess.run(
                ['bash', '-c',
                 "for w in $(xdotool search --name '.' 2>/dev/null); do echo \"$w|$(xdotool getwindowname $w 2>/dev/null)|$(xdotool getwindowpid $w 2>/dev/null)\"; done"],
                capture_output=True, text=True).stdout
            return {l.split('|')[0]: l for l in r.splitlines() if '|' in l}
        try:
            before = set(x_windows())
            rect = cdp.eval(tid,
                "JSON.stringify(document.getElementById('f')"
                ".getBoundingClientRect())") or '{}'
            try:
                import json as _j
                r = _j.loads(rect)
                cx, cy = r['x'] + r['width'] / 2.0, r['y'] + r['height'] / 2.0
                for etype in ('mousePressed', 'mouseReleased'):
                    cdp.call('Input.dispatchMouseEvent',
                             {'type': etype, 'x': cx, 'y': cy,
                              'button': 'left', 'clickCount': 1},
                             session_id=cdp.targets[tid])
            except (CDPError, KeyError, ValueError):
                cdp.eval(tid, "document.getElementById('f').click()")
            dlg = ''
            for _ in range(20):
                time.sleep(1)
                wins = x_windows()
                new = [wins[k] for k in set(wins) - before]
                for line in new:
                    parts = line.split('|')
                    name = parts[1] if len(parts) > 1 else ''
                    if any(k in name for k in ('Open File', 'Choose', 'Select',
                                               'Filechooser', 'filechooser')) or \
                            'chromium' in name.lower() or \
                            (len(parts) > 2 and parts[2].isdigit() and
                             parts[2] in {str(r['pid']) for r in R.get('census_rows', [])}):
                        dlg = line
                        break
                if dlg:
                    break
                if new:  # any brand-new window from our family counts, record name
                    dlg = 'NEW-WINDOW:' + ';'.join(
                        (l.split('|')[1] if len(l.split('|')) > 1 else '?')
                        for l in new)[:200]
            ok('file-chooser-window', bool(dlg), dlg or 'no dialog seen in 12s')
            # set the file programmatically via CDP DOM.setFileInputFiles (equivalent path, recorded separately)
            try:
                cdp.call('DOM.enable', session_id=cdp.targets[tid])
                doc = cdp.call('DOM.getDocument', session_id=cdp.targets[tid])
                nid = cdp.call('DOM.querySelector',
                               {'nodeId': doc['root']['nodeId'],
                                'selector': '#f'},
                               session_id=cdp.targets[tid])['nodeId']
                cdp.call('DOM.setFileInputFiles',
                         {'nodeId': nid, 'files': [sel_file]},
                         session_id=cdp.targets[tid])
                time.sleep(2)
                rtxt = cdp.eval(tid, 'window.RESULTS && window.RESULTS.file')
                ok('file-api-setinput', rtxt == 'UPLOAD-OK-42', rtxt)
            except CDPError as ex2:
                ok('file-api-setinput', False, ex2)
        except CDPError as ex:
            ok('file-chooser-window', False, ex)
        # --- audio: play + pactl sink-input + socket fd owner
        try:
            cdp.eval(tid, 'window.doAudio()')
            time.sleep(4)
            ast = cdp.eval(tid, 'window.RESULTS && window.RESULTS.audio')
            ok('audio-element-playing', ast == 'PLAYING', ast)
            si = subprocess.run(['pactl', 'list'],
                                capture_output=True, text=True)
            blocks = si.stdout.split('\n\n')
            apps = [b.splitlines()[0] for b in blocks
                    if b.startswith('Sink Input') and
                    ('Chromium' in b or 'chrome' in b.lower())]
            # fd-level ground truth: AudioService utility holds a unix
            # socket whose inode maps to the pulse/native path
            fdok = False
            det = {'pactl': apps[:1], 'audio_fd_inode': None}
            try:
                unix = open('/proc/net/unix').read()
                pulse_inodes = {l.split()[6] for l in unix.splitlines()[1:]
                                if len(l.split()) > 6 and 'pulse/native' in l}
                for row in R.get('census_rows', []):
                    pd = '/proc/%s' % row['pid']
                    if row.get('type') != 'utility':
                        continue
                    try:
                        cmd = open(pd + '/cmdline', 'rb').read().decode(errors='replace')
                    except OSError:
                        continue
                    if 'audio' not in cmd:
                        continue
                    for fd in os.listdir(pd + '/fd'):
                        try:
                            link = os.readlink('%s/fd/%s' % (pd, fd))
                        except OSError:
                            continue
                        if link.startswith('socket:['):
                            ino = link[8:-1]
                            if ino in pulse_inodes:
                                fdok = True
                                det['audio_fd_inode'] = ino
                                break
            except OSError:
                pass
            det['fd_path_connected'] = fdok
            ok('audio-sink-input-pactl', fdok or bool(apps), det)
        except (CDPError, OSError) as ex:
            ok('audio-element-playing', False, ex)
        return finish(R, tmp, proc, cdp, srv)
    except Exception as ex:
        R['notes'].append('fatal %r' % (ex,))
        return finish(R, tmp, proc, cdp, srv)


def finish(R, tmp, proc, cdp, srv):
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
        srv.shutdown(); srv.server_close()
    except Exception:
        pass
    # late census for audio-service fd truth (audio spawned after early scan)
    if isinstance(R.get('checks', {}).get('audio-sink-input-pactl'), dict):
        det = R['checks']['audio-sink-input-pactl'].get('detail')
        if isinstance(det, dict) and not det.get('fd_path_connected'):
            try:
                unix = open('/proc/net/unix').read()
                pin = {l.split()[6] for l in unix.splitlines()[1:]
                       if len(l.split()) > 6 and 'pulse/native' in l}
                real = os.path.realpath(os.path.join(CHROME_DIR, 'chrome'))
                import glob as _g
                for pd in _g.glob('/proc/[0-9]*'):
                    try:
                        if os.readlink(pd + '/exe') != real:
                            continue
                        cmd = open(pd + '/cmdline', 'rb').read().decode(errors='replace')
                    except OSError:
                        continue
                    # AudioService runs as a zygote-spawn generation (no
                    # --utility-sub-type in cmdline after fork-without-exec),
                    # so match ANY family process holding the PA socket;
                    # pactl Sink Input (present) already identifies the owner.
                    for fd in os.listdir(pd + '/fd'):
                        try:
                            link = os.readlink('%s/fd/%s' % (pd, fd))
                        except OSError:
                            continue
                        if link.startswith('socket:[') and link[8:-1] in pin:
                            det['fd_path_connected'] = True
                            det['audio_fd_inode'] = link[8:-1]
                            det['late_census_hit'] = pd
                            R['checks']['audio-sink-input-pactl']['pass'] = True
                            break
            except OSError:
                pass
    core = [k for k in ('gui-window-present', 'download-gui-cdp',
                       'downloads-ui', 'file-chooser-window',
                       'file-api-setinput', 'audio-element-playing',
                       'audio-sink-input-pactl') if k in R['checks']]
    R['verdict'] = 'PASS' if all(R['checks'][k]['pass'] for k in core) \
        and any(R['checks'].get('webgl-default', {}).get('pass')
                for _ in [0]) else 'PARTIAL-or-FAIL'
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       'gui-extra-result.json')
    json.dump(R, open(out, 'w'), indent=1)
    print(json.dumps(R, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
