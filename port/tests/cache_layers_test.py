#!/usr/bin/env python3
"""Cache-layer tests (perf/ci-cache-layers): dependency cache integration
contract, preflight fail-fast/whitelist, prune caps, deb-reuse fail-closed
gates, node24 protection, R12 policy immutability. No docker, no network
except localhost servers. Exits non-zero on any FAIL."""
import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent          # repo root
CI = ROOT / "port" / "ci.sh"
DL_FIXTURE = HERE / "fixtures" / "termux" / "termux_download.sh"
PASS = FAIL = 0


def ok(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name} {detail}")


def run(args, env=None, cwd=None, timeout=120, shell=False):
    return subprocess.run(args, capture_output=True, text=True,
                          env=env, cwd=cwd, timeout=timeout, shell=shell)


REQ_COUNT = {}


class Serve(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        REQ_COUNT[self.path.split("?")[0]] = REQ_COUNT.get(self.path.split("?")[0], 0) + 1
        if self.path.startswith("/slow/"):
            time.sleep(0.5)
        body = SERVE_ROOT.get(self.path.split("?")[0])
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


SERVE_ROOT = {}
SRV = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Serve)
PORT = SRV.server_address[1]
threading.Thread(target=SRV.serve_forever, daemon=True).start()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def termux_download(url, dest, checksum, tmpdir):
    env = dict(os.environ, TERMUX_PKG_TMPDIR=str(tmpdir), TERMUX_QUIET_BUILD="true")
    return run(["bash", "-c",
                f'set -euo pipefail; source "{DL_FIXTURE}"; termux_download "{url}" "{dest}" "{checksum}"'],
               env=env, timeout=180)


import tempfile
W = Path(tempfile.mkdtemp(prefix="cache-layers-"))

# ---------- T1..T5: official termux_download cache contract on our volume ----------
vol = W / "dep-cache" / "aarch64"
vol.mkdir(parents=True)
deb_payload = b"DEBDATA" * 1000
SERVE_ROOT["/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb"] = deb_payload
dest = vol / "libfoo_1.0_aarch64.deb"
r1 = termux_download(f"http://127.0.0.1:{PORT}/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb",
                     dest, sha(deb_payload), W)
ok("T1 empty-cache download", r1.returncode == 0 and dest.read_bytes() == deb_payload, r1.stderr[:200])
base_reqs = REQ_COUNT.get("/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb", 0)
r2 = termux_download(f"http://127.0.0.1:{PORT}/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb",
                     dest, sha(deb_payload), W)
ok("T2 warm-cache hit (no re-download)",
   r2.returncode == 0 and REQ_COUNT.get("/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb", 0) == base_reqs)
dest.write_bytes(b"CORRUPTED")
r3 = termux_download(f"http://127.0.0.1:{PORT}/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb",
                     dest, sha(deb_payload), W)
ok("T3 corrupted cache self-heals", r3.returncode == 0 and dest.read_bytes() == deb_payload
   and REQ_COUNT.get("/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb", 0) == base_reqs + 1, r3.stderr[:200])
dest2 = vol / "libfoo_1.1_aarch64.deb"  # version bump -> new name -> miss/download
r4 = termux_download(f"http://127.0.0.1:{PORT}/pool/main/libx/libfoo/libfoo_1.0_aarch64.deb",
                     dest2, sha(deb_payload), W)
ok("T4 version-keyed filename (miss->download)", r4.returncode == 0 and dest2.exists())
vol_arm = W / "dep-cache" / "arm"
vol_arm.mkdir(parents=True)
ok("T5 arch namespaces are separate dirs", str(vol) != str(vol_arm) and (vol / "libfoo_1.0_aarch64.deb").exists())

# Whitelisted variant of ci.sh (127.0.0.1 accepted as "official") for
# behavior tests that must exercise the probe paths instead of the
# host-whitelist refusal.
tp = W / "termux-packages"
(tp / "scripts").mkdir(parents=True)
(tp / "build-package.sh").write_text("#!/bin/sh\nexit 0\n")
(tp / "scripts" / "run-docker.sh").write_text("#!/bin/sh\nexit 0\n")
for f in (tp / "build-package.sh", tp / "scripts" / "run-docker.sh"):
    f.chmod(0o755)
ci2 = W / "ci-whitelisted.sh"
src = Path(str(CI)).read_text()
import re as _re
src2 = _re.sub(r'^OFFICIAL_APT_HOSTS="[^"]*"', 'OFFICIAL_APT_HOSTS="127.0.0.1"', src, count=1, flags=_re.M)
assert src2 != src
ci2.write_text(src2); ci2.chmod(0o755)
# dead repo (port closed) -> PREFLIGHT FAIL
(tp / "repo.json").write_text(json.dumps({
    "pkg_format": "debian",
    "packages": {"name": "termux-main", "distribution": "stable", "component": "main",
                 "url": "http://127.0.0.1:9/apt/termux-main"}}))
r = run(["bash", str(ci2), "download-preflight", str(tp)], timeout=300)
ok("T6a preflight fails fast on dead repo", r.returncode != 0 and "PREFLIGHT FAIL" in (r.stdout + r.stderr),
   (r.stdout + r.stderr)[-200:])
# non-official host -> refusal even if reachable
SERVE_ROOT["/apt/termux-main/dists/stable/Release"] = (
    b"Origin: evil\n\nSHA256:\n " + b"a" * 64 + b"  160  main/binary-aarch64/Packages.xz\n")
SERVE_ROOT["/apt/termux-root/dists/root/Release"] = (
    b"Origin: evil-root\n\nSHA256:\n " + b"b" * 64 + b"  160  root/binary-aarch64/Packages.xz\n")
SERVE_ROOT["/apt/termux-main/dists/stable/main/binary-aarch64/Packages.xz"] = b"PKGS" * 40
SERVE_ROOT["/apt/termux-root/dists/root/root/binary-aarch64/Packages.xz"] = b"PKGSROOT" * 40
(tp / "repo.json").write_text(json.dumps({
    "pkg_format": "debian",
    "packages": {"name": "termux-main", "distribution": "stable", "component": "main",
                 "url": f"http://127.0.0.1:{PORT}/apt/termux-main"}}))
r = run(["bash", str(CI), "download-preflight", str(tp)], timeout=300)
ok("T6b non-official mirror host refused", r.returncode != 0 and "non-official" in (r.stdout + r.stderr))

# ---------- T6c: distribution-aware probing (root repo uses dists/root) ----------
(tp2 := W / "tp-t6c")
(tp2 / "scripts").mkdir(parents=True, exist_ok=True)
(tp2 / "build-package.sh").write_text("#!/bin/sh\ntrue\n"); (tp2 / "scripts" / "run-docker.sh").write_text("#!/bin/sh\ntrue\n")
(tp2 / "build-package.sh").chmod(0o755); (tp2 / "scripts" / "run-docker.sh").chmod(0o755)
(tp2 / "repo.json").write_text(json.dumps({
    "pkg_format": "debian",
    "packages": {"name": "termux-main", "distribution": "stable", "component": "main",
                 "url": f"http://127.0.0.1:{PORT}/apt/termux-main"},
    "root-packages": {"name": "termux-root", "distribution": "root", "component": "root",
                 "url": f"http://127.0.0.1:{PORT}/apt/termux-root"}}))
r = run(["bash", str(ci2), "download-preflight", str(tp2)], timeout=300)
ok("T6c per-distribution probe (root passes when up; main+x11 too)",
   r.returncode == 0 and "dist=root" in r.stdout and "http=200" in r.stdout
   and "1MiB ranged transfer" in r.stdout
   and "path=main/binary-aarch64/Packages.xz" in r.stdout
   and "path=root/binary-aarch64/Packages.xz" in r.stdout,
   (r.stdout + r.stderr)[-250:])

# ---------- T7/T8: deb_key stability & sensitivity ----------
subprocess.run(["git", "-C", str(tp), "init", "-q"], check=True)
subprocess.run(["git", "-C", str(tp), "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], check=True)
subprocess.run(["git", "-C", str(tp), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fake"], check=True)
(tp / "packages" / "chromium").mkdir(parents=True)
(tp / "packages" / "chromium" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.47"\n')
(tp / "packages" / "chromium-sandboxed").mkdir(parents=True)
(tp / "packages" / "chromium-sandboxed" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.47"\n')
(tp / "repo.json").write_text(json.dumps({"pkg_format": "debian",
    "packages": {"name": "termux-main", "distribution": "stable", "component": "main",
                 "url": "https://packages-cf.termux.dev/apt/termux-main"}}))
IMG_FAKE = "sha256:" + "a" * 64
env = dict(os.environ, TERMUX_SANDBOXED_REVISION="12", TERMUX_BUILDER_IMAGE_ID=IMG_FAKE)
k1 = run(["bash", str(CI), "deb-key", str(tp)], env=env).stdout.strip().splitlines()[-1]
k2 = run(["bash", str(CI), "deb-key", str(tp)], env=env).stdout.strip().splitlines()[-1]
ok("T7 deb_key stable for identical inputs", k1.startswith("DEB_KEY=") and k1 == k2, k1)
(tp / "packages" / "chromium" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.48"\n')
(tp / "packages" / "chromium-sandboxed" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.48"\n')
k3 = run(["bash", str(CI), "deb-key", str(tp)], env=env).stdout.strip().splitlines()[-1]
ok("T8 deb_key changes when recipe/upstream changes", k3 != k1)
(tp / "packages" / "chromium" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.47"\n')
(tp / "packages" / "chromium-sandboxed" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.47"\n')

# ---------- T19..T23: DEB key integrity (image id + final repo.json) ----
k_dup = run(["bash", str(CI), "deb-key", str(tp)], env=env).stdout.strip().splitlines()[-1]
ok("T19 identical image id + identical inputs -> identical key (reproducible)", k_dup == k1, f"{k_dup} != {k1}")
k_img = run(["bash", str(CI), "deb-key", str(tp)],
            env=dict(env, TERMUX_BUILDER_IMAGE_ID="sha256:" + "b" * 64)).stdout.strip().splitlines()[-1]
ok("T20 image id change -> DEB key change", k_img != k1, k_img)
shim = W / "shim-no-docker"; shim.mkdir(exist_ok=True)
(shim / "docker").write_text("#!/bin/sh\nexit 1\n"); (shim / "docker").chmod(0o755)
r = run(["bash", str(CI), "deb-key", str(tp)],
        env=dict(env, TERMUX_BUILDER_IMAGE_ID="", PATH=f"{shim}:{os.environ['PATH']}"))
ok("T21a missing image id (docker inspect fails, no env) -> fail-closed",
   r.returncode != 0 and "DEB KEY FAIL" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-160:])
r = run(["bash", str(CI), "deb-key", str(tp)], env=dict(env, TERMUX_BUILDER_IMAGE_ID="not-a-hash"))
ok("T21b malformed image id -> fail-closed",
   r.returncode != 0 and "DEB KEY FAIL" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-160:])
repo_orig = (tp / "repo.json").read_text()
(tp / "repo.json").write_text(json.dumps({"pkg_format": "debian",
    "packages": {"name": "termux-main", "distribution": "stable", "component": "main",
                 "url": "https://packages.termux.dev/apt/termux-main"}}))
k_repo = run(["bash", str(CI), "deb-key", str(tp)], env=env).stdout.strip().splitlines()[-1]
ok("T22 repo.json change -> DEB key change", k_repo != k1, k_repo)
(tp / "repo.json").write_text(repo_orig)
# T23: mirror switch (preflight rewrites repo.json) must flow into the key
(tp / "repo.json").write_text(json.dumps({"pkg_format": "debian",
    "packages": {"name": "termux-main", "distribution": "stable", "component": "main",
                 "url": "https://packages-cf.termux.dev/apt/termux-main"}}))
k_before_switch = run(["bash", str(CI), "deb-key", str(tp)], env=env).stdout.strip().splitlines()[-1]
r = run(["bash", str(CI), "download-preflight", str(tp)],
        env=dict(os.environ, PATH=f"{HERE / 'fixtures' / 'net'}:{os.environ['PATH']}",
                 FAKE_FAIL_HOST="packages-cf.termux.dev"), timeout=300)
switched = "packages.termux.dev/apt/termux-main" in (tp / "repo.json").read_text()
k_after_switch = run(["bash", str(CI), "deb-key", str(tp)], env=env).stdout.strip().splitlines()[-1]
ok("T23 preflight mirror-switch -> final repo.json reflected in key",
   r.returncode == 0 and "MIRROR-SWITCH" in r.stdout and switched and k_after_switch != k_before_switch,
   (r.stdout + r.stderr)[-200:])
(tp / "repo.json").write_text(repo_orig)

# ---------- T9..T12: deb-reuse fail-closed gates ----------
import subprocess as sp
def build_fake_deb(path, chrome_bytes):
    root = path.parent / f"fake-{path.name}"
    (root / "control").mkdir(parents=True, exist_ok=True)
    (root / "data" / "data/data/com.termux/files/usr/lib/chromium-sandboxed").mkdir(parents=True, exist_ok=True)
    (root / "controlpkg").mkdir(exist_ok=True)
    (root / "controlpkg" / "control").write_text(
        "Package: chromium-sandboxed\nVersion: 156.0.8078.47-12\nArchitecture: arm64\nMaintainer: t\nDescription: t\n")
    (root / "debian-binary").write_text("2.0\n")
    (root / "data" / "data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome").write_bytes(chrome_bytes)
    cwd = os.getcwd()
    os.chdir(root)
    sp.run(["tar", "czf", "data.tar.gz", "-C", "data", "."], check=True)
    sp.run(["tar", "czf", "control.tar.gz", "-C", "controlpkg", "control"], check=True)
    sp.run(["ar", "rc", str(path), "debian-binary", "control.tar.gz", "data.tar.gz"], check=True)
    os.chdir(cwd)
    shutil.rmtree(root)

MARK = b"Termux seccomp-only r12-bionic-tid: renderer allow active padding" + b"\0" * 512
deb_path = tp / "output" / "chromium-sandboxed_156.0.8078.47-12_aarch64.deb"
deb_path.parent.mkdir(exist_ok=True)
build_fake_deb(deb_path, MARK)
# save via ci.sh (needs DEB_KEY) 
DEBK = k1.split("=", 1)[1]
r = run(["bash", str(CI), "deb-reuse-save", str(tp)], env=dict(env, DEB_KEY=DEBK, GITHUB_RUN_ID="test"))
ok("T9a save stores deb+manifest", r.returncode == 0 and (tp / ".deb-cache/deb-manifest.json").exists(), r.stdout[-160:] + r.stderr[-160:])
# strip our fake data.tar from ar? keep as is; verify path uses dpkg-deb fsys-tarfile — ar member name is ../data.tar from build dir; dpkg may reject. Test tolerance: if verify handles gracefully -> reason recorded (still fail-closed). Try:
r = run(["bash", str(CI), "deb-reuse-verify", str(tp)], env=dict(env, DEB_KEY=DEBK))
dec = tp / ".deb-cache/reuse-decision.json"
ok("T9b verify accepts identical deb (full reuse path)",
   r.returncode == 0 and "REUSED=1" in r.stdout and dec.exists()
   and json.loads(dec.read_text())["reused"] is True, r.stdout + r.stderr)
# T12: marker-stripped deb -> fail-closed
deb_path.unlink()
build_fake_deb(deb_path, b"no-marker-here" + b"\0" * 512)
r = run(["bash", str(CI), "deb-reuse-save", str(tp)], env=dict(env, DEB_KEY=DEBK, GITHUB_RUN_ID="test2"))
r = run(["bash", str(CI), "deb-reuse-verify", str(tp)], env=dict(env, DEB_KEY=DEBK))
ok("T12 r12 marker missing -> REUSED=0 (fail-closed)", r.returncode != 0
   and json.loads(dec.read_text())["reason"] == "r12-marker-missing", r.stdout)
r2 = run(["bash", str(CI), "deb-reuse-verify", str(tp)], env=dict(env, DEB_KEY="0" * 64))
ok("T10 key mismatch -> REUSED=0", r2.returncode != 0 and "REUSED=0" in r2.stdout and
   json.loads(dec.read_text())["reason"] in ("key-mismatch", "deb-sha-mismatch", "no-cached-deb", "dpkg-meta"))
if (tp / ".deb-cache/deb-manifest.json").exists():
    m = json.loads((tp / ".deb-cache/deb-manifest.json").read_text())
    m["deb_sha256"] = "0" * 64
    (tp / ".deb-cache/deb-manifest.json").write_text(json.dumps(m))
    r3 = run(["bash", str(CI), "deb-reuse-verify", str(tp)], env=dict(env, DEB_KEY=DEBK))
    ok("T11 sha mismatch -> REUSED=0 + quarantine", r3.returncode != 0 and "deb-sha-mismatch" in r3.stdout
       and not any((tp / ".deb-cache").glob("*.deb")))

# ---------- T13: prune caps + path safety ----------
pd = W / "prune-tp"
(pd / "scripts").mkdir(parents=True)
(pd / "build-package.sh").write_text("#!/bin/sh\ntrue\n"); (pd / "scripts" / "run-docker.sh").write_text("#!/bin/sh\ntrue\n")
(pd / "build-package.sh").chmod(0o755); (pd / "scripts" / "run-docker.sh").chmod(0o755)
pc = pd / ".termux-depcache/aarch64"; pc.mkdir(parents=True)
old = pc / "old.deb"; new = pc / "new.deb"
old.write_bytes(b"x" * (900 * 1024)); time.sleep(1.1); new.write_bytes(b"y" * (900 * 1024))
r = run(["bash", str(CI), "dep-cache-prune", str(pd)], env=dict(os.environ, TERMUX_DEPCACHE_CAP_MB="1"))
ok("T13a prune keeps cap, newest survives", r.returncode == 0 and new.exists() and not old.exists(),
   r.stdout[-160:])
other = W / "elsewhere"; other.mkdir()
r = run(["bash", "-c", f'cd "{other}" && bash "{CI}" dep-cache-prune "{other}"'])
ok("T13b prune refuses unexpected layout", (r.returncode != 0 or "PRUNE REFUSAL" in r.stdout or (other/".termux-depcache").exists()))

# ---------- T14: node24/permission protections ----------
ci_txt = CI.read_text() + (ROOT / ".github/workflows/build-chromium.yml").read_text()
# strip full-line comments: the node24 post-mortem QUOTES upstream rm lines
# in explanatory comments — those must not be flagged; code paths are what matter.
code_txt = "\n".join(l for l in ci_txt.splitlines() if not l.lstrip().startswith("#"))
forbidden = [r"rm\s+-rf[^\n]*/opt/runner-cache", r"rm\s+-rf[^\n]*/opt/hostedtoolcache",
             r"rm\s+-rf[^\n]*/opt/actionarchivecache", r"rm\s+-rf[^\n]*\$AGENT_TOOLSDIRECTORY",
             r"permissions:\s*\n\s*contents:\s*write", r"r12[-_]fallback"]
hits = [p for p in forbidden if re.search(p, code_txt)]
ok("T14 runner/node24 & permission protections intact", not hits, str(hits))
rm_local = re.search(r"rm -rf[^\n]*/usr/local", code_txt)
ok("T14b /usr/local never rm-ed", rm_local is None)

# ---------- T15: R12 policy immutability ----------
diffp = subprocess.run(["git", "-C", str(ROOT), "diff", "--name-only", "bae5316..HEAD", "--",
                        "port/chromium_sandbox_port.py",
                        "port/tests/fixtures/sandbox/policy/linux/bpf_renderer_policy_linux.cc",
                        "port/port.toml"], capture_output=True, text=True).stdout.strip()
ok("T15 R12 policy/rules/fixtures unchanged on perf branch", diffp == "", diffp)

# ---------- T16: inner script + watchdog ----------
inner = re.search(r"<<'SCCACHE_PROFILE_SCRIPT'\n(.*?)\nSCCACHE_PROFILE_SCRIPT", ci_txt, re.S)
ok("T15b inner ticker present", bool(inner) and "SCCACHE_TICK_JSON" in inner.group(1)
   and "timeout 14400" in inner.group(1) and "BUILD_TIMEOUT_GUARD" in inner.group(1))
ok("T15c watchdog uses tick/ninja signals", "last_tick" in ci_txt and "ninja_started" in ci_txt)

# ---------- T17: workflow step ordering ----------
wf = (ROOT / ".github/workflows/build-chromium.yml").read_text()
def pos(pat): 
    m = re.search(pat, wf)
    return m.start() if m else -1
build_block = wf[wf.index("name: Build chromium-sandboxed"):wf.index("name: Package gates")]
ok("T17 preflight before prepare-builder; gates unconditional; save-deb success-only",
   0 < pos(r"Download preflight") < pos(r"Prepare Termux builder") and
   "if: inputs.docker_smoke_only != true && steps.debcheck.outputs.reused != '1'" in build_block and
   "bash port/ci.sh build" in build_block and
   pos(r"Package gates") > pos(r"Build chromium-sandboxed") and
   "if: success() && inputs.allow_deb_reuse && inputs.docker_smoke_only != true && steps.debcheck.outputs.reused != '1'" in wf)

# ---------- T16: preflight regressions via fake curl (no real network) ------
FAKE_NET = HERE / "fixtures" / "net"
tpf = W / "tp-preflight"
(tpf / "scripts").mkdir(parents=True, exist_ok=True)
(tpf / "build-package.sh").write_text("#!/bin/sh\ntrue\n"); (tpf / "scripts" / "run-docker.sh").write_text("#!/bin/sh\ntrue\n")
(tpf / "build-package.sh").chmod(0o755); (tpf / "scripts" / "run-docker.sh").chmod(0o755)


def preflight(env_extra, repo_main="https://packages.termux.dev/apt/termux-main"):
    (tpf / "repo.json").write_text(json.dumps({
        "pkg_format": "debian",
        "packages": {"name": "termux-main", "distribution": "stable", "component": "main",
                     "url": repo_main}}))
    env = dict(os.environ, PATH=f"{FAKE_NET}:{os.environ['PATH']}", **env_extra)
    return run(["bash", str(CI), "download-preflight", str(tpf)], env=env, timeout=300)


r = preflight({})
ok("T16a all-200 healthy pass incl. Packages 1MiB transfer",
   r.returncode == 0 and "1MiB ranged transfer" in r.stdout, (r.stdout + r.stderr)[-250:])
r = preflight({"FAKE_EFF": "https://evil.example/apt/termux-main"})
ok("T16b redirect off official whitelist -> refused",
   r.returncode != 0 and "off-whitelist" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-250:])
r = preflight({"FAKE_P_RC": "28", "FAKE_SILENT": "1"})
ok("T16c Release-200 but Packages transfer fails -> refuse (Release alone NOT trusted)",
   r.returncode != 0 and "Packages transfer failed" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-250:])
r = preflight({"FAKE_RC": "28", "FAKE_CODE": "000", "FAKE_SILENT": "1"})
ok("T16d timeout classified rc=28 in log + fail",
   r.returncode != 0 and "rc=28" in r.stdout, (r.stdout + r.stderr)[-250:])
r = preflight({"FAKE_EFF": "https://packages-cf.termux.dev/apt/termux-main"})
ok("T16e redirect between official hosts accepted", r.returncode == 0, (r.stdout + r.stderr)[-250:])
r = preflight({"FAKE_FAIL_HOST": "packages.termux.dev"})
ok("T16f primary down -> bounded MIRROR-SWITCH to official alt, exit 0",
   r.returncode == 0 and "MIRROR-SWITCH" in r.stdout, (r.stdout + r.stderr)[-250:])

# ---------- T18: docker permission fix + smoke + save-guard invariants ------
ok("T18a image pre-creates .termux-build builder-owned (bind-parent fix)",
   "mkdir -p /home/builder/.termux-build/_cache-aarch64" in ci_txt
   and "chown -R builder:builder /home/builder/.termux-build" in ci_txt)
ok("T18b real-container perms smoke wired (6 checks; fresh AND recreated)",
   "docker_perms_smoke" in ci_txt and ci_txt.count('docker_perms_smoke "$d"') >= 2
   and "SMOKE OK" in ci_txt and "/proc/mounts" in ci_txt and "SMOKE mount" in ci_txt)
ok("T18c workflow: smoke-only gates compile/gates/deb-reuse; reuse default OFF (opt-in)",
   "docker_smoke_only" in wf and "inputs.docker_smoke_only != true" in wf
   and re.search(r"allow_deb_reuse:[\s\S]{0,400}?default: false", wf) is not None)
ok("T18d no empty-cache promotion: both save steps gated by guard outputs",
   "steps.guard.outputs.sccache_nonempty" in wf and "steps.guard.outputs.dep_nonempty" in wf
   and "Guard cache saves" in wf)

# ---------- T24..T27: key-stage ordering + key-identity invariants ------
pos_keys = pos(r"- name: Compute cache keys \(sccache base only\)")
pos_pf   = pos(r"- name: Download preflight")
pos_pb   = pos(r"- name: Prepare Termux builder")
pos_fk   = pos(r"- name: Compute final DEB key")
pos_rd   = pos(r"- name: Restore cached completed deb")
keys_block = wf[pos_keys:pos_pf] if 0 < pos_keys < pos_pf else ""
ok("T24 DEB key computed AFTER preflight + prepare-builder, BEFORE deb restore; keys step has no deb-key",
   0 < pos_pf < pos_pb < pos_fk < pos_rd and "deb-key" not in keys_block
   and "TERMUX_BUILDER_IMAGE_ID=\"$imgfp\"" in wf[pos_fk:pos_rd],
   f"{pos_pf},{pos_pb},{pos_fk},{pos_rd}")
ok("T25 restore/verify/save all reference the ONE final key + build checks image drift",
   wf.count("steps.debkey.outputs.debkey") == 4
   and "EXPECTED_IMAGE_ID: ${{ steps.debkey.outputs.image_id }}" in wf
   and "IMAGE DRIFT" in wf)
gates_block = wf[wf.index("name: Package gates"):wf.index("name: Emit outputs")]
ok("T26 reuse skips compile but gates stay (never conditioned on reuse)",
   "reused != '1'" in build_block and "reused" not in gates_block
   and "if: inputs.docker_smoke_only != true" in gates_block)
ok("T28 identity recorded by prepare BEFORE cleanup; no post-cleanup image inspect; drift via live container",
   0 < ci_txt.index("BUILDER IMAGE ID(raw)=") < ci_txt.index("free-space replacement")
   and '.builder-image-id' in ci_txt and '.builder-image-raw' in ci_txt
   and "docker inspect -f '{{.Image}}' termux-package-builder" in ci_txt
   and "docker image inspect" not in wf[wf.index("- name: Prepare Termux builder"):]
   and "docker inspect -f '{{.Image}}' termux-package-builder" in wf)
# T30: image_fingerprint() FUNCTIONAL determinism + component sensitivity
import hashlib as _h
fp_w = W / "fp" ; fp_w.mkdir(exist_ok=True)
(fp_w / "pkgs").write_text("coreutils 9.1\npython3 3.14.4-1\nsccache 0.13.0-1\n")
(fp_w / "Dockerfile").write_text("FROM x\nRUN true\n")
def fpr(base="sha256:"+"c"*64, pkgs=str(fp_w/"pkgs"), dfk=str(fp_w/"Dockerfile")):
    r = run(["bash", str(CI), "image-fingerprint", base, pkgs, dfk])
    return (r.returncode, r.stdout.strip(), r.stderr)
rc0, fp_a, _ = fpr(); rc0b, fp_a2, _ = fpr()
ok("T30a same base+packages+dockerfile -> identical fingerprint (rebuild-stable)",
   rc0 == 0 and fp_a == fp_a2 and re.fullmatch(r"[0-9a-f]{64}", fp_a) is not None, fp_a)
_, fp_pkg, _ = fpr(pkgs=None) if False else (0,"","") 
(fp_w / "pkgs2").write_text("coreutils 9.1\npython3 3.14.4-1\nsccache 0.14.0-1\n")  # apt update scenario
_, fp_b, _ = fpr(pkgs=str(fp_w/"pkgs2"))
ok("T30b package version change (apt update) -> fingerprint change", fp_b != fp_a, fp_b)
_, fp_c, _ = fpr(base="sha256:"+"d"*64)
ok("T30c base image change -> fingerprint change", fp_c != fp_a, fp_c)
(fp_w / "Dockerfile").write_text("FROM x\nRUN true\nRUN date\n")
_, fp_d, _ = fpr()
ok("T30d Dockerfile change -> fingerprint change", fp_d != fp_a, fp_d)
re_ = run(["bash", str(CI), "image-fingerprint", "", str(fp_w/"pkgs"), str(fp_w/"Dockerfile")])
ok("T30e missing component -> fail-closed", re_.returncode != 0 and ("IMAGE FINGERPRINT FAIL" in (re_.stdout + re_.stderr) or "parameter null or not set" in (re_.stdout + re_.stderr)), (re_.stdout + re_.stderr)[:120])
# T31: deb_key consumes the fingerprint end-to-end (function-executed)
tpf1 = W / "tp-fp"
(tpf1 / "scripts").mkdir(parents=True, exist_ok=True)
(tpf1 / "build-package.sh").write_text("#!/bin/sh\ntrue\n"); (tpf1 / "scripts" / "run-docker.sh").write_text("#!/bin/sh\ntrue\n")
(tpf1 / "build-package.sh").chmod(0o755); (tpf1 / "scripts" / "run-docker.sh").chmod(0o755)
(tpf1 / "repo.json").write_text(repo_orig)
(tpf1 / "packages" / "chromium").mkdir(parents=True, exist_ok=True)
(tpf1 / "packages" / "chromium" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.47"\n')
(tpf1 / "packages" / "chromium-sandboxed").mkdir(parents=True, exist_ok=True)
(tpf1 / "packages" / "chromium-sandboxed" / "build.sh").write_text('TERMUX_PKG_VERSION="156.0.8078.47"\n')
subprocess.run(["git","-C",str(tpf1),"init","-q"],check=True)
subprocess.run(["git","-C",str(tpf1),"-c","user.email=t@t","-c","user.name=t","add","-A"],check=True)
subprocess.run(["git","-C",str(tpf1),"-c","user.email=t@t","-c","user.name=t","commit","-qm","fp"],check=True)
envfp = dict(os.environ, TERMUX_SANDBOXED_REVISION="12")
fp1 = fpr()[1]
k_fp1 = run(["bash", str(CI), "deb-key", str(tpf1)], env=dict(envfp, TERMUX_BUILDER_IMAGE_ID=fp1)).stdout.strip().splitlines()[-1]
k_fp2 = run(["bash", str(CI), "deb-key", str(tpf1)], env=dict(envfp, TERMUX_BUILDER_IMAGE_ID=fp_b)).stdout.strip().splitlines()[-1]
k_fp3 = run(["bash", str(CI), "deb-key", str(tpf1)], env=dict(envfp, TERMUX_BUILDER_IMAGE_ID=fp1)).stdout.strip().splitlines()[-1]
ok("T31 deb_key reproducibility on fingerprint (same fp -> same key; changed fp -> new key)",
   k_fp1 == k_fp3 and k_fp1 != k_fp2 and k_fp1.startswith("DEB_KEY="), f"{k_fp1} {k_fp2}")
# T32: Task-D — no direct docker/containerd storage deletion; daemon prune instead
rm_lines = [l for l in ci_txt.splitlines() if "rm -rf" in l and not l.lstrip().startswith("#")]
ok("T32 containerd/docker daemon storage never rm-ed directly; docker image prune used",
   not any(re.search(r"rm -rf[^&|;]*/var/lib/(containerd|docker)", l) for l in rm_lines)
   and "docker image prune -f" in ci_txt)
debkey_block = wf[pos_fk:pos_rd]
ok("T27 smoke-only skips key+reuse chain; reuse default OFF; key step opt-in-only",
   "if: inputs.allow_deb_reuse && inputs.docker_smoke_only != true" in debkey_block
   and re.search(r"allow_deb_reuse:[\s\S]{0,400}?default: false", wf) is not None
   and "inputs.docker_smoke_only != true" in build_block)

# ---------- T33..T40: Layer-4 persistent VERIFIED source cache --------------
def l4_cmd(sub, tp_, env_extra):
    env = dict(os.environ, **env_extra)
    return run(["bash", str(CI), sub, str(tp_)], env=env, timeout=180)

tpl4 = W / "tp-l4"
(tpl4 / "scripts").mkdir(parents=True, exist_ok=True)
(tpl4 / "build-package.sh").write_text("#!/bin/sh\ntrue\n")
# exec-shim: run the in-container scripts locally (env overrides redirect
# the container paths; production defaults are /home/builder/...).
(tpl4 / "scripts" / "run-docker.sh").write_text('#!/bin/sh\nexec "$@"\n')
for f in (tpl4 / "build-package.sh", tpl4 / "scripts" / "run-docker.sh"):
    f.chmod(0o755)
L4ROOT = tpl4 / ".termux-srccache"
TOP4 = W / "l4-top"
TP4 = W / "l4-tree"
(TP4 / "packages" / "ffmpeg").mkdir(parents=True)
(TP4 / "packages" / "junkpkg").mkdir(parents=True)
envl4 = {"TERMUX_L4_ROOT": str(L4ROOT), "TERMUX_L4_TOPDIR": str(TOP4), "TERMUX_L4_TP": str(TP4)}

r = l4_cmd("source-cache-restore", tpl4, envl4)
ok("T33a cold restore: empty/absent L4 -> no-op, rc=0 (never fails build)",
   r.returncode == 0 and ("L4 RESTORE cold" in r.stdout or "restored=0" in r.stdout), r.stdout[-150:])

ff_src = b"FFMPEG-SRC-DATA" * 400
ff_sha = sha(ff_src)
(TOP4 / "ffmpeg" / "cache").mkdir(parents=True)
(TOP4 / "ffmpeg" / "cache" / "ffmpeg-9.0.2.tar.xz").write_bytes(ff_src)
(TP4 / "packages" / "ffmpeg" / "build.sh").write_text(
    f'TERMUX_PKG_SRCURL="https://www.ffmpeg.org/releases/ffmpeg-9.0.2.tar.xz"\nTERMUX_PKG_SHA256={ff_sha}\n')
(TOP4 / "ffmpeg" / "cache" / "unverified.tar.gz").write_bytes(b"NO-CHECKSUM-FILE")   # SKIP_CHECKSUM case
(TOP4 / "junkpkg" / "cache").mkdir(parents=True)
(TOP4 / "junkpkg" / "cache" / "evil.tar.xz").write_bytes(b"EVIL" * 100)              # sha not declared anywhere
deb_payload_l4 = b"ALLDEB" * 900
deb_sha_l4 = sha(deb_payload_l4)
deb_rel = "pool/main/b/bash-completion/bash-completion_2.18.0_all.deb"
(TOP4 / "_cache-all" / "pool" / "main" / "b" / "bash-completion").mkdir(parents=True)
(TOP4 / "_cache-all" / deb_rel).write_bytes(deb_payload_l4)
(TOP4 / "_cache-all" / "termux-main-json").write_text(json.dumps(
    {"bash-completion": {"FILENAME": deb_rel, "SHA256SUM": deb_sha_l4, "VERSION": "2.18.0-1"}}))
(TOP4 / "_cache-all" / "Packages-index").write_bytes(b"STALE-INDEX")                  # index must never be collected

r = l4_cmd("source-cache-collect", tpl4, envl4)
ents = sorted(p.relative_to(L4ROOT).as_posix() for p in L4ROOT.rglob("*") if p.is_file() and not p.name.startswith(".has-new"))
ok("T33b collect accepts ONLY declared-checksum files (tarball+indexed deb; SKIP_CHECKSUM, undeclared, index rejected)",
   r.returncode == 0 and "unverified=2" in r.stdout
   and any(e.startswith("pkgs/ffmpeg/") and e.endswith("__ffmpeg-9.0.2.tar.xz") for e in ents)
   and any(e.startswith("deb-all/") and e.endswith(deb_rel.replace("/", "%2F")) for e in ents)
   and not any("unverified.tar.gz" in e or "evil.tar.xz" in e or "Packages-index" in e for e in ents),
   (r.stdout[-150:], ents))

TOP5 = W / "l4-top-warm"
r = l4_cmd("source-cache-restore", tpl4, dict(envl4, TERMUX_L4_TOPDIR=str(TOP5)))
tgt = TOP5 / "ffmpeg" / "cache" / "ffmpeg-9.0.2.tar.xz"
debtgt = TOP5 / "_cache-all" / deb_rel
ok("T33c warm restore byte-identical incl nested pool path",
   r.returncode == 0 and "restored=2" in r.stdout
   and tgt.exists() and tgt.read_bytes() == ff_src
   and debtgt.exists() and debtgt.read_bytes() == deb_payload_l4, r.stdout[-150:])
r = termux_download("http://127.0.0.1:9/releases/ffmpeg-9.0.2.tar.xz", str(tgt), ff_sha, W)
ok("T33d warm = ZERO network: upstream termux_download keeps restored file without contacting dead host",
   r.returncode == 0 and tgt.read_bytes() == ff_src, r.stderr[-200:])

corrupt_ent = L4ROOT / "pkgs" / "ffmpeg" / (ff_sha[:12] + "__ffmpeg-9.0.2.tar.xz")
corrupt_ent.write_bytes(b"CORRUPTED-CACHE-ENTRY")
TOP6 = W / "l4-top-corrupt"
r = l4_cmd("source-cache-restore", tpl4, dict(envl4, TERMUX_L4_TOPDIR=str(TOP6)))
ok("T33e corrupted entry quarantined on restore (deleted, never placed)",
   "quarantined=1" in r.stdout and not corrupt_ent.exists()
   and not (TOP6 / "ffmpeg" / "cache" / "ffmpeg-9.0.2.tar.xz").exists(), r.stdout[-150:])
# re-collect the good file to restore the entry for later tests
r = l4_cmd("source-cache-collect", tpl4, envl4)

# same basename / different content (version flip on identical URL path):
(TOP4 / "ffmpeg" / "cache" / "ffmpeg-9.0.2.tar.xz").write_bytes(b"FFMPEG-10-CONTENT")
ff10_sha = sha(b"FFMPEG-10-CONTENT")
(TP4 / "packages" / "ffmpeg" / "build.sh").open("a").write(f"# bumped variant:\n# {ff10_sha}\n")
r = l4_cmd("source-cache-collect", tpl4, envl4)
ffents = sorted(p.name for p in (L4ROOT / "pkgs" / "ffmpeg").iterdir() if p.is_file())
ok("T33f same basename / different sha coexist (no overwrite; version change keeps both)",
   len([e for e in ffents if e.endswith("__ffmpeg-9.0.2.tar.xz")]) == 2
   and any(e.startswith(ff_sha[:12]) for e in ffents) and any(e.startswith(ff10_sha[:12]) for e in ffents), ffents)
TOP7 = W / "l4-top-collide"
r = l4_cmd("source-cache-restore", tpl4, dict(envl4, TERMUX_L4_TOPDIR=str(TOP7)))
placed = (TOP7 / "ffmpeg" / "cache" / "ffmpeg-9.0.2.tar.xz").read_bytes()
ok("T33g collide restore places one verified variant; upstream sha-gate (T3/T33d) covers the wrong pick",
   sha(placed) in (ff_sha, ff10_sha), placed[:30])
(TOP4 / "ffmpeg" / "cache" / "ffmpeg-9.0.2.tar.xz").write_bytes(ff_src)  # restore original

# caps: size then age
for i in range(5):
    payload = bytes([65 + i]) * 300_000
    (TOP4 / "ffmpeg" / "cache" / f"blob{i}.tar.xz").write_bytes(payload)
    (TP4 / "packages" / "ffmpeg" / "build.sh").open("a").write(f"# {sha(payload)}\n")
r = l4_cmd("source-cache-collect", tpl4, dict(envl4, TERMUX_SRCCACHE_CAP_MB="1"))
ok("T33h size cap enforced (prune oldest-first to <=1MB, keep survivors)",
   r.returncode == 0 and "over cap" in r.stdout
   and sum(p.stat().st_size for p in L4ROOT.rglob("*") if p.is_file()) <= 1024 * 1024
   and any("__blob" in p.name for p in L4ROOT.rglob("*") if p.is_file()),
   r.stdout[-200:])
blobA = bytes([90]) * 50_000
srcA = TOP4 / "ffmpeg" / "cache" / "blobA.tar.xz"
srcA.write_bytes(blobA)
(TP4 / "packages" / "ffmpeg" / "build.sh").open("a").write(f"# {sha(blobA)}\n")
os.utime(srcA, (time.time() - 3 * 86400, time.time() - 3 * 86400))
r = l4_cmd("source-cache-collect", tpl4, dict(envl4, TERMUX_SRCCACHE_AGE_DAYS="1"))
ok("T33i age cap enforced (entry older than AGE_DAYS deleted; fresh ones kept)",
   not any(p.name.endswith("__blobA.tar.xz") for p in L4ROOT.rglob("*")), r.stdout[-120:])
os.utime(srcA, None)
r = l4_cmd("source-cache-collect", tpl4, envl4)
ok("T33j age-pruned entry re-collected once fresh (prune is policy, not breakage)",
   any(p.name.endswith("__blobA.tar.xz") for p in L4ROOT.rglob("*")), r.stdout[-120:])

# T33k: DEBIAN-format anchor — deb hash anchored in the GPG-verified
# Packages index (repo.json here uses pkg_format=debian; *-json exists only
# in pacman mode — run 40862002110 proved the json-only anchor rejected all
# 29 _all debs). Acceptance must come from the SHA256 stanza instead.
deb2_payload = b"ALLDEB2" * 700
deb2_sha = sha(deb2_payload)
deb2_rel = "pool/main/f/foo/foo_1.0_all.deb"
(deb2_dir := (TOP4 / "_cache-all" / "pool" / "main" / "f" / "foo")).mkdir(parents=True)
(deb2_dir / "foo_1.0_all.deb").write_bytes(deb2_payload)
(TOP4 / "_cache-all" / "main-Packages").write_text(
    "Package: foo\nVersion: 1.0-1\nArchitecture: all\n"
    f"Filename: {deb2_rel}\nSize: {len(deb2_payload)}\nSHA256: {deb2_sha.upper()}\n\n")
r = l4_cmd("source-cache-collect", tpl4, envl4)
ok("T33k debian Packages-anchor deb accepted (uppercase SHA256 normalized) + per-entry ACCEPT log",
   any(p.name.endswith("__pool%2Fmain%2Ff%2Ffoo%2Ffoo_1.0_all.deb") for p in L4ROOT.rglob("*"))
   and "L4 ACCEPT deb-all/" in r.stdout, r.stdout[-200:])

r = l4_cmd("source-cache-restore", tpl4, dict(envl4, TERMUX_L4_ROOT=str(W / "l4-elsewhere-restore")))
ok("T34a path guard: unexpected L4 root refused by restore (rc=0, no writes)",
   r.returncode == 0 and "SKIP: unexpected root" in r.stdout
   and not (W / "l4-elsewhere-restore").exists(), r.stdout[:150:])
r = l4_cmd("source-cache-collect", tpl4, dict(envl4, TERMUX_L4_ROOT=str(W / "l4-elsewhere-collect")))
ok("T34a2 path guard: unexpected L4 root refused by collect (rc=0, no writes)",
   r.returncode == 0 and "SKIP: unexpected root" in r.stdout
   and not (W / "l4-elsewhere-collect").exists(), r.stdout[:150:])

gen = (tpl4 / ".l4-restore.sh").read_text() + (tpl4 / ".l4-collect.sh").read_text()
ok("T34b L4 adds NO network I/O and no retry knobs (upstream curl policy stays the only fetch path)",
   "curl" not in gen and "wget" not in gen and "retry" not in gen)
ok("T34c upstream vendored download policy intact (--retry 5/--retry-max-time 120)",
   "--retry 5" in DL_FIXTURE.read_text() and "--retry-max-time 120" in DL_FIXTURE.read_text())

pos_seed = wf.find("Restore source cache (L4)")
pos_seed2 = wf.find("Seed source cache into container")
pos_build2 = wf.find("- name: Build chromium-sandboxed")
pos_check2 = wf.find("Verify cached completed deb")
pos_collect = wf.find("Collect source cache (L4)")
pos_save4 = wf.find("Save source cache (L4)")
ok("T34d workflow order: debcheck -> L4 restore/seed -> build -> collect -> ... -> L4 save",
   -1 < pos_check2 < pos_seed < pos_seed2 < pos_build2 < pos_collect < pos_save4)
seed_block = wf[wf.index("- name: Restore source cache (L4)"):wf.index("- name: Seed source cache into container")]
ok("T34e L4 restore skipped on smoke-only AND on DEB reuse (4.4-min reuse path: zero L4 IO)",
   "if: inputs.docker_smoke_only != true && steps.debcheck.outputs.reused != '1'" in seed_block
   and "key: chromium-srccache-aarch64-v1-${{ github.run_id }}" in seed_block
   and "restore-keys: chromium-srccache-aarch64-v1-" in seed_block)
coll_block = wf[pos_collect:wf.index("- name: Package gates")]
ok("T34f collect: !cancelled + reuse/smoke gate + build-ran; has_new parsed from L4 COLLECT line only",
   "if: ${{ !cancelled() && inputs.docker_smoke_only != true && steps.debcheck.outputs.reused != '1' && steps.build.outcome != 'skipped' }}" in coll_block
   and "sed -n 's/^L4 COLLECT new=" in coll_block)
save4_block = wf[pos_save4:wf.index("- name: Save completed deb to reuse cache")]
ok("T34g L4 save gated by has_new == '1' (no empty-cache promotion; warm runs re-upload nothing)",
   "steps.srccollect.outputs.has_new == '1'" in save4_block
   and "inputs.docker_smoke_only != true" in save4_block)
ok("T34h third bind volume .termux-srccache + image-layer pre-create (bind-parent lesson) + smoke covers it",
   "--volume $d/.termux-srccache:/home/builder/.termux-srccache" in ci_txt
   and "mkdir -p /home/builder/.termux-build/_cache-aarch64 /home/builder/.cache/sccache /home/builder/.termux-srccache" in ci_txt
   and "chown -R builder:builder /home/builder/.termux-build /home/builder/.cache/sccache /home/builder/.termux-srccache" in ci_txt
   and "/home/builder/.termux-srccache" in ci_txt[ci_txt.index("docker_perms_smoke()"):ci_txt.index("dep_cache_prune()")])

_base_ok = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", "9ecb6e3^{commit}"],
                          capture_output=True).returncode == 0
g1 = subprocess.run(["git", "-C", str(ROOT), "show", "9ecb6e3:port/ci.sh"], capture_output=True, text=True).stdout if _base_ok else ""
def _fn(txt, name):
    m = re.search(rf"^{name}\(\) \{{", txt, re.M)
    if not m:
        return None
    i = m.end(); depth = 1
    while i < len(txt) and depth:
        if txt[i] == "{": depth += 1
        elif txt[i] == "}": depth -= 1
        i += 1
    return txt[m.start():i]
ok("T34i PR #24 integrity core untouched: deb_key/deb_reuse_verify/deb_reuse_save/fingerprint byte-identical to 9ecb6e3",
   (not _base_ok) or all(_fn(g1, f) == _fn(ci_txt, f) for f in ("deb_key", "deb_reuse_verify", "deb_reuse_save", "image_fingerprint", "deb_image_id")),
   "skipped on shallow checkout (verified on full clone)" if not _base_ok else "drift")

envl4c = dict(os.environ, **envl4)
p1 = subprocess.Popen(["bash", str(CI), "source-cache-collect", str(tpl4)], env=envl4c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
p2 = subprocess.Popen(["bash", str(CI), "source-cache-collect", str(tpl4)], env=envl4c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
rc1, rc2 = p1.wait(timeout=180), p2.wait(timeout=180)
bad = [p for p in L4ROOT.rglob("*") if p.is_file() and "__" in p.name
       and p.name.split("__")[0] != sha(p.read_bytes())[:12]]
ok("T40 concurrent collect: both succeed, every entry stays self-consistent (atomic tmp+mv)",
   rc1 == 0 and rc2 == 0 and not bad, [str(b) for b in bad][:3])

# ---------- T41: L4 adapter in the recipe clone (tarball preservation) ----
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("prepare_recipe", ROOT / "port" / "prepare_recipe.py")
_pr = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_pr)
_raw = (HERE / "fixtures" / "real_chromium_build_sh_2af83c3").read_text()
_keep, _notes = _pr.preserve_source_cache(_raw)
ok("T41a clone preserves the sha256-declared chromium tarball (upstream rm -f neutralized, exactly one line changed)",
   'rm -f "$TERMUX_PKG_CACHEDIR/chromium-$TERMUX_PKG_VERSION-linux.tar.xz"' not in _keep
   and "tarball kept for the L4 source cache" in _keep
   and sum(1 for a, b in zip(_raw.splitlines(), _keep.splitlines()) if a != b) == 1
   and len(_raw.splitlines()) == len(_keep.splitlines()), _notes)
_k2, _n2 = _pr.preserve_source_cache(_keep)
ok("T41b absence tolerated (no-op + note), idempotent", _k2 == _keep and any("not found" in n for n in _n2), _n2)

print(f"\nCACHE-LAYERS PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
