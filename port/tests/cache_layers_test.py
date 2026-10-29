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

print(f"\nCACHE-LAYERS PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
