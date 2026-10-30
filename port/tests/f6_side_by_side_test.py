#!/usr/bin/env python3
"""F6 side-by-side packaging contract suite (DESIGN Round 26).

Proves the release-blocker fix (stock chromium path collision) end to end on
the PORTION verifiable without a device install, and pins the two latent
regressions the never-CI-verified hotfix carried (rewrite chain drop; gate
"./" root-row crash). Scenario ledger mapping in the audit report.

A* rewrite_identity / rewrite_launcher contracts (+fail-closed drift)
B* package_identity_gate.py vs dpkg-deb fixtures (+ the real pre-F6 deb)
C* stock-vs-sandboxed file-set disjointness (static + real stock deb if env)
D* cached-DEB reuse chain cannot smuggle pre-F6 packaging past release gates
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "port"))
import prepare_recipe  # noqa: E402
from prepare_recipe import RecipeError  # noqa: E402

FIX = ROOT / "port/tests/fixtures"
GATE = str(ROOT / "port/package_identity_gate.py")
CI = str(ROOT / "port/ci.sh")
PASS = FAIL = 0


def ok(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS  " + label)
    else:
        FAIL += 1
        print("FAIL  " + label + (f"  [{detail}]" if detail else ""))


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


RAW = (FIX / "termux-build.sh").read_text()

# ---------------- A: rewrite contracts ----------------
out = prepare_recipe.rewrite_identity(RAW)
ok("A1 lib-dir move SURVIVES the bin replace (hotfix chain-regression pin)",
   re.search(r"\blib/chromium\b(?!-sandboxed)", out) is None
   and "lib/chromium-sandboxed" in out and "bin/chromium-sandboxed" in out
   and "bin/chromium-browser" not in out)
ok("A2 all isolated installers present (driver/headless/man/desktop/icons/appdata/desktop-fields)",
   all(s in out for s in (
       'bin/chromedriver-sandboxed', 'bin/headless_shell-sandboxed',
       'share/man/man1/chromium-sandboxed.1', 'share/applications/chromium-sandboxed.desktop',
       'apps/chromium-sandboxed.png', 'share/metainfo/chromium-sandboxed.appdata.xml',
       's/@@usr_bin_symlink_name/chromium-sandboxed/g', 's/@@PACKAGE/chromium-sandboxed/g',
       's/@@MENUNAME/Chromium (Sandboxed)/g',
       's/chromium-browser\\.desktop/chromium-sandboxed.desktop/'))
   and 's/@@MENUNAME/Chromium/g' not in out)
for label, tamper in (
    # destructive tampers: the anchor itself must stop matching (a benign
    # suffix would still contain the substring and prove nothing)
    ("desktop-entry", lambda t: t.replace('share/applications/chromium.desktop',
                                          'share/applications/firefox.desktop', 1)),
    ("headless-anchor", lambda t: t.replace(
        'ln -sfr $TERMUX_PREFIX/lib/chromium/headless_shell $TERMUX_PREFIX/bin/',
        'ln -sfr   $TERMUX_PREFIX/lib/chromium/headless_shell   $TERMUX_PREFIX/bin/')),
):
    try:
        prepare_recipe.rewrite_identity(tamper(RAW))
        ok(f"A3 fail-closed on anchor drift ({label})", False, "no raise")
    except RecipeError:
        ok(f"A3 fail-closed on anchor drift ({label})", True)

LT = (FIX / "chromium-launcher.sh.in").read_text()
lo = prepare_recipe.rewrite_launcher(LT)
ok("A4 launcher isolated (desktop ID, /etc config, fallback profile dir)",
   'CHROME_DESKTOP="chromium-sandboxed.desktop"' in lo
   and '@TERMUX_PREFIX@/etc/chromium-sandboxed/*.conf' in lo
   and '/.config}/chromium-sandboxed' in lo
   and 'export CHROME_DESKTOP="chromium.desktop"' not in lo)
try:
    prepare_recipe.rewrite_launcher(lo)
    ok("A4b rewrite_launcher is stock-template-only (second pass raises)", False)
except RecipeError:
    ok("A4b rewrite_launcher is stock-template-only (second pass raises)", True)

# A5: prepare + audit end-to-end; tampered audits fail
def build_tree(tmp, name, launcher=True, launcher_text=None):
    tp = Path(tmp) / name
    (tp / "x11-packages/chromium").mkdir(parents=True)
    (tp / "build-package.sh").write_text("#!/bin/sh\n"); (tp / "build-package.sh").chmod(0o755)
    (tp / "x11-packages/chromium/build.sh").write_text(RAW)
    if launcher:
        (tp / "x11-packages/chromium/chromium-launcher.sh.in").write_text(
            launcher_text if launcher_text is not None else LT)
    return tp

with tempfile.TemporaryDirectory(prefix="f6-a5-") as tmp:
    tp = build_tree(tmp, "good")
    r = run(["python3", str(ROOT / "port/prepare_recipe.py"), "prepare", "--termux-dir", str(tp)])
    ok("A5 prepare succeeds on real-layout fixture tree", r.returncode == 0, (r.stdout + r.stderr)[-200:])
    r = run(["python3", str(ROOT / "port/prepare_recipe.py"), "audit", "--termux-dir", str(tp)])
    ok("A5b audit passes (isolated needles, no stock leak)", r.returncode == 0, (r.stdout + r.stderr)[-200:])
    # idempotence: second prepare leaves bytes identical
    b1 = (tp / "x11-packages/chromium-sandboxed/build.sh").read_bytes()
    l1 = (tp / "x11-packages/chromium-sandboxed/chromium-launcher.sh.in").read_bytes()
    run(["python3", str(ROOT / "port/prepare_recipe.py"), "prepare", "--termux-dir", str(tp)])
    ok("A5c prepare idempotent (build.sh + rewritten launcher byte-stable)",
       b1 == (tp / "x11-packages/chromium-sandboxed/build.sh").read_bytes()
       and l1 == (tp / "x11-packages/chromium-sandboxed/chromium-launcher.sh.in").read_bytes())
    # tamper a: stock desktop line injected post-prepare
    dst = tp / "x11-packages/chromium-sandboxed/build.sh"
    keep = dst.read_text()
    dst.write_text(keep.replace('"$TERMUX_PREFIX/share/man/man1/chromium-sandboxed.1"',
        '"$TERMUX_PREFIX/share/man/man1/chromium-sandboxed.1" "$TERMUX_PREFIX/share/applications/chromium.desktop"', 1))
    r = run(["python3", str(ROOT / "port/prepare_recipe.py"), "audit", "--termux-dir", str(tp)])
    ok("A5d audit refuses injected stock installer path", r.returncode != 0 and "stock-owned" in (r.stdout + r.stderr))
    dst.write_text(keep)
    # tamper b: launcher leak
    tl = tp / "x11-packages/chromium-sandboxed/chromium-launcher.sh.in"
    tl.write_text(LT)
    r = run(["python3", str(ROOT / "port/prepare_recipe.py"), "audit", "--termux-dir", str(tp)])
    ok("A5e audit refuses stock launcher template leak", r.returncode != 0)
    # tamper c: launcher missing
    tl.unlink()
    r = run(["python3", str(ROOT / "port/prepare_recipe.py"), "audit", "--termux-dir", str(tp)])
    ok("A5f audit refuses missing launcher template", r.returncode != 0)

# ---------------- B: package_identity_gate ----------------
def make_good_deb(root: Path):
    (root / "DEBIAN").mkdir(parents=True); (root / "DEBIAN").chmod(0o755)
    (root / "DEBIAN/control").write_text(
        "Package: chromium-sandboxed\nVersion: 156.0.8078.47-13\nArchitecture: aarch64\n"
        "Maintainer: t\ndescription: f\n")
    (root / "DEBIAN/control").chmod(0o644)
    usr = root / "data/data/com.termux/files/usr"
    lib = usr / "lib/chromium-sandboxed"; binp = usr / "bin"
    lib.mkdir(parents=True); binp.mkdir(parents=True)
    (lib / "chrome").write_text("E"); (lib / "libtermux-gnp-fix.so").write_text("so")
    (lib / "chromium-shield-wrapper.sh").write_text("exec chromium-launcher.sh\n")
    (lib / "chromium-launcher.sh").write_text("exec chrome\n")
    (binp / "chromedriver-sandboxed").write_text("d"); (binp / "headless_shell-sandboxed").write_text("h")
    for rel in ("share/man/man1/chromium-sandboxed.1",
                "share/applications/chromium-sandboxed.desktop",
                "share/metainfo/chromium-sandboxed.appdata.xml",
                "share/icons/hicolor/48x48/apps/chromium-sandboxed.png"):
        f = usr / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text("i")
    os.symlink("../lib/chromium-sandboxed/chromium-shield-wrapper.sh", binp / "chromium-sandboxed")

with tempfile.TemporaryDirectory(prefix="f6-b-") as tmp:
    root = Path(tmp) / "dtree"; make_good_deb(root)
    deb = Path(tmp) / "good.deb"
    run(["dpkg-deb", "-b", str(root), str(deb)], check=True)
    r = run(["python3", GATE, str(deb)])
    ok("B1 well-formed isolated deb PASSES (hotfix './' root-row crash pin)",
       r.returncode == 0 and "PACKAGE-IDENTITY-PASS" in r.stdout, (r.stdout + r.stderr)[-160:])
    cases = (
        ("stock desktop", "share/applications/chromium.desktop"),
        ("stock driver symlink", "bin/chromedriver"),
        ("stock lib dir member", "lib/chromium/extra.so"),
        ("stock icon", "share/icons/hicolor/24x24/apps/chromium.png"),
    )
    for i, (label, rel) in enumerate(cases):
        t2 = Path(tmp) / f"bad{i}"; make_good_deb(t2)
        f = t2 / "data/data/com.termux/files/usr" / rel
        f.parent.mkdir(parents=True, exist_ok=True); f.write_text("stock")
        d2 = t2.parent / f"bad{i}.deb"
        run(["dpkg-deb", "-b", str(t2), str(d2)], check=True)
        r = run(["python3", GATE, str(d2)])
        ok(f"B2 gate refuses {label}", r.returncode == 1 and rel.split("/")[-1] in r.stderr, r.stderr[-140:])
    t3 = Path(tmp) / "nomiss"; make_good_deb(t3)
    (t3 / "data/data/com.termux/files/usr/lib/chromium-sandboxed/chromium-shield-wrapper.sh").unlink()
    d3 = Path(tmp) / "miss.deb"; run(["dpkg-deb", "-b", str(t3), str(d3)], check=True)
    r = run(["python3", GATE, str(d3)])
    ok("B3 required isolated file missing -> refused", r.returncode == 1 and "missing" in r.stderr, r.stderr[-140:])
    t4 = Path(tmp) / "outside"; make_good_deb(t4)
    (t4 / "opt").mkdir(); (t4 / "opt/foo").write_text("x")
    d4 = Path(tmp) / "outside.deb"; run(["dpkg-deb", "-b", str(t4), str(d4)], check=True)
    r = run(["python3", GATE, str(d4)])
    ok("B4 file outside Termux prefix -> refused", r.returncode == 1 and "outside Termux prefix" in r.stderr)
    t5 = Path(tmp) / "wrongname"; make_good_deb(t5)
    (t5 / "DEBIAN/control").write_text((t5 / "DEBIAN/control").read_text().replace(
        "Package: chromium-sandboxed", "Package: chromium-sandboxed-x"))
    d5 = Path(tmp) / "wrong.deb"; run(["dpkg-deb", "-b", str(t5), str(d5)], check=True)
    r = run(["python3", GATE, str(d5)])
    ok("B5 wrong package identity -> refused", r.returncode == 1 and "identity" in r.stderr)
    r = run(["python3", GATE])
    ok("B6 usage error -> rc2 (never vacuous pass)", r.returncode == 2)
    real = Path("/data/data/com.termux/files/home/Project/chromium-evidence/r12/"
                "artifacts-c3/termux-packages/output/chromium-sandboxed_156.0.8078.47-12_aarch64.deb")
    if real.is_file():
        r = run(["python3", GATE, str(real)])
        ok("B7 REAL pre-F6 C3 deb rejected with stock-path evidence (F6 confirmed real)",
           r.returncode == 1 and "share/applications/chromium.desktop" in r.stderr
           and "bin/chromedriver" in r.stderr, r.stderr[-200:])
    else:
        ok("B7 REAL pre-F6 deb check skipped (artifact absent on this runner)", True)

# ---------------- C: disjointness vs stock ----------------
prefixes = re.compile(r"\$TERMUX_PREFIX(/[^\s\"'|)]+)?")
def prefix_paths(text):
    s = set()
    for m in prefixes.finditer(text):
        p = m.group(0)
        if p in ("$TERMUX_PREFIX", "$TERMUX_PREFIX/"):
            continue
        s.add(p[len("$TERMUX_PREFIX"):].rstrip("/\\"))
    return s
stock_paths = prefix_paths(RAW)
new_paths = prefix_paths(prepare_recipe.rewrite_identity(RAW))
collide = {p for p in (stock_paths & new_paths)
           if not re.match(r"^/(bin|lib|share|etc)$", p)
           and "/" in p.strip("/") and not p.endswith(("/", "-sandboxed", "-sandboxed.1"))
           and "chromium-sandboxed" not in p and p not in ("/include", "/tmp")}
real_stock = [p for p in collide if re.search(r"chromium(\.|-browser|driver$|/)", p) and "sandboxed" not in p]
ok("C1 recipe-derived install sets are disjoint on chromium-owned paths",
   not real_stock, str(sorted(real_stock))[:200])
stock_deb = os.environ.get("F6_STOCK_DEB", "")
if stock_deb and Path(stock_deb).is_file():
    listing = run(["dpkg-deb", "-c", stock_deb], check=True).stdout
    stockfiles = {l.split(maxsplit=5)[5].split(" -> ")[0].removeprefix("./")
                  for l in listing.splitlines() if len(l.split(maxsplit=5)) == 6}
    ourfiles = {l.split(maxsplit=5)[5].split(" -> ")[0].removeprefix("./")
                for l in run(["dpkg-deb", "-c", str(deb)], check=True).stdout.splitlines()
                if len(l.split(maxsplit=5)) == 6}
    ourfiles = {f for f in ourfiles if not f.endswith("/")}
    overlap = sorted(f for f in (stockfiles & ourfiles) if f and not f.endswith("/"))
    ok("C2 REAL stock deb co-installation: zero shared file paths", not overlap, str(overlap)[:250])
else:
    ok("C2 real stock deb comparison deferred (set F6_STOCK_DEB; CI stage covers via identity gate)", True)
# C2b: installed-artifact conflict surface (device-only, informational pin):
# the live -4 tree demonstrates EXACTLY which stock-owned paths the pre-F6
# packaging claimed — the F6 rewrite must remove every one of them.
ii = run(["dpkg", "-l", "chromium-sandboxed"])
if "ii" in ii.stdout:
    files = run(["dpkg", "-L", "chromium-sandboxed"]).stdout.splitlines()
    stock_claims = [f for f in files if f.endswith(("/share/applications/chromium.desktop",
                                                    "/share/man/man1/chromium.1",
                                                    "/share/metainfo/chromium.appdata.xml"))
                    or re.search(r"/share/icons/hicolor/\d+x\d+/apps/chromium\.png$", f)]
    isolated_claims = [f for f in files if "chromium-sandboxed." in f and "/share/" in f]
    ok("C2b installed pre-F6 artifact owns the stock paths F6 removes (conflict surface pinned)",
       len(stock_claims) >= 4 and not isolated_claims,
       f"claims={len(stock_claims)} isolated={isolated_claims[:2]}")
else:
    ok("C2b installed-tree check skipped (no -4 package on this runner)", True)

# ---------------- D: cached-DEB reuse chain ----------------
with tempfile.TemporaryDirectory(prefix="f6-d-") as tmp:
    real = Path("/data/data/com.termux/files/home/Project/chromium-evidence/r12/"
                "artifacts-c3/termux-packages/output/chromium-sandboxed_156.0.8078.47-12_aarch64.deb")
    if not real.is_file():
        ok("D1 pre-F6 forged-consistent cache cannot pass release chain (skipped: no artifact)", True)
    else:
        tp = Path(tmp) / "termux-packages"
        (tp / ".deb-cache").mkdir(parents=True)
        shutil.copy(real, tp / ".deb-cache" / real.name)
        env = dict(os.environ, TERMUX_SANDBOXED_REVISION="12", TERMUX_BUILDER_IMAGE_ID="sha256:" + "a" * 64)
        for g in (["init", "-q"], ["-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"],
                  ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fake"]):
            run(["git", "-C", str(tp)] + g, check=True)
        kr = run(["bash", CI, "deb-key", str(tp)], env=env, cwd=str(ROOT))
        assert kr.returncode == 0 and kr.stdout.strip(), (kr.stdout + kr.stderr)[-200:]
        key = kr.stdout.strip().splitlines()[-1].split("=", 1)[1]
        ds = run(["sha256sum", str(real)]).stdout.split()[0]
        cs = run("dpkg-deb --fsys-tarfile %s | tar -xO ./data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome | sha256sum" % real,
                 shell=True).stdout.split()[0]
        import json
        (tp / ".deb-cache/deb-manifest.json").write_text(json.dumps({
            "deb_sha256": ds, "chrome_sha256": cs,
            "version_arch": run(["dpkg-deb", "-W", "--showformat=${Package} ${Version} ${Architecture}\\n", str(real)]).stdout.strip(),
            "deb_key": key, "termux_sha": "f" * 40, "run_id": "forged", "generated_at": "2026-10-30T00:00:00Z"}))
        (tp / "repo.json").write_text('{"pkg_format":"debian"}')
        r = run(["bash", CI, "deb-reuse-verify", str(tp)], env=dict(env, DEB_KEY=key))
        ok("D1a forged-consistent pre-F6 cache passes CONTENT gates (chrome bytes unchanged — by design)",
           r.returncode == 0 and "REUSED=1" in r.stdout, (r.stdout + r.stderr)[-160:])
        # ...but the release chain (Package gates body) now refuses it via identity gate
        import yaml
        wf = yaml.safe_load((ROOT / ".github/workflows/build-chromium.yml").read_text())
        body = next(s for s in wf["jobs"]["build"]["steps"] if s.get("name", "").startswith("Package gates"))["run"]
        (tp / "output").mkdir(exist_ok=True)
        shutil.copy(real, tp / "output" / real.name)
        ws = Path(tmp) / "ci"; (ws / "port").mkdir(parents=True)
        shutil.copy(ROOT / "port/package_identity_gate.py", ws / "port/package_identity_gate.py")
        shutil.copytree(tp, ws / "termux-packages", dirs_exist_ok=True)
        (ws / "gates.sh").write_text(body)
        (ws / "termux-packages/port-apply-chromium.log").write_text(
            "\n".join(f"[        APPLIED] {x} y" for x in
                      ["R1", "R2", "R3", "R4", "R5", "R7", "R9a", "R10", "R11", "R12"])
            + "\n[     VERIFIED] anti-injection scan (--no-sandbox appenders)\n")
        g = run(["bash", "-c", "exec bash gates.sh"], cwd=str(ws),
                env=dict(os.environ, DEB_REUSED="1"))
        ok("D1b release chain REFUSES pre-F6 packaging even on REUSED=1 (identity gate)",
           g.returncode != 0 and "PACKAGE-IDENTITY-FAIL" in (g.stdout + g.stderr), (g.stdout + g.stderr)[-200:])
        # stale-cache honesty: key mismatch never reused
        (tp / ".deb-cache/deb-manifest.json").write_text(json.dumps({
            "deb_sha256": ds, "chrome_sha256": cs, "version_arch": "chromium-sandboxed 156.0.8078.47-12 aarch64",
            "deb_key": "STALE", "termux_sha": "f" * 40, "run_id": "x", "generated_at": "z"}))
        r = run(["bash", CI, "deb-reuse-verify", str(tp)], env=dict(env, DEB_KEY=key))
        ok("D2 stale-key cached deb refused (REUSED=0 key-mismatch)",
           r.returncode != 0 and "REUSED=0 REASON=key-mismatch" in r.stdout, (r.stdout + r.stderr)[-160:])

print(f"\nF6-SUITE PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
