#!/usr/bin/env python3
"""Round 28: dependency-.deb persistence (chromium-host-tools reuse).

Verifies the ONLY mechanism that removes the repeated ~3h source build of
chromium-host-tools: upstream `--reuse-built-packages` picks a deb from
$TERMUX_OUTPUT_DIR (scripts/build/termux_download_deb_pac.sh @ de1dd3d1) when
the pinned version is gone from the live repo index. We persist those debs in
.termux-depcache/deps/ and seed them back into output/ before the build.

No network, no docker. Exits non-zero on any FAIL.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CI = ROOT / "port" / "ci.sh"
WF = ROOT / ".github/workflows/build-chromium.yml"
PASS = FAIL = 0


def ok(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"PASS  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name} {detail}")


def run(args, env=None, timeout=180, cwd=None):
    return subprocess.run(args, capture_output=True, text=True, env=env,
                          timeout=timeout, cwd=cwd)


def mk_workspace(root: Path) -> Path:
    """Minimal termux-packages layout that need_termux_dir() accepts."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "scripts").mkdir(exist_ok=True)
    bp = root / "build-package.sh"
    bp.write_text("#!/bin/sh\ntrue\n")
    bp.chmod(0o755)
    rd = root / "scripts" / "run-docker.sh"
    rd.write_text("#!/bin/sh\ntrue\n")
    rd.chmod(0o755)
    return root


def mkdeb(out: Path, pkg: str, ver: str, arch: str, payload: bytes) -> Path:
    """Build a real .deb with dpkg-deb so validation is exercised for real."""
    tree = out.parent / f".tree-{pkg}-{ver}-{arch}"
    (tree / "DEBIAN").mkdir(parents=True, exist_ok=True)
    (tree / "DEBIAN").chmod(0o755)   # dpkg-deb rejects 0700 control dirs
    tree.chmod(0o755)
    (tree / "DEBIAN" / "control").write_text(
        f"Package: {pkg}\nVersion: {ver}\nArchitecture: {arch}\n"
        "Maintainer: test <t@example.invalid>\nDescription: test fixture\n"
    )
    (tree / "share").mkdir(parents=True, exist_ok=True)
    (tree / "share" / f"{pkg}.bin").write_bytes(payload)
    out.parent.mkdir(parents=True, exist_ok=True)
    r = run(["dpkg-deb", "--build", "--root-owner-group", str(tree), str(out)])
    if r.returncode != 0:
        raise SystemExit(f"dpkg-deb --build failed: {r.stderr}")
    return out


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def cish(ws: Path, *args, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return run(["bash", str(CI), *args, str(ws)], env=env)


if not shutil.which("dpkg-deb"):
    print("FAIL  dpkg-deb unavailable: cannot exercise real deb validation")
    print("\nHOSTTOOLS-SUITE PASS=0 FAIL=1")
    sys.exit(1)

W = Path(tempfile.mkdtemp(prefix="hosttools-"))
try:
    ci_txt = CI.read_text()
    wf = WF.read_text()

    # ---------- static contract: the upstream reuse path is wired ----------
    ok("R1 build invocation passes upstream --reuse-built-packages with force/install/arch flags intact",
       re.search(r"timeout 14400 \./build-package\.sh -f -I -a aarch64 --reuse-built-packages chromium-sandboxed", ci_txt) is not None,
       "flag missing or package order changed")

    ok("R2 seed step runs BEFORE the build and is skipped for smoke-only / reused-DEB paths",
       wf.index("- name: Seed dependency debs into output")
       < wf.index("- name: Build chromium-sandboxed")
       and "bash port/ci.sh dep-output-seed" in wf
       and re.search(r"name: Seed dependency debs into output.*?\n        if: inputs\.docker_smoke_only != true && steps\.debcheck\.outputs\.reused != '1'",
                     wf, re.S) is not None)

    pos_collect = wf.index("- name: Collect dependency debs from output")
    ok("R3 collect step runs even when the build fails/guards out (always()) and precedes depcache prune+save",
       pos_collect > wf.index("- name: Build chromium-sandboxed")
       and pos_collect < wf.index("- name: Prune termux dep cache")
       and "always() && inputs.docker_smoke_only != true && steps.debcheck.outputs.reused != '1'" in wf[pos_collect:pos_collect + 400])

    ok("R4 ci.sh dispatches seed/collect/report (no dead function)",
       all(f"dep-output-{c})" in ci_txt for c in ("seed", "collect", "report")))

    ok("R5 deps/ lives OUTSIDE the _cache-aarch64 bind mount (termux can never read it as a repo hit)",
       "--volume $d/.termux-depcache/aarch64:/home/builder/.termux-build/_cache-aarch64" in ci_txt
       and 'deps="$d/.termux-depcache/deps"' in ci_txt
       and ".termux-depcache/deps:/home/builder" not in ci_txt)

    ok("R6 persistence functions perform NO network I/O (curl/wget absent; upstream stays the only fetcher)",
       not re.search(r"\b(curl|wget)\b", ci_txt[ci_txt.index("_dep_deb_meta()"):ci_txt.index("# ---- Layer 4")]))

    # ---------- collect ----------
    ws = mk_workspace(W / "tp1")
    hosttools = mkdeb(W / "src" / "chromium-host-tools_156.0.8078.47_aarch64.deb",
                      "chromium-host-tools", "156.0.8078.47", "aarch64", b"HT" * 900)
    target = mkdeb(W / "src" / "chromium-sandboxed_156.0.8078.47-4_aarch64.deb",
                   "chromium-sandboxed", "156.0.8078.47-4", "aarch64", b"TGT" * 300)
    (ws / "output").mkdir()
    shutil.copy2(hosttools, ws / "output" / hosttools.name)
    shutil.copy2(target, ws / "output" / target.name)

    r = cish(ws, "dep-output-collect")
    deps = ws / ".termux-depcache" / "deps"
    man = deps / "MANIFEST"
    ok("R7 collect persists a real dependency deb + records its sha256 in MANIFEST",
       r.returncode == 0 and (deps / hosttools.name).is_file()
       and man.is_file() and f"{sha(hosttools)}\t{hosttools.name}" in man.read_text(),
       (r.stdout + r.stderr)[-300:])

    ok("R8 collect NEVER persists the chromium-sandboxed target (no stale-target reuse path)",
       not (deps / target.name).exists() and target.name not in man.read_text())

    ok("R9 collect reports new=1 on first sighting",
       "DEPSED collect new=1 total=1" in r.stdout, r.stdout[-200:])

    r = cish(ws, "dep-output-collect")
    ok("R10 collect is idempotent: unchanged deb re-collected as new=0 (no cache churn / no re-upload)",
       "DEPSED collect new=0 total=1" in r.stdout, r.stdout[-200:])

    bad = ws / "output" / "libexpat_2.9.0_aarch64.deb"
    bad.write_bytes(hosttools.read_bytes()[:120])
    r = cish(ws, "dep-output-collect")
    ok("R11 collect rejects a truncated deb (control/member parse must both succeed)",
       not (deps / bad.name).exists() and "DEPSED collect SKIP unusable libexpat_2.9.0_aarch64.deb" in r.stdout,
       r.stdout[-300:])

    arm = mkdeb(W / "src" / "fribidi_1.0.17_arm.deb", "fribidi", "1.0.17", "arm", b"F" * 40)
    shutil.copy2(arm, ws / "output" / arm.name)
    r = cish(ws, "dep-output-collect")
    ok("R12 collect rejects a non-aarch64 deb (architecture is a hard gate)",
       not (deps / arm.name).exists() and arm.name not in man.read_text(), r.stdout[-300:])

    mis = ws / "output" / "libaom_3.15.2_aarch64.deb"
    shutil.copy2(mkdeb(W / "src" / "libaom_3.15.2_arm.deb", "libaom", "3.15.2", "arm", b"L" * 40), mis)
    r = cish(ws, "dep-output-collect")
    ok("R13 collect rejects name/control mismatch (filename must be exactly <pkg>_<ver>_<arch>.deb)",
       not (deps / mis.name).exists(), r.stdout[-300:])

    # arch-independent dependency (mesa / vulkan-headers are built as _all and
    # looked up with DEP_ARCH=all; rejecting them forces a rebuild every run —
    # observed live in run 41657628374: 2 _all debs built, both rejected)
    alld = mkdeb(W / "src" / "vulkan-headers_1.4.366_all.deb",
                 "vulkan-headers", "1.4.366", "all", b"V" * 60)
    shutil.copy2(alld, ws / "output" / alld.name)
    r = cish(ws, "dep-output-collect")
    ok("R23 collect ACCEPTS arch-independent (_all) dependency debs and persists them",
       (deps / alld.name).is_file() and alld.name in man.read_text(), r.stdout[-250:])

    # ---------- seed ----------
    ws2 = mk_workspace(W / "tp2")
    r = cish(ws2, "dep-output-seed")
    ok("R14 seed is a safe no-op on a cold depcache (no output/ created, rc=0)",
       r.returncode == 0 and "DEPSED seed cold" in r.stdout and not (ws2 / "output").exists(),
       (r.stdout + r.stderr)[-200:])

    (ws2 / ".termux-depcache" / "deps").mkdir(parents=True)
    for nm in (hosttools.name, alld.name):
        shutil.copy2(deps / nm, ws2 / ".termux-depcache" / "deps" / nm)
    shutil.copy2(man, ws2 / ".termux-depcache" / "deps" / "MANIFEST")
    r = cish(ws2, "dep-output-seed",
             env_extra={"DEP_SEED_ALLOW": "chromium-host-tools vulkan-headers"})
    seeded = ws2 / "output" / hosttools.name
    ok("R15 seed round-trips every persisted deb (aarch64 + _all) into output/ byte-identically",
       r.returncode == 0 and seeded.is_file() and sha(seeded) == sha(hosttools)
       and (ws2 / "output" / alld.name).is_file()
       and sha(ws2 / "output" / alld.name) == sha(alld)
       and "DEPSED seed entries=2 seeded=2 skipped=0" in r.stdout,
       (r.stdout + r.stderr)[-300:])

    (ws2 / ".termux-depcache" / "deps" / "MANIFEST").write_text(f"{'0' * 64}\t{hosttools.name}\n")
    (ws2 / "output").mkdir(exist_ok=True)
    (ws2 / "output" / hosttools.name).unlink()
    r = cish(ws2, "dep-output-seed")
    ok("R16 seed refuses a manifest sha256 mismatch (tampered/corrupt entry never installed)",
       not (ws2 / "output" / hosttools.name).exists()
       and "DEPSED seed SKIP sha mismatch" in r.stdout and "seeded=0" in r.stdout,
       r.stdout[-250:])

    (ws2 / ".termux-depcache" / "deps" / target.name).write_bytes(target.read_bytes())
    (ws2 / ".termux-depcache" / "deps" / "MANIFEST").write_text(
        f"{sha(target)}\t{target.name}\n"
        f"{'a' * 64}\t../../etc/evil.deb\n"
        f"{sha(arm)}\t{arm.name}\n")
    r = cish(ws2, "dep-output-seed")
    ok("R17 seed refuses the target package, path traversal and non-aarch64 entries",
       not (ws2 / "output" / target.name).exists()
       and not (W / "etc" / "evil.deb").exists()
       and not (ws2 / "output" / arm.name).exists()
       and "SKIP unsafe entry" in r.stdout and "seeded=0" in r.stdout,
       r.stdout[-350:])

    # ---------- seed allowlist (measured necessity: parent reuse hides subpackages) ----------
    ws6 = mk_workspace(W / "tp6")
    (ws6 / ".termux-depcache" / "deps").mkdir(parents=True)
    for nm in (hosttools.name, alld.name):
        shutil.copy2(deps / nm, ws6 / ".termux-depcache" / "deps" / nm)
    shutil.copy2(man, ws6 / ".termux-depcache" / "deps" / "MANIFEST")
    r = cish(ws6, "dep-output-seed")   # default allowlist
    ok("R24 default seed allowlist is chromium-host-tools only (parent reuse that hides subpackages is refused)",
       r.returncode == 0
       and (ws6 / "output" / hosttools.name).is_file()
       and not (ws6 / "output" / alld.name).exists()
       and "DEPSED seed SKIP not allowlisted: " + alld.name in r.stdout
       and "seeded=1" in r.stdout,
       (r.stdout + r.stderr)[-300:])

    # ---------- prune ----------
    ws3 = mk_workspace(W / "tp3")
    dc = ws3 / ".termux-depcache"
    (dc / "aarch64").mkdir(parents=True)
    (dc / "deps").mkdir(parents=True)
    old_pkg = dc / "aarch64" / "termux-main-stable-main-Packages"
    old_pkg.write_text("Package: x\n")
    keep = mkdeb(W / "src2" / "libexpat_2.9.0_aarch64.deb", "libexpat", "2.9.0", "aarch64", b"E" * 50)
    shutil.copy2(keep, dc / "deps" / keep.name)
    stale = time.time() - 40 * 86400
    os.utime(dc / "deps" / keep.name, (stale, stale))
    os.utime(old_pkg, (stale, stale))
    r = cish(ws3, "dep-cache-prune")
    ok("R18 prune never age-deletes our only surviving dependency deb (deps/ exempt from the 30-day rule)",
       r.returncode == 0 and (dc / "deps" / keep.name).is_file(),
       (r.stdout + r.stderr)[-250:])
    ok("R19 prune still age-deletes stale repo-index files under aarch64/ (existing policy intact)",
       not old_pkg.exists())

    for i in range(4):
        p = mkdeb(W / f"src3-{i}" / f"pkg{i}_1.{i}_aarch64.deb", f"pkg{i}", f"1.{i}", "aarch64", bytes([65 + i]) * 30)
        shutil.copy2(p, dc / "deps" / p.name)
        ts = time.time() - (10 - i) * 60
        os.utime(dc / "deps" / p.name, (ts, ts))
    r = cish(ws3, "dep-cache-prune", env_extra={"TERMUX_DEPCACHE_MAX_DEPS": "2"})
    left = sorted(p.name for p in (dc / "deps").glob("*.deb"))
    ok("R20 deps/ is bounded by count (newest kept) instead of unbounded growth",
       r.returncode == 0 and len(left) == 2 and "pkg3_1.3_aarch64.deb" in left and "pkg2_1.2_aarch64.deb" in left,
       f"left={left} out={(r.stdout + r.stderr)[-200:]}")

    # ---------- upstream selection semantics ----------
    # The pinned upstream branch is exactly:
    #   cache_file=_cache-aarch64/<pkg>_<ver>_<arch>.deb
    #   output_file=$TERMUX_OUTPUT_DIR/<same name>
    #   PKG_HASH empty + REUSE flag + [ -f output_file ] -> ln -sf; return 0
    # so "will termux reuse it?" == "does output/<exact DEP_VERSION name> exist?".
    # We assert that OUR persistence never renames: the seeded file must be
    # byte-identical in name to the deb upstream would look for.
    ws5 = mk_workspace(W / "tp5")
    (ws5 / "output").mkdir()
    shutil.copy2(hosttools, ws5 / "output" / hosttools.name)
    cish(ws5, "dep-output-collect")
    (ws5 / "output" / hosttools.name).unlink()
    r = cish(ws5, "dep-output-seed")
    ok("R21 seeded name is byte-identical to the DEP_VERSION lookup name (no renaming/prefixing)",
       r.returncode == 0 and (ws5 / "output" / hosttools.name).is_file()
       and sorted(p.name for p in (ws5 / "output").glob("*.deb")) == [hosttools.name],
       f"out={(r.stdout + r.stderr)[-250:]}")

    ws4 = mk_workspace(W / "tp4")
    r = cish(ws4, "dep-output-collect")
    ok("R22 collect on a workspace with no output/ is a tolerated no-op (never fails the pipeline)",
       r.returncode == 0 and "new=0 total=0" in r.stdout, (r.stdout + r.stderr)[-200:])
finally:
    shutil.rmtree(W, ignore_errors=True)

print(f"\nHOSTTOOLS-SUITE PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
