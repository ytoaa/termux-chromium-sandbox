#!/usr/bin/env python3
"""Round 31 — C-5 regression: essential dependency debs survive depcache prune.

Measured defect (run 41906007952): TERMUX_DEPCACHE_MAX_DEPS=40 < 41 dependency
debs, the count prune ordered by mtime, and the allowlisted chromium-host-tools
deb was evicted -> the next seed reported "entries=41 seeded=0" with NO cause in
the log, and host-tools was rebuilt from source (157 min).

Checks the fix at the ci.sh level with real dpkg-deb fixtures (no network):
  P1  static: prune protects DEP_SEED_ALLOW packages, has an essential bound
  P2  static: seed names MISSING entries and warns REQUIRED-MISSING/INCOMPLETE
  P3  41 deps, host-tools oldest  -> survives, seed=1, missing=0
  P4  host-tools newest           -> survives, oldest ORDINARY dep deleted
  P5  equal mtimes                -> survives (tie no longer decides)
  P6  39 / P7 40 deps             -> untouched, seed=1
  P8  42 / P9 45 deps             -> capped at 40 ordinary, seed=1, missing=0
  P10 host-tools file deleted     -> MISSING + REQUIRED-MISSING + seeded=0
  P11 ordinary file deleted       -> MISSING, no REQUIRED-MISSING
  P12 essential set over bound    -> trimmed to newest N
  P13 byte cap                    -> essential protected, ordinary pruned
  P14 manifest reconciled with disk after prune
  P15 missing deb does not fail the seed step (build recovers by rebuilding)
  P16 prune is idempotent
  P17 seed summary format carries missing=N
  P18 workflow skips seed on REUSED=1 (no pointless seed of a reused deb)
  P19 C-1 save gates still present (REUSED=1 writes nothing)
  P20 no essential deb is ever removed by the ordinary cap (10x shuffle)
"""
import os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / "port" / "ci.sh"
WF = ROOT / ".github" / "workflows" / "build-chromium.yml"
PASS = FAIL = 0
TMP = Path(tempfile.mkdtemp(prefix="c5-"))
POOL = TMP / "pool"

def ok(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"PASS  {name}" + (f"  [{detail}]" if detail else ""))
    else:
        FAIL += 1; print(f"FAIL  {name}  [{detail}]")

def mkdeb(pkg, ver, arch, outdir):
    t = Path(tempfile.mkdtemp(prefix="d-", dir=str(TMP)))
    (t / "DEBIAN").mkdir(); (t / "usr/share/doc" / pkg).mkdir(parents=True)
    (t / "DEBIAN/control").write_text(
        f"Package: {pkg}\nVersion: {ver}\nArchitecture: {arch}\n"
        f"Maintainer: t <t@example.invalid>\nDescription: fixture\n")
    (t / "usr/share/doc" / pkg / "README").write_text("fixture\n")
    for d in (t, t / "DEBIAN", t / "usr", t / "usr/share", t / "usr/share/doc", t / "usr/share/doc" / pkg):
        os.chmod(d, 0o755)
    subprocess.run(["dpkg-deb", "--build", str(t), str(outdir / f"{pkg}_{ver}_{arch}.deb")],
                   check=True, capture_output=True)
    shutil.rmtree(t)

def termux_dir(name, ordinary, hosttools=True, hosttools_mtime=None, ordinary_mtime=None):
    d = TMP / name / "termux-packages"
    (d / "scripts").mkdir(parents=True); (d / ".termux-depcache/deps").mkdir(parents=True)
    for f in ("build-package.sh", "scripts/run-docker.sh"):
        (d / f).write_text("#!/bin/sh\n"); os.chmod(d / f, 0o755)
    deps = d / ".termux-depcache/deps"
    for f in POOL.glob("*.deb"):
        if f.name.startswith("chromium-host-tools") and not hosttools:
            continue
        if not f.name.startswith("chromium-host-tools"):
            n = int(re.match(r"dep(\d+)_", f.name).group(1))
            if n > ordinary:
                continue
        shutil.copy2(f, deps / f.name)
    if hosttools_mtime:
        os.utime(deps / "chromium-host-tools_156.0.8078.47_aarch64.deb", (hosttools_mtime, hosttools_mtime))
    if ordinary_mtime:
        for f in deps.glob("dep*.deb"):
            os.utime(f, (ordinary_mtime, ordinary_mtime))
    with (deps / "MANIFEST").open("w") as m:
        for f in sorted(deps.glob("*.deb")):
            sha = subprocess.run(["sha256sum", str(f)], capture_output=True, text=True).stdout.split()[0]
            m.write(f"{sha}\t{f.name}\n")
    return d, deps

def run(*args, env=None):
    e = dict(os.environ); e.update(env or {})
    return subprocess.run(["bash", str(CI), *args], capture_output=True, text=True, env=e)

def seed(d, env=None):
    r = run("dep-output-seed", str(d), env=env)
    m = re.search(r"DEPSED seed entries=(\d+) seeded=(\d+) skipped=(\d+) missing=(\d+)", r.stdout)
    return r, (tuple(int(x) for x in m.groups()) if m else None)

def prune(d, env=None):
    return run("dep-cache-prune", str(d), env=env)

# ---- fixture pool: host-tools + 45 ordinary debs (built once) -------------
POOL.mkdir(parents=True)
mkdeb("chromium-host-tools", "156.0.8078.47", "aarch64", POOL)
for i in range(1, 46):
    mkdeb(f"dep{i:02d}", "1.0", "aarch64", POOL)

wf = WF.read_text()
ci = CI.read_text()

# P1/P2 static contract
ok("P1 prune protects DEP_SEED_ALLOW packages and bounds the essential set",
   'allow=" ${DEP_SEED_ALLOW:-chromium-host-tools} "' in ci
   and "TERMUX_DEPCACHE_MAX_ESSENTIAL" in ci
   and "essential debs protected" in ci)
ok("P2 seed names MISSING entries and warns REQUIRED-MISSING/INCOMPLETE",
   "DEPSED seed MISSING" in ci and "DEPSED seed REQUIRED-MISSING" in ci
   and "DEPSED seed INCOMPLETE" in ci and "missing=$missing" in ci)

# P3 oldest essential survives
d, deps = termux_dir("p3", 40, hosttools_mtime=1000000000, ordinary_mtime=2000000000)
prune(d); r, s = seed(d)
ok("P3 41 deps with host-tools OLDEST: essential survives and seeds",
   (deps / "chromium-host-tools_156.0.8078.47_aarch64.deb").exists() and s == (41, 1, 40, 0),
   f"files={len(list(deps.glob('*.deb')))} seed={s}")

# P4 newest essential, oldest ordinary deleted
d, deps = termux_dir("p4", 40, hosttools_mtime=2000000000, ordinary_mtime=1000000000)
for f in deps.glob("dep*.deb"):
    os.utime(f, (1000000000 + int(re.match(r"dep(\d+)_", f.name).group(1)),) * 2)
prune(d); r, s = seed(d)
missing_dep01 = not (deps / "dep01_1.0_aarch64.deb").exists()
ok("P4 host-tools NEWEST: survives while the oldest ordinary dep is the one capped",
   (deps / "chromium-host-tools_156.0.8078.47_aarch64.deb").exists() and s == (41, 1, 40, 0),
   f"dep01_gone={missing_dep01} seed={s}")

# P5 equal mtimes
d, deps = termux_dir("p5", 40, hosttools_mtime=1500000000, ordinary_mtime=1500000000)
prune(d); r, s = seed(d)
ok("P5 equal mtimes: tie-break can no longer evict the essential deb",
   (deps / "chromium-host-tools_156.0.8078.47_aarch64.deb").exists() and s[1] == 1, f"seed={s}")

# P6/P7 boundary counts
for name, n, want_files in (("p6", 38, 39), ("p7", 39, 40)):
    d, deps = termux_dir(name, n, hosttools_mtime=1000000000, ordinary_mtime=2000000000)
    prune(d); r, s = seed(d)
    ok(f"P6/P7 boundary ordinary={n}: no cap applied, seed works",
       len(list(deps.glob('*.deb'))) == want_files and s[1] == 1, f"files={len(list(deps.glob('*.deb')))} seed={s}")

# P8/P9 above cap
for name, n in (("p8", 41), ("p9", 44)):
    d, deps = termux_dir(name, n, hosttools_mtime=1000000000, ordinary_mtime=2000000000)
    prune(d); r, s = seed(d)
    ok(f"P8/P9 ordinary={n}: capped to 40 ordinary + essential, manifest reconciled, seed ok",
       len(list(deps.glob('*.deb'))) == 41 and s == (41, 1, 40, 0),
       f"files={len(list(deps.glob('*.deb')))} seed={s}")

# P10 required deb missing
d, deps = termux_dir("p10", 40, hosttools=False, ordinary_mtime=2000000000)
with (deps / "MANIFEST").open("a") as m:
    m.write("0" * 64 + "\tchromium-host-tools_156.0.8078.47_aarch64.deb\n")
r, s = seed(d)
ok("P10 host-tools file absent: MISSING + REQUIRED-MISSING + seeded=0 + missing=1",
   "DEPSED seed MISSING chromium-host-tools" in r.stdout
   and "REQUIRED-MISSING: chromium-host-tools" in r.stdout and s == (41, 0, 41, 1), f"seed={s}")

# P11 ordinary deb missing -> MISSING but no REQUIRED-MISSING
d, deps = termux_dir("p11", 40, hosttools_mtime=1000000000, ordinary_mtime=2000000000)
(deps / "dep05_1.0_aarch64.deb").unlink()
r, s = seed(d)
ok("P11 ordinary deb absent: MISSING logged, no REQUIRED-MISSING warning",
   "DEPSED seed MISSING dep05_1.0_aarch64.deb" in r.stdout and "REQUIRED-MISSING" not in r.stdout
   and s[3] == 1, f"seed={s}")

# P12 essential set over bound
d = TMP / "p12" / "termux-packages"; (d / "scripts").mkdir(parents=True); (d / ".termux-depcache/deps").mkdir(parents=True)
for f in ("build-package.sh", "scripts/run-docker.sh"):
    (d / f).write_text("#!/bin/sh\n"); os.chmod(d / f, 0o755)
deps = d / ".termux-depcache/deps"
allow = []
for i in range(1, 11):
    mkdeb(f"ess{i}", "1.0", "aarch64", deps); allow.append(f"ess{i}")
    os.utime(deps / f"ess{i}_1.0_aarch64.deb", (1500000000 + i, 1500000000 + i))
prune(d, {"DEP_SEED_ALLOW": " ".join(allow), "TERMUX_DEPCACHE_MAX_ESSENTIAL": "8"})
kept = sorted(p.name for p in deps.glob("*.deb"))
ok("P12 essential set over bound: trimmed to newest 8, oldest essentials removed",
   len(kept) == 8 and "ess1_1.0_aarch64.deb" not in kept and "ess10_1.0_aarch64.deb" in kept, f"{kept}")

# P13 byte cap protects essential
d, deps = termux_dir("p13", 40, hosttools_mtime=1000000000, ordinary_mtime=2000000000)
prune(d, {"TERMUX_DEPCACHE_CAP_MB": "0"})
ok("P13 byte cap: ordinary debs pruned, essential deb survives",
   (deps / "chromium-host-tools_156.0.8078.47_aarch64.deb").exists()
   and len(list(deps.glob("dep*.deb"))) == 0,
   f"files={sorted(p.name for p in deps.glob('*.deb'))}")

# P14 manifest reconciled
d, deps = termux_dir("p14", 44, hosttools_mtime=1000000000, ordinary_mtime=2000000000)
prune(d)
manifest = (deps / "MANIFEST").read_text().splitlines()
ok("P14 manifest reconciled with disk after prune (no permanent phantom missing)",
   len(manifest) == len(list(deps.glob("*.deb"))) == 41, f"manifest={len(manifest)}")

# P15 seed does not fail the step when a deb is missing
d, deps = termux_dir("p15", 40, hosttools=False)
with (deps / "MANIFEST").open("a") as m:
    m.write("0" * 64 + "\tchromium-host-tools_156.0.8078.47_aarch64.deb\n")
r, s = seed(d)
ok("P15 missing required deb does not fail the seed step (build recovers by rebuilding)",
   r.returncode == 0 and "REQUIRED-MISSING" in r.stdout, f"rc={r.returncode}")

# P16 idempotent prune
d, deps = termux_dir("p16", 44, hosttools_mtime=1000000000, ordinary_mtime=2000000000)
prune(d); n1 = len(list(deps.glob("*.deb"))); prune(d); n2 = len(list(deps.glob("*.deb")))
ok("P16 prune is idempotent", n1 == n2 == 41, f"{n1}->{n2}")

# P17 summary format
ok("P17 seed summary carries entries/seeded/skipped/missing",
   'DEPSED seed entries=$n seeded=$seeded skipped=$skipped missing=$missing' in ci)

# P18/P19 workflow contract
seed_step = wf[wf.index("- name: Seed dependency debs into output"):wf.index("- name: Collect dependency debs from output")]
save_dep = wf[wf.index("- name: Save termux dep cache"):wf.index("- name: Save sccache")]
save_sc = wf[wf.index("- name: Save sccache"):wf.index("- name: Save source cache (L4)")]
ok("P18 seed step is skipped on REUSED=1",
   "steps.debcheck.outputs.reused != '1'" in seed_step.split("\n")[1])
ok("P19 C-1 save gates intact (REUSED=1 writes no cache generation)",
   "steps.debcheck.outputs.reused != '1'" in save_dep.split("\n")[1]
   and "steps.debcheck.outputs.reused != '1'" in save_sc.split("\n")[1])

# P20 10 shuffles: essential never removed by the ordinary cap
survived = 0
for k in range(10):
    d, deps = termux_dir(f"p20_{k}", 40 + (k % 5), hosttools_mtime=1000000000 + k, ordinary_mtime=1000000000 + (k % 3))
    prune(d)
    survived += 1 if (deps / "chromium-host-tools_156.0.8078.47_aarch64.deb").exists() else 0
ok("P20 essential deb survives 10 mixed-mtime/over-cap shuffles", survived == 10, f"{survived}/10")

shutil.rmtree(TMP, ignore_errors=True)
print(f"\nDEPCACHE-PRUNE PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
