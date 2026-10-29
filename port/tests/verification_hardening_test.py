#!/usr/bin/env python3
"""Audit-round (2026-10-30, DESIGN Round 25) contract tests.

Covers the verification-hardening fixes ONLY — no shipping security policy
changes (policy C++ immutability stays pinned by T34i/T15 and [47]-[51]):

  H*  generated post_get_source hook: transformer rc / per-rule records /
      scan marker, independent of the external builder's shell options.
  G*  CI Package gates step (extracted from the workflow YAML): anchored
      rule grep (R1 must not match R10/11/12), evidence-chain fail-closed,
      REUSED=1 skip, deb bin->wrapper symlink gate, maintainer-script gate.
  W*  bpf_evidence wrapper_guard: effective-PREFIX mixed-identity refusal
      (set-but-empty PREFIX under a custom installed root).
  S*  anti-injection scan: unreadable target is a named fail-closed
      offender, not an uncaught OSError traceback.
  X*  x11_gate LD_PRELOAD assembly must be quote-safe (no word splitting).
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "port"))
import prepare_recipe  # noqa: E402
from chromium_sandbox_port import Port, PortError  # noqa: E402

BASE = ROOT / "port/tests/fixtures"
WORKFLOW = ROOT / ".github/workflows/build-chromium.yml"
PASS = FAIL = 0


def ok(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS  " + label)
    else:
        FAIL += 1
        print("FAIL  " + label + (f"  [{detail}]" if detail else ""))


def sh(script, env=None, cwd=None):
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env=env, cwd=cwd, timeout=300)


# --------------------------------------------------------------------------
# H: generated hook contract
# --------------------------------------------------------------------------
RULES = ["R1", "R2", "R3", "R4", "R5", "R7", "R9a", "R10", "R11", "R12"]


def stub_output(records, marker=True):
    lines = [f"[        APPLIED] {r} audit fixture rule" for r in records]
    if marker:
        lines.append("[     VERIFIED] anti-injection scan (--no-sandbox appenders)")
    return "\n".join(lines) + "\n"


def run_hook(stub_stdout, stub_rc, pipefail, tmp):
    """Write a stub transformer + execute the GENERATED hook body."""
    d = Path(tmp) / f"hook-{abs(hash((stub_stdout, stub_rc, pipefail))) % 99999999}"
    builder = d / "builder"; src = d / "src"; tdir = d / "tmp"
    for p in (builder, src, tdir):
        p.mkdir(parents=True)
    (builder / "termux-chromium-sandbox-port.py").write_text(
        "#!/usr/bin/env python3\nimport sys\nsys.stdout.write(%r)\nsys.exit(%d)\n"
        % (stub_stdout, stub_rc))
    hookf = d / "hook.sh"
    hookf.write_text(prepare_recipe.HOOK + "\ntermux_step_post_get_source\n")
    env = dict(os.environ, TERMUX_PKG_BUILDER_DIR=str(builder),
               TERMUX_PKG_SRCDIR=str(src), TERMUX_PKG_TMPDIR=str(tdir))
    r = sh(("set -o pipefail; " if pipefail else "") + f"exec bash {hookf}", env=env)
    return r


FULL = stub_output(RULES)
with tempfile.TemporaryDirectory(prefix="vh-hook-") as tmp:
    r = run_hook(stub_output(RULES[:9]), 1, pipefail=False, tmp=tmp)
    ok("H1 transformer early death refused WITHOUT builder pipefail (rc captured)",
       r.returncode != 0 and "partial apply refused" in r.stderr, (r.stdout + r.stderr)[-200:])
    r = run_hook(stub_output(RULES[:9]), 1, pipefail=True, tmp=tmp)
    ok("H2 transformer early death refused WITH pipefail too (both modes)",
       r.returncode != 0, (r.stdout + r.stderr)[-160:])
    r = run_hook(FULL, 0, pipefail=False, tmp=tmp)
    ok("H3 full apply accepted (all rule records + scan marker)",
       r.returncode == 0, (r.stdout + r.stderr)[-200:])
    r = run_hook(stub_output([x for x in RULES if x != "R12"]), 0, pipefail=False, tmp=tmp)
    ok("H4 silent rule loss tolerated by old >=8 counter is now refused (R12 missing)",
       r.returncode != 0 and "R12 record missing" in r.stderr, (r.stdout + r.stderr)[-160:])
    r = run_hook(stub_output(RULES, marker=False), 0, pipefail=False, tmp=tmp)
    ok("H5 missing anti-injection scan completion marker refused",
       r.returncode != 0 and "scan completion marker missing" in r.stderr, (r.stdout + r.stderr)[-160:])
    r = run_hook(stub_output([x for x in RULES if x != "R1"]) + "[        APPLIED] R10 decoy rule\n",
                 0, pipefail=False, tmp=tmp)
    ok("H6 R1 record missing while R10/11/12 present -> refused (anchored grep)",
       r.returncode != 0 and "R1 record missing" in r.stderr, (r.stdout + r.stderr)[-160:])
    # H7: end-to-end with the REAL transformer over the fixture tree.
    d = Path(tmp) / "e2e"
    builder = d / "builder"; tdir = d / "tmp"; srcroot = d / "src"
    for p in (builder, tdir):
        p.mkdir(parents=True)
    shutil.copytree(BASE, srcroot)
    shutil.copy(ROOT / "port/chromium_sandbox_port.py",
                builder / "termux-chromium-sandbox-port.py")
    hookf = d / "hook.sh"
    hookf.write_text(prepare_recipe.HOOK + "\ntermux_step_post_get_source\n")
    env = dict(os.environ, TERMUX_PKG_BUILDER_DIR=str(builder),
               TERMUX_PKG_SRCDIR=str(srcroot), TERMUX_PKG_TMPDIR=str(tdir))
    r = sh(f"exec bash {hookf}", env=env)
    ok("H7 real transformer end-to-end satisfies the hook contract",
       r.returncode == 0 and (tdir / "port-apply.log").is_file()
       and "anti-injection scan" in (tdir / "port-apply.log").read_text(),
       (r.stdout + r.stderr)[-250:])

# --------------------------------------------------------------------------
# G: CI Package gates step, extracted from the workflow and executed
# --------------------------------------------------------------------------
import yaml  # noqa: E402

wf = yaml.safe_load(WORKFLOW.read_text())
steps = wf["jobs"]["build"]["steps"]
gstep = next(s for s in steps if s.get("name", "").startswith("Package gates"))
body = gstep["run"]
ok("G0 gates step: anchored rule grep + scan marker + REUSED handling present",
   'grep -qE "\\] ${r} "' in body and "anti-injection scan" in body
   and "DEB_REUSED" in body and "for r in R1 R2 R3 R4 R5 R7 R9a R10 R11 R12" in body,
   body[:160])


def make_deb(root: Path, symlink_target="chromium-shield-wrapper.sh", postinst=False):
    (root / "DEBIAN").mkdir(parents=True)
    (root / "DEBIAN").chmod(0o755)  # dpkg-deb -b refuses 0700 (device umask)
    (root / "DEBIAN/control").write_text(
        "Package: chromium-sandboxed\nVersion: 156.0.8078.47-12\n"
        "Architecture: aarch64\nMaintainer: t\ndescription: fixture\n")
    lib = root / "data/data/com.termux/files/usr/lib/chromium-sandboxed"
    binp = root / "data/data/com.termux/files/usr/bin"
    lib.mkdir(parents=True); binp.mkdir(parents=True)
    (lib / "libtermux-gnp-fix.so").write_text("so")
    (lib / "chromium-shield-wrapper.sh").write_text("exec chromium-launcher.sh\n")
    (lib / "chromium-launcher.sh").write_text("#!/bin/sh\nexec chrome\n")
    ln = binp / "chromium-sandboxed"
    if ln.exists() or ln.is_symlink():
        ln.unlink()
    os.symlink(f"../lib/chromium-sandboxed/{symlink_target}", ln)
    if postinst:
        (root / "DEBIAN/postinst").write_text("#!/bin/sh\nexit 0\n")
    for f in (root / "DEBIAN").iterdir():
        f.chmod(0o755 if f.name != "control" else 0o644)  # dpkg-deb: scripts must be executable
    out = root.parent / "out.deb"
    subprocess.run(["dpkg-deb", "-b", str(root), str(out)], check=True,
                   capture_output=True)
    return out


def run_gates(tmp, tag, log_content=None, reused="0", **debkw):
    ws = Path(tmp) / f"gates-{tag}"
    tp = ws / "termux-packages"
    (tp / "output").mkdir(parents=True)
    deb = make_deb(ws / "dtree", **debkw)
    shutil.move(str(deb), tp / "output" / "chromium-sandboxed_156.0.8078.47-12_aarch64.deb")
    if log_content is not None:
        (tp / "port-apply-chromium.log").write_text(log_content)
    (ws / "gates.sh").write_text(body)
    env = dict(os.environ, DEB_REUSED=reused)
    return sh("exec bash gates.sh", env=env, cwd=str(ws))


with tempfile.TemporaryDirectory(prefix="vh-gates-") as tmp:
    r = run_gates(tmp, "good", log_content=FULL)
    ok("G1 good deb + good evidence log -> PORT GATES PASS",
       r.returncode == 0 and "PORT GATES PASS" in r.stdout, (r.stdout + r.stderr)[-200:])
    bad = stub_output([x for x in RULES if x != "R1"]) + "[        APPLIED] R10 decoy rule\n"
    r = run_gates(tmp, "nor1", log_content=bad)
    ok("G2 log missing R1 while R10 present -> refused (substring bug fixed)",
       r.returncode != 0 and "R1 not applied" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-200:])
    r = run_gates(tmp, "nomarker", log_content=stub_output(RULES, marker=False))
    ok("G3 scan marker missing in log -> refused",
       r.returncode != 0 and "anti-injection scan" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-200:])
    r = run_gates(tmp, "noev", log_content=None, reused="0")
    ok("G4 fresh build with EMPTY evidence chain -> refused (no more WARN-only)",
       r.returncode != 0 and "refusing" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-200:])
    r = run_gates(tmp, "reused", log_content=None, reused="1")
    ok("G5 REUSED=1 skips evidence discovery but still runs binary gates",
       r.returncode == 0 and "REUSED=1" in r.stdout and "PORT GATES PASS" in r.stdout,
       (r.stdout + r.stderr)[-200:])
    r = run_gates(tmp, "badsym", log_content=FULL, symlink_target="chromium-launcher.sh")
    ok("G6 bin symlink NOT repointed to shield wrapper -> refused",
       r.returncode != 0 and "not repointed" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-200:])
    r = run_gates(tmp, "postinst", log_content=FULL, postinst=True)
    ok("G7 unexpected maintainer script (postinst) -> refused",
       r.returncode != 0 and "maintainer script" in (r.stdout + r.stderr), (r.stdout + r.stderr)[-200:])

# --------------------------------------------------------------------------
# W: bpf_evidence wrapper_guard effective-PREFIX semantics
# --------------------------------------------------------------------------
BE = ROOT / "port/bpf_evidence.sh"
with tempfile.TemporaryDirectory(prefix="vh-guard-") as tmp:
    t = Path(tmp)
    wrapper_dir = t / "pfx/usr/lib/chromium-sandboxed"
    wrapper_dir.mkdir(parents=True)
    w = wrapper_dir / "chromium-shield-wrapper.sh"
    w.write_text("exec launcher\n")
    r = sh(f'TCS_PREFIX={t}/pfx PREFIX= bash {BE} _internal_guard {w}')
    ok("W1 set-but-empty PREFIX under custom installed root -> refused (mixed identity)",
       r.returncode != 0 and "mixed identity" in r.stdout, (r.stdout + r.stderr)[-200:])
    r = sh(f'TCS_PREFIX={t}/pfx PREFIX={t}/pfx bash {BE} _internal_guard {w}')
    ok("W2 PREFIX matching installed root -> allowed",
       r.returncode == 0, (r.stdout + r.stderr)[-160:])
    r = sh(f'TCS_PREFIX={t}/pfx bash {BE} _internal_guard {w}')
    ok("W3 PREFIX unset under CUSTOM root -> refused (effective = device default)",
       r.returncode != 0 and "mixed identity" in r.stdout, (r.stdout + r.stderr)[-160:])

# --------------------------------------------------------------------------
# S: anti-injection scan unreadable target => named offender (fail closed)
# --------------------------------------------------------------------------
with tempfile.TemporaryDirectory(prefix="vh-scan-") as tmp:
    src = Path(tmp) / "src"
    (src / "content").mkdir(parents=True)
    os.symlink(str(src / "content" / "dangling-target.cc"), str(src / "content" / "gone.cc"))
    (src / "content" / "fine.cc").write_text("int x;\n")
    p = Port(src)
    try:
        p.anti_injection_scan(["content"])
        ok("S1 dangling symlink in scan tree -> PortError (unreadable offender)", False, "no raise")
    except PortError as e:
        ok("S1 dangling symlink in scan tree -> PortError (unreadable offender)",
           "unreadable" in str(e) and "gone.cc" in str(e), str(e)[:160])
    except OSError as e:
        ok("S1 dangling symlink in scan tree -> PortError (unreadable offender)", False,
           f"uncaught OSError: {e}")
    src2 = Path(tmp) / "src2"
    (src2 / "content").mkdir(parents=True)
    (src2 / "content" / "a.cc").write_text("int x;\n")
    try:
        Port(src2).anti_injection_scan(["content"])
        ok("S2 clean tree scan passes with completion marker", True)
    except PortError as e:
        ok("S2 clean tree scan passes with completion marker", False, str(e)[:120])

# --------------------------------------------------------------------------
# X: x11_gate LD_PRELOAD quote-safety
# --------------------------------------------------------------------------
xg = (ROOT / "port/x11_gate.sh").read_text()
ok("X1 unquoted 'env ${PRE:+LD_PRELOAD=$PRE}' pattern eliminated",
   "${PRE:+LD_PRELOAD=$PRE}" not in xg and 'prearg=(LD_PRELOAD="$PRE")' in xg,
   "")
r = sh('f(){ local -a prearg=(); [ -n "${PRE:-}" ] && prearg=(LD_PRELOAD="$PRE"); '
       'setsid env "${prearg[@]}" true; }; PRE="/a dir/x.so" f; echo ok')
ok("X2 array expansion survives a preload path with spaces (bash semantics)",
   r.returncode == 0 and "ok" in r.stdout, (r.stdout + r.stderr)[-120:])

print(f"\nVERIFY-HARDENING PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
