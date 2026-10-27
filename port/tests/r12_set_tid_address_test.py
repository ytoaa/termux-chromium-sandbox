#!/usr/bin/env python3
"""R12 contract tests: renderer-only Bionic set_tid_address allow (Issue #12).

These prove the SOURCE TRANSFORM is exact, minimal, bionic-guarded and
fail-closed on drift; device behaviour is proven separately by the
candidate gate (E-burst census + strace siginfo).
"""
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "port"))
from chromium_sandbox_port import Port, PortError, R12_MARKER  # noqa: E402

BASE = ROOT / "port/tests/fixtures"
RP = "sandbox/policy/linux/bpf_renderer_policy_linux.cc"
passed = failed = 0


def check(label, ok):
    global passed, failed
    if ok:
        passed += 1
        print("PASS  " + label)
    else:
        failed += 1
        print("FAIL  " + label)


def attempt(fn):
    try:
        fn()
        return True
    except PortError:
        return False


def srcdir(root, label):
    new = root / label
    shutil.copytree(BASE, new)
    return new


with tempfile.TemporaryDirectory(prefix="r12-test-") as folder:
    root = Path(folder)

    # --- positive: clean transform -------------------------------------
    valid = srcdir(root, "valid")
    p = Port(valid)
    check("R12 fixture transforms cleanly", attempt(p.apply))
    check("R12 both records present",
          {"R12 logging include (Bionic)",
           "R12 bionic set_tid_address renderer allow"} <= {c.name for c in p.changes})
    src = (valid / RP).read_text()
    check("R12 marker appears exactly 3x (include+comment+VLOG)",
          src.count(R12_MARKER) == 3)
    check("R12 approved body present verbatim once", src.count(Port.R12_NEW) == 1)
    check("R12 guarded include present verbatim once", src.count(Port.R12_INCLUDE_NEW) == 1)
    i = src.index("case __NR_set_tid_address:")
    blk = src[max(0, i - 1500):i]
    tail = src[i:i + 320]
    check("R12 arm sits inside a __BIONIC__ guard opened after getcpu",
          blk.rfind("#if defined(__BIONIC__)") > blk.rfind("case __NR_getcpu:") > -1)
    check("R12 adds exactly one case label (no second syscall sneaks in)",
          "case __NR_" not in blk[blk.rindex("#if defined(__BIONIC__)"):])
    check("R12 arm is Allow()+VLOG, never KILL/TRAP/ERRNO",
          'VLOG(1) << "Termux seccomp-only r12-bionic-tid' in tail
          and "return Allow();" in tail[:tail.index("#endif")]
          and all(b not in tail for b in ("KillProcess", "KillThread",
                                            "CrashSIGSYS", "Error(", "Trap(")))
    check("R12 no sandbox-disabling strings",
          "--no-sandbox" not in src and "--disable-seccomp" not in src)
    check("R12 binary-gate marker string survives as a literal",
          '"Termux seccomp-only r12-bionic-tid: renderer allow active"' in src)
    check("R12 verify passes after apply", attempt(Port(valid).verify))
    check("R12 apply idempotent (ALREADY_PRESENT, bytes unchanged)",
          attempt(Port(valid).apply) and (valid / RP).read_text() == src)
    check("R12 logging include is bionic-guarded",
          src.count('#if defined(__BIONIC__)\n#include "base/logging.h"') == 1)

    # --- negative: fail-closed controls --------------------------------
    t = srcdir(root, "drift")
    f = t / RP
    f.write_text(f.read_text().replace("    case __NR_getcpu:",
                                        "    case __NR_getcpu_DRIFT:"))
    check("R12 anchor drift -> PortError", attempt(lambda: Port(t).apply()) is False)

    t = srcdir(root, "missing")
    (t / RP).unlink()
    check("R12 missing file -> PortError (required, not optional)",
          attempt(lambda: Port(t).apply()) is False)

    t = srcdir(root, "duparm")
    f = t / RP
    f.write_text(f.read_text().replace(Port.R12_NEW, Port.R12_NEW + """
#if defined(__BIONIC__)
    case __NR_set_tid_address:
      return Allow();
#endif""", 1))
    check("R12 duplicated syscall arm -> verify PortError",
          attempt(lambda: Port(t).verify()) is False)

    t = srcdir(root, "unguard")
    f = t / RP
    f.write_text(f.read_text().replace(Port.R12_NEW, Port.R12_NEW.replace(
        "#if defined(__BIONIC__)\n    // " + R12_MARKER,
        "// " + R12_MARKER).replace("""      return Allow();
#endif
      return Allow();""", "      return Allow();"), 1))
    check("R12 unguarded (non-bionic-affecting) rewrite -> verify PortError",
          attempt(lambda: Port(t).verify()) is False)

    t = srcdir(root, "widened")
    f = t / RP
    f.write_text(f.read_text().replace(Port.R12_NEW, Port.R12_NEW.replace(
        "    case __NR_set_tid_address:\n      VLOG",
        "    case __NR_set_tid_address:\n    case __NR_unshare:\n      VLOG"), 1))
    check("R12 second widened syscall -> verify PortError",
          attempt(lambda: Port(t).verify()) is False)

    t = srcdir(root, "killswap")
    f = t / RP
    f.write_text(f.read_text().replace(Port.R12_NEW, Port.R12_NEW.replace(
        'VLOG(1) << "Termux seccomp-only r12-bionic-tid: renderer allow active";\n      return Allow();',
        'return Error(EPERM);'), 1))
    check("R12 marker/Allow tamper (silent policy change) -> verify PortError",
          attempt(lambda: Port(t).verify()) is False)

print(f"R12-TESTS PASS={passed} FAIL={failed}")
sys.exit(0 if failed == 0 else 1)
