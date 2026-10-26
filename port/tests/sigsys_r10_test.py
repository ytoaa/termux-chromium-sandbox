#!/usr/bin/env python3
"""R10 SIGSYS regression checks using the pinned Chromium fixture.

This does not claim Android device validation or successful real BPF startup.
"""
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "port"))
from chromium_sandbox_port import Port, PortError, R10_MARKER  # noqa: E402

SRC = ROOT / "port" / "tests" / "fixtures"
SBX = "sandbox/policy/linux/sandbox_linux.cc"
errors = []
count = 0


def check(name, ok):
    global count
    count += 1
    if not ok:
        errors.append(name)
        print("FAIL  " + name)
    else:
        print("PASS  " + name)


def fresh(tmp, name):
    path = tmp / name
    shutil.copytree(SRC, path)
    return path


def refusal(action):
    try:
        action()
    except PortError:
        return True
    return False


with tempfile.TemporaryDirectory() as dirname:
    tmp = Path(dirname)
    src = fresh(tmp, "valid")
    p = Port(src)
    check("R10 fresh fixture apply", not refusal(p.apply) and
          "R10 bionic SIGSYS reservation before BPF" in
          [c.name for c in p.changes])
    text = (src / SBX).read_text()
    check("R10 single source-marker comment", text.count("// " + R10_MARKER) == 1)
    check("R10 SIGSYS reset present", text.count("signal(SIGSYS, SIG_DFL)") == 1)
    check("R10 signal.h included", text.count("#include <signal.h>") == 1)
    start = text.index(R10_MARKER)
    end = text.index("SandboxSeccompBPF::StartSandboxWithExternalPolicy(", start)
    check("R10 reset immediately precedes BPF", end > start and
          "signal(SIGSYS, SIG_DFL)" in text[start:end] and end - start < 2200)
    check("R10 fail closed on signal failure",
          "CHECK(old_sigsys_handler != SIG_ERR)" in text[start:end])
    guard_start = text.rfind("#if defined(__BIONIC__)", 0, start)
    guard_end = text.find("#endif  // defined(__BIONIC__)", start)
    check("R10 enclosed in Bionic-only guard",
          0 <= guard_start < start < guard_end < end)
    check("R10 does not introduce sandbox-off switch",
          "--no-sandbox" not in text[start:end] and
          "disable-seccomp-filter-sandbox" not in text[start:end])
    check("R10 verification passes", not refusal(Port(src).verify))
    check("R10 idempotent", not refusal(Port(src).apply) and
          text == (src / SBX).read_text())

    # A real downstream source shape change MUST stop application.
    drift = fresh(tmp, "drift")
    file = drift / SBX
    old = file.read_text()
    file.write_text(old.replace("  SandboxSeccompBPF::StartSandboxWithExternalPolicy(",
                                "  UnexpectedBPFStarter("))
    check("R10 upstream installer drift refused", refusal(Port(drift).apply))

    tampered = fresh(tmp, "tampered")
    pp = Port(tampered)
    pp.apply()
    file = tampered / SBX
    file.write_text(file.read_text().replace("signal(SIGSYS, SIG_DFL)",
                                              "signal(SIGSYS, SIG_IGN)"))
    check("R10 sandboxed signal reset tampering rejected",
          refusal(Port(tampered).verify))

print(f"R10-TESTS PASS={count-len(errors)} FAIL={len(errors)}")
sys.exit(1 if errors else 0)
