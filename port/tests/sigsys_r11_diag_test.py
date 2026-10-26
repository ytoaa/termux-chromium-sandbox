#!/usr/bin/env python3
"""R11 diagnostic-only source-contract tests; these do not prove device behavior."""
from pathlib import Path
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "port"))
from chromium_sandbox_port import (  # noqa: E402
    Port, PortError, R11_BEFORE_MARKER, R11_TRAP_MARKER, R11_REG_MARKER
)

BASE = ROOT / "port/tests/fixtures"
SB = "sandbox/policy/linux/sandbox_linux.cc"
TR = "sandbox/linux/seccomp-bpf/trap.cc"
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


with tempfile.TemporaryDirectory(prefix="r11-test-") as folder:
    root = Path(folder)
    valid = srcdir(root, "valid")
    p = Port(valid)
    check("R11 upstream fixture transforms cleanly", attempt(p.apply))
    check("R11 all three source anchors recorded", {
        "R11 SIGSYS action snapshot before R10",
        "R11 classify prior handler at Trap::Trap",
        "R11 report first Trap::Registry creation",
    } <= {c.name for c in p.changes})
    src = (valid / SB).read_text()
    trap = (valid / TR).read_text()
    check("R11 markers unique in source",
          src.count("// " + R11_BEFORE_MARKER) == 1
          and trap.count("// " + R11_TRAP_MARKER) == 1
          and trap.count("// " + R11_REG_MARKER) == 1)
    i = src.index(R11_BEFORE_MARKER)
    reset = src.index("signal(SIGSYS, SIG_DFL)", i)
    bpf = src.index("SandboxSeccompBPF::StartSandboxWithExternalPolicy(", reset)
    check("R11 read-only snapshot precedes unmodified R10 reset then BPF",
          i < reset < bpf and
          src.count("const auto old_sigsys_handler = signal(SIGSYS, SIG_DFL);") == 1
          and "CHECK(sigaction(SIGSYS, nullptr, &termux_r11_before) == 0)"
          in src[i:reset])
    check("R11 pre snapshot checks categorical, no raw pointer logging",
          all(s in src[i:reset] for s in ("default", "ignored", "installed"))
          and "reinterpret_cast" not in src[i:reset]
          and "void*" not in src[i:reset])
    owner = trap.index(R11_TRAP_MARKER)
    oldwarn = trap.index("if (!IsDefaultSignalAction(old_sa))", owner)
    registry = trap.index(R11_REG_MARKER)
    check("R11 Trap owner probe before previous-handler warning",
          owner < oldwarn < registry)
    check("R11 records Chromium-specific previous owner",
          "r11_previous_chromium" in trap[owner:oldwarn]
          and "SigSysAction" in trap[owner:oldwarn]
          and all(c in trap[owner:oldwarn]
                  for c in ('"default"', '"ignored"', '"chromium"', '"foreign"')))
    check("R11 tracks first registry initialization",
          "if (!global_trap_) {" in trap[registry-85:registry]
          and "global_trap_ = new Trap();" in trap[registry:registry + 250])
    check("R11 is Bionic guard scoped",
          "#if defined(__BIONIC__)" in src[i - 260:i]
          and "#if defined(__BIONIC__)" in trap[owner-135:owner]
          and "#if defined(__BIONIC__)" in trap[registry-100:registry])
    check("R11 cannot inject sandbox-off flags",
          "--no-sandbox" not in src[i:bpf]
          and "--no-sandbox" not in trap[owner:oldwarn]
          and "--disable-seccomp-filter-sandbox" not in src[i:bpf])
    check("R11 does not change original Trap syscall installer",
          trap.count("sys_sigaction(LINUX_SIGSYS, &sa, &old_sa)") == 1)
    check("R11 verify passes", attempt(Port(valid).verify))
    check("R11 apply idempotent", attempt(Port(valid).apply)
          and (valid / SB).read_text() == src
          and (valid / TR).read_text() == trap)
    tamper = srcdir(root, "tamper-trap")
    target = tamper / TR
    target.write_text(target.read_text().replace(
        "  if (!IsDefaultSignalAction(old_sa)) {",
        "  if (IsDefaultSignalAction(old_sa)) {", 1))
    check("R11 Trap source drift fails closed", not attempt(Port(tamper).apply))
    tamper = srcdir(root, "tamper-after")
    Port(tamper).apply()
    target = tamper / SB
    target.write_text(target.read_text().replace(
        "sigaction(SIGSYS, nullptr, &termux_r11_before)",
        "sigaction(SIGSYS, nullptr, nullptr)"))
    check("R11 tampered SIGSYS snapshot fails verifier",
          not attempt(Port(tamper).verify))

print(f"R11-DIAG-TESTS PASS={passed} FAIL={failed}")
sys.exit(1 if failed else 0)
