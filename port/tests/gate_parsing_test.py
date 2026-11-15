#!/usr/bin/env python3
"""Unit tests for port/gate_lib.sh (device_gate / bpf_evidence census parsing).

These parsers shipped three real bugs on the R32 testbed:
  * the census file was read with a "[ported] " label that only existed in the
    display stream, so filters/presence were always 0;
  * renderer children that keep --type=zygote were never reclassified;
  * kernels without Seccomp_filters made the verdict fail despite a live,
    filter-mode renderer.
This suite builds a fake PROC_ROOT and exercises the real shell functions.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "gate_lib.sh"


def write_proc(root: Path, pid: int, exe: Path, cmdline: bytes, status: str):
    d = root / str(pid)
    d.mkdir(parents=True)
    os.symlink(exe, d / "exe")
    (d / "cmdline").write_bytes(cmdline)
    (d / "status").write_text(status)


class GateParsingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gate-parse-"))
        self.proc = self.tmp / "proc"
        self.proc.mkdir()
        self.bin = self.tmp / "chrome"
        self.bin.write_text("#!/bin/sh\n")
        self.bin.chmod(0o755)
        self.other = self.tmp / "other"
        self.other.write_text("x")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_bash(self, script: str) -> str:
        r = subprocess.run(
            ["bash", "-c", f'set -euo pipefail; . "{LIB}"; {script}'],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_zygote_child_reclassified_as_renderer(self):
        write_proc(self.proc, 100, self.bin, b"chrome\0--type=browser\0", "Seccomp:\t2\nPPid:\t1\n")
        write_proc(self.proc, 200, self.bin, b"chrome\0--type=zygote\0", "Seccomp:\t2\nPPid:\t100\n")
        # renderer forked from zygote: still says --type=zygote, PPid is a zygote
        write_proc(self.proc, 300, self.bin, b"chrome\0--type=zygote\0=renderer\0", "Seccomp:\t2\nPPid:\t200\n")
        write_proc(self.proc, 400, self.bin, b"chrome\0--type=utility\0", "Seccomp:\t2\nPPid:\t100\n")
        # foreign binary must be ignored
        write_proc(self.proc, 500, self.other, b"x\0--type=renderer\0", "Seccomp:\t2\nPPid:\t100\n")
        out = self.tmp / "rows.txt"
        self.run_bash(f'gate_classify "{self.proc}" "{self.bin}" "{out}"')
        rows = out.read_text().splitlines()
        self.assertIn("browser 0 2", rows)
        self.assertIn("zygote 0 2", rows)
        self.assertIn("renderer 0 2", rows)
        self.assertIn("utility 0 2", rows)
        self.assertEqual(sum(1 for r in rows if r.startswith("renderer")), 1)
        self.assertEqual(sum(1 for r in rows if r.startswith("zygote")), 1)
        # readlink must not have followed the foreign binary
        self.assertEqual(len(rows), 4)

    def test_filter_count_exported(self):
        write_proc(self.proc, 100, self.bin, b"chrome\0--type=browser\0",
                   "Seccomp:\t2\nSeccomp_filters:\t3\nPPid:\t1\n")
        write_proc(self.proc, 200, self.bin, b"chrome\0--type=renderer\0",
                   "Seccomp:\t2\nSeccomp_filters:\t2\nPPid:\t100\n")
        out = self.tmp / "rows.txt"
        self.run_bash(f'gate_classify "{self.proc}" "{self.bin}" "{out}"')
        out_rows = out.read_text()
        self.assertIn("renderer 2 2", out_rows)
        self.assertEqual(self.run_bash(f'gate_field "{out}" renderer 2').strip(), "2")
        self.assertEqual(self.run_bash(f'gate_present "{out}" renderer').strip(), "1")

    def test_presence_and_mode_evidence(self):
        rows = self.tmp / "rows.txt"
        rows.write_text("browser 0 2\nrenderer 0 2\nrenderer 0 2\nutility 0 2\n")
        self.assertEqual(self.run_bash(f'gate_field "{rows}" renderer 2').strip(), "0")
        self.assertEqual(self.run_bash(f'gate_field "{rows}" renderer 3').strip(), "2")
        self.assertEqual(self.run_bash(f'gate_present "{rows}" renderer').strip(), "2")

    def test_decide_proxy_pass(self):
        rows = self.tmp / "rows.txt"
        rows.write_text("browser 0 2\nrenderer 0 2\nzygote 0 2\n")
        out = self.run_bash(f'gate_decide "{rows}" 0 1 ported')
        self.assertTrue(out.rstrip().endswith("PASS"), out)
        self.assertIn("presence+mode proxy ok", out)

    def test_decide_filter_count_pass(self):
        rows = self.tmp / "rows.txt"
        rows.write_text("renderer 2 2\n")
        out = self.run_bash(f'gate_decide "{rows}" 0 1 ported')
        self.assertTrue(out.rstrip().endswith("PASS"), out)
        self.assertNotIn("proxy", out)

    def test_decide_fail_without_renderer(self):
        rows = self.tmp / "rows.txt"
        rows.write_text("browser 0 2\nzygote 0 2\n")
        out = self.run_bash(f'gate_decide "{rows}" 0 1 ported')
        self.assertTrue(out.rstrip().endswith("FAIL"), out)

    def test_decide_fail_on_crash_or_codecs(self):
        rows = self.tmp / "rows.txt"
        rows.write_text("renderer 2 2\n")
        self.assertTrue(self.run_bash(f'gate_decide "{rows}" 1 1').rstrip().endswith("FAIL"))
        self.assertTrue(self.run_bash(f'gate_decide "{rows}" 0 0').rstrip().endswith("FAIL"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
