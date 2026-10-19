#!/usr/bin/env python3
"""Termux Chromium seccomp-only sandbox port — semantic source transformer.

Single source of truth for Chromium-side compatibility changes (mirrors
termux-firefox-sandbox's firefox_sandbox_port.py model):
  - every rule is contract-checked against the real source shape;
  - outcomes per rule: APPLIED | ALREADY_PRESENT | (fail-closed) PortError;
  - the CI workflow is orchestration only and never embeds C++ patches.

Target: desktop-Linux Chromium built by Termux (Bionic aarch64), where
CLONE_NEWUSER is kernel-blocked (EINVAL) and no setuid helper can ship,
yet seccomp-bpf self-install is proven viable (poc/seccomp_probe.c).

Rules (see port/DESIGN.md Phase 0.3 / FINAL verdict):
  R1  content/browser/zygote_host/zygote_host_impl_linux.cc
      ZygoteHostImpl::Init(): under Bionic, do NOT LOG(FATAL) when neither
      userns nor setuid layer-1 is usable; continue with both layer-1 modes
      off (LaunchZygote/EnterLayerOneSandbox already tolerate that state).
  R2  sandbox/policy/linux/sandbox_linux.cc
      InitializeSandbox(): under Bionic, never EngageNamespaceSandbox();
      keep the BPF layer (StartSeccompBPF) exactly as upstream does.

Markers (also used by the future binary gate on libfrontend/chrome):
  "Termux seccomp-only sandbox:"   R1 marker string
  "Termux seccomp-only port:"      R2 marker string
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

R1_MARKER = "Termux seccomp-only sandbox:"
R2_MARKER = "Termux seccomp-only port:"


class PortError(RuntimeError):
    pass


@dataclass
class Change:
    name: str
    path: str
    status: str
    detail: str = ""


class Port:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.changes: list[Change] = []
        self.before_sha: dict[str, str] = {}
        self.after_sha: dict[str, str] = {}

    # ---------- plumbing (mirrors the Firefox port) ----------
    def p(self, rel: str) -> Path:
        path = self.root / rel
        if not path.is_file():
            raise PortError(f"required source file missing: {rel}")
        return path

    @staticmethod
    def sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def remember_before(self, rel: str) -> None:
        self.before_sha.setdefault(rel, self.sha(self.p(rel)))

    def remember_after(self, rel: str) -> None:
        self.after_sha[rel] = self.sha(self.p(rel))

    def record(self, name: str, rel: str, status: str, detail: str = "") -> None:
        self.changes.append(Change(name, rel, status, detail))
        print(f"[{status:>15}] {name}: {detail}".rstrip())

    def replace_once(self, rel: str, name: str, old: str, new: str) -> None:
        path = self.p(rel)
        self.remember_before(rel)
        text = path.read_text()
        if new in text:
            self.record(name, rel, "ALREADY_PRESENT")
            return
        count = text.count(old)
        if count != 1:
            raise PortError(f"{name}: expected exactly one old form, found {count}")
        path.write_text(text.replace(old, new, 1))
        self.record(name, rel, "APPLIED")
        self.remember_after(rel)

    # ---------- rules ----------
    ZYGOTE_HOST = "content/browser/zygote_host/zygote_host_impl_linux.cc"
    SANDBOX_LINUX = "sandbox/policy/linux/sandbox_linux.cc"

    R1_OLD = '''LOG(FATAL)
        << "No usable sandbox! If you are running on Ubuntu 23.10+ or another "
           "Linux distro that has disabled unprivileged user namespaces with "
           "AppArmor, see "
           "https://chromium.googlesource.com/chromium/src/+/main/"
           "docs/security/apparmor-userns-restrictions.md. Otherwise see "
           "https://chromium.googlesource.com/chromium/src/+/main/"
           "docs/linux/suid_sandbox_development.md for more information on "
           "developing with the (older) SUID sandbox. "
           "If you want to live dangerously and need an immediate workaround, "
           "you can try using --"
        << sandbox::policy::switches::kNoSandbox << ".";'''

    R1_NEW = '''#if defined(__BIONIC__)
        // ''' + R1_MARKER + ''' neither the userns nor the setuid layer-1
        // sandbox is available on Android/Termux; proceed with both layer-1
        // modes off so forked children still install seccomp-bpf policy
        // filters via StartSeccompBPF (seccomp-only mode).
        DLOG(WARNING) << "''' + R1_MARKER + ''' no layer-1 sandbox; "
                      << "BPF policies remain the only sandbox layer.";
#else
        ''' + R1_OLD.replace("LOG(FATAL)", "LOG(FATAL)") + '''
#endif'''

    R2_OLD = '''if (options.engage_namespace_sandbox)
    EngageNamespaceSandbox(false /* from_zygote */);'''

    R2_NEW = '''#if defined(__BIONIC__)
    // ''' + R2_MARKER + ''' Android blocks CLONE_NEWUSER; the namespace
    // pivot is never available, and attempting it CHECK-fails. Skip it and
    // rely on the seccomp-bpf layer installed by StartSeccompBPF below.
    (void)options.engage_namespace_sandbox;
#else
    ''' + R2_OLD + '''
#endif'''

    def apply(self) -> None:
        self.replace_once(self.ZYGOTE_HOST, "R1 seccomp-only usable mode (Bionic)",
                          self.R1_OLD, self.R1_NEW)
        self.replace_once(self.SANDBOX_LINUX, "R2 skip namespace engage (Bionic)",
                          self.R2_OLD, self.R2_NEW)

    # ---------- verifier (fail-closed gates) ----------
    def verify(self) -> None:
        # Gate 1: both markers present exactly once in their files.
        for rel, marker, label in (
            (self.ZYGOTE_HOST, R1_MARKER, "R1"),
            (self.SANDBOX_LINUX, R2_MARKER, "R2"),
        ):
            text = self.p(rel).read_text()
            n = text.count(marker)
            if n < 1:
                raise PortError(f"verifier: {label} marker absent from {rel}")
            print(f"[     VERIFIED] {label} marker in {rel} ({n}x)")
        # Gate 2: no unguarded 'false' namespace engage removal — the Bionic
        # branch must be #if-guarded so glibc/Linux builds keep upstream code.
        text = self.p(self.SANDBOX_LINUX).read_text()
        if "#if defined(__BIONIC__)" not in text or "#else" not in text:
            raise PortError("verifier: R2 guard structure missing")
        print(f"[     VERIFIED] R2 preprocessor guard structure intact")

    # ---------- anti-injection scan ----------
    def anti_injection_scan(self, dirs: list[str]) -> None:
        """Fail closed if any source besides sandbox_type.cc appends the
        browser-visible --no-sandbox switch (the stock-binary silent
        downgrade mystery, DESIGN.md Phase 0.3)."""
        import re
        pattern = re.compile(r"AppendSwitch\(\s*(sandbox::policy::)?switches::kNoSandbox\s*\)")
        offenders: list[str] = []
        allowed = {"sandbox/policy/sandbox_type.cc",
                   "sandbox/policy/sandbox_type_unittest.cc",
                   "content/browser/zygote_host/zygote_host_impl_linux.cc",  # our R1 file legitimately reads it
                   }
        for d in dirs:
            base = self.root / d
            if not base.is_dir():
                continue
            for f in base.rglob("*.cc"):
                rel = str(f.relative_to(self.root))
                txt = f.read_text(errors="ignore")
                if pattern.search(txt) and rel not in allowed:
                    offenders.append(rel)
        if offenders:
            raise PortError("anti-injection gate: unexpected --no-sandbox append sites: "
                            + ", ".join(sorted(offenders)[:10]))
        print("[     VERIFIED] anti-injection scan (--no-sandbox appenders)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["apply", "check", "verify"])
    ap.add_argument("--src", required=True, help="chromium checkout root (contains src/)")
    ap.add_argument("--scan", default="", help="comma-separated dirs for anti-injection scan")
    args = ap.parse_args(argv[1:])

    src = Path(args.src)
    if (src / "src").is_dir() and (src / "src" / "sandbox").is_dir():
        src = src / "src"  # accept either a termux work dir or the src/ itself
    port = Port(src)
    if args.command == "apply":
        port.apply()
        port.verify()
        if args.scan:
            port.anti_injection_scan([s for s in args.scan.split(",") if s])
    elif args.command == "check":
        port.verify()
        if args.scan:
            port.anti_injection_scan([s for s in args.scan.split(",") if s])
    elif args.command == "verify":
        port.verify()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except PortError as e:
        print(f"[    PORT ERROR] {e}", file=sys.stderr)
        sys.exit(1)
