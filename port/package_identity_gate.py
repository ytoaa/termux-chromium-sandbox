#!/usr/bin/env python3
"""Fail-closed side-by-side package ownership gate before Artifact publication.

Read actual dpkg-deb file entries (including symlinks), not source-code strings.
Stock Chromium files in chromium-sandboxed are always a packaging regression.
"""
from __future__ import annotations
import fnmatch
import re
import subprocess
import sys

PREFIX = "data/data/com.termux/files/usr/"
REQUIRED = {
    "bin/chromium-sandboxed",
    "bin/chromedriver-sandboxed",
    "bin/headless_shell-sandboxed",
    "lib/chromium-sandboxed/chrome",
    "lib/chromium-sandboxed/chromium-shield-wrapper.sh",
    "lib/chromium-sandboxed/libtermux-gnp-fix.so",
    # manpage: termux-package-build gzips man/ files automatically, so the
    # real deb ships .1.gz; accept either spelling (run 41022366268 proved
    # the plain form never exists in a produced deb — the old exact
    # requirement failed every correct package, i.e. a gate bug, not drift).
    "share/applications/chromium-sandboxed.desktop",
    "share/metainfo/chromium-sandboxed.appdata.xml",
}
REQUIRED_GLOBS = (
    ("share/man/man1/chromium-sandboxed.1*",
     "isolated manpage (plain or .gz)"),
    ("share/icons/hicolor/*/apps/chromium-sandboxed.png",
     "isolated hicolor icon"),
)
DENIED = (
    "bin/chromium-browser",
    "bin/chromedriver",
    "bin/headless_shell",
    "share/man/man1/chromium.1*",
    "share/applications/chromium.desktop",
    "share/metainfo/chromium.appdata.xml",
    "share/icons/hicolor/*/apps/chromium.png",
    "lib/chromium/*",
)

def list_paths(deb: str) -> set[str]:
    p = subprocess.run(["dpkg-deb", "--contents", deb],
                       capture_output=True, text=True, check=True)
    paths: set[str] = set()
    for line in p.stdout.splitlines():
        # dpkg-deb -c columns: perms owner size date time ./path [-> target].
        fields = line.split(maxsplit=5)
        if len(fields) != 6:
            raise ValueError(f"unexpected dpkg-deb listing row: {line!r}")
        raw = fields[5].split(" -> ", 1)[0]
        if raw.endswith("/"):
            continue  # shared parent directories are not owned file collisions
        path = raw.removeprefix("./")
        # NOTE (F6 port, 2026-10-30): the hotfix stripped "./" BEFORE the
        # trailing-slash skip, so the package root row ("./") became "" and
        # raised on every real deb (branch never CI-verified). Order fixed;
        # pinned by f6_side_by_side_test D1 (a well-formed deb must PASS).
        if not path.startswith(PREFIX):
            raise ValueError(f"unexpected package file outside Termux prefix: {path}")
        paths.add(path[len(PREFIX):])
    return paths

def check_paths(paths: set[str]) -> list[str]:
    errors = []
    if not paths:
        return ["package has no installable files"]
    for entry in sorted(paths):
        for pat in DENIED:
            if fnmatch.fnmatchcase(entry, pat):
                errors.append(f"stock Chromium-owned path: {entry}")
                break
    for pattern, what in REQUIRED_GLOBS:
        if not any(fnmatch.fnmatchcase(p, pattern) for p in paths):
            errors.append(f"required isolated package file missing: {what} [{pattern}]")
    for missing in sorted(REQUIRED - paths):
        errors.append(f"required isolated package file missing: {missing}")
    if not any(re.fullmatch(r"share/icons/hicolor/\d+x\d+/apps/chromium-sandboxed\.png", p)
               for p in paths):
        errors.append("isolated Chromium icon missing")
    return errors

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: package_identity_gate.py <deb>", file=sys.stderr)
        return 2
    try:
        deb = sys.argv[1]
        pkg = subprocess.check_output(
            ["dpkg-deb", "-f", deb, "Package"], text=True).strip()
        if pkg != "chromium-sandboxed":
            raise ValueError(f"wrong package identity: {pkg}")
        files = list_paths(deb)
        errs = check_paths(files)
    except (subprocess.CalledProcessError, ValueError, OSError) as ex:
        print(f"PACKAGE-IDENTITY-FAIL: {ex}", file=sys.stderr)
        return 1
    if errs:
        for item in errs:
            print(f"PACKAGE-IDENTITY-FAIL: {item}", file=sys.stderr)
        return 1
    print(f"PACKAGE-IDENTITY-PASS: chromium-sandboxed, {len(files)} private files")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
