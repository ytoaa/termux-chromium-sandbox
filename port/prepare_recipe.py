#!/usr/bin/env python3
"""Prepare a Termux recipe copy that (a) carries a SEPARATE package
identity 'chromium-sandboxed' (hard constraint: never replaces stock
'chromium') and (b) applies chromium_sandbox_port.py at
termux_step_post_get_source, contract-checked.

Modes:
  prepare --termux-dir <termux-packages>   # idempotent in-place prep
  audit  --termux-dir <termux-dir>         # verify state, no writes
Exit non-zero on any contract violation (fail closed).
"""
from __future__ import annotations
import argparse, hashlib, re, shutil, subprocess, sys
from pathlib import Path

PKG_SRC = "x11-packages/chromium"
PKG_DST = "x11-packages/chromium-sandboxed"
HOOK_BEGIN = "# >>> termux-chromium-sandbox port hook (generated; do not edit) >>>"
HOOK_END   = "# <<< termux-chromium-sandbox port hook <<<"

class RecipeError(RuntimeError):
    pass

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def rewrite_identity(text: str) -> str:
    # side-by-side identity: distinct lib dir + launcher name
    t = text
    t = t.replace("lib/chromium", "lib/chromium-sandboxed")
    t = t.replace("bin/chromium-browser", "bin/chromium-sandboxed")
    t = t.replace('desktop="chromium.desktop"', 'desktop="chromium-sandboxed.desktop"')
    # NOTE: termux_step_post_make_install (dummy-lib cleanup) is deliberately
    # left intact: it removes files THIS clone's own build created in its own
    # staging dir. It never touches the stock package.
    return t

HOOK = f"""
{HOOK_BEGIN}
termux_step_post_get_source() {{
\tpython3 "$TERMUX_PKG_BUILDER_DIR/termux-chromium-sandbox-port.py" apply \\
\t\t--src "$TERMUX_PKG_SRCDIR" --scan content,chrome \\
\t\t| tee "$TERMUX_PKG_TMPDIR/port-apply.log"
\t\t# mirror into BUILDER_DIR (repo tree) so the CI host can grep it —
\t\t# TMPDIR lives under the container home which is not mounted back.
\t\tcp "$TERMUX_PKG_TMPDIR/port-apply.log" "$TERMUX_PKG_BUILDER_DIR/port-apply.log" 2>/dev/null || true
\t\t# BUILDER_DIR at hook time is the container-local recipe copy (.termux-build),
\t\t# NOT the mounted repo — also drop it at the mounted repo root for CI host gates.
\t\tcat "$TERMUX_PKG_TMPDIR/port-apply.log" > /home/builder/termux-packages/port-apply-chromium.log 2>/dev/null || true
\tc=$(grep -c "ALREADY_PRESENT\\|APPLIED" "$TERMUX_PKG_TMPDIR/port-apply.log" || true)
\t[ "$c" -ge 7 ] || {{ echo "port hook: fewer than 7 rules applied" >&2; exit 1; }}
}}
{HOOK_END}
"""

TARBALL_REPO = "chromium-linux-tarballs/chromium-tarballs"

def host_tools_version(termux_dir: Path) -> str | None:
    f = termux_dir / "x11-packages" / "chromium-host-tools" / "build.sh"
    if not f.is_file():
        return None
    m = re.search(r'^TERMUX_PKG_VERSION="?([0-9][0-9.]*)"?', f.read_text(), re.M)
    return m.group(1) if m else None

def fetch_tarball_sha256(version: str) -> str:
    """sha256 from the release's .hashes asset (fail closed)."""
    if not re.fullmatch(r"[0-9.]+", version):
        raise RecipeError(f"bad version string for fetch: {version!r}")
    url = (f"https://github.com/{TARBALL_REPO}/releases/download/"
           f"{version}/chromium-{version}-linux.tar.xz.hashes")
    r = subprocess.run(["curl", "-fsSL", "--max-time", "60", url],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RecipeError(f"cannot fetch tarball hashes for {version}: {r.stderr[:200]}")
    m = re.search(r"([0-9a-f]{64})\s+chromium-%s-linux\.tar\.xz" % re.escape(version), r.stdout)
    if not m:
        raise RecipeError(f"sha256 for {version} not found in hashes asset")
    return m.group(1)

def align_versions(text: str, termux_dir: Path) -> tuple[str, list]:
    """Upstream drift guard: the recipe's own post_get_source compares our
    TERMUX_PKG_VERSION against chromium-host-tools/build.sh and termux_error_exit
    on mismatch. Upstream master can carry a transient window where host-tools
    moved ahead (observed 10-16: host .84 vs chromium .79 -> run #8 death).
    We align the CLONE to host-tools, taking TERMUX_PKG_SHA256 from the release
    .hashes asset. Only when that version's tarball exists (fail closed)."""
    notes = []
    ht = host_tools_version(termux_dir)
    if ht is None:
        return text, notes
    cur = re.search(r'^TERMUX_PKG_VERSION=([0-9][0-9.]*)', text, re.M).group(1)
    if cur == ht:
        return text, notes
    sha = fetch_tarball_sha256(ht)
    text = re.sub(r'^TERMUX_PKG_VERSION=[0-9][0-9.]*', f"TERMUX_PKG_VERSION={ht}", text, count=1, flags=re.M)
    text = re.sub(r'^TERMUX_PKG_SHA256=[0-9a-f]+', f"TERMUX_PKG_SHA256={sha}", text, count=1, flags=re.M)
    notes.append(f"aligned clone {cur} -> host-tools {ht} (sha256 from release hashes)")
    return text, notes


SANDBOX_DISABLE_PATCHES = (
    "1001-chromium-disable-sandbox",
    "1004-chromium-headless-disable-sandbox-by-default",
)

def exclude_sandbox_disable_patches(text: str) -> str:
    """THE off-switch removal: termux's cr-patches 1001/1004 inject
    AppendSwitch(kNoSandbox) into chrome/shell PreSandboxStartup under
    #ifdef __TERMUX__ (plus hide the bad-flags warnings). Our port's whole
    purpose is the OPPOSITE; skip exactly those patches in the recipe's
    cr-patches loop. The anti-injection scan in the transformer remains the
    verification gate: if upstream renames/reshuffles these patches, the
    scan catches the surviving injection and the build dies (fail closed)."""
    needle = "-name *.patch | sort)"
    if needle not in text:
        raise RecipeError("cr-patches loop shape changed (no '| sort)'); review exclude_sandbox_disable_patches")
    if any(p in text for p in SANDBOX_DISABLE_PATCHES):
        return text  # already excluded
    filters = " ".join(f"-e '{p}'" for p in SANDBOX_DISABLE_PATCHES)
    text = text.replace(needle, f"-name *.patch | grep -v {filters} | sort)")
    return text

SCCACHE_CCW_MARKER = 'cc_wrapper="sccache"'

def wire_sccache(text: str) -> str:
    """Marathon fuel: chromium's build.sh calls gn gen WITHOUT cc_wrapper, so
    sccache never intercepts a compile (run #10: 350min compiled, 206B cache —
    verified by fetching the real args.gn block). Append the wrapper right
    after the recipe seeds args.gn. Fail-closed: anchor drift raises."""
    if SCCACHE_CCW_MARKER in text:
        return text
    anchor = 'cat $_common_args_file > $TERMUX_PKG_BUILDDIR/out/Release/args.gn'
    if anchor not in text:
        raise RecipeError("args.gn seeding line changed (no 'cat $_common_args_file'); review wire_sccache")
    text = text.replace(anchor, anchor +
        "\n\t# termux-chromium-sandbox-port: sccache interception (multi-cycle marathon cache)\n"
        "\techo '" + SCCACHE_CCW_MARKER + "' >> $TERMUX_PKG_BUILDDIR/out/Release/args.gn", 1)
    return text

def prepare(termux_dir: Path) -> dict:
    src_dir = termux_dir / PKG_SRC
    dst_dir = termux_dir / PKG_DST
    if not (src_dir / "build.sh").is_file():
        raise RecipeError(f"missing {src_dir}/build.sh")
    dst_dir.mkdir(parents=True, exist_ok=True)
    report = {}
    # Termux builder mounts termux-packages only: ship the transformer and
    # the contract ledger inside the recipe (TERMUX_PKG_BUILDER_DIR) so the
    # hook works in-container (firefox-proven pattern).
    here = Path(__file__).resolve().parent
    shutil.copy2(here / "chromium_sandbox_port.py", dst_dir / "termux-chromium-sandbox-port.py")
    shutil.copy2(here / "port.toml", dst_dir / "termux-chromium-sandbox-port.toml")

    # copy all recipe files except build.sh (rewritten)
    for f in sorted(src_dir.iterdir()):
        target = dst_dir / f.name
        if f.name == "build.sh":
            text = f.read_text()
            text = rewrite_identity(text)
            text = exclude_sandbox_disable_patches(text)
            text = wire_sccache(text)
            text, align_notes = align_versions(text, termux_dir)
            for n in align_notes:
                print("NOTE:", n)
            if HOOK_BEGIN not in text:
                # Chain, NEVER clobber: if the recipe defines its own
                # termux_step_post_get_source (chromium does — it applies
                # chromium-host-tools/cr-patches!), rename it and call it
                # first from our wrapper. A blindly appended duplicate would
                # silently shadow it and drop every cr-patch (learned the
                # hard way: v8 BUILD.gn assert fired, run #7).
                if re.search(r"^termux_step_post_get_source\(\)\s*\{", text, re.M):
                    text = re.sub(r"^termux_step_post_get_source\(\)\s*\{",
                                  "termux_step_post_get_source_upstream() {",
                                  text, count=1, flags=re.M)
                    wrapper = HOOK.replace(
                        "termux_step_post_get_source() {",
                        "termux_step_post_get_source() {\n\ttermux_step_post_get_source_upstream")
                else:
                    wrapper = HOOK
                if not text.endswith("\n"):
                    text += "\n"
                text += wrapper
            target.write_text(text)
            report["build.sh"] = sha(target)
        elif f.is_dir():
            shutil.copytree(f, target, dirs_exist_ok=True)
            report[f.name + "/"] = "tree"
        else:
            if target.is_file() and sha(target) == sha(f):
                continue
            target.write_bytes(f.read_bytes())
            report[f.name] = sha(target)
    # marker: package identity
    if "chromium-sandboxed" not in (dst_dir / "build.sh").read_text():
        raise RecipeError("identity rewrite failed: no chromium-sandboxed token")
    return report

def audit(termux_dir: Path) -> None:
    bs = (termux_dir / PKG_DST / "build.sh")
    if not bs.is_file():
        raise RecipeError("recipe clone not prepared (run prepare first)")
    text = bs.read_text()
    for needle, label in (
        ("lib/chromium-sandboxed", "side-by-side lib dir"),
        ("bin/chromium-sandboxed", "distinct launcher"),
        (HOOK_BEGIN, "port hook present"),
        ("$TERMUX_PKG_BUILDER_DIR/termux-chromium-sandbox-port.py", "in-container transformer call"),
        ("--scan content,chrome", "anti-injection scan wired"),
        (SCCACHE_CCW_MARKER, "sccache cc_wrapper wired into args.gn"),
    ):
        if needle not in text:
            raise RecipeError(f"audit fail: missing {label}")
    if "grep -v" not in text or "1001-chromium-disable-sandbox" not in text \
       or "1004-chromium-headless-disable-sandbox-by-default" not in text:
        raise RecipeError("audit fail: sandbox-disable patch exclusion missing")
    if re.search(r"\blib/chromium\b(?!-sandboxed)", text):
        raise RecipeError("audit fail: residual stock lib/chromium path")
    print("[AUDIT OK] chromium-sandboxed recipe contract holds")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["prepare", "audit"])
    ap.add_argument("--termux-dir", required=True)
    a = ap.parse_args()
    d = Path(a.termux_dir)
    if a.command == "prepare":
        rep = prepare(d)
        for k, v in sorted(rep.items()):
            print(f"sha256 {k}: {v}")
    else:
        audit(d)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except RecipeError as e:
        print(f"[RECIPE ERROR] {e}", file=sys.stderr)
        sys.exit(1)
