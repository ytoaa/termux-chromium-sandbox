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
\tc=$(grep -c "ALREADY_PRESENT\\|APPLIED" "$TERMUX_PKG_TMPDIR/port-apply.log" || true)
\t[ "$c" -ge 2 ] || {{ echo "port hook: fewer than 2 rules applied" >&2; exit 1; }}
}}
{HOOK_END}
"""
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
    ):
        if needle not in text:
            raise RecipeError(f"audit fail: missing {label}")
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
