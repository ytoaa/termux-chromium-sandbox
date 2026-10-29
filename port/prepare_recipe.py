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
import argparse, hashlib, os, re, shutil, subprocess, sys
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
\t[ "$c" -ge 8 ] || {{ echo "port hook: fewer than 8 rules applied" >&2; exit 1; }}
}}
{HOOK_END}
"""

TARBALL_REPO = "chromium-linux-tarballs/chromium-tarballs"

def host_tools_version(termux_dir: Path) -> str | None:
    f = termux_dir / "x11-packages" / "chromium-host-tools" / "build.sh"
    if not f.is_file():
        return None
    parsed = parse_version_line(f.read_text())
    return parsed[0] if parsed else None

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

# Phase B remediation B: ONE strict version-line parser for recipe and
# host-tools alike. Accepts exactly bare / "..." / '...' dotted versions,
# optional leading indentation, optional trailing spaces + # comment.
# Anything else (junk suffixes, mismatched quotes, spaced assignment) does
# NOT partially match — callers must treat None as invalid.
VER_STRICT = re.compile(
    r"^[ \t]*TERMUX_PKG_VERSION="
    r"(?:\"([0-9]+(?:\.[0-9]+)*)\"|'([0-9]+(?:\.[0-9]+)*)'"
    r"|([0-9]+(?:\.[0-9]+)*))"
    r"([ \t]+#.*|[ \t]*)$", re.M)


def parse_version_line(text: str):
    """-> (version, quote_char, trailing_text) or None (never partial)."""
    m = VER_STRICT.search(text)
    if not m:
        return None
    ver = m.group(1) or m.group(2) or m.group(3)
    quote = '"' if m.group(1) is not None else ("'" if m.group(2) is not None else '')
    return ver, quote, m.group(4)


RM_TARBALL_RE = re.compile(
    r'^[ \t]*rm -f "\$TERMUX_PKG_CACHEDIR/chromium-\$TERMUX_PKG_VERSION-linux\.tar\.xz"[ \t]*$',
    re.M)

def preserve_source_cache(text: str) -> tuple[str, list]:
    """L4 adapter (clone-only; stock package never touched).

    Upstream deletes the 1.87 GB extracted chromium tarball at the end of
    post_patch ("keep more space"). That is the single largest repeated
    download of every full rebuild (github release, sha256-verified at
    fetch) and L4 can only persist files present in TERMUX_PKG_CACHEDIR
    at collect time. The container has ~94 GB free after our free-space
    step, so the space rationale does not apply on this fleet; keeping
    the file lets the verified tarball be saved to (and restored from)
    the L4 cache, eliminating the re-download and its failure window
    across rebuilds. Absence of the line (upstream drift) is harmless:
    the file simply stays, and we note it.
    """
    notes: list[str] = []
    new, n = RM_TARBALL_RE.subn(
        "\t: 'tarball kept for the L4 source cache - was an upstream "
        "rm -f; disk is managed by the ci.sh free-space step'", text, count=1)
    if n == 0:
        notes.append("preserve_source_cache: upstream tarball-removal line "
                     "not found (already removed upstream?) - no change")
    return new, notes


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
    # Phase B remediation A: upstream drifted to QUOTED version lines
    # (TERMUX_PKG_VERSION="156.0.8078.47" at 2af83c387...). Support quoted
    # and bare forms, preserve the file's own quote style on rewrite, and
    # raise an explicit RecipeError instead of crashing on None.group(1).
    parsed = parse_version_line(text)
    if not parsed:
        raise RecipeError("TERMUX_PKG_VERSION line unrecognised in recipe "
                          "(expected bare or quoted dotted version)")
    cur, quote, _trailing = parsed
    if cur == ht:
        return text, notes
    sha = fetch_tarball_sha256(ht)
    text = VER_STRICT.sub(lambda mm: 'TERMUX_PKG_VERSION={0}{1}{0}{2}'.format(
        quote, ht, mm.group(4)), text, count=1)
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

SHIELD_BEGIN = '# >>> termux-chromium-sandbox-port: bionic shield hook >>>'
SHIELD_END = '# <<< termux-chromium-sandbox-port: bionic shield hook <<<'
SHIELD_HOOK = r"""
# >>> termux-chromium-sandbox-port: bionic shield hook >>>
termux_step_post_make_install() {
	termux_step_post_make_install_upstream

	# Ship the pthread_getattr_np shield and route the launcher through it.
	# bionic reads /proc/self/maps for the MAIN thread and LOG(FATAL)s once the
	# seccomp BPF denies openat, so any main-thread call after "Activated
	# seccomp-bpf" kills the child. Rules R7/R8 fix the in-tree callers; this
	# shim covers every other caller (crash handlers, unwinders, future code).
	local _p="$TERMUX_PREFIX/lib/chromium-sandboxed"
	local _so="$_p/libtermux-gnp-fix.so"
	${CC:-clang} -O2 -shared -fPIC -o "$_so" "$TERMUX_PKG_BUILDER_DIR/gnp_shim.c"
	if [ -n "${STRIP:-}" ]; then "$STRIP" --strip-unneeded "$_so" 2>/dev/null || true; fi

	# IMPORTANT (run #25 lesson): bin/chromium-sandboxed is a SYMLINK to
	# chromium-launcher.sh, and 'cat > symlink' follows it - writing the
	# wrapper there made the launcher exec itself. Keep the launcher intact and
	# put the wrapper in its own file, then repoint the bin symlink at it.
	local _wrap="$_p/chromium-shield-wrapper.sh"
	cat > "$_wrap" <<'SHIMWRAP'
#!/data/data/com.termux/files/usr/bin/bash
# termux-chromium-sandbox-port: bionic pthread_getattr_np shield (port/DESIGN.md)
_p="${PREFIX:-/data/data/com.termux/files/usr}/lib/chromium-sandboxed"
export LD_PRELOAD="$_p/libtermux-gnp-fix.so${LD_PRELOAD:+:$LD_PRELOAD}"
# Termux seccomp-only audio-pulse-server: (R9b candidate — port/DESIGN.md)
# Point libpulse at the real PulseAudio socket so a sandboxed AudioService
# utility skips runtime-dir discovery/verification (which trips base-policy
# EPERM on non-brokerable calls). A user-set PULSE_SERVER — INCLUDING an
# empty string — is never overwritten; no socket means no-op. Zero sandbox
# policy change: allowlists, broker grants and syscall filters untouched
# (see harness [34]: widening tokens are banned in this block).
if [ -z "${PULSE_SERVER+x}" ]; then
  _pas=""
  case "${XDG_RUNTIME_DIR:-}" in
    /*) [ -S "$XDG_RUNTIME_DIR/pulse/native" ] && _pas="$XDG_RUNTIME_DIR/pulse/native" ;;
  esac
  if [ -z "$_pas" ]; then
    _pat="${PREFIX:-/data/data/com.termux/files/usr}/tmp/pulse/native"
    [ -S "$_pat" ] && _pas="$_pat"
  fi
  [ -n "$_pas" ] && export PULSE_SERVER="unix:$_pas"
fi
exec "$_p/chromium-launcher.sh" "$@"
SHIMWRAP
	chmod +x "$_wrap"
	rm -f "$TERMUX_PREFIX/bin/chromium-sandboxed"
	ln -sfr "$_wrap" "$TERMUX_PREFIX/bin/chromium-sandboxed"

	# Fail closed if the real launcher was clobbered (recursion guard).
	if grep -q 'libtermux-gnp-fix.so' "$_p/chromium-launcher.sh" 2>/dev/null; then
		echo "port shield: launcher was clobbered (would exec itself)" >&2
		exit 1
	fi
}
# <<< termux-chromium-sandbox-port: bionic shield hook <<<
"""

def chain_shield_hook(text: str) -> str:
    """Ship the bionic pthread_getattr_np shield.

    Chain, NEVER clobber (run #7 lesson): the chromium recipe already defines
    termux_step_post_make_install (it removes dummy .a/.so files), so rename it
    and call it first from our wrapper.
    """
    if SHIELD_BEGIN in text:
        return text
    if re.search(r"^termux_step_post_make_install\(\)\s*\{", text, re.M):
        text = re.sub(r"^termux_step_post_make_install\(\)\s*\{",
                      "termux_step_post_make_install_upstream() {",
                      text, count=1, flags=re.M)
        hook = SHIELD_HOOK
    else:
        hook = SHIELD_HOOK.replace("\n\ttermux_step_post_make_install_upstream\n", "\n")
    if not text.endswith("\n"):
        text += "\n"
    return text + hook


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
    shutil.copy2(here / "gnp_shim.c", dst_dir / "gnp_shim.c")

    # copy all recipe files except build.sh (rewritten)
    for f in sorted(src_dir.iterdir()):
        target = dst_dir / f.name
        if f.name == "build.sh":
            text = f.read_text()
            text = rewrite_identity(text)
            text = exclude_sandbox_disable_patches(text)
            text = wire_sccache(text)
            text, keep_notes = preserve_source_cache(text)
            for n in keep_notes:
                print("NOTE:", n)
            text = chain_shield_hook(text)
            text, align_notes = align_versions(text, termux_dir)
            for n in align_notes:
                print("NOTE:", n)
            # Maintenance revision override (Round 15): only set when the
            # caller explicitly passes TERMUX_SANDBOXED_REVISION (empty =
            # byte-identical to pre-Round-15 behavior, so #31 reproducibility
            # holds). Chromium upstream version is NEVER touched here —
            # upstream version and our package revision stay independent.
            rev = (os.environ.get("TERMUX_SANDBOXED_REVISION") or "").strip()
            if rev:
                if not re.fullmatch(r"[0-9]{1,2}", rev):
                    raise RecipeError(f"invalid TERMUX_SANDBOXED_REVISION: {rev!r}")
                if re.search(r"^TERMUX_PKG_REVISION=", text, re.M):
                    text = re.sub(r'^TERMUX_PKG_REVISION=.*$',
                                  f'TERMUX_PKG_REVISION="{rev}"', text,
                                  count=1, flags=re.M)
                else:
                    text = re.sub(r'^(TERMUX_PKG_VERSION=.*)$',
                                  r'\1\nTERMUX_PKG_REVISION="%s"' % rev, text,
                                  count=1, flags=re.M)
                print("NOTE: TERMUX_PKG_REVISION set to", rev)
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
        (SHIELD_BEGIN, "bionic shield hook present"),
        ("libtermux-gnp-fix.so", "pthread_getattr_np shield install"),
        ("termux_step_post_make_install_upstream", "shield chain calls upstream hook"),
    ):
        if needle not in text:
            raise RecipeError(f"audit fail: missing {label}")
    if "grep -v" not in text or "1001-chromium-disable-sandbox" not in text \
       or "1004-chromium-headless-disable-sandbox-by-default" not in text:
        raise RecipeError("audit fail: sandbox-disable patch exclusion missing")
    if re.search(r"\blib/chromium\b(?!-sandboxed)", text):
        raise RecipeError("audit fail: residual stock lib/chromium path")
    if not (termux_dir / PKG_DST / "gnp_shim.c").is_file():
        raise RecipeError("audit fail: gnp_shim.c not shipped in the recipe dir")
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
