#!/data/data/com.termux/files/usr/bin/bash
# [37] TERMUX_PKG_REVISION injection: unset=unchanged, N=injected, bad=fail-closed
set -u
FIX=$PWD/port/tests/fixtures
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mk(){ mkdir -p "$1/x11-packages/chromium"; cp "$FIX/termux-build.sh" "$1/x11-packages/chromium/build.sh"; }
mk "$W/a"; (cd "$W/a" && env -u TERMUX_SANDBOXED_REVISION python3 $OLDPWD/port/prepare_recipe.py prepare --termux-dir "$W/a" >/dev/null 2>&1)
grep -q 'TERMUX_PKG_REVISION' "$W/a/x11-packages/chromium-sandboxed/build.sh" && echo 'FAIL  [37a] default must not add revision' || echo 'PASS  [37a] default unchanged'
mk "$W/b"; (cd "$W/b" && TERMUX_SANDBOXED_REVISION=2 python3 $OLDPWD/port/prepare_recipe.py prepare --termux-dir "$W/b" >/dev/null 2>&1)
grep -q 'TERMUX_PKG_REVISION="2"' "$W/b/x11-packages/chromium-sandboxed/build.sh" && echo 'PASS  [37b] revision injected' || echo 'FAIL  [37b] revision missing'
grep -q 'TERMUX_PKG_VERSION' "$W/b/x11-packages/chromium-sandboxed/build.sh" && bash -n "$W/b/x11-packages/chromium-sandboxed/build.sh" && echo 'PASS  [37c] upstream version untouched + shell valid' || echo 'FAIL  [37c]'
mk "$W/c"; ! (cd "$W/c" && TERMUX_SANDBOXED_REVISION=999 python3 $OLDPWD/port/prepare_recipe.py prepare --termux-dir "$W/c" >/dev/null 2>&1) && echo 'PASS  [37d] out-of-range revision rejected' || echo 'FAIL  [37d] accepted bad revision'
