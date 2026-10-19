#!/usr/bin/env bash
# termux-chromium-sandbox CI orchestration (Firefox-port pattern).
# Draft: wired for gate/apply/verify; build steps finalize in Phase 2a review.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${TERMUX_BUILDER_IMAGE_NAME:=termux-chromium-builder:sccache}"
export TERMUX_BUILDER_IMAGE_NAME
cmd=${1:-help}
case "$cmd" in
  selftest)
    bash "$here/tests/run_tests.sh"
    ;;
  apply)          # $2 = chromium src root (dir containing sandbox/, content/)
    [ -d "${2:-}" ] || { echo "usage: ci.sh apply <src>" >&2; exit 2; }
    python3 "$here/chromium_sandbox_port.py" apply --src "$2" --scan content,chrome
    ;;
  verify)
    [ -d "${2:-}" ] || { echo "usage: ci.sh verify <src>" >&2; exit 2; }
    python3 "$here/chromium_sandbox_port.py" check --src "$2" --scan content,chrome
    ;;
  recipe-prepare)   # $2 = termux-packages dir
    [ -x "${2:-}/build-package.sh" ] || { echo "not a termux-packages dir: $2" >&2; exit 2; }
    python3 "$here/prepare_recipe.py" prepare --termux-dir "$2"
    python3 "$here/prepare_recipe.py" audit   --termux-dir "$2"
    ;;
  recipe-audit)
    python3 "$here/prepare_recipe.py" audit --termux-dir "${2:?}"
    ;;
  prepare-builder) [ -n "${2:-}" ] || { echo "usage: ci.sh prepare-builder <termux-packages>" >&2; exit 2; }; prepare_builder "$2" ;;
  build) [ -n "${2:-}" ] || { echo "usage: ci.sh build <termux-packages>" >&2; exit 2; }; build_chromium "$2" ;;
  resolve-ref)    # $2 = termux-packages ref -> prints exact sha
    : "${GITHUB_TOKEN:=${GH_TOKEN:?need GITHUB_TOKEN or GH_TOKEN}}"
    ref=${2:-main}
    gh api --method GET "repos/termux/termux-packages/commits/${ref}" --jq .sha
    ;;
  *)
    echo "commands: selftest | apply <src> | verify <src> | recipe-prepare <tp> | recipe-audit <tp> | resolve-ref [ref]" >&2
    exit 2
    ;;
esac
