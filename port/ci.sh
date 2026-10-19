#!/usr/bin/env bash
# termux-chromium-sandbox CI orchestration (Firefox-port pattern).
# Draft: wired for gate/apply/verify; build steps finalize in Phase 2a review.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
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
  resolve-ref)    # $2 = termux-packages ref -> prints exact sha
    : "${GITHUB_TOKEN:?}"
    ref=${2:-main}
    gh api --method GET "repos/termux/termux-packages/commits/${ref}" --jq .sha
    ;;
  *)
    echo "commands: selftest | apply <src> | verify <src> | resolve-ref [ref]" >&2
    exit 2
    ;;
esac
