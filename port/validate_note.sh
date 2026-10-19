#!/usr/bin/env bash
# Helper: after a full REGRESSION pass, update port.toml ledger fields
# (phase=validated when gates green; candidate otherwise) and print the
# exact git commit message to use. Non-destructive: edits only the two
# last_validated_* fields under [port] when --mark-validated is passed.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); cd "$here/.."
port=$(awk -F'"' '/^version = /{print $2; exit}' port/port.toml)
usage() { echo "usage: validate_note.sh <chromium-version> [--mark-validated]"; exit 2; }
[ $# -ge 1 ] || usage
ff=$1; shift; mark=${1:-}
[ -z "${mark:-}" ] || [ "$mark" = "--mark-validated" ] || usage
if [ "$mark" = "--mark-validated" ]; then
  sed -i "s/^last_validated_chromium = \"[^\"]*\"/last_validated_chromium = \"$ff\"/; s/^last_validated_port = \"[^\"]*\"/last_validated_port = \"$port\"/; s/^phase = \"[^\"]*\"/phase = \"validated\"/" port/port.toml
  grep -E '^(version|phase|last_validated)' port/port.toml
fi
cat <<MSG
proposed commit message:

    port.toml: ${port} validated against chromium ${ff} (device gate PASS)

    Evidence: evidence/${port}-${ff}/ (filter census, codecs, user-confirmed
    playback). Gate procedure: port/REGRESSION.md sections 0-7, single sitting.
MSG
