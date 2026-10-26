#!/usr/bin/env bash
# Serialize manual Pre-release consent WITHOUT relying on Python on the build
# runner. The Termux builder may remove host executables before this always()
# step; Bash itself is available because Actions uses it to run the step.
set -euo pipefail

: "${SOURCE_EVENT:?SOURCE_EVENT is required}"
: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${SOURCE_HEAD_SHA:?SOURCE_HEAD_SHA is required}"

raw="${REQUESTED_PUBLISH:-}"
case "$raw" in
  true|false|'') ;;
  *) echo "PUBLISH-INTENT-REFUSE: invalid publish input" >&2; exit 1 ;;
esac
# All interpolated values must fit tight, JSON-safe grammars. Never embed raw
# workflow input text into JSON, and never infer consent from absent input.
if [[ ! "$SOURCE_EVENT" =~ ^[a-z][a-z0-9_]*$ ]]; then
  echo "PUBLISH-INTENT-REFUSE: invalid source event" >&2; exit 1
fi
if [[ ! "$SOURCE_RUN_ID" =~ ^[0-9]+$ ]]; then
  echo "PUBLISH-INTENT-REFUSE: invalid source run ID" >&2; exit 1
fi
if [[ ! "$SOURCE_HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "PUBLISH-INTENT-REFUSE: invalid source head SHA" >&2; exit 1
fi

consent=false
if [[ "$SOURCE_EVENT" == "workflow_dispatch" && "$raw" == "true" ]]; then
  consent=true
fi

printf '{"schema":1,"event":"%s","run_id":"%s","head_sha":"%s","publish":%s}\n' \
  "$SOURCE_EVENT" "$SOURCE_RUN_ID" "$SOURCE_HEAD_SHA" "$consent" \
  > publish-intent.json
echo "PUBLISH-INTENT-OK: manual consent=$consent (event=$SOURCE_EVENT)"
