#!/usr/bin/env bash
# termux-chromium-sandbox CI orchestration (Firefox-port pattern).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${TERMUX_BUILDER_IMAGE_NAME:=termux-chromium-builder:sccache}"
export TERMUX_BUILDER_IMAGE_NAME

need_termux_dir() {
  local d="${1:?usage: <termux-packages-dir>}"
  test -x "$d/build-package.sh"
  test -x "$d/scripts/run-docker.sh"
  echo "$d"
}

run_docker() { local d="$1"; shift; ( cd "$d" && ./scripts/run-docker.sh "$@" ); }

prepare_zram_workspace() {
  local d workspace action key
  d="$(realpath "${1:?}")"
  workspace="${GITHUB_WORKSPACE:-}"
  [ -n "$workspace" ] || { echo "ERROR: GITHUB_WORKSPACE is not set" >&2; return 2; }
  workspace="$(realpath "$workspace")"
  action="$d/.github/actions/zram/action.yml"
  key="$d/scripts/linux-kernel-signing-keys.gpg"
  test -f "$action"; test -f "$key"
  # termux-packages' zram action assumes it sits at github.workspace; we keep
  # it in a subdirectory, so bridge the two inputs it references (contract
  # greps fail closed if upstream changes).
  mkdir -p "$workspace/scripts" "$workspace/.github/actions/zram"
  cp -f "$key" "$workspace/scripts/linux-kernel-signing-keys.gpg"
  cp -f "$action" "$workspace/.github/actions/zram/action.yml"
  grep -Fq '${{ github.workspace }}/scripts/linux-kernel-signing-keys.gpg' "$action"
  grep -Fq "path: scripts/zram.ko.zst" "$action"
  echo "Prepared Termux zram workspace bridge."
}

prepare_builder() {
  local d cache base attempt pulled
  d="$(need_termux_dir "${1:?}")"
  cache="$d/.sccache"
  base="ghcr.io/termux/package-builder:latest"
  mkdir -p "$cache"; sudo chown -R "$(id -u):$(id -g)" "$cache"; chmod -R a+rwX "$cache"
  pulled=0
  for attempt in 1 2 3 4 5; do docker pull "$base" && { pulled=1; break; }; sleep $((attempt*15)); done
  [ "$pulled" -eq 1 ] || { docker build -t "$base" "$d/scripts/"; docker buildx prune -af || true; }
  cat > /tmp/Dockerfile.chromium-sccache <<'DOCKERFILE'
FROM ghcr.io/termux/package-builder:latest
USER root
RUN apt-get update \
    && apt-get install -yq --no-install-recommends sccache python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
USER builder:builder
WORKDIR /home/builder/termux-packages
DOCKERFILE
  docker build -f /tmp/Dockerfile.chromium-sccache -t "$TERMUX_BUILDER_IMAGE_NAME" "$d"
  docker rm -f termux-package-builder 2>/dev/null || true
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="--volume ${cache}:/home/builder/.cache/sccache"
  run_docker "$d" true
  run_docker "$d" bash -lc 'set -euxo pipefail; export SCCACHE_DIR=/home/builder/.cache/sccache SCCACHE_CACHE_SIZE=6G; command -v sccache; python3 --version; echo test > "$SCCACHE_DIR/.write-test"; rm "$SCCACHE_DIR/.write-test"'
  [ -f "$d/scripts/free-space.sh" ] && sed -i '/ruby3\.2-doc/d' "$d/scripts/free-space.sh" || true
  df -h; (cd "$d" && ./scripts/free-space.sh) || true; df -h
}

build_chromium() {
  local d
  d="$(need_termux_dir "${1:?}")"
  # GH steps do NOT share env: prepare-builder's TERMUX_DOCKER_RUN_EXTRA_ARGS
  # died with its own step (run #10 post-mortem: build container had no sccache
  # volume). Re-export HERE, in the same shell that starts run-docker.
  mkdir -p "$d/.sccache"
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="--volume $d/.sccache:/home/builder/.cache/sccache"
  (
    cd "$d"
    set -o pipefail
    echo "======================================"
    echo "Termux Chromium seccomp-only sandbox port build"
    echo "termux-packages HEAD: $(git -C . rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "sccache host dir: $d/.sccache"
    echo "======================================"
    setsid bash -c './scripts/run-docker.sh env \
      SCCACHE_DIR=/home/builder/.cache/sccache \
      SCCACHE_CACHE_SIZE=6G \
      ./build-package.sh -f -I -a aarch64 chromium-sandboxed 2>&1 | tee chromium-build.log' &
    local bpid=$!
    # Early evidence gate: after 30 min the sccache dir MUST have objects.
    # Zero/near-zero means interception is dead (cc_wrapper/volume wiring) —
    # abort at 30min with an actionable error instead of burning 350.
    (
      sleep 1800
      n=$(find "$d/.sccache" -type f 2>/dev/null | wc -l)
      if [ "$n" -lt 50 ]; then
        echo "SCCACHE DEAD: $n cache files after 30min (expect thousands) — cc_wrapper wiring or volume mount broken. Aborting early."
        kill -TERM -"$bpid" 2>/dev/null; sleep 5; kill -KILL -"$bpid" 2>/dev/null
      else
        echo "SCCACHE ALIVE: $n cache files at 30min — interception working."
      fi
    ) &
    local wpid=$!
    wait "$bpid"; local rc=$?
    kill "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
    n=$(find "$d/.sccache" -type f 2>/dev/null | wc -l)
    echo "SCCACHE FILES: $n ($(du -sh "$d/.sccache" 2>/dev/null | cut -f1))"
    exit $rc
  )
}

cmd=${1:-help}
case "$cmd" in
  selftest) bash "$here/tests/run_tests.sh" ;;
  apply)    # $2 = chromium src root
    [ -d "${2:-}" ] || { echo "usage: ci.sh apply <src>" >&2; exit 2; }
    python3 "$here/chromium_sandbox_port.py" apply --src "$2" --scan content,chrome
    ;;
  verify)
    [ -d "${2:-}" ] || { echo "usage: ci.sh verify <src>" >&2; exit 2; }
    python3 "$here/chromium_sandbox_port.py" check --src "$2" --scan content,chrome
    ;;
  recipe-prepare)
    d="$(need_termux_dir "${2:?usage: ci.sh recipe-prepare <termux-packages>}")"
    python3 "$here/prepare_recipe.py" prepare --termux-dir "$d"
    python3 "$here/prepare_recipe.py" audit   --termux-dir "$d"
    ;;
  recipe-audit)
    d="$(need_termux_dir "${2:?usage: ci.sh recipe-audit <termux-packages>}")"
    python3 "$here/prepare_recipe.py" audit --termux-dir "$d"
    ;;
  prepare-zram-workspace) prepare_zram_workspace "${2:?usage: ci.sh prepare-zram-workspace <termux-packages>}" ;;
  prepare-builder)        prepare_builder "${2:?usage: ci.sh prepare-builder <termux-packages>}" ;;
  build)                  build_chromium "${2:?usage: ci.sh build <termux-packages>}" ;;
  resolve-ref)
    : "${GITHUB_TOKEN:=${GH_TOKEN:?need GITHUB_TOKEN or GH_TOKEN}}"
    gh api --method GET "repos/termux/termux-packages/commits/${2:-master}" --jq .sha
    ;;
  *)
    echo "commands: selftest | apply <src> | verify <src> | recipe-prepare <tp> | recipe-audit <tp> | prepare-zram-workspace <tp> | prepare-builder <tp> | build <tp> | resolve-ref [ref]" >&2
    exit 2
    ;;
esac
