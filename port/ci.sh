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
  # --- free-space replacement (runner-safe subset) ---------------------
  # Upstream scripts/free-space.sh (pin de1dd3d1) contains
  #   sudo rm -rf /opt/ghc /opt/az /opt/hostedtoolcache /opt/actionarchivecache /opt/runner-cache
  # Since 2026-10-27 this runner fleet symlinks
  #   ~/actions-runner/cached/<runnerVer>/externals -> /opt/runner-cache/externals
  # so that rm SEVERS THE ACTION RUNTIME (node24) and every later node-based
  # step dies with "externals/node24/bin/node: No such file or directory"
  # (Save sccache / Upload artifacts / Post checkout; reproduced 6/6 long
  # builds since run 40569099539; attribution proof: diag run 40656237966 —
  # DIRS GONE /opt/runner-cache immediately after that single rm; disk was
  # NOT pressured, ruling out the GC hypothesis). Run only the
  # runner-independent cleanup subset here; keep df evidence inline.
  ( cd "$d" && sudo rm -rf /opt/ghc /opt/az /opt/pipx \
      /usr/share/dotnet /usr/share/swift /usr/share/miniconda /usr/share/az_* \
      /usr/share/gradle-* /usr/share/java /home/runner/.rustup /etc/skel \
      /home/packer /home/linuxbrew /usr/src \
      /var/lib/containerd/io.containerd.content.v1.content ) || true
  df -h
  # Early presence gate for the runner action runtime (diagnostic only —
  # never fabricates success; if the fleet layout regresses again this step
  # fails FAST with the cause in its log instead of 90 minutes later).
  n24=""
  for cand in "$HOME"/actions-runner/cached/*/externals/node24/bin/node; do
    [ -x "$cand" ] && "$cand" -v >/dev/null 2>&1 && n24="$cand" && break
  done
  if [ -z "$n24" ]; then
    echo "NODE24 PRESENT-CHECK FAILED: runner action runtime missing/dangling (externals symlink target gone?)" >&2
    ls -la "$HOME"/actions-runner/cached/*/externals 2>&1 >&2 || true
    exit 1
  fi
  echo "NODE24 PRESENT: $n24 ($("$n24" -v))"
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
    # run #17: pipefail must be set INSIDE the bash -c (the subshell option
    # does not propagate) - otherwise tee's exit 0 masks ninja failures and
    # the build step falsely reports success.
    # R12 diagnostic: capture cache hit/miss statistics in the SAME
    # container process/session as the compiler. An external Docker step
    # could launch a fresh sccache server and incorrectly report zero hits.
    # The script lives only in the temporary termux-packages workspace.
    cat > .r12-sccache-profile.sh <<'SCCACHE_PROFILE_SCRIPT'
#!/usr/bin/env bash
set -u
echo "SCCACHE_PROFILE_BEGIN"
echo "SCCACHE_PROFILE_CACHE_DIR=$SCCACHE_DIR"
if command -v sccache >/dev/null 2>&1; then
  sccache --version || true
  sccache --zero-stats >/dev/null 2>&1 || echo "SCCACHE_PROFILE_WARN zero-stats failed"
else
  echo "SCCACHE_PROFILE_WARN sccache executable missing"
fi
build_started=$(date +%s)
./build-package.sh -f -I -a aarch64 chromium-sandboxed
build_rc=$?
build_finished=$(date +%s)
echo "SCCACHE_PROFILE_BUILD_SECONDS=$((build_finished - build_started))"
echo "SCCACHE_PROFILE_BUILD_RC=$build_rc"
if command -v sccache >/dev/null 2>&1; then
  echo "SCCACHE_STATS_JSON_BEGIN"
  sccache --show-stats --stats-format=json || echo "SCCACHE_STATS_UNAVAILABLE"
  echo "SCCACHE_STATS_JSON_END"
fi
echo "SCCACHE_PROFILE_END"
exit "$build_rc"
SCCACHE_PROFILE_SCRIPT
    chmod 755 .r12-sccache-profile.sh
    setsid bash -c 'set -o pipefail; ./scripts/run-docker.sh env \
      SCCACHE_DIR=/home/builder/.cache/sccache \
      SCCACHE_CACHE_SIZE=6G \
      bash ./.r12-sccache-profile.sh 2>&1 | tee chromium-build.log' &
    local bpid=$!
    # Early evidence gate: after 30 min the sccache dir MUST have objects.
    # Zero/near-zero means interception is dead (cc_wrapper/volume wiring) —
    # abort at 30min with an actionable error instead of burning 350.
    (
      sleep 1800
      n=$(find "$d/.sccache" -type f 2>/dev/null | wc -l)
      if [ "$n" -lt 50 ]; then
        echo "SCCACHE DEAD: $n cache files after 30min (expect thousands) — cc_wrapper wiring or volume mount broken. Aborting early."
        kill -TERM -"$bpid" 2>/dev/null || true; sleep 5; kill -KILL -"$bpid" 2>/dev/null || true
      else
        echo "SCCACHE ALIVE: $n cache files at 30min — interception working."
      fi
    ) &
    local wpid=$!
    wait "$bpid"; local rc=$?
    # run #11 post-mortem: the watchdog had exited at T+30min; under the global
    # set -e a kill/wait on that reaped pid returned 1 and aborted the step
    # 0.3s after "build done" — a false failure on a perfectly good package.
    kill "$wpid" 2>/dev/null || true
    wait "$wpid" 2>/dev/null || true
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
