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
    # run #17: pipefail must be set INSIDE the bash -c (the subshell option
    # does not propagate) - otherwise tee's exit 0 masks ninja failures and
    # the build step falsely reports success.
    setsid bash -c 'set -o pipefail; ./scripts/run-docker.sh env \
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


r12_fallback_upload() {
  # R12 EXPERIMENTAL ONLY (branch r12-bionic-set-tid-address): node-free
  # artifact delivery. The shared runner pool intermittently loses
  # actions-runner/cached/*/externals/node24 during long builds (disk GC),
  # killing actions/upload-artifact although the build itself succeeded
  # (runs 40569099539 attempts 1+2, 2026-10-27). Deb (~160MB) is split into
  # 90MB volumes (<100MB per-file cap) + logs + MANIFEST + SHA256SUMS.parts
  # and pushed to the ORPHAN BRANCH r12-artifacts via git+GH_TOKEN. This is
  # NOT a publish channel: no releases, no apt, no maintenance-state writes.
  # WARN-only; never flips a green build red.
  local d="$1" url tmp rid out deb attempt br rc
  set +e   # WARN-only helper: never propagate a failure to the job
  br="${R12_FALLBACK_BRANCH:-r12-artifacts}"
  d=$(need_termux_dir "${1:-}") || { echo "R12-FALLBACK WARN: bad termux dir"; set -e; return 0; }
  rid="${GITHUB_RUN_ID:-unknown}"
  deb=$(find "$d/output" -name 'chromium-sandboxed_*_aarch64.deb' 2>/dev/null | head -1 || true)
  [ -n "$deb" ] || { echo "R12-FALLBACK WARN: no deb found"; return 0; }
  [ -n "${GH_TOKEN:-}" ] || { echo "R12-FALLBACK WARN: no GH_TOKEN"; return 0; }
  url="https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY:-ytoaa/termux-chromium-sandbox}.git"
  tmp=$(mktemp -d)
  if git ls-remote --exit-code "$url" "refs/heads/$br" >/dev/null 2>&1; then
    git clone -q --depth 1 -b "$br" "$url" "$tmp" || { rm -rf "$tmp"; echo "R12-FALLBACK WARN: clone failed"; set -e; return 0; }
  else
    git init -q "$tmp" || { rm -rf "$tmp"; echo "R12-FALLBACK WARN: init failed"; set -e; return 0; }
    git -C "$tmp" remote add origin "$url"
    git -C "$tmp" symbolic-ref HEAD "refs/heads/$br" || { rm -rf "$tmp"; echo "R12-FALLBACK WARN: branch ref failed"; set -e; return 0; }
  fi
  local debname; debname=$(basename "$deb")
  out="$tmp/run-$rid"; mkdir -p "$out"
  cp -f "$deb" "$out/" || { rm -rf "$tmp"; echo "R12-FALLBACK WARN: cp deb failed"; return 0; }
  ( cd "$out" && split -b 90m "$debname" "$debname.part." && rm -f "$debname" )
  cp -f "$d/chromium-build.log" "$out/" 2>/dev/null || true
  find "$d" -maxdepth 1 -name 'port-apply*.log' -exec cp -f {} "$out/" \; 2>/dev/null || true
  find "$d/.termux-build" -name 'port-apply*.log' 2>/dev/null | head -1 | while read -r f; do cp -f "$f" "$out/port-apply-builder.log"; done
  cp -f "$PWD/termux-pin.txt" "$out/" 2>/dev/null || true
  cp -f "$PWD/publish-intent.json" "$out/" 2>/dev/null || true
  { echo "run_id=$rid"; echo "run_attempt=${GITHUB_RUN_ATTEMPT:-1}"
    echo "head_sha=${GITHUB_SHA:-unknown}"; echo "event=${GITHUB_EVENT_NAME:-unknown}"
    echo "deb_name=$(basename "$deb")"; echo "deb_bytes=$(stat -c %s "$deb")"
    sha256sum "$deb" | sed 's/^/deb_sha256=/'
  } > "$out/MANIFEST.txt"
  ( cd "$out" && sha256sum ./* > SHA256SUMS.parts ) || true
  git -C "$tmp" config user.email "ci@localhost"
  git -C "$tmp" config user.name "r12-fallback-upload"
  git -C "$tmp" add -A >/dev/null 2>&1
  git -C "$tmp" commit -qm "r12 candidate artifacts run-$rid" || true
  rc=1
  for attempt in 1 2; do
    if git -C "$tmp" push -q origin "HEAD:refs/heads/$br" 2>/dev/null; then
      rc=0; break
    fi
    sleep 20
    rm -rf "$tmp"; tmp=$(mktemp -d)
    git clone -q --depth 1 -b "$br" "$url" "$tmp" 2>/dev/null || { rm -rf "$tmp"; tmp=""; break; }
    out="$tmp/run-$rid"; mkdir -p "$out"
    cp -f "$deb" "$out/" && ( cd "$out" && split -b 90m "$debname" "$debname.part." && rm -f "$debname" )
    cp -f "$d/chromium-build.log" "$out/" 2>/dev/null || true
    git -C "$tmp" config user.email "ci@localhost"; git -C "$tmp" config user.name "r12-fallback-upload"
    git -C "$tmp" add -A >/dev/null 2>&1
    git -C "$tmp" commit -qm "r12 candidate artifacts run-$rid retry" || break
  done
  if [ "$rc" -eq 0 ]; then echo "R12-FALLBACK OK: run-$rid pushed to $br";
  else echo "R12-FALLBACK WARN: push failed (primary artifact upload may still work)"; fi
  [ -n "$tmp" ] && rm -rf "$tmp"
  set -e; return 0
}

cmd=${1:-help}
case "$cmd" in
  selftest) bash "$here/tests/run_tests.sh" ;;
  r12-fallback-upload) r12_fallback_upload "${2:-}" ;;
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
