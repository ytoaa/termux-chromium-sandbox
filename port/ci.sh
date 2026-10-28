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

# --- cache-layer helpers ---------------------------------------------------
# Bind-mount BOTH caches into the builder container:
#   .sccache            -> /home/builder/.cache/sccache           (Layer 2)
#   .termux-depcache/aarch64 -> /home/builder/.termux-build/_cache-aarch64
#                          (Layer 1: termux_download content-addressed
#                           .deb + Packages cache; integrity is enforced by
#                           the OFFICIAL pipeline — Release(.gpg) is always
#                           re-downloaded and GPG-verified per
#                           termux_get_repo_files.sh, Packages/.deb hashes
#                           come from that verified metadata and are
#                           sha256-checked by termux_download on every use,
#                           so a corrupted/version-mismatched cache entry is
#                           transparently re-downloaded.)
docker_volume_args() {
  local d="$1"
  mkdir -p "$d/.sccache" "$d/.termux-depcache/aarch64"
  echo "--volume $d/.sccache:/home/builder/.cache/sccache --volume $d/.termux-depcache/aarch64:/home/builder/.termux-build/_cache-aarch64"
}

dep_cache_prune() {
  # Keep .termux-depcache bounded (age then size). Never touches anything
  # outside <termux-packages>/.termux-depcache.
  local d root cap_bytes total f
  d="$(need_termux_dir "${1:?}")"
  root="$(cd "$d" && mkdir -p .termux-depcache && realpath .termux-depcache)"
  case "$root" in
    */.termux-depcache) ;;
    *) echo "PRUNE REFUSAL: unexpected path: $root" >&2; return 2 ;;
  esac
  cap_bytes=$(( ${TERMUX_DEPCACHE_CAP_MB:-2048} * 1024 * 1024 ))
  find "$root" -type f -mtime +30 -delete 2>/dev/null || true
  total=$(du -sb "$root" 2>/dev/null | cut -f1); total=${total:-0}
  if [ "$total" -gt "$cap_bytes" ]; then
    echo "DEPCACHE over cap ($total B > $cap_bytes B); pruning oldest first"
    find "$root" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | cut -d' ' -f2- | \
    while IFS= read -r f; do
      total=$(du -sb "$root" | cut -f1)
      [ "$total" -le "$cap_bytes" ] && break
      rm -f -- "$f"
    done
  fi
  echo "DEPCACHE size: $(du -sh "$root" 2>/dev/null | cut -f1)"
}

# Layer 6: bounded pre-build connectivity probe against OFFICIAL termux
# mirrors only. Never trusts an unlisted mirror; switching only happens
# between whitelisted official hosts and the effective repo.json is hashed
# into the deb key, so any switch is visible in build inputs. Fails FAST
# (<5 min) instead of letting build-package curl(28)-loop for hours.
OFFICIAL_APT_HOSTS="packages.termux.dev packages-cf.termux.dev"
_probe_repo() {
  local url="$1" code speed
  code=$(timeout 25 curl -fsS --connect-timeout 8 --retry 1 --retry-delay 2 \
    --speed-limit 2000 --speed-time 20 -o /dev/null -w '%{http_code} %{speed_download}' "$1/dists/stable/Release" 2>/dev/null) \
    || code=$(timeout 25 curl -fsS --connect-timeout 8 --retry 1 --retry-delay 2 \
    --speed-limit 2000 --speed-time 20 -o /dev/null -w '%{http_code} %{speed_download}' "$1/dists/x11/Release" 2>/dev/null) \
    || code="000 0"
  echo "$code"
}
download_preflight() {
  local d repo host urls entry url base healthy rc=0
  d="$(need_termux_dir "${1:?}")"
  repo="$d/repo.json"
  test -f "$repo" || { echo "PREFLIGHT FAIL: repo.json missing" >&2; return 1; }
  echo "PREFLIGHT begin $(date -u +%FT%TZ) repo.json=$(sha256sum "$repo" | cut -c1-16)"
  jq -r 'del(.pkg_format) | .[] | .url' "$repo" | while IFS= read -r url; do
    host="${url#https://}"; host="${host%%/*}"
    case " $OFFICIAL_APT_HOSTS " in *" $host "*) ;; *)
      echo "PREFLIGHT FAIL: non-official repo host in repo.json: $host" >&2; exit 1 ;;
    esac
    read -r code speed <<<"$(_probe_repo "$url")"
    echo "PREFLIGHT probe url=$url http=$code speed=${speed:-0}"
    if [ "$code" != "200" ]; then
      # try the other official host for the same repo path
      for alt in $OFFICIAL_APT_HOSTS; do
        [ "$alt" = "$host" ] && continue
        local_url="https://$alt/${url#https://$host/}"
        read -r code speed <<<"$(_probe_repo "$local_url")"
        echo "PREFLIGHT probe alt url=$local_url http=$code speed=${speed:-0}"
        if [ "$code" = "200" ]; then
          cp -f "$repo" "$d/repo.json.orig-backup"
          jq --arg old "$url" --arg new "$local_url" \
             'walk(if type=="object" and .url==$old then .url=$new else . end)' \
             "$d/repo.json.orig-backup" > "$repo.tmp" && mv "$repo.tmp" "$repo"
          echo "PREFLIGHT MIRROR-SWITCH $url -> $local_url (verified official hosts only; integrity chain unchanged)"
          break
        fi
      done
      if ! grep -q "MIRROR-SWITCH $url" /dev/null 2>/dev/null && [ "$code" != "200" ]; then
        :
      fi
    fi
  done || rc=1
  # Final gate: every repo entry must currently answer 200 on its selected host.
  jq -r 'del(.pkg_format) | .[] | .url' "$repo" | while IFS= read -r url; do
    read -r code speed <<<"$(_probe_repo "$url")"
    if [ "$code" != "200" ]; then
      echo "PREFLIGHT FAIL: repo unreachable/slow: $url (http=$code). Refusing to start a multi-hour build; no unverified mirror or stale-dep fallback is permitted." >&2
      exit 1
    fi
  done || rc=1
  echo "PREFLIGHT done rc=$rc $(date -u +%FT%TZ) effective_repo_sha=$(sha256sum "$repo" | cut -c1-16)"
  return $rc
}

# Layer 3: composite, immutable key over ALL build-affecting inputs.
deb_key() {
  local d termux_sha port_hash recipe_sha upstream ver arch rev repo_sha k
  d="$(need_termux_dir "${1:?}")"
  termux_sha=$(git -C "$d" rev-parse HEAD 2>/dev/null || true)
  [ -n "$termux_sha" ] || { echo "DEB KEY FAIL: termux dir is not a git checkout" >&2; return 1; }
  port_hash=$(cd "$here/.." && python3 port/maintenance.py port-input-hash --root . | tail -1)
  [ -n "$port_hash" ] || { echo "DEB KEY FAIL: port-input-hash empty" >&2; return 1; }
  recipe_sha=$( { find "$d/packages/chromium-sandboxed" -type f \( -name '*.sh' -o -name '*.sub' -o -name 'RECIPE*' \) -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null || true; } | sha256sum | cut -d' ' -f1)
  upstream=$( { grep -hoE 'TERMUX_PKG_VERSION=.[0-9][0-9.]*' "$d"/packages/*chromium*/build.sh 2>/dev/null || true; } | head -1 | sed -e 's/.*=//' -e 's/[^0-9.]//g')
  [ -n "$upstream" ] || upstream=$( { grep -m1 -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$d/../../port/port.toml" 2>/dev/null || true; } | head -1)
  [ -n "$upstream" ] || upstream=unknown
  repo_sha=$( { sha256sum "$d/repo.json" 2>/dev/null || true; } | cut -d' ' -f1)
  [ -n "$repo_sha" ] || repo_sha=absent
  rev="${TERMUX_SANDBOXED_REVISION:-?}"
  arch="aarch64"
  ver="chromium-sandboxed"
  k=$(printf '%s\n' "pkg=$ver" "rev=$rev" "arch=$arch" "upstream=${upstream:-unknown}" "termux=$termux_sha" "port=$port_hash" "recipe=$recipe_sha" "repojson=$repo_sha" "image=$TERMUX_BUILDER_IMAGE_NAME" | sha256sum | cut -d' ' -f1)
  echo "DEB_KEY=$k"
}

deb_reuse_verify() {
  # FAIL-CLOSED reuse gate: only an artifact whose manifest hashes match the
  # CACHED deb exactly (and whose DEB_KEY equals the current key) may skip
  # compilation. Any mismatch -> REUSED=0, normal build proceeds. The
  # package security gates ALWAYS run afterwards regardless of reuse.
  local d cache deb manifest want have wantc havec version
  d="$(need_termux_dir "${1:?}")"
  cache="$d/.deb-cache"
  mkdir -p "$cache"
  fail_reuse() { printf '{"reused":false,"reason":"%s","deb_key":"%s","at":"%s"}\n' "$1" "${DEB_KEY:-?}" "$(date -u +%FT%TZ)" > "$cache/reuse-decision.json"; echo "REUSED=0 REASON=$1"; return 1; }
  deb=$(ls "$cache"/*.deb 2>/dev/null | head -1 || true)
  manifest="$cache/deb-manifest.json"
  if [ -z "$deb" ] || [ ! -f "$manifest" ]; then
    fail_reuse "no-cached-deb"
  fi
  want=$(jq -r '.deb_sha256' "$manifest"); wantc=$(jq -r '.chrome_sha256' "$manifest")
  have=$(sha256sum "$deb" | cut -d' ' -f1)
  if [ "$want" != "$have" ]; then rm -f "$cache"/*.deb "$manifest"; fail_reuse "deb-sha-mismatch"; fi
  if [ "$(jq -r '.deb_key' "$manifest")" != "${DEB_KEY:-}" ]; then fail_reuse "key-mismatch"; fi
  version=$(dpkg-deb -W --showformat='${Package} ${Version} ${Architecture}\n' "$deb" 2>/dev/null || true)
  case "$version" in chromium-sandboxed\ *) ;; *) fail_reuse "dpkg-meta";; esac
  if [ "$(jq -r '.version_arch' "$manifest")" != "$version" ]; then fail_reuse "version-arch-mismatch"; fi
  wantc_have=$(dpkg-deb --fsys-tarfile "$deb" 2>/dev/null | tar -xO ./data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome 2>/dev/null | sha256sum | cut -d' ' -f1)
  if [ "$wantc_have" != "$wantc" ]; then fail_reuse "chrome-sha-mismatch"; fi
  dpkg-deb --fsys-tarfile "$deb" 2>/dev/null | tar -xO ./data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome 2>/dev/null \
    | grep -ac "Termux seccomp-only r12-bionic-tid" >/dev/null 2>&1 || { fail_reuse "r12-marker-missing"; }
  mkdir -p "$d/output"
  cp -f "$deb" "$d/output/$(basename "$deb")"
  printf '{"reused":true,"deb":"%s","deb_key":"%s","at":"%s"}\n' "$(basename "$deb")" "${DEB_KEY:-?}" "$(date -u +%FT%TZ)" > "$cache/reuse-decision.json"
  echo "REUSED=1 DEB=$(basename "$deb") KEY=${DEB_KEY:-?}"
  return 0
}

deb_reuse_save() {
  local d deb manifest
  d="$(need_termux_dir "${1:?}")"
  deb=$(ls "$d"/output/chromium-sandboxed_*_aarch64.deb 2>/dev/null | head -1 || true)
  [ -n "$deb" ] || { echo "DEB SAVE SKIP: no built deb"; return 0; }
  mkdir -p "$d/.deb-cache"
  manifest="$d/.deb-cache/deb-manifest.json"
  local chromesha
  chromesha=$(dpkg-deb --fsys-tarfile "$deb" 2>/dev/null | tar -xO ./data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome 2>/dev/null | sha256sum | cut -d' ' -f1)
  jq -n \
    --arg deb_sha256 "$(sha256sum "$deb" | cut -d' ' -f1)" \
    --arg chrome_sha256 "$chromesha" \
    --arg version_arch "$(dpkg-deb -W --showformat='${Package} ${Version} ${Architecture}\n' "$deb")" \
    --arg deb_key "${DEB_KEY:?deb-reuse-save requires DEB_KEY env}" \
    --arg termux_sha "$(git -C "$d" rev-parse HEAD)" \
    --arg run_id "${GITHUB_RUN_ID:-local}" \
    --arg generated_at "$(date -u +%FT%TZ)" \
    '{deb_sha256:$deb_sha256,chrome_sha256:$chrome_sha256,version_arch:$version_arch,deb_key:$deb_key,termux_sha:$termux_sha,run_id:$run_id,generated_at:$generated_at}' \
    > "$manifest"
  cp -f "$deb" "$d/.deb-cache/$(basename "$deb")"
  echo "DEB SAVE ok $(basename "$deb") key=$DEB_KEY"
}

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
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="$(docker_volume_args "$d")"
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
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="$(docker_volume_args "$d")"
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
( while :; do
    sleep 600
    el=$(( $(date +%s) - build_started ))
    stats=$(sccache --show-stats --stats-format=json 2>/dev/null | tr -d '\n ' | head -c 1200)
    files=$(find "$SCCACHE_DIR" -type f 2>/dev/null | wc -l)
    echo "SCCACHE_TICK_JSON elapsed=${el}s sccache_files=${files} stats=${stats:-unavailable}"
  done ) & tickpid=$!
timeout 14400 ./build-package.sh -f -I -a aarch64 chromium-sandboxed
build_rc=$?
kill "$tickpid" 2>/dev/null || true
wait "$tickpid" 2>/dev/null || true
if [ "$build_rc" = 124 ]; then
  echo "BUILD_TIMEOUT_GUARD: build-package.sh exceeded 240 minutes; failing naturally (not silently) so diagnostics/artifact steps still run"
fi
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
      # Distinguish REAL compile activity from restored stale files:
      # ninja start marker or nonzero sccache counters in a tick line.
      ninja_started=$(grep -acE '\[1/[0-9]{4,}\]' "$d/chromium-build.log" 2>/dev/null || true)
      tick=$(grep -a 'SCCACHE_TICK_JSON' "$d/chromium-build.log" 2>/dev/null | tail -1 || true)
      active=0
      [ "${ninja_started:-0}" -gt 0 ] && active=1
      case "$tick" in *'"compile_requests":0'*) ;; '') ;; *) [ -n "$tick" ] && ! printf '%s' "$tick" | grep -q '"compile_requests":0[^0-9]' && active=1 ;; esac
      if [ "$n" -lt 50 ] && [ "$active" = 0 ]; then
        echo "SCCACHE DEAD: $n cache files, no ninja start, no compile activity in ticks after 30min — cc_wrapper wiring/volume or download phase broken. Aborting early."
        kill -TERM -"$bpid" 2>/dev/null || true; sleep 5; kill -KILL -"$bpid" 2>/dev/null || true
      else
        echo "SCCACHE ALIVE at 30min: files=$n ninja_started=${ninja_started:-0} last_tick=${tick:-none}"
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
  dep-cache-prune)     dep_cache_prune "${2:?usage: ci.sh dep-cache-prune <termux-packages>}" ;;
  download-preflight)  download_preflight "${2:?usage: ci.sh download-preflight <termux-packages>}" ;;
  deb-key)             deb_key "${2:?usage: ci.sh deb-key <termux-packages>}" ;;
  deb-reuse-verify)    deb_reuse_verify "${2:?usage: ci.sh deb-reuse-verify <termux-packages>}" ;;
  deb-reuse-save)      deb_reuse_save "${2:?usage: ci.sh deb-reuse-save <termux-packages>}" ;;
  resolve-ref)
    : "${GITHUB_TOKEN:=${GH_TOKEN:?need GITHUB_TOKEN or GH_TOKEN}}"
    gh api --method GET "repos/termux/termux-packages/commits/${2:-master}" --jq .sha
    ;;
  *)
    echo "commands: selftest | apply <src> | verify <src> | recipe-prepare <tp> | recipe-audit <tp> | prepare-zram-workspace <tp> | prepare-builder <tp> | build <tp> | dep-cache-prune <tp> | download-preflight <tp> | deb-key <tp> | deb-reuse-verify <tp> | deb-reuse-save <tp> | resolve-ref [ref]" >&2
    exit 2
    ;;
esac
