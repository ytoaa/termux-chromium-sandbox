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
# Bind-mount ALL caches into the builder container:
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
#   .termux-srccache    -> /home/builder/.termux-srccache        (Layer 4:
#                          content-addressed persistent cache for VERIFIED
#                          upstream source tarballs (TERMUX_PKG_CACHEDIR =
#                          ~/.termux-build/<pkg>/cache) and arch-independent
#                          termux .deb files (~/.termux-build/_cache-all).
#                          Both live on the container overlay otherwise and
#                          were re-downloaded EVERY run (53 files / ~2.19 GB
#                          per full build, identical URL list in
#                          fp-cold-full.log and keybuild2-full.log); run
#                          40834221022 died on a transient ffmpeg.org
#                          curl(28)/(35) outage. See source_cache_* below.)
docker_volume_args() {
  local d="$1"
  mkdir -p "$d/.sccache" "$d/.termux-depcache/aarch64" "$d/.termux-srccache"
  echo "--volume $d/.sccache:/home/builder/.cache/sccache --volume $d/.termux-depcache/aarch64:/home/builder/.termux-build/_cache-aarch64 --volume $d/.termux-srccache:/home/builder/.termux-srccache"
}

docker_perms_smoke() {
  # REAL-container permission contract (fail-closed). Runs inside the builder
  # container as the image user and verifies, in order:
  #   1) mkdir under /home/builder/.termux-build  (the exact EACCES surface of
  #      run 40717335376 — bind-mount parent must be builder-writable)
  #   2) file create/read/remove inside the build dir
  #   3) dep-cache leaf writable
  #   4) restored dep-cache content readable (warm) or clean-empty (cold)
  #   5) sccache leaf writable SIMULTANEOUSLY (both bind mounts coexist)
  #   6) evidence: container uid/gid, ls -ld of every level, /proc/mounts rows
  # Host-side evidence (host uid, host dir ownership, docker Mounts) printed
  # by the caller. Container-recreation coverage lives in prepare_builder.
  local d
  d="$(need_termux_dir "${1:?}")"
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="$(docker_volume_args "$d")"
  run_docker "$d" bash -lc '
    set -euo pipefail
    echo "SMOKE uid=$(id -u) gid=$(id -g) user=$(id -un)"
    grep -E "termux-build/_cache-aarch64|cache/sccache|\.termux-srccache" /proc/mounts >/dev/null \
      || { echo "SMOKE FAIL: expected bind mounts absent from /proc/mounts"; exit 1; }
    echo "SMOKE ownership evidence:"
    ls -ld /home/builder /home/builder/.cache /home/builder/.cache/sccache \
           /home/builder/.termux-build /home/builder/.termux-build/_cache-aarch64 \
           /home/builder/.termux-srccache
    b=/home/builder/.termux-build/smoke-$$
    mkdir -p "$b/sub"
    echo payload > "$b/sub/f"
    [ "$(cat "$b/sub/f")" = payload ]
    rm -rf "$b"
    c=/home/builder/.termux-build/_cache-aarch64
    echo w > "$c/.smoke-write" && rm "$c/.smoke-write"
    n=$(find "$c" -maxdepth 1 -type f 2>/dev/null | wc -l)
    if [ "$n" -gt 0 ]; then
      sha256sum "$(find "$c" -maxdepth 1 -type f | head -1)" >/dev/null \
        && echo "SMOKE dep-cache warm: files=$n first-entry sha readable"
    else
      echo "SMOKE dep-cache cold: empty mount, writable"
    fi
    s=/home/builder/.cache/sccache
    echo w > "$s/.smoke-write" && rm "$s/.smoke-write"
    r=/home/builder/.termux-srccache
    echo w > "$r/.smoke-write" && rm "$r/.smoke-write" \
      || { echo "SMOKE FAIL: srccache leaf not writable"; exit 1; }
    echo "SMOKE OK"'
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

# ---- Layer 4: persistent VERIFIED source cache -----------------------------
# Closes the residual risk documented in REPORT-PR24-FINAL-AO.md §N: termux
# source tarballs (TERMUX_PKG_CACHEDIR=$TERMUX_TOPDIR/<pkg>/cache, see
# scripts/build/termux_step_setup_variables.sh:118 @ de1dd3d1) and
# arch-independent .deb files ($TERMUX_TOPDIR/_cache-all) sit on the
# container OVERLAY (only _cache-aarch64 is bind-mounted), so every full
# build re-downloads ~2.19 GB / 53 files (identical URL lists in
# fp-cold-full.log vs keybuild2-full.log) and a transient upstream outage
# (ffmpeg.org curl 28/35, run 40834221022) kills the build.
# TRUST MODEL — integrity is never relaxed, only repeated network fetch is
# eliminated (fail-closed in three independent layers):
#   SAVE gate: a file enters L4 only if its sha256 is ∈ the trust set T =
#     (a) every 64-hex checksum declared in termux-packages */build.sh
#         (TERMUX_PKG_SHA256 etc.), union
#     (b) SHA256SUM values from the <repo>-json index maps that
#         termux_get_repo_files.sh downloads and GPG-verifies (via
#         Release) EVERY run. Files fetched WITHOUT a checksum
#         (SKIP_CHECKSUM / empty TERMUX_PKG_SHA256, see
#         get_source/termux_download_src_archive.sh:10-14) can never be in
#         T, so unverified content is NEVER persisted. Entries are stored
#         content-addressed as <sha12>__<urlencoded-name>.
#   RESTORE gate: entry is copied only after re-hashing it and matching the
#         sha12 in its own name (mismatch => quarantine = delete), via a
#         tmp file + atomic mv, and never over an existing target.
#   BUILD gate (upstream, untouched): termux_download.sh:30-35 keeps an
#         existing cache file ONLY if it matches the recipe/index checksum
#         and otherwise re-downloads; so even a fully corrupted or poisoned
#         L4 can only cause a re-download — never unverified input.
# Ubuntu-Packages.gz debs (mesa hostbuild) and the elf-cleaner binary are
# downloaded WITHOUT a build.sh-declared checksum set and are deliberately
# NOT persisted in v1 (documented residual risk; small, official hosts).
# No new bind of .termux-build/_cache itself (PR #24 host-tool protection
# intact); L4 uses its own neutral mount, pre-created builder-owned in the
# image layer exactly like _cache-aarch64.

_l4_write_scripts() {
  # Generate the two IN-CONTAINER scripts into the termux-packages workspace
  # (bind-mounted as /home/builder/termux-packages, same mechanism as the
  # proven .r12-sccache-profile.sh). Container paths are overridable ONLY
  # for the local test harness; production uses the defaults.
  local d="$1"
  # ATOMIC publish (tmp+mv): two concurrent collect calls must never make
  # bash execute a half-written script (race caught by cache test T40).
  cat > "$d/.l4-restore.sh.$$.tmp" <<'L4RESTORE'
#!/usr/bin/env bash
# L4 restore: verified content-addressed entries -> termux cache dirs.
# MUST NEVER fail a build: unguarded errors exit 0; upstream still
# re-verifies every restored byte against its own checksum on use.
L4="${TERMUX_L4_ROOT:-/home/builder/.termux-srccache}"
TOP="${TERMUX_L4_TOPDIR:-/home/builder/.termux-build}"
restored=0 present=0 quarantined=0 badname=0
case "$L4" in */.termux-srccache) ;; *) echo "L4 RESTORE SKIP: unexpected root '$L4'"; exit 0 ;; esac
[ -d "$L4" ] || { echo "L4 RESTORE cold: no $L4"; exit 0; }
l4_decode() { local s="$1"; s=${s//%2F//}; s=${s//%25/%}; printf '%s' "$s"; }
l4_restore_one() { # $1=entry file, $2=target dir, $3=decoded relname
  local ent="$1" dir="$2" name="$3" tgt tmp have b
  tgt="$dir/$name"
  if [ -e "$tgt" ]; then present=$((present+1)); return 0; fi
  mkdir -p "$(dirname "$tgt")" 2>/dev/null || { echo "L4 RESTORE WARN: mkdir $dir failed"; return 0; }
  tmp="$dir/.l4.$$.tmp"
  cp -p -- "$ent" "$tmp" 2>/dev/null || { rm -f -- "$tmp"; echo "L4 RESTORE WARN: copy $ent failed"; return 0; }
  b=${ent##*/}
  have=$(sha256sum "$tmp" 2>/dev/null | cut -c1-12)
  if [ "$have" != "${b%%__*}" ]; then
    rm -f -- "$tmp" "$ent"; quarantined=$((quarantined+1))
    echo "L4 RESTORE quarantine (sha mismatch): $b"
    return 0
  fi
  mv -f -- "$tmp" "$tgt" 2>/dev/null || { rm -f -- "$tmp"; echo "L4 RESTORE WARN: mv $tgt failed"; return 0; }
  restored=$((restored+1))
}
if [ -d "$L4/pkgs" ]; then
  while IFS= read -r -d '' ent; do
    base=${ent##*/}; pkg=${ent%/"$base"}; pkg=${pkg##*/}
    sha12=${base%%__*}; name=${base#*__}
    case "$sha12" in *[!0-9a-f]*) badname=$((badname+1)); rm -f -- "$ent"; continue ;; esac
    [ "${#sha12}" -eq 12 ] && [ "$name" != "$base" ] || { badname=$((badname+1)); rm -f -- "$ent"; continue; }
    case "$pkg" in _cache*|tmp-checkout*|.*) badname=$((badname+1)); rm -f -- "$ent"; continue ;; esac
    l4_restore_one "$ent" "$TOP/$pkg/cache" "$(l4_decode "$name")"
  done < <(find "$L4/pkgs" -mindepth 2 -maxdepth 2 -type f ! -name '.l4.*' ! -name '.has-new' -print0 2>/dev/null)
fi
if [ -d "$L4/deb-all" ]; then
  while IFS= read -r -d '' ent; do
    base=${ent##*/}
    rel=${base#*__}; sha12=${base%%__*}
    [ "$rel" != "$base" ] || { badname=$((badname+1)); rm -f -- "$ent"; continue; }
    case "$sha12" in *[!0-9a-f]*) badname=$((badname+1)); rm -f -- "$ent"; continue ;; esac
    [ "${#sha12}" -eq 12 ] || { badname=$((badname+1)); rm -f -- "$ent"; continue; }
    case "$rel" in *Packages*|*-json|*.l4tmp*) badname=$((badname+1)); rm -f -- "$ent"; continue ;; esac
    l4_restore_one "$ent" "$TOP/_cache-all" "$(l4_decode "$rel")"
  done < <(find "$L4/deb-all" -mindepth 1 -type f ! -name '.l4.*' ! -name '.has-new' -print0 2>/dev/null)
fi
echo "L4 RESTORE restored=$restored present=$present quarantined=$quarantined badname=$badname"
exit 0
L4RESTORE
  cat > "$d/.l4-collect.sh.$$.tmp" <<'L4COLLECT'
#!/usr/bin/env bash
# L4 collect: persist files whose sha256 is VERIFIED by a trusted
# declaration (build.sh checksums or GPG-anchored repo index SHA256SUM).
# Anything without such a declaration (SKIP_CHECKSUM / empty SHA256 /
# unindexed file) is counted as unverified and NEVER written.
L4="${TERMUX_L4_ROOT:-/home/builder/.termux-srccache}"
TOP="${TERMUX_L4_TOPDIR:-/home/builder/.termux-build}"
TP="${TERMUX_L4_TP:-/home/builder/termux-packages}"
CAP_MB="${TERMUX_SRCCACHE_CAP_MB:-6144}"
AGE_DAYS="${TERMUX_SRCCACHE_AGE_DAYS:-45}"
FCAP_MB="${TERMUX_SRCCACHE_FILE_CAP_MB:-4096}"
case "$L4" in */.termux-srccache) ;; *) echo "L4 COLLECT SKIP: unexpected root '$L4'"; exit 0 ;; esac
mkdir -p "$L4" 2>/dev/null || { echo "L4 COLLECT WARN: cannot create $L4"; exit 0; }
l4_encode() { local s="$1"; s=${s//%/%25}; s=${s//\//%2F}; printf '%s' "$s"; }
tset=$(mktemp) || exit 0; jset=$(mktemp) || { rm -f "$tset"; exit 0; }
allset=$(mktemp) || { rm -f "$tset" "$jset"; exit 0; }
# (a) checksums declared in recipes: TERMUX_PKG_SHA256=..., inline
# termux_download ... <sha>, arrays — any 64-hex token in any */build.sh.
find "$TP" -mindepth 3 -maxdepth 3 -name build.sh -type f -print0 2>/dev/null \
  | xargs -0 grep -hoE '[0-9a-f]{64}' 2>/dev/null | sort -u > "$tset" || true
# (b) SHA256SUM values from GPG-verified repo index maps (downloaded and
# gpg --verified EVERY run by termux_get_repo_files.sh).
for j in "$TOP"/_cache-all/*-json "$TOP"/_cache-aarch64/*-json; do
  [ -f "$j" ] || continue
  jq -r '.[].SHA256SUM // empty' "$j" 2>/dev/null | grep -E '^[0-9a-f]{64}$' >> "$jset" || true
done
sort -u "$tset" "$jset" > "$allset" 2>/dev/null || true
new=0 bytes=0 kept=0 unverified=0
l4_accept() { # $1=src file, $2=namespace dir, $3=relpath inside namespace
  local f="$1" ns="$2" rel="$3" sz sha ent tmp enc
  sz=$(stat -c %s -- "$f" 2>/dev/null || echo 0)
  [ "$sz" -gt 0 ] || return 0
  [ "$sz" -le $((FCAP_MB*1024*1024)) ] || { echo "L4 COLLECT skip-toobig: $rel ($sz)"; return 0; }
  sha=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
  [ -n "$sha" ] || return 0
  grep -qx "$sha" "$allset" || { unverified=$((unverified+1)); return 0; }
  enc=$(l4_encode "$rel")
  ent="$ns/${sha:0:12}__$enc"
  if [ -e "$ent" ]; then kept=$((kept+1)); return 0; fi
  mkdir -p "$ns" 2>/dev/null || return 0
  tmp="$ent.l4tmp.$$"
  cp -p -- "$f" "$tmp" 2>/dev/null || { rm -f -- "$tmp"; return 0; }
  if [ "$(sha256sum "$tmp" 2>/dev/null | cut -d' ' -f1)" != "$sha" ]; then
    rm -f -- "$tmp"; echo "L4 COLLECT WARN: copy corrupted, dropped $rel"; return 0
  fi
  mv -f -- "$tmp" "$ent" 2>/dev/null || { rm -f -- "$tmp"; return 0; }
  new=$((new+1)); bytes=$((bytes+sz))
}
if [ -d "$TOP" ]; then
  for pkgd in "$TOP"/*/cache; do
    [ -d "$pkgd" ] || continue
    pkg=${pkgd%/cache}; pkg=${pkg##*/}
    case "$pkg" in _cache*|tmp-checkout*|.*) continue ;; esac
    while IFS= read -r -d '' f; do
      l4_accept "$f" "$L4/pkgs/$pkg" "${f##*/}"
    done < <(find "$pkgd" -mindepth 1 -maxdepth 1 -type f ! -name '.l4.*' ! -name 'download.*' ! -name '*.l4tmp.*' -print0 2>/dev/null)
  done
  if [ -d "$TOP/_cache-all" ]; then
    while IFS= read -r -d '' f; do
      rel=${f#"$TOP"/_cache-all/}
      case "$rel" in *-json|*Packages*|*.l4tmp.*|.*) continue ;; esac
      l4_accept "$f" "$L4/deb-all" "$rel"
    done < <(find "$TOP/_cache-all" -mindepth 1 -type f -print0 2>/dev/null)
  fi
fi
# Bounded store: age first, then oldest-first to the size cap (same policy
# shape as the proven dep-cache prune; touches ONLY this namespace).
find "$L4" -type f -mtime "+$AGE_DAYS" -delete 2>/dev/null || true
total=$(du -sb "$L4" 2>/dev/null | cut -f1); total=${total:-0}
if [ "$total" -gt $((CAP_MB*1024*1024)) ]; then
  echo "L4 COLLECT over cap ($total > $((CAP_MB*1024*1024))); pruning oldest first"
  find "$L4" -type f ! -name '.has-new' -printf '%T@ %p\n' 2>/dev/null | sort -n | cut -d' ' -f2- | \
  while IFS= read -r f; do
    total=$(du -sb "$L4" | cut -f1)
    [ "$total" -le $((CAP_MB*1024*1024)) ] && break
    rm -f -- "$f"
  done
fi
total=$(du -sb "$L4" 2>/dev/null | cut -f1); total=${total:-0}
if [ "$new" -gt 0 ]; then printf '1' > "$L4/.has-new" 2>/dev/null || true; else rm -f -- "$L4/.has-new" 2>/dev/null || true; fi
echo "L4 COLLECT new=$new bytes=$bytes kept=$kept unverified=$unverified total_bytes=$total"
exit 0
L4COLLECT
  chmod 644 "$d/.l4-restore.sh.$$.tmp" "$d/.l4-collect.sh.$$.tmp"
  mv -f "$d/.l4-restore.sh.$$.tmp" "$d/.l4-restore.sh"
  mv -f "$d/.l4-collect.sh.$$.tmp" "$d/.l4-collect.sh"
}

source_cache_restore() {
  local d
  d="$(need_termux_dir "${1:?usage: ci.sh source-cache-restore <termux-packages>}")"
  _l4_write_scripts "$d"
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="$(docker_volume_args "$d")"
  run_docker "$d" bash ./.l4-restore.sh
}

source_cache_collect() {
  local d
  d="$(need_termux_dir "${1:?usage: ci.sh source-cache-collect <termux-packages>}")"
  _l4_write_scripts "$d"
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="$(docker_volume_args "$d")"
  run_docker "$d" bash ./.l4-collect.sh
}

# Layer 6: bounded pre-build connectivity probe against OFFICIAL termux
# mirrors only. Never trusts an unlisted mirror; switching only happens
# between whitelisted official hosts and the effective repo.json is hashed
# into the deb key, so any switch is visible in build inputs. Fails FAST
# (<5 min) instead of letting build-package curl(28)-loop for hours.
OFFICIAL_APT_HOSTS="packages.termux.dev packages-cf.termux.dev"
_official_host_p() { case " $OFFICIAL_APT_HOSTS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
_probe_raw() {
  # $1=url, $2=output file for body ('' = discard), rest=extra curl args.
  # Prints "http_code speed_download rc effective_host". curl -w output is
  # emitted on -f-style failures too, so the HTTP status survives (a bare
  # `|| code=000` used to erase the 404-vs-timeout distinction the post-
  # mortem needed). -L follows redirects (max 5) BUT the effective host is
  # returned and MUST pass the official whitelist — a redirect must never
  # silently move us to an unverified origin.
  local url="$1" out_file="$2"; shift 2
  local out rc
  local -a args=(-fsSL --max-redirs 5 --connect-timeout 8 --retry 1
                 --retry-delay 2 --speed-limit 2000 --speed-time 20
                 -w '%{http_code} %{speed_download} %{url_effective}')
  [ -n "$out_file" ] && args+=(-o "$out_file") || args+=(-o /dev/null)
  # NOTE: `out=$(cmd); rc=$?` would abort the whole step under set -e the
  # moment curl fails (same silent-death trap that bit "Compute cache keys"
  # pre-e800770). Guard the status capture explicitly.
  out=$(timeout 90 curl "${args[@]}" "$@" "$url" 2>/dev/null) && rc=0 || rc=$?
  [ -n "$out" ] || out="000 0 $url"
  local code speed eff host
  set -- $out
  code="${1:-000}"; speed="${2:-0}"; eff="${3:-$url}"
  host="${eff#*://}"; host="${host%%/*}"; host="${host%%:*}"
  echo "$code $speed $rc $host"
}
_probe_entry() {
  # One repo entry is HEALTHY only when (a) Release fetches 200 from an
  # official host, (b) the Release body names a real Packages index and
  # (c) a bounded 1 MiB ranged GET of THAT index actually transfers.
  # Release-200 alone does not prove the 85 MB-class .deb pipeline works
  # (run 40662494279: healthy-looking HEAD while downloads crawled at
  # 1.5-40 KB/s); the path is PARSED FROM the Release checksum table
  # (Debian layout is dists/<dist>/<component>/binary-aarch64/Packages...)
  # instead of guessed, so a layout/component change cannot false-block.
  local url="$1" dist="$2" component="${3:-main}"
  local tmpb code speed rc eff ppath="" parsed_ppath="" pec psp prc peff p_path=none
  tmpb=$(mktemp)
  read -r code speed rc eff <<<"$(_probe_raw "$url/dists/$dist/Release" "$tmpb")"
  echo "PREFLIGHT probe url=$url dist=$dist Release http=$code rc=$rc speed=${speed:-0} eff_host=${eff:-?}"
  if ! _official_host_p "${eff:-?}"; then
    echo "PREFLIGHT FAIL: Release redirected off-whitelist: $url -> ${eff:-?}" >&2
    rm -f "$tmpb"; return 1
  fi
  [ "$rc" = "0" ] && [ "$code" = "200" ] || { rm -f "$tmpb"; return 1; }
  # checksum-table rows are "  <hash> <size> <path>" -> path is $3
  ppath=$(awk '{ if ($3 ~ /\/binary-aarch64\/Packages(\.[a-z0-9]+)?$/) { print $3; exit } }' "$tmpb" 2>/dev/null || true)
  rm -f "$tmpb"
  parsed_ppath="$ppath"
  [ -n "$ppath" ] || ppath="$component/binary-aarch64/Packages.xz"
  read -r pec psp prc peff <<<"$(_probe_raw "$url/dists/$dist/$ppath" "" --max-time 60 -r 0-1048575)"
  p_path="$ppath"
  case "$prc:${pec:-000}" in
    0:200|0:206) ;;
    *)
      if [ "$ppath" != "$component/binary-aarch64/Packages.xz" ]; then
        # parsed path failed — retry the component-guessed path once
        ppath="$component/binary-aarch64/Packages.xz"
        read -r pec psp prc peff <<<"$(_probe_raw "$url/dists/$dist/$ppath" "" --max-time 60 -r 0-1048575)"
        p_path="$ppath"
        case "$prc:${pec:-000}" in 0:200|0:206) ;; *) p_path=none ;; esac
      else
        p_path=none
      fi
      ;;
  esac
  echo "PREFLIGHT probe url=$url dist=$dist Packages path=$p_path parsed=${parsed_ppath:-none} fallback=$component/binary-aarch64/Packages.xz http=${pec:-000} rc=${prc:-?} speed=${psp:-0} eff_host=${peff:-?} (1MiB ranged transfer)"
  if [ "$p_path" = "none" ]; then
    echo "PREFLIGHT FAIL: Release OK but Packages transfer failed at $url dist=$dist — Release-200 alone is not trusted for multi-hundred-MB dependency pulls; refusing to start the build." >&2
    return 1
  fi
  if ! _official_host_p "${peff:-?}"; then
    echo "PREFLIGHT FAIL: Packages redirected off-whitelist: $url -> ${peff:-?}" >&2
    return 1
  fi
  return 0
}
download_preflight() {
  local d repo host urls entry url dist healthy rc=0
  d="$(need_termux_dir "${1:?}")"
  repo="$d/repo.json"
  test -f "$repo" || { echo "PREFLIGHT FAIL: repo.json missing" >&2; return 1; }
  echo "PREFLIGHT begin $(date -u +%FT%TZ) repo.json=$(sha256sum "$repo" | cut -c1-16)"
  jq -r 'del(.pkg_format) | .[] | .url + " " + .distribution + " " + (.component // "main")' "$repo" | while IFS=' ' read -r url dist component; do
    host="${url#*://}"; host="${host%%/*}"; host="${host%%:*}"
    _official_host_p "$host" || {
      echo "PREFLIGHT FAIL: non-official repo host in repo.json: $host" >&2; exit 1; }
    if ! _probe_entry "$url" "$dist" "$component"; then
      for alt in $OFFICIAL_APT_HOSTS; do
        [ "$alt" = "$host" ] && continue
        local_url="https://$alt/${url#*://$host/}"
        echo "PREFLIGHT switching $url -> $local_url (official whitelist only)"
        if _probe_entry "$local_url" "$dist" "$component"; then
          cp -f "$repo" "$d/repo.json.orig-backup"
          jq --arg old "$url" --arg new "$local_url" \
             'walk(if type=="object" and .url==$old then .url=$new else . end)' \
             "$d/repo.json.orig-backup" > "$repo.tmp" && mv "$repo.tmp" "$repo"
          echo "PREFLIGHT MIRROR-SWITCH $url -> $local_url (official whitelist only; integrity chain unchanged)"
          break
        fi
      done
    fi
  done || rc=1
  # Final gate: every repo entry must currently pass Release AND Packages
  # transfer probes on its selected (official) host.
  jq -r 'del(.pkg_format) | .[] | .url + " " + .distribution + " " + (.component // "main")' "$repo" | while IFS=' ' read -r url dist component; do
    _probe_entry "$url" "$dist" "$component" || {
      echo "PREFLIGHT FAIL: repo unreachable/slow: $url dist=$dist. Refusing to start a multi-hour build; no unverified mirror or stale-dep fallback is permitted." >&2
      exit 1
    }
  done || rc=1
  echo "PREFLIGHT done rc=$rc $(date -u +%FT%TZ) effective_repo_sha=$(sha256sum "$repo" | cut -c1-16)"
  return $rc
}

# Layer 3: composite, immutable key over ALL build-affecting inputs.
image_fingerprint() {
  # Deterministic CONTENT identity of the final builder image, from three
  # reproducible components: base image id + sorted installed-package
  # versions + Dockerfile content hash.
  # Why not the raw `docker image inspect .Id`: the image config embeds
  # the build `created` timestamp, so the raw id rotates on EVERY rebuild
  # even with byte-identical inputs — proven empirically: runs
  # 40825927463 vs 40834221022 (same commit, same base digest) recorded
  # ids 7ccda63d… vs 0b9d985a…. Keying on the raw id made the DEB cache
  # unhittable (structural defect; task-C hypothesis CONFIRMED).
  # The fingerprint keeps the SAME security property the raw id was meant
  # to provide — any real environment change (base `:latest` drift, apt
  # security update, Dockerfile edit) changes one of the three components
  # and rotates the key — while being reproducible across rebuilds:
  # a rebuilt-but-unchanged environment re-hits the DEB cache; a changed
  # environment NEVER reuses a stale DEB.
  local base_id="$1" pkgs_file="$2" dockerfile="$3"
  [ -n "$base_id" ] || { echo "IMAGE FINGERPRINT FAIL: empty base image id" >&2; return 1; }
  [ -s "$pkgs_file" ] || { echo "IMAGE FINGERPRINT FAIL: missing/empty package list" >&2; return 1; }
  [ -f "$dockerfile" ] || { echo "IMAGE FINGERPRINT FAIL: Dockerfile '$dockerfile' missing" >&2; return 1; }
  { printf 'base=%s\n' "$base_id"; cat "$pkgs_file"; printf 'dockerfile='; sha256sum "$dockerfile" | cut -d' ' -f1; } | sha256sum | cut -d' ' -f1
}
deb_image_id() {
  # Resolution order:
  #   1) TERMUX_BUILDER_IMAGE_ID env — the workflow passes the fingerprint
  #      recorded by prepare_builder (single computation site); docker-less
  #      unit tests inject synthetic values.
  #   2) derive from the live final image (base id + dpkg -W + Dockerfile).
  # Anything else (missing/empty/malformed) FAILS CLOSED — deb-key never
  # computes a key that silently omits image identity.
  local id
  id="${TERMUX_BUILDER_IMAGE_ID:-}"
  if [ -z "$id" ] && command -v docker >/dev/null 2>&1; then
    local base_id pkgsf
    pkgsf=$(mktemp)
    base_id=$(docker image inspect --format '{{.Id}}' "${TERMUX_BUILDER_BASE_IMAGE:-ghcr.io/termux/package-builder:latest}" 2>/dev/null) || base_id=""
    docker run --rm --entrypoint /usr/bin/dpkg-query "$TERMUX_BUILDER_IMAGE_NAME" -W -f '${Package} ${Version}\n' 2>/dev/null | LC_ALL=C sort > "$pkgsf" || true
    id=$(image_fingerprint "$base_id" "$pkgsf" "${TERMUX_BUILDER_DOCKERFILE:-/tmp/Dockerfile.chromium-sccache}") || id=""
    rm -f "$pkgsf"
  fi
  if ! [[ "$id" =~ ^(sha256:)?[0-9a-f]{64}$ ]]; then
    echo "DEB KEY FAIL: builder image fingerprint missing/invalid (need docker image '$TERMUX_BUILDER_IMAGE_NAME' present, or TERMUX_BUILDER_IMAGE_ID=<64-hex>) — refusing to compute a key without image identity" >&2
    return 1
  fi
  echo "$id"
}
deb_key() {
  local d termux_sha port_hash recipe_sha upstream ver arch rev repo_sha k imageid
  d="$(need_termux_dir "${1:?}")"
  termux_sha=$(git -C "$d" rev-parse HEAD 2>/dev/null || true)
  [ -n "$termux_sha" ] || { echo "DEB KEY FAIL: termux dir is not a git checkout" >&2; return 1; }
  port_hash=$(cd "$here/.." && python3 port/maintenance.py port-input-hash --root . | tail -1)
  [ -n "$port_hash" ] || { echo "DEB KEY FAIL: port-input-hash empty" >&2; return 1; }
  imageid=$(deb_image_id) || return 1
  recipe_sha=$( { find "$d/packages/chromium-sandboxed" -type f \( -name '*.sh' -o -name '*.sub' -o -name 'RECIPE*' \) -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null || true; } | sha256sum | cut -d' ' -f1)
  upstream=$( { grep -hoE 'TERMUX_PKG_VERSION=.[0-9][0-9.]*' "$d"/packages/*chromium*/build.sh 2>/dev/null || true; } | head -1 | sed -e 's/.*=//' -e 's/[^0-9.]//g')
  [ -n "$upstream" ] || upstream=$( { grep -m1 -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$d/../../port/port.toml" 2>/dev/null || true; } | head -1)
  [ -n "$upstream" ] || upstream=unknown
  repo_sha=$( { sha256sum "$d/repo.json" 2>/dev/null || true; } | cut -d' ' -f1)
  [ -n "$repo_sha" ] || repo_sha=absent
  rev="${TERMUX_SANDBOXED_REVISION:-?}"
  arch="aarch64"
  ver="chromium-sandboxed"
  k=$(printf '%s\n' "pkg=$ver" "rev=$rev" "arch=$arch" "upstream=${upstream:-unknown}" "termux=$termux_sha" "port=$port_hash" "recipe=$recipe_sha" "repojson=$repo_sha" "image=$TERMUX_BUILDER_IMAGE_NAME" "imageid=$imageid" | sha256sum | cut -d' ' -f1)
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
  local d cache base attempt pulled imgid cimg base_id pkgsf imgfp
  d="$(need_termux_dir "${1:?}")"
  cache="$d/.sccache"
  base="ghcr.io/termux/package-builder:latest"
  mkdir -p "$cache"; sudo chown -R "$(id -u):$(id -g)" "$cache"; chmod -R a+rwX "$cache"
  pulled=0
  for attempt in 1 2 3 4 5; do docker pull "$base" && { pulled=1; break; }; sleep $((attempt*15)); done
  [ "$pulled" -eq 1 ] || { docker build -t "$base" "$d/scripts/"; docker buildx prune -af || true; }
  # PRE-CREATE the bind-mount PARENTS, builder-owned. Root cause of run
  # 40717335376 (step15, 15:38:47Z): "mkdir: cannot create directory
  # '/home/builder/.termux-build/chromium-sandboxed': Permission denied".
  # dockerd runs as root and auto-creates any MISSING target path of a
  # -v/--volume mount as root:root 0755 INSIDE the container. Our dep-cache
  # mount targets .../.termux-build/_cache-aarch64; the image never had
  # .termux-build (upstream creates it at build runtime as builder), so the
  # leaf mount made dockerd plant a root-owned .termux-build and the builder
  # user could no longer create the package dir under it. The leaf itself is
  # irrelevant (replaced by the bind, host-dir uid decides access, same
  # mechanism that made the sccache mount work since run #10). Fix is
  # ownership-correct pre-creation only — NO chmod -R 777, no new mounts.
  # .termux-build stays a builder-owned normal dir (upstream layout intact;
  # host tool-build artifacts like _cache/python-3.14 live alongside and are
  # deliberately NOT bind-mounted over — that is why we mount at the
  # _cache-aarch64 LEAF and never at .termux-build level).
  cat > /tmp/Dockerfile.chromium-sccache <<'DOCKERFILE'
FROM ghcr.io/termux/package-builder:latest
USER root
RUN apt-get update \
    && apt-get install -yq --no-install-recommends sccache python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /home/builder/.termux-build/_cache-aarch64 /home/builder/.cache/sccache /home/builder/.termux-srccache \
    && chown -R builder:builder /home/builder/.termux-build /home/builder/.cache/sccache /home/builder/.termux-srccache
USER builder:builder
WORKDIR /home/builder/termux-packages
DOCKERFILE
  docker build -f /tmp/Dockerfile.chromium-sccache -t "$TERMUX_BUILDER_IMAGE_NAME" "$d"
  # Record the FINAL image identity NOW, before the free-space cleanup
  # below (run 40823773715 evidence: `rm -rf /var/lib/containerd/io.
  # containerd.content.v1.content` deletes containerd's content store;
  # afterwards `docker image inspect` cannot read the image config blob
  # — "blob not found" — while the ALREADY-CREATED container keeps
  # working because its snapshot is extracted, which is why the old flow
  # (image never inspected post-prepare) hid this). Persisting the ids
  # here keeps the DEB key bound to the true final image without
  # depending on post-cleanup inspect.
  # Two values:
  #   .builder-image-raw — docker's own image id. NOT reproducible across
  #     rebuilds (config `created` timestamp; runs 40825927463/40834221022
  #     proved 7ccda63d… vs 0b9d985a… from identical inputs), so it is
  #     used ONLY for the within-run same-image drift guard.
  #   .builder-image-id  — deterministic content fingerprint (base id +
  #     sorted dpkg package versions + Dockerfile hash), see
  #     image_fingerprint(); this is what the DEB key hashes, so an
  #     unchanged environment can actually REUSE the cached DEB while any
  #     real environment change still rotates the key.
  imgid=$(docker image inspect --format '{{.Id}}' "$TERMUX_BUILDER_IMAGE_NAME") || {
    echo "PREPARE FAIL: built image '$TERMUX_BUILDER_IMAGE_NAME' not inspectable" >&2; exit 1; }
  [[ "$imgid" =~ ^(sha256:)?[0-9a-f]{64}$ ]] || { echo "PREPARE FAIL: invalid image id '$imgid'" >&2; exit 1; }
  base_id=$(docker image inspect --format '{{.Id}}' "$base") || {
    echo "PREPARE FAIL: base image '$base' not inspectable" >&2; exit 1; }
  pkgsf=$(mktemp)
  docker run --rm --entrypoint /usr/bin/dpkg-query "$TERMUX_BUILDER_IMAGE_NAME" -W -f '${Package} ${Version}\n' | LC_ALL=C sort > "$pkgsf" || {
    echo "PREPARE FAIL: dpkg-query package list failed in final image" >&2; rm -f "$pkgsf"; exit 1; }
  [ -s "$pkgsf" ] || { echo "PREPARE FAIL: empty package list from final image" >&2; rm -f "$pkgsf"; exit 1; }
  imgfp=$(image_fingerprint "$base_id" "$pkgsf" /tmp/Dockerfile.chromium-sccache) || { rm -f "$pkgsf"; exit 1; }
  rm -f "$pkgsf"
  printf '%s' "$imgid" > "$d/.builder-image-raw"
  printf '%s' "$imgfp" > "$d/.builder-image-id"
  echo "BUILDER IMAGE ID(raw)=$imgid FINGERPRINT=$imgfp BASE=$base_id"
  docker rm -f termux-package-builder 2>/dev/null || true
  export TERMUX_DOCKER_RUN_EXTRA_ARGS="$(docker_volume_args "$d")"
  # Host-side evidence for the permission contract (see docker_perms_smoke).
  echo "SMOKE host uid=$(id -u) gid=$(id -g) user=$(id -un)"
  stat -c 'SMOKE hostdir %a %U:%G %n' "$d/.sccache" "$d/.termux-depcache/aarch64" || true
  run_docker "$d" true
  docker inspect -f '{{range .Mounts}}SMOKE mount {{.Source}} -> {{.Destination}}\n{{end}}' termux-package-builder || true
  docker_perms_smoke "$d"
  # Check 6 of the contract: everything must still hold after the container
  # is destroyed and recreated from the same image + same volume args.
  echo "SMOKE container-recreation: rm -f + re-create"
  docker rm -f termux-package-builder 2>/dev/null || true
  docker_perms_smoke "$d"
  run_docker "$d" bash -lc 'set -euxo pipefail; export SCCACHE_DIR=/home/builder/.cache/sccache SCCACHE_CACHE_SIZE=6G; command -v sccache; python3 --version; echo test > "$SCCACHE_DIR/.write-test"; rm "$SCCACHE_DIR/.write-test"'
  # Same-image contract at the source: the LIVE container the later build
  # step will exec into must have been created from the exact image the
  # DEB key will hash. Container metadata .Image is readable even after
  # the content-store cleanup below (it is not fetched from the blob
  # store), so this remains checkable at build time too.
  cimg=$(docker inspect -f '{{.Image}}' termux-package-builder 2>/dev/null) || {
    echo "PREPARE FAIL: builder container missing after setup" >&2; exit 1; }
  [ "$cimg" = "$imgid" ] || {
    echo "PREPARE FAIL: builder container image $cimg != recorded image id $imgid" >&2; exit 1; }
  echo "CONTAINER IMAGE MATCH OK: termux-package-builder <- $cimg"
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
  # Task-D review (run 40823773715 + df evidence): the former extra entry
  # `sudo rm -rf /var/lib/containerd/io.containerd.content.v1.content` is
  # REMOVED. It directly gutted the docker daemon's content store (broke
  # image inspection post-prepare; version-fragile internal layout; on a
  # shared runner it would also starve other jobs' images), while disk
  # pressure is measurably absent (root fs 94G avail / 36% used after the
  # remaining cleanup, keybuild2-full.log). Reclaimed instead via the
  # daemon-managed `docker image prune -f` below (dangling images from
  # previous runs' rebuilds of this tag) — same space, zero corruption
  # risk, no conflict with the node24 protections (which forbid touching
  # runner-runtime paths like /opt/runner-cache).
  ( cd "$d" && sudo rm -rf /opt/ghc /opt/az /opt/pipx \
      /usr/share/dotnet /usr/share/swift /usr/share/miniconda /usr/share/az_* \
      /usr/share/gradle-* /usr/share/java /home/runner/.rustup /etc/skel \
      /home/packer /home/linuxbrew /usr/src ) || true
  docker image prune -f >/dev/null 2>&1 || true
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
  docker-perms-smoke)    docker_perms_smoke "${2:?usage: ci.sh docker-perms-smoke <termux-packages>}" ;;
  build)                  build_chromium "${2:?usage: ci.sh build <termux-packages>}" ;;
  dep-cache-prune)     dep_cache_prune "${2:?usage: ci.sh dep-cache-prune <termux-packages>}" ;;
  source-cache-restore) source_cache_restore "${2:?usage: ci.sh source-cache-restore <termux-packages>}" ;;
  source-cache-collect) source_cache_collect "${2:?usage: ci.sh source-cache-collect <termux-packages>}" ;;
  download-preflight)  download_preflight "${2:?usage: ci.sh download-preflight <termux-packages>}" ;;
  deb-key)             deb_key "${2:?usage: ci.sh deb-key <termux-packages>}" ;;
  image-fingerprint)   image_fingerprint "${2:?}" "${3:?}" "${4:?}" ;;
  deb-reuse-verify)    deb_reuse_verify "${2:?usage: ci.sh deb-reuse-verify <termux-packages>}" ;;
  deb-reuse-save)      deb_reuse_save "${2:?usage: ci.sh deb-reuse-save <termux-packages>}" ;;
  resolve-ref)
    : "${GITHUB_TOKEN:=${GH_TOKEN:?need GITHUB_TOKEN or GH_TOKEN}}"
    gh api --method GET "repos/termux/termux-packages/commits/${2:-master}" --jq .sha
    ;;
  *)
    echo "commands: selftest | apply <src> | verify <src> | recipe-prepare <tp> | recipe-audit <tp> | prepare-zram-workspace <tp> | prepare-builder <tp> | docker-perms-smoke <tp> | image-fingerprint <base> <pkgs> <dockerfile> | build <tp> | dep-cache-prune <tp> | source-cache-restore <tp> | source-cache-collect <tp> | download-preflight <tp> | deb-key <tp> | deb-reuse-verify <tp> | deb-reuse-save <tp> | resolve-ref [ref]" >&2
    exit 2
    ;;
esac
