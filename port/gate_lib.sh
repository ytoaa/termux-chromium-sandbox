#!/usr/bin/env bash
# Shared device-gate census helpers.
# These were previously inline in device_gate.sh and shipped three parsing bugs
# (label prefix looked up in the file that never had it; missing zygote->renderer
# reclassification; filter-count-only checks on kernels that do not export
# Seccomp_filters). Keeping them here lets unit tests exercise the real code.
#
# Row format: "<type> <filters> <seccomp>" (filters=0 when the kernel hides it).

# gate_classify PROC_ROOT BIN OUT
#   Two-pass census: Linux zygote children fork WITHOUT execv, so sandboxed
#   renderer processes keep --type=zygote in cmdline; a zygote row whose PPid is
#   itself a zygote is a renderer.
gate_classify() {
  local proc_root=$1 bin=$2 out=$3
  local pid exe t f sc pp zypids=" " rows=()
  : > "$out"
  for pid in $(ls "$proc_root" 2>/dev/null | grep -E '^[0-9]+$'); do
    exe=$(readlink "$proc_root/$pid/exe" 2>/dev/null) || continue
    [ "$exe" = "$bin" ] || continue
    t=$(tr '\0' '\n' < "$proc_root/$pid/cmdline" 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
    [ "${t:-}" = zygote ] && zypids="$zypids$pid "
  done
  for pid in $(ls "$proc_root" 2>/dev/null | grep -E '^[0-9]+$'); do
    exe=$(readlink "$proc_root/$pid/exe" 2>/dev/null) || continue
    [ "$exe" = "$bin" ] || continue
    t=$(tr '\0' '\n' < "$proc_root/$pid/cmdline" 2>/dev/null | sed -n 's/^--type=\(.*\)/\1/p' | head -1)
    f=$(awk '/^Seccomp_filters:/{print $2}' "$proc_root/$pid/status" 2>/dev/null)
    sc=$(awk '/^Seccomp:/{print $2}' "$proc_root/$pid/status" 2>/dev/null)
    pp=$(awk '/^PPid:/{print $2}' "$proc_root/$pid/status" 2>/dev/null)
    case "$zypids" in
      *" ${pp:-} "*)
        if [ "${t:-}" = zygote ]; then t=renderer; fi ;;
    esac
    echo "${t:-browser} ${f:-0} ${sc:-0}" >> "$out"
  done
  sort -u -o "$out" "$out"
}

# gate_field FILE TYPE FIELD(2|3) -> maximum numeric value for that type
gate_field() {
  awk -v t="$2" -v c="$3" '$1==t{if($c>m)m=$c}END{print m+0}' "$1" 2>/dev/null
}

# gate_present FILE TYPE -> number of rows of that type
gate_present() {
  awk -v t="$2" '$1==t{c++}END{print c+0}' "$1" 2>/dev/null
}

# gate_decide PROCS_FILE CRASH_COUNT CODECS_OK(0|1) [LABEL]
#   Prints the measured verdict and its supporting lines; echoes PASS or FAIL.
#   PASS rule: either the kernel exports Seccomp_filters and a renderer has >=2
#   filters, or (renderer alive AND Seccomp=2 filter mode AND 0 crash lines AND
#   a complete codec report) — the documented proxy for kernels that hide the
#   filter count (Android 13 testbed).
gate_decide() {
  local procs=$1 crash=$2 codecs=$3 label=${4:-ported}
  local ren ren_sc present verdict=PASS
  ren=$(gate_field "$procs" renderer 2)
  ren_sc=$(gate_field "$procs" renderer 3)
  present=$(gate_present "$procs" renderer)
  echo "${label} renderer filters=${ren} seccomp=${ren_sc} present=${present} crashing=${crash}"
  if [ "${crash:-0}" -ne 0 ]; then
    echo "GATE FAIL: crash signatures present (crashing=$crash)"
    verdict=FAIL
  fi
  if [ "${ren:-0}" -ge 2 ]; then
    echo "renderer BPF census ok (filters=$ren)"
  elif [ "${present:-0}" -gt 0 ] && [ "${ren_sc:-0}" -eq 2 ] && [ "${crash:-0}" -eq 0 ]; then
    echo "GATE NOTE: Seccomp_filters unexportable; renderer x$present alive, Seccomp=2, 0 CRASHING — presence+mode proxy ok"
  else
    echo "GATE FAIL: no ported renderer with >=2 filters (BPF missing; present=$present seccomp=$ren_sc crashing=$crash)"
    verdict=FAIL
  fi
  if [ "${codecs:-0}" -eq 1 ]; then echo "codecs ok"; else echo "GATE FAIL: codec report incomplete or unsupported"; verdict=FAIL; fi
  echo "$verdict"
}
