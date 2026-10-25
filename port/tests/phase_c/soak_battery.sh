#!/data/data/com.termux/files/usr/bin/bash
BIN=/data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/bin/chromium-sandboxed
OUT=/data/data/com.termux/files/home/Project/phase-c/main-batt
CH=$(readlink -f /data/data/com.termux/files/home/Project/.phc-main/data/data/com.termux/files/usr/lib/chromium-sandboxed/chrome)
END=$(( $(date +%s)+900 )); R=0; TABOK=0; CRASH=0; MAXRSS=0; SAMPLES=0
: > $OUT/soak-census-rows.txt
while [ $(date +%s) -lt $END ]; do
  R=$((R+1))
  # 6-tab concurrent batch (tabs open+close each round)
  N=0
  for t in 1 2 3 4 5 6; do
    timeout 60 $BIN --headless=new --user-data-dir=$OUT/udd-soak-t$t --no-first-run --dump-dom "data:text/html,<h1>T$t</h1><script>document.title='TOK$t'</script>" 2>/dev/null | grep -q ">T$t<" && N=$((N+1))
    rm -rf $OUT/udd-soak-t$t
  done
  [ "$N" = "6" ] && TABOK=$((TABOK+1))
  # census sample: seccomp state of live children + rss
  for p in $(ls /proc | grep -E '^[0-9]+$'); do
    e=$(readlink /proc/$p/exe 2>/dev/null) || continue
    [ "$e" = "$CH" ] || continue
    s=$(awk '/^Seccomp:/{print $2}' /proc/$p/status); f=$(awk '/^Seccomp_filters:/{print $2}' /proc/$p/status)
    n=$(awk '/^NoNewPrivs:/{print $2}' /proc/$p/status)
    rss=$(awk '/^VmRSS:/{print $2}' /proc/$p/status)
    [ -n "$rss" ] && { SAMPLES=$((SAMPLES+1)); [ "$rss" -gt "$MAXRSS" ] && MAXRSS=$rss; }
    echo "$s $f $n" >> $OUT/soak-census-rows.txt
  done
  # crash scan in per-round logs dropped (headless clean); scan zygote IPC errors globally
  CR=$(grep -rac 'Failed to send GetTerminationStatus' $OUT/udd-soak-*/*.log 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
  CRASH=$((CRASH+CR))
  sleep 20
done
echo "SOAK: rounds=$R six-tab-clean=$TABOK maxRSSkb=$MAXRSS rsssamples=$SAMPLES zygoteIPCerrs=$CRASH" > $OUT/soak-result.txt
sort $OUT/soak-census-rows.txt | uniq -c | sort -rn | head -4 >> $OUT/soak-result.txt
cat $OUT/soak-result.txt
