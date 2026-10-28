#!/bin/bash
# node24 externals presence probe (diagnostic branch only)
tag="$1"
n=$(find ~/actions-runner/cached -type f -name node -path '*node24*' 2>/dev/null | head -1)
if [ -n "$n" ]; then
  ex=YES
  if "$n" -v >/dev/null 2>&1; then execv="OK:$("$n" -v)"; else execv=FAIL; fi
  tgt=$(readlink -f "$n" 2>/dev/null)
else ex=NO; execv=NA; tgt=NA; fi
echo "NODEPROBE tag=$tag exists=$ex exec=$execv target=$tgt"
for D in /opt/runner-cache /opt/hostedtoolcache /opt/actionarchivecache "$AGENT_TOOLSDIRECTORY" /usr/local; do
  [ -n "$D" ] && { [ -e "$D" ] && echo "DIRS present $D" || echo "DIRS GONE   $D"; }
done
df -h / | tail -1 | sed 's/^/DF /'
df -i / | tail -1 | sed 's/^/DFI /'
