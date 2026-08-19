#!/bin/bash
# Runs unwind-check over a sample of system binaries and reports anything
# that crashed, hung, or came out slow. This is the non-hermetic
# counterpart to `bazel test :all`: the fixtures prove the analysis is
# right, this proves the parser survives real-world input.
#
#   ./robustness-sweep.sh [count]     # default 400
#
# Anything printed as ABNORMAL is a bug in this tool: the only exit codes
# it may produce are 0 (all blessed), 1 (a mismatch), 2 (review) and
# 3 (the run failed cleanly).
set -u

BIN=${BIN:-./bazel-bin/unwind-check}
COUNT=${1:-400}

if [ ! -x "$BIN" ]; then
  echo "no $BIN; run: bazel build :unwind-check" >&2
  exit 1
fi

abnormal=0 count=0 fdes=0 blessed=0 review=0 mismatch=0 slow=""
list=$( (ls -d /usr/lib/x86_64-linux-gnu/*.so.* ; ls -d /usr/bin/*) 2>/dev/null |
        shuf -n "$COUNT" --random-source=/dev/zero )

for f in $list; do
  [ -f "$f" ] || continue
  head -c4 "$f" 2>/dev/null | grep -q $'\x7fELF' || continue
  count=$((count + 1))
  start=$(date +%s%N)
  out=$(timeout 120 "$BIN" --summary_only --addr2line=off "$f" 2>/dev/null)
  rc=$?
  elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
  if [ $rc -gt 3 ]; then
    echo "ABNORMAL rc=$rc $f"
    abnormal=$((abnormal + 1))
    continue
  fi
  # "N FDEs: N blessed, N review, N mismatch"
  read -r a _ b _ c _ d _ <<< "$out"
  fdes=$((fdes + ${a:-0}))
  blessed=$((blessed + ${b:-0}))
  review=$((review + ${c:-0}))
  mismatch=$((mismatch + ${d:-0}))
  [ $elapsed -gt 5000 ] && slow="$slow ${elapsed}ms:$(basename "$f")"
done

echo "binaries=$count abnormal_exits=$abnormal"
echo "totals: fdes=$fdes blessed=$blessed review=$review mismatch=$mismatch"
echo "slow_over_5s:$slow"
[ $abnormal -eq 0 ]
