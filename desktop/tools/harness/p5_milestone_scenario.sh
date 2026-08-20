#!/usr/bin/env bash
# p5_milestone_scenario.sh - Network OS Phase 5 §99 milestone harness.
#
# Verification plan items (phase doc §9):
#   1. §99 scenario (no kills) - delivery_test (in-process wire: A->B,
#      RECEIVED_ACK -> signed receipt -> CONFIRMED) run LOOP times.
#   3/4. Idempotent repeat + late confirmation - covered by delivery_test.
#   2. Kill-at-the-arrow (durability): drives delivery_kill_probe to write
#      delivery state + signed receipt, then "process death" (close+reopen)
#      and verify the state + receipt survived - the receipt-commit arrow
#      (invariants 4/17).
#
# The live 3-desktop-peer session + tcpdump transport path (doc §9 items 8/11)
# is covered by phase4_live_test.sh / phase4_tcpdump_test.sh; Phase 6 wires the
# pull path. Run this after every later phase to confirm no regression in §99.
set -u

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
DT="$REPO/desktop/build_fixcheck/bin/delivery_test"
KP="$REPO/desktop/build_fixcheck/bin/delivery_kill_probe"
LOG=/tmp/p5_milestone.log
LOOP="${1:-5}"

> "$LOG"
fails=0

if [ -x "$DT" ]; then
    for ((n = 1; n <= LOOP; n++)); do
        if ! "$DT" >>"$LOG" 2>&1; then
            echo "FAIL: delivery_test pass $n" >>"$LOG"
            fails=$((fails + 1))
        fi
    done
else
    echo "FAIL: delivery_test not built" >>"$LOG"
    fails=$((fails + 1))
fi

run_probe() {
    local tag="$1" confirmed=0
    [ "${2:-}" = "-c" ] && confirmed=1
    local W=/tmp/p5_kill_${tag}
    rm -rf "$W" && mkdir -p "$W"
    local OID="${tag}-object1234567890abcdef"
    local RID="${tag}-receipt1234567890abcdef"
    if ! "$KP" --write --db "$W/obj.sqlite" --object "$OID" --receipt "$RID" \
            $([ "$confirmed" = 1 ] && echo --confirmed) >>"$LOG" 2>&1; then
        echo "FAIL: probe write $tag" >>"$LOG"; return 1
    fi
    if ! "$KP" --check --db "$W/obj.sqlite" --object "$OID" --receipt "$RID" \
            $([ "$confirmed" = 1 ] && echo --confirmed) >>"$LOG" 2>&1; then
        echo "FAIL: probe reopen-check $tag" >>"$LOG"; return 1
    fi
    echo "probe $tag survived reopen" >>"$LOG"
}

for ((i = 1; i <= 10; i++)); do
    run_probe "delivered_$i" || fails=$((fails + 1))
    run_probe "confirmed_$i" -c || fails=$((fails + 1))
done

echo "p5 milestone: delivery_test ${LOOP}x + 20 durability probes, failures=$fails" | tee -a "$LOG"
exit $((fails > 0 ? 1 : 0))
