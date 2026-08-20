#!/usr/bin/env bash
# phase1_smoke.sh — Network OS Phase 1 live peer smoke (Verification 4).
# 2 sessions x 3 runs: two peers discover, handshake, reach READY, exchange
# messages in both directions (receiver replies ACK). Records rc per run.
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
CFG="$REPO/desktop/tools/phase0_bench_config.json"
LOG=/tmp/p1_smoke.log

[ -x "$BIN/message_latency_runner" ] || { echo "SKIP: message_latency_runner missing"; exit 0; }

> "$LOG"
fails=0
for s in 1 2; do
    for r in 1 2 3; do
        echo "=== session $s run $r ===" >> "$LOG"
        ROLE=receiver CONFIG_PATH="$CFG" SELF_ID="p1recv" SELF_PORT=33011 \
            "$BIN/message_latency_runner" > /tmp/p1_recv.log 2>&1 &
        RP=$!
        sleep 1
        ROLE=sender CONFIG_PATH="$CFG" SELF_ID="p1send" SELF_PORT=33012 \
            TARGET_ID="p1recv" TARGET_NETID="127.0.0.1:33011" \
            SIZES=1024,8192 ITERATIONS=10 OUT_JSON="/tmp/p1_smoke_${s}${r}.json" \
            "$BIN/message_latency_runner" >> "$LOG" 2>&1
        RC=$?
        wait "$RP" 2>/dev/null
        echo "rc=$RC" >> "$LOG"
        [ "$RC" -ne 0 ] && fails=$((fails + 1))
    done
done

echo "phase1 smoke: 6 runs, failures=$fails"
exit $((fails > 0 ? 1 : 0))
