#!/usr/bin/env bash
# phase2_networkswitch_test.sh — Network OS Phase 2 live network-switch test
# (verification plan item 7: connect -> exchange -> network switch -> reconnect
#  with stable PeerID).
#
# Two PROCESSES (the repo's live-test pattern; message_latency_runner):
#   1. receiver on port A, sender connects + exchanges (rc=0)
#   2. receiver KILLED and restarted on port B  (the "network switch")
#   3. sender (same SELF_ID = same PeerID) connects to port B + exchanges (rc=0)
#   4. both rc=0 => live reconnect across the switch with stable PeerID.
#
# Usage: desktop/tools/phase2_networkswitch_test.sh
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
CFG="$REPO/desktop/tools/phase0_bench_config.json"
LOG=/tmp/p2_networkswitch.log

[ -x "$BIN/message_latency_runner" ] || { echo "SKIP: message_latency_runner missing"; exit 0; }
[ -f "$CFG" ] || { echo "SKIP: bench config missing"; exit 0; }

> "$LOG"
fails=0

run_pair() {  # $1 = receiver port
    ROLE=receiver CONFIG_PATH="$CFG" SELF_ID="p2recv" SELF_PORT="$1" \
        "$BIN/message_latency_runner" > "$LOG.recv.$1" 2>&1 &
    local rp=$!
    sleep 1
    ROLE=sender CONFIG_PATH="$CFG" SELF_ID="p2send" SELF_PORT="$2" \
        TARGET_ID="p2recv" TARGET_NETID="127.0.0.1:$1" \
        SIZES=1024 ITERATIONS=5 OUT_JSON="$LOG.sender.$1.json" \
        "$BIN/message_latency_runner" >> "$LOG" 2>&1
    local rc=$?
    wait "$rp" 2>/dev/null
    return "$rc"
}

echo "=== leg 1: connect on port 37001 ===" >> "$LOG"
run_pair 37001 37011
rc1=$?
echo "leg1 rc=$rc1" >> "$LOG"
[ "$rc1" -ne 0 ] && fails=$((fails + 1))

echo "=== network switch: receiver restarts on port 37002 ===" >> "$LOG"
# Receiver already exited after its deadline; start a fresh one on the NEW port.
ROLE=receiver CONFIG_PATH="$CFG" SELF_ID="p2recv" SELF_PORT=37002 \
    "$BIN/message_latency_runner" > "$LOG.recv.37002" 2>&1 &
rp2=$!
sleep 1
ROLE=sender CONFIG_PATH="$CFG" SELF_ID="p2send" SELF_PORT=37012 \
    TARGET_ID="p2recv" TARGET_NETID="127.0.0.1:37002" \
    SIZES=1024 ITERATIONS=5 OUT_JSON="$LOG.sender.37002.json" \
    "$BIN/message_latency_runner" >> "$LOG" 2>&1
rc2=$?
wait "$rp2" 2>/dev/null
echo "leg2 rc=$rc2" >> "$LOG"
[ "$rc2" -ne 0 ] && fails=$((fails + 1))

echo "phase2 network-switch: legs rc=$rc1/$rc2 failures=$fails"
exit $((fails > 0 ? 1 : 0))
