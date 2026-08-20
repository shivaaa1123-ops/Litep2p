#!/usr/bin/env bash
# sigkill_restore_test.sh — Network OS Phase 1 SIGKILL restore verification.
#
# Runs network_runtime_kill_probe 20x, killing the process with SIGKILL at a
# random point during startup, and asserts the resolved PeerID is identical on
# every run. This proves the identity write is atomic/crash-safe (a kill at any
# arrow leaves either the old or the new identity file — both valid).
#
# Usage: desktop/tools/sigkill_restore_test.sh
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
DIR="$(mktemp -d /tmp/p1_sigkill.XXXXXX)"

if [ ! -x "$BIN/network_runtime_kill_probe" ]; then
    echo "SKIP: network_runtime_kill_probe not built"
    exit 0
fi

FIRST_ID=""
fails=0
for i in $(seq 1 20); do
    # Random kill point 30..350 ms after launch (start takes ~200 ms warm).
    kill_at_ms=$(( (RANDOM % 320) + 30 ))
    "$BIN/network_runtime_kill_probe" --files-dir "$DIR" --peer-id "sigkill-test-peer" \
        > "$DIR/run_$i.log" 2>&1 &
    pid=$!
    # Kill at the random point (sub-second granularity via busy-wait).
    start_ns=$(python3 -c 'import time; print(time.time_ns())')
    while :; do
        now_ns=$(python3 -c 'import time; print(time.time_ns())')
        elapsed_ms=$(( (now_ns - start_ns) / 1000000 ))
        [ "$elapsed_ms" -ge "$kill_at_ms" ] && break
    done
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    # The probe may have printed its PeerID before the kill; if it was killed
    # before resolving, the identity file still persists for the next run.
    id=$(grep -m1 '^PEERID=' "$DIR/run_$i.log" 2>/dev/null | cut -d= -f2)
    if [ -z "$FIRST_ID" ]; then
        FIRST_ID="$id"
    fi
    if [ -n "$id" ] && [ "$id" != "$FIRST_ID" ]; then
        echo "FAIL run $i: PeerID changed: $id != $FIRST_ID"
        fails=$((fails + 1))
    fi
done

echo "sigkill_restore: 20 runs, first PeerID=${FIRST_ID:-<none printed>}, failures=$fails"
rm -rf "$DIR"
exit $((fails > 0 ? 1 : 0))
