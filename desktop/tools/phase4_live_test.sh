#!/usr/bin/env bash
# phase4_live_test.sh — Network OS Phase 4 live handoff smoke (Verification 6).
# 2 sessions x 3 runs: S -> C durable handoff over a real encrypted session
# with D offline; then the sender "restarts" (new process, same files_dir) and
# proves the signed lease + DURABILITY_REACHED state survived (kill-proof).
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
CFG="$REPO/desktop/tools/phase0_bench_config.json"
LOG=/tmp/p4_live.log

[ -x "$BIN/handoff_live" ] || { echo "SKIP: handoff_live not built"; exit 0; }

> "$LOG"
fails=0
for s in 1 2; do
    for r in 1 2 3; do
        echo "=== session $s run $r ===" >> "$LOG"
        W=/tmp/p4_live_${s}${r}
        rm -rf "$W" && mkdir -p "$W/c" "$W/s"

        "$BIN/handoff_live" --role carrier --id p4carrier --port 33121 \
            --files-dir "$W/c" --config "$CFG" \
            --carrier-pk-file "$W/c_pk.hex" --sender-pk-file "$W/s_pk.hex" \
            --target-id p4sender > "$W/carrier.log" 2>&1 &
        CPID=$!
        sleep 2

        "$BIN/handoff_live" --role sender --id p4sender --port 33122 \
            --files-dir "$W/s" --config "$CFG" \
            --target-id p4carrier --target-netid 127.0.0.1:33121 \
            --carrier-pk-file "$W/c_pk.hex" --sender-pk-file "$W/s_pk.hex" \
            > "$W/sender.log" 2>&1
        SRC=$?
        sleep 1
        kill "$CPID" 2>/dev/null
        wait "$CPID" 2>/dev/null

        MARKER=$(grep '^HANDOFF_COMPLETE' "$W/sender.log" | awk '{print $2}')
        CARRIER_STORED=$(grep -c '^CARRIER_STORED$' "$W/carrier.log" 2>/dev/null)
        echo "session ${s}${r}: sender_rc=$SRC carrier_stored=$CARRIER_STORED marker=${MARKER:-none}" >> "$LOG"

        if [ "$SRC" -ne 0 ] || [ -z "${MARKER:-}" ] || [ "$CARRIER_STORED" -lt 1 ]; then
            echo "  FAIL session ${s}${r}" >> "$LOG"
            fails=$((fails + 1))
            continue
        fi

        # Restart the sender against the SAME files_dir -> prove durability.
        "$BIN/handoff_live" --role sender --id p4sender --files-dir "$W/s" \
            --verify 1 --marker "$MARKER" >> "$LOG" 2>&1
        VRC=$?
        echo "  restart_proof_rc=$VRC" >> "$LOG"
        [ "$VRC" -ne 0 ] && fails=$((fails + 1))
    done
done

echo "phase4 live handoff: 6 runs, failures=$fails" | tee -a "$LOG"
exit $((fails > 0 ? 1 : 0))
