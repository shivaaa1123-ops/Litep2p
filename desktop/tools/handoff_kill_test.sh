#!/usr/bin/env bash
# handoff_kill_test.sh — Network OS Phase 4 SIGKILL harness (verification plan
# item 2: kill-at-every-arrow, 10 cycles; invariant 2 — never
# acknowledged-but-not-stored; all-or-nothing single-transaction commit).
#
# For each cycle: launch the carrier probe, kill -9 at a random arrow
# (CARRIER_OPENED / OFFER_RECEIVED / ACCEPT_SENT / DATA_RECEIVED / COMMIT),
# then reopen the DB and assert:
#   - reopen succeeds (quick_check on open — no corruption)
#   - objects == leases (0/0 pre-commit, 1/1 post-commit — never mixed)
#   - if ACK_SENT was printed, the state must be 1/1 (committed)
#
# Usage: desktop/tools/handoff_kill_test.sh
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
PROBE="$BIN/handoff_kill_probe"
WORK="$(mktemp -d /tmp/p4_kill.XXXXXX)"

[ -x "$PROBE" ] || { echo "SKIP: handoff_kill_probe not built"; exit 0; }

fails=0
for cycle in $(seq 1 10); do
    DB="$WORK/kill_$cycle.sqlite"
    rm -f "$DB" "$DB-wal" "$DB-shm"

    "$PROBE" --db "$DB" --mode run > "$WORK/run.$cycle.log" 2>&1 &
    pid=$!
    # Kill at a random arrow: after 2..7 markers (before or mid-commit).
    target=$(( (RANDOM % 6) + 2 ))
    for i in $(seq 1 2000); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        seen=$(grep -cE '^(CARRIER_OPENED|OFFER_RECEIVED|ACCEPT_SENT|DATA_RECEIVED|ACK_SENT|RUN_DONE)$' "$WORK/run.$cycle.log" 2>/dev/null)
        seen=${seen:-0}
        [ "$seen" -ge "$target" ] && break
        sleep 0.002
    done
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    MARKERS=$(grep -cE '^(CARRIER_OPENED|OFFER_RECEIVED|ACCEPT_SENT|DATA_RECEIVED|ACK_SENT|RUN_DONE)$' "$WORK/run.$cycle.log" 2>/dev/null)
    MARKERS=${MARKERS:-0}
    ACKED=$(grep -c '^ACK_SENT$' "$WORK/run.$cycle.log" 2>/dev/null)

    # Verify: reopen must succeed and object<->lease must be all-or-nothing.
    VOUT=$("$PROBE" --db "$DB" --mode verify 2>&1)
    if [ $? -ne 0 ]; then
        echo "FAIL cycle $cycle: verify failed (markers=$MARKERS acked=$ACKED): $VOUT"
        fails=$((fails + 1))
    else
        OBJS=$(echo "$VOUT" | sed -n 's/.*objects=\([0-9]*\).*/\1/p')
        LEASES=$(echo "$VOUT" | sed -n 's/.*leases=\([0-9]*\).*/\1/p')
        if [ "$ACKED" = "1" ] && [ "$OBJS" != "1" ]; then
            echo "FAIL cycle $cycle: ACK_SENT but objects=$OBJS (acknowledged-but-not-stored!)"
            fails=$((fails + 1))
        elif [ "$OBJS" = "$LEASES" ]; then
            echo "ok cycle $cycle: markers=$MARKERS acked=$ACKED objects=$OBJS leases=$LEASES"
        else
            echo "FAIL cycle $cycle: partial commit objects=$OBJS leases=$LEASES"
            fails=$((fails + 1))
        fi
    fi
done

rm -rf "$WORK"
echo "handoff_kill_test: 10 cycles, failures=$fails"
exit $((fails > 0 ? 1 : 0))
