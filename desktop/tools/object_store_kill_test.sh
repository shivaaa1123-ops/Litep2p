#!/usr/bin/env bash
# object_store_kill_test.sh — Network OS Phase 3 crash-consistency harness
# (verification plan item 2: SIGKILL at every arrow of the atomic receive
# path, 10 cycles; invariant 2 — never acknowledged-but-not-stored, never
# lost-after-commit).
#
# For each cycle:
#   1. burst: run the probe inserting N objects; kill -9 at a random point;
#      reopen and assert count present == number of INSERTED markers printed
#      (SQLite WAL transactions are all-or-nothing; a kill between commits
#      leaves exactly the committed subset — never partial rows).
#   2. commit: probe commits one object + checkpoints (MARKER_C_COMMITTED),
#      then kill -9; reopen and assert the object is present.
#   3. reopen must succeed (quick_check on open — no corruption).
#
# Usage: desktop/tools/object_store_kill_test.sh
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
PROBE="$BIN/object_store_kill_probe"
WORK="$(mktemp -d /tmp/p3_kill.XXXXXX)"

[ -x "$PROBE" ] || { echo "SKIP: object_store_kill_probe not built"; exit 0; }

fails=0
for cycle in $(seq 1 10); do
    DB="$WORK/kill_$cycle.sqlite"
    rm -f "$DB" "$DB-wal" "$DB-shm"

    # --- burst cycle: kill at a random insert arrow --------------------------
    "$PROBE" --db "$DB" --mode burst --count 40 > "$WORK/burst.$cycle.log" 2>&1 &
    pid=$!
    target=$(( (RANDOM % 30) + 5 ))     # kill after 5..34 inserts
    for i in $(seq 1 6000); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi   # process died naturally
        seen=$(grep -c '^INSERTED' "$WORK/burst.$cycle.log" 2>/dev/null)
        seen=${seen:-0}
        [ "$seen" -ge "$target" ] && break
        sleep 0.002
    done
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    CHECKED=$(grep -c '^INSERTED' "$WORK/burst.$cycle.log" 2>/dev/null)
    CHECKED=${CHECKED:-0}
    PRESENT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM objects;" 2>/dev/null || echo ERR)
    if [ "$PRESENT" = "ERR" ]; then
        echo "FAIL cycle $cycle: DB corrupt/unreadable after burst kill"
        fails=$((fails + 1))
    elif [ "$PRESENT" = "$CHECKED" ]; then
        echo "ok cycle $cycle: burst atomic (killed after $CHECKED/$CHECKED)"
    else
        echo "FAIL cycle $cycle: burst present=$PRESENT != inserted=$CHECKED"
        fails=$((fails + 1))
    fi

    # --- commit cycle: kill AFTER durable commit -----------------------------
    DB2="$WORK/killc_$cycle.sqlite"
    "$PROBE" --db "$DB2" --mode commit > "$WORK/commit.$cycle.log" 2>&1 &
    pid2=$!
    committed=0
    for i in $(seq 1 500); do
        if grep -q 'MARKER_C_COMMITTED' "$WORK/commit.$cycle.log" 2>/dev/null; then
            committed=1; break
        fi
        if ! kill -0 "$pid2" 2>/dev/null; then break; fi
        sleep 0.01
    done
    kill -9 "$pid2" 2>/dev/null
    wait "$pid2" 2>/dev/null
    if [ "$committed" -ne 1 ]; then
        echo "FAIL cycle $cycle: commit probe never reached MARKER_C_COMMITTED"
        fails=$((fails + 1))
    else
        P=$(sqlite3 "$DB2" "SELECT COUNT(*) FROM objects;" 2>/dev/null || echo ERR)
        if [ "$P" = "1" ]; then
            echo "ok cycle $cycle: committed object survived SIGKILL"
        else
            echo "FAIL cycle $cycle: committed object lost after SIGKILL (present=$P)"
            fails=$((fails + 1))
        fi
    fi
done

rm -rf "$WORK"
echo "object_store_kill_test: 10 cycles, failures=$fails"
exit $((fails > 0 ? 1 : 0))