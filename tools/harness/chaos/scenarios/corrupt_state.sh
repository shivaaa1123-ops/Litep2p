#!/usr/bin/env bash
# §46 (test env): corrupt a byte of the store file; runtime must fail-safe and
# reopen cleanly (crash-safe open path), never start with silently broken state.
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-2}"
DB="/data/data/$CHAOS_APP_ID/files/networkos.sqlite"
for i in $(seq 1 "$N"); do
  adb -s "$S" shell am force-stop "$CHAOS_APP_ID"
  # Requires a debuggable build / run-as access; otherwise skip honestly.
  if ! adb -s "$S" shell "run-as $CHAOS_APP_ID test -f $DB" 2>/dev/null; then
    chaos_result corrupt_state SKIP "store not accessible (release build?)"; exit 2
  fi
  SZ=$(adb -s "$S" shell "run-as $CHAOS_APP_ID stat -c %s $DB" | tr -d '\r')
  OFF=$((SZ / 2))
  adb -s "$S" shell "run-as $CHAOS_APP_ID dd if=/dev/zero of=$DB bs=1 seek=$OFF count=1 conv=notrunc" >/dev/null 2>&1
  chaos_verify_consistent "$S" || { chaos_result corrupt_state FAIL "iter $i did not fail safe"; exit 1; }
done
chaos_result corrupt_state PASS "$N/$N fail-safe on corruption"
