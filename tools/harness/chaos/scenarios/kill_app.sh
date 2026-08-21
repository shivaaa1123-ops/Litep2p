#!/usr/bin/env bash
# §46: kill the app process; runtime must recover to a consistent state.
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?serial}"; N="${2:-3}"
for i in $(seq 1 "$N"); do
  chaos_logcat_clear "$S"
  adb -s "$S" shell am start -n "$CHAOS_APP_ID/.MainActivity" >/dev/null 2>&1; sleep 5
  adb -s "$S" shell "p -f $CHAOS_APP_ID" >/dev/null 2>&1 || adb -s "$S" shell "kill \$(pidof $CHAOS_APP_ID)" >/dev/null 2>&1 || true
  sleep 2
  chaos_verify_consistent "$S" || { chaos_result kill_app FAIL "iter $i no recovery"; exit 1; }
done
chaos_result kill_app PASS "$N/$N recovered"
