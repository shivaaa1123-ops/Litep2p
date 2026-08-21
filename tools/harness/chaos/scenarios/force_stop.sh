#!/usr/bin/env bash
# §46: force-stop (pm) then cold start.
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-3}"
for i in $(seq 1 "$N"); do
  chaos_logcat_clear "$S"
  adb -s "$S" shell am force-stop "$CHAOS_APP_ID"; sleep 2
  chaos_verify_consistent "$S" || { chaos_result force_stop FAIL "iter $i"; exit 1; }
done
chaos_result force_stop PASS "$N/$N"
