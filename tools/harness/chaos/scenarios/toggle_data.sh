#!/usr/bin/env bash
# §46: mobile data off/on.
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-3}"
for i in $(seq 1 "$N"); do
  adb -s "$S" shell svc data disable; sleep 4
  adb -s "$S" shell svc data enable;  sleep 6
  chaos_verify_consistent "$S" || { chaos_result toggle_data FAIL "iter $i"; exit 1; }
done
chaos_result toggle_data PASS "$N/$N"
