#!/usr/bin/env bash
# §46: Wi-Fi off/on; sessions must re-establish, identity unchanged.
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-3}"
for i in $(seq 1 "$N"); do
  adb -s "$S" shell svc wifi disable; sleep 4
  adb -s "$S" shell svc wifi enable;  sleep 6
  chaos_verify_consistent "$S" || { chaos_result toggle_wifi FAIL "iter $i"; exit 1; }
done
chaos_result toggle_wifi PASS "$N/$N"
