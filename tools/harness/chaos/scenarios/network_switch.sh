#!/usr/bin/env bash
# §46: switch networks (wifi -> data -> wifi); identity must not change (inv 12).
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-3}"
for i in $(seq 1 "$N"); do
  adb -s "$S" shell svc wifi disable; sleep 3
  adb -s "$S" shell svc data enable; sleep 5
  adb -s "$S" shell svc data disable; sleep 3
  adb -s "$S" shell svc wifi enable; sleep 6
  chaos_verify_consistent "$S" || { chaos_result network_switch FAIL "iter $i"; exit 1; }
done
chaos_result network_switch PASS "$N/$N"
