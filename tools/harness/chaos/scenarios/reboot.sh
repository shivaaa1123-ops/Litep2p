#!/usr/bin/env bash
# §46: full device reboot; runtime must come back consistent after boot.
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-2}"
for i in $(seq 1 "$N"); do
  adb -s "$S" reboot || { chaos_result reboot SKIP "cannot reboot"; exit 2; }
  adb -s "$S" wait-for-device
  sleep 25   # boot settle
  chaos_verify_consistent "$S" || { chaos_result reboot FAIL "iter $i"; exit 1; }
done
chaos_result reboot PASS "$N/$N"
