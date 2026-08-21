#!/usr/bin/env bash
# §46: device sleep/wake (Doze entry/exit); idle must create almost no work (inv 11).
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-3}"
for i in $(seq 1 "$N"); do
  adb -s "$S" shell input keyevent KEYCODE_SLEEP 2>/dev/null || adb -s "$S" shell "input keyevent 26"; sleep 8
  adb -s "$S" shell input keyevent KEYCODE_WAKEUP 2>/dev/null || adb -s "$S" shell "input keyevent 26"; sleep 4
  chaos_verify_consistent "$S" || { chaos_result sleep_wake FAIL "iter $i"; exit 1; }
done
chaos_result sleep_wake PASS "$N/$N"
