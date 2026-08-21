#!/usr/bin/env bash
# §46: fill storage until low-space, verify honest rejection + recovery (inv 7).
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-2}"
for i in $(seq 1 "$N"); do
  adb -s "$S" shell "dd if=/dev/zero of=/sdcard/chaos_fill.bin bs=1048576 count=512" >/dev/null 2>&1
  sleep 3
  chaos_verify_consistent "$S" || { chaos_result fill_storage FAIL "iter $i under pressure"; adb -s "$S" shell rm -f /sdcard/chaos_fill.bin; exit 1; }
  adb -s "$S" shell rm -f /sdcard/chaos_fill.bin
  chaos_verify_consistent "$S" || { chaos_result fill_storage FAIL "iter $i after relief"; exit 1; }
done
chaos_result fill_storage PASS "$N/$N honest pressure handling"
