#!/usr/bin/env bash
# §46: clock change (+/- hours); TTL math must stay sane (no mass-expiry crash).
set -u; cd "$(dirname "$0")/.."; source ./chaos_lib.sh
S="${1:?}"; N="${2:-2}"
for i in $(seq 1 "$N"); do
  adb -s "$S" shell "date @\$(($(date +%s) + 7200))" >/dev/null 2>&1 || adb -s "$S" shell su -c 'date @'"$(date +%s)" >/dev/null 2>&1 || { chaos_result change_time SKIP "needs set-time permission"; exit 2; }
  sleep 3
  chaos_verify_consistent "$S" || { chaos_result change_time FAIL "forward jump iter $i"; exit 1; }
  adb -s "$S" shell "date @\$(($(date +%s)))" >/dev/null 2>&1
done
chaos_result change_time PASS "$N/$N"
