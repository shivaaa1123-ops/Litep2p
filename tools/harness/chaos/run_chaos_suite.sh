#!/usr/bin/env bash
# run_chaos_suite.sh — Phase 11 Android chaos suite orchestrator (§46).
# Runs every scenario ITERATIONS times per connected device; each scenario
# must return the runtime to a known, consistent state EVERY time.
# Usage: tools/harness/chaos/run_chaos_suite.sh [--iterations N]
set -u
cd "$(dirname "$0")"
# shellcheck source=chaos_lib.sh
source ./chaos_lib.sh

ITER="${CHAOS_ITERATIONS}"
[ "${1:-}" = "--iterations" ] && [ -n "${2:-}" ] && ITER="$2"

SERIAL="$(chaos_device)" || { chaos_result suite SKIP "no adb device"; exit 2; }
echo "chaos suite on device: ${SERIAL} (iterations=${ITER})"

declare -a SCENARIOS=(
    scenarios/kill_app.sh
    scenarios/force_stop.sh
    scenarios/toggle_wifi.sh
    scenarios/toggle_data.sh
    scenarios/network_switch.sh
    scenarios/reboot.sh
    scenarios/fill_storage.sh
    scenarios/change_time.sh
    scenarios/sleep_wake.sh
    scenarios/corrupt_state.sh
)

pass=0; fail=0; skip=0
for s in "${SCENARIOS[@]}"; do
    [ -x "$s" ] || s="bash $s"
    out="$(bash "$s" "${SERIAL}" "${ITER}" 2>&1)"
    rc=$?
    case $rc in
        0) pass=$((pass+1)); echo "$out" ;;
        2) skip=$((skip+1)); echo "$out" ;;
        *) fail=$((fail+1)); echo "$out" ;;
    esac
done

echo "----------------------------------------"
echo "chaos suite: ${pass} pass, ${fail} fail, ${skip} skip"
[ "${fail}" -eq 0 ]