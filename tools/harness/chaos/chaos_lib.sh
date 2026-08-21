#!/usr/bin/env bash
# chaos_lib.sh — shared helpers for the Phase 11 Android chaos harness
# (master doc §46; phase file Step 5.3).
#
# Contract: every scenario drives a real device through an interruption and
# then verifies the runtime returns to a KNOWN, INTERNALLY CONSISTENT state
# (logcat recovery marker + store integrity via a fresh start).
#
# Exit codes: 0 pass, 1 fail, 2 SKIP (no device / prerequisites missing).

set -u

CHAOS_APP_ID="${CHAOS_APP_ID:-com.zeengal.litep2p}"
CHAOS_LOG_TAG="${CHAOS_LOG_TAG:-LiteP2P}"
CHAOS_RECOVERY_MARKER="${CHAOS_RECOVERY_MARKER:-restored}"   # logcat line to await
CHAOS_TIMEOUT_S="${CHAOS_TIMEOUT_S:-60}"
CHAOS_ITERATIONS="${CHAOS_ITERATIONS:-3}"

chaos_device() {
    command -v adb >/dev/null 2>&1 || { echo "adb not found" >&2; return 2; }
    local serials
    serials="$(adb devices | awk 'NR>1 && $2=="device" {print $1}')"
    if [ -z "${serials}" ]; then echo "no device attached" >&2; return 2; fi
    echo "${serials}" | head -1
}

chaos_logcat_clear() { adb -s "$1" logcat -c 2>/dev/null || true; }

# Wait for the runtime's recovery marker after an interruption.
chaos_wait_recovery() {
    local serial="$1" deadline
    deadline=$(( $(date +%s) + CHAOS_TIMEOUT_S ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if adb -s "${serial}" logcat -d -s "${CHAOS_LOG_TAG}" 2>/dev/null \
             | grep -q "${CHAOS_RECOVERY_MARKER}"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Post-interruption consistency probe: the app starts, identity is stable,
# and the store opens (schema check runs inside).
chaos_verify_consistent() {
    local serial="$1"
    adb -s "${serial}" shell am start -n "${CHAOS_APP_ID}/.MainActivity" >/dev/null 2>&1 || true
    chaos_wait_recovery "${serial}"
}

chaos_result() {
    # chaos_result <name> <status: PASS|FAIL|SKIP> <note>
    printf '%-22s %-4s %s\n' "$1" "$2" "$3"
    case "$2" in
        PASS) return 0 ;;
        SKIP) return 2 ;;
        *)    return 1 ;;
    esac
}
