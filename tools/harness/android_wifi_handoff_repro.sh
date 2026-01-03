#!/usr/bin/env bash
set -euo pipefail

# One-command Android LTE<->WiFi style handoff repro + log capture.
#
# This script:
# - Clears logcat
# - Restarts the Android app
# - Toggles WiFi off -> on (simulates LTE->WiFi handoff behavior where availability may not go false)
# - Captures high-signal logs into timestamped files
#
# Requirements:
# - `adb` available on PATH
# - Device connected/authorized
#
# Optional environment variables:
# - ANDROID_PKG (default: com.zeengal.litep2p)
# - ANDROID_ACTIVITY (default: .MainActivity)
# - TAGS (default: LiteP2P_Native:I Litep2p:W)

ANDROID_PKG="${ANDROID_PKG:-com.zeengal.litep2p}"
ANDROID_ACTIVITY="${ANDROID_ACTIVITY:-.MainActivity}"
TAGS="${TAGS:-LiteP2P_Native:I Litep2p:W}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/tools/harness/runs"
mkdir -p "${OUT_DIR}"

TS="$(date +%Y%m%d_%H%M%S)"
OUT_LOG="${OUT_DIR}/android_handoff_${TS}.log"

echo "==> Clearing logcat"
adb logcat -c

echo "==> Restarting app: ${ANDROID_PKG}/${ANDROID_ACTIVITY}"
adb shell am force-stop "${ANDROID_PKG}" || true
adb shell am start -n "${ANDROID_PKG}/${ANDROID_ACTIVITY}"
sleep 2

echo "==> WiFi disable (simulate LTE)"
adb shell svc wifi disable || true
sleep 5

echo "==> WiFi enable (handoff to WiFi)"
adb shell svc wifi enable || true
sleep 12

echo "==> Dumping logcat to ${OUT_LOG}"
adb logcat -d -v time -s ${TAGS} > "${OUT_LOG}"

echo
echo "==> High-signal excerpts:"
grep -E "Network change detected|Discovery: Found peer|Upgrading CONNECTING peer|Endpoint changed while CONNECTING|Attempting to connect|CONNECT_SUCCESS|CONNECT_FAILED|HANDSHAKE_FAILED|CONNECT_REQUEST|PEER_LIST|Hole punch" "${OUT_LOG}" \
  | tail -n 200 || true

echo
echo "==> Saved: ${OUT_LOG}"


