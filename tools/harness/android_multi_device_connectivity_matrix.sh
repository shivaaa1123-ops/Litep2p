#!/usr/bin/env bash
set -euo pipefail

# Run the Android connectivity matrix on multiple Android devices (adb serials),
# while keeping a shared set of desktop peers running.
#
# This is useful when you actually have N real Android devices and want to
# validate handoff behavior across them all.
#
# Environment variables:
# - ADB_BIN (default: adb)
# - ANDROID_SERIALS (optional) comma-separated adb serials. If unset, auto-detect all "device" entries.
# - REQUIRE_ANDROID_COUNT (default: 1) fail if fewer devices are detected.
# - ANDROID_ID_PREFIX (default: android-) sets ANDROID_PEER_ID as ${ANDROID_ID_PREFIX}${idx}
# - DESKTOP_COUNT (default: 5) number of desktop peers to start
# - DESKTOP_CONFIG (default: ./config.json)
# - DESKTOP_BIN (optional) desktop peer binary
# - DESKTOP_ID_PREFIX (default: desktop-)
# - DESKTOP_BASE_PORT (default: 31001)
# - DESKTOP_LOG_LEVEL (default: info)
# - LOOPS (default: 3)
# - SCENARIOS (default: wifi,data,no_network)
# - FORCE_TRANSPORT_BREAK (default: 1)
# - ENFORCE_SLA (default: 1)
# - SLA_SECONDS (default: 8)
# - SLA_REQUIRE_READY (default: 0)
# - WATCHDOG_ENABLE (default: 1)
# - STABILIZE_SECS (default: 3)
# - WIFI_DISABLE_SECS / WIFI_ENABLE_SECS / DATA_DISABLE_SECS / DATA_ENABLE_SECS / AIRPLANE_* (optional)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADB_BIN="${ADB_BIN:-adb}"

ANDROID_SERIALS="${ANDROID_SERIALS:-}"
REQUIRE_ANDROID_COUNT="${REQUIRE_ANDROID_COUNT:-1}"
ANDROID_ID_PREFIX="${ANDROID_ID_PREFIX:-android-}"

DESKTOP_COUNT="${DESKTOP_COUNT:-5}"
DESKTOP_CONFIG="${DESKTOP_CONFIG:-${ROOT_DIR}/config.json}"
DESKTOP_BIN="${DESKTOP_BIN:-}"
DESKTOP_ID_PREFIX="${DESKTOP_ID_PREFIX:-desktop-}"
DESKTOP_BASE_PORT="${DESKTOP_BASE_PORT:-31001}"
DESKTOP_LOG_LEVEL="${DESKTOP_LOG_LEVEL:-info}"

LOOPS="${LOOPS:-3}"
SCENARIOS="${SCENARIOS:-wifi,data,no_network}"
FORCE_TRANSPORT_BREAK="${FORCE_TRANSPORT_BREAK:-1}"
ENFORCE_SLA="${ENFORCE_SLA:-1}"
SLA_SECONDS="${SLA_SECONDS:-8}"
SLA_REQUIRE_READY="${SLA_REQUIRE_READY:-0}"
WATCHDOG_ENABLE="${WATCHDOG_ENABLE:-1}"
STABILIZE_SECS="${STABILIZE_SECS:-3}"

serials=()
if [[ -n "${ANDROID_SERIALS}" ]]; then
  IFS=',' read -r -a serials <<<"${ANDROID_SERIALS}"
else
  # Auto-detect authorized devices.
  while IFS= read -r s; do
    [[ -n "${s}" ]] && serials+=("${s}")
  done < <("${ADB_BIN}" devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}')
fi

# Trim whitespace.
for i in "${!serials[@]}"; do
  serials[$i]="$(printf '%s' "${serials[$i]}" | tr -d '[:space:]')"
done

if [[ "${#serials[@]}" -lt "${REQUIRE_ANDROID_COUNT}" ]]; then
  echo "ERROR: Need at least ${REQUIRE_ANDROID_COUNT} Android devices, but detected ${#serials[@]}." >&2
  echo "Hint: set ANDROID_SERIALS=serial1,serial2,... or plug in more devices." >&2
  "${ADB_BIN}" devices -l || true
  exit 1
fi

echo "==> Detected Android devices (${#serials[@]}): ${serials[*]}"

echo "==> Starting ${DESKTOP_COUNT} desktop peers (shared)"
peer_out="$(
  cd "${ROOT_DIR}" && \
  COUNT="${DESKTOP_COUNT}" \
  ID_PREFIX="${DESKTOP_ID_PREFIX}" \
  BASE_PORT="${DESKTOP_BASE_PORT}" \
  DESKTOP_BIN="${DESKTOP_BIN}" \
  CONFIG="${DESKTOP_CONFIG}" \
  LOG_LEVEL="${DESKTOP_LOG_LEVEL}" \
  RUNS_DIR="${ROOT_DIR}/tools/harness/runs" \
  "${ROOT_DIR}/tools/harness/start_desktop_peers.sh"
)"

echo "${peer_out}"
DESKTOP_PEERS_RUN_DIR="$(printf '%s\n' "${peer_out}" | awk -F': ' '/Desktop peers run dir:/ {print $2; exit}')"
if [[ -z "${DESKTOP_PEERS_RUN_DIR}" ]]; then
  echo "ERROR: Could not determine desktop peers run dir." >&2
  exit 1
fi

cleanup() {
  set +e
  "${ROOT_DIR}/tools/harness/stop_desktop_peers.sh" "${DESKTOP_PEERS_RUN_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Export common knobs used by android_connectivity_matrix.sh / android_wifi_handoff_repro.sh.
export LOOPS SCENARIOS FORCE_TRANSPORT_BREAK ENFORCE_SLA SLA_SECONDS SLA_REQUIRE_READY WATCHDOG_ENABLE STABILIZE_SECS

# Keep the same conservative defaults as android_connectivity_matrix.sh (unless user overrides).
export WIFI_DISABLE_SECS="${WIFI_DISABLE_SECS:-8}"
export WIFI_ENABLE_SECS="${WIFI_ENABLE_SECS:-15}"
export DATA_DISABLE_SECS="${DATA_DISABLE_SECS:-4}"
export DATA_ENABLE_SECS="${DATA_ENABLE_SECS:-4}"
export AIRPLANE_ENABLE_SECS="${AIRPLANE_ENABLE_SECS:-8}"
export AIRPLANE_DISABLE_SECS="${AIRPLANE_DISABLE_SECS:-12}"

idx=1
for serial in "${serials[@]}"; do
  if [[ -z "${serial}" ]]; then
    continue
  fi

  echo
  echo "================================================================================"
  echo "==> Android device ${idx}/${#serials[@]} serial=${serial}"

  # Run the standard harness per device, but do NOT start/stop desktop peers inside each run.
  ANDROID_SERIAL="${serial}" \
  ANDROID_PEER_ID="${ANDROID_ID_PREFIX}${idx}" \
  START_DESKTOP=0 \
  bash "${ROOT_DIR}/tools/harness/android_wifi_handoff_repro.sh"

  idx=$((idx + 1))
done

echo
echo "==> Done. Desktop peers logs: ${DESKTOP_PEERS_RUN_DIR}"
