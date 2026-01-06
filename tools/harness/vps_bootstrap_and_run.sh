#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# One-command bootstrap + run for WAN/LAN reliability tests on a VPS.
#
# What it does:
# - Installs build/runtime deps (Ubuntu/Debian)
# - Builds the desktop peer + session_manager_test
# - Runs unit tests (fast gate)
# - Starts a peer in daemon mode and prints how to tail logs
#
# Usage (on VPS):
#   sudo bash tools/harness/vps_bootstrap_and_run.sh
#
# Notes:
# - This script is designed to be copy/paste friendly for non-experts.
# - For WAN multi-node tests, run this on BOTH VPS peers, then we’ll run orchestration steps.

REPO_DIR="${REPO_DIR:-$PWD}"
PEER_ID="${PEER_ID:-vps-peer}"
PEER_PORT="${PEER_PORT:-30001}"
LOG_LEVEL="${LOG_LEVEL:-info}"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }; }

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash $0" >&2
  exit 1
fi

echo "==> Installing OS dependencies"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    python3 python3-venv \
    curl ca-certificates \
    git \
    iproute2 iptables
else
  echo "Unsupported distro (expected Debian/Ubuntu with apt-get)." >&2
  exit 2
fi

echo "==> Checking repo dir: ${REPO_DIR}"
cd "${REPO_DIR}"

need_cmd cmake

echo "==> Building desktop targets"
mkdir -p desktop/build_linux_harness
cd desktop/build_linux_harness
cmake -G Ninja ..
ninja litep2p_peer_linux session_manager_test || ninja litep2p_peer_mac session_manager_test || true

echo "==> Running unit tests (must pass)"
set +e
./bin/session_manager_test > "${REPO_DIR}/tools/harness/vps_session_manager_test.log" 2>&1
TEST_EXIT=$?
set -e
tail -n 30 "${REPO_DIR}/tools/harness/vps_session_manager_test.log" || true
if [[ "${TEST_EXIT}" -ne 0 ]]; then
  echo "Unit tests FAILED on this VPS (exit=${TEST_EXIT}). Fix before proceeding." >&2
  exit "${TEST_EXIT}"
fi

echo "==> Starting peer daemon"
PEER_BIN=""
if [[ -x "./bin/litep2p_peer_linux" ]]; then PEER_BIN="./bin/litep2p_peer_linux"; fi
if [[ -z "${PEER_BIN}" && -x "./bin/litep2p_peer_mac" ]]; then PEER_BIN="./bin/litep2p_peer_mac"; fi
if [[ -z "${PEER_BIN}" ]]; then
  echo "Could not find a peer binary in ./bin (expected litep2p_peer_linux or litep2p_peer_mac)." >&2
  exit 3
fi

LOG_FILE="${REPO_DIR}/tools/harness/vps_peer_${PEER_ID}.log"
PID_FILE="${REPO_DIR}/tools/harness/vps_peer_${PEER_ID}.pid"

mkdir -p "${REPO_DIR}/tools/harness"
rm -f "${PID_FILE}"

("${PEER_BIN}" --id "${PEER_ID}" --port "${PEER_PORT}" --no-tui --daemon --log-level "${LOG_LEVEL}" > "${LOG_FILE}" 2>&1 & echo $! > "${PID_FILE}")
sleep 1

echo
echo "==> Peer started"
echo "    id=${PEER_ID} port=${PEER_PORT}"
echo "    pid=$(cat "${PID_FILE}")"
echo "    log=${LOG_FILE}"
echo
echo "Tail logs:"
echo "  tail -f ${LOG_FILE}"
echo
echo "Stop peer:"
echo "  kill -TERM \$(cat ${PID_FILE})"


