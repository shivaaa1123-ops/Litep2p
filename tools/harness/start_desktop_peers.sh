#!/usr/bin/env bash
set -euo pipefail

# Start multiple desktop peers (macOS/Linux) in daemon mode, with per-peer logs + pidfiles.
#
# Environment variables:
# - COUNT (default: 3)
# - ID_PREFIX (default: desktop-)
# - BASE_PORT (default: 31001)
# - DESKTOP_BIN (optional) explicit path to litep2p_peer_* binary
# - CONFIG (default: ./config.json)
# - LOG_LEVEL (default: info)
# - RUNS_DIR (default: ./tools/harness/runs)
#
# Remote machine support (to avoid NAT hairpinning when peers are behind the same NAT):
# - REMOTE_HOST (optional) SSH target like user@host
# - REMOTE_PASS (optional) SSH password (uses sshpass)
# - REMOTE_BIN (optional) path to litep2p binary on remote machine (default: ~/litep2p/litep2p_peer_linux)
# - REMOTE_CONFIG (optional) path to config on remote machine (default: ~/litep2p/config.json)
# - REMOTE_COUNT (default: half of COUNT, rounded down) number of peers to start on remote machine
#
# Output:
# - Creates ./tools/harness/runs/desktop_peers_<timestamp>/
#   - <id>.log
#   - <id>.pid
# - Updates symlink: ./tools/harness/runs/desktop_peers_latest -> that directory

COUNT="${COUNT:-3}"
ID_PREFIX="${ID_PREFIX:-desktop-}"
BASE_PORT="${BASE_PORT:-31001}"
DESKTOP_BIN="${DESKTOP_BIN:-}"
CONFIG="${CONFIG:-./config.json}"
LOG_LEVEL="${LOG_LEVEL:-info}"
RUNS_DIR="${RUNS_DIR:-./tools/harness/runs}"

# Remote machine settings
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_PASS="${REMOTE_PASS:-}"
REMOTE_BIN="${REMOTE_BIN:-~/litep2p/litep2p_peer_linux}"
REMOTE_CONFIG="${REMOTE_CONFIG:-~/litep2p/config.json}"
# By default, run half the peers on remote (to test cross-machine connectivity)
REMOTE_COUNT="${REMOTE_COUNT:-$((COUNT / 2))}"

pick_bin() {
  if [[ -n "${DESKTOP_BIN}" ]]; then
    echo "${DESKTOP_BIN}"
    return 0
  fi

  local c
  for c in \
    "./desktop/build_mac/bin/litep2p_peer_mac" \
    "./desktop/build_linux/bin/litep2p_peer_linux" \
    "./desktop/build_linux_docker/bin/litep2p_peer_linux" \
    "./build/litep2p_peer"; do
    if [[ -x "$c" ]]; then
      echo "$c"
      return 0
    fi
  done

  return 1
}

if [[ ! -f "${CONFIG}" ]]; then
  echo "ERROR: config not found: ${CONFIG}" >&2
  exit 1
fi

BIN="$(pick_bin)" || {
  echo "ERROR: desktop peer binary not found. Build it first (macOS): cd desktop && ./build_mac.sh" >&2
  exit 1
}

TS="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${RUNS_DIR}/desktop_peers_${TS}"
mkdir -p "${RUN_DIR}"

# Helpful symlink for stop script.
ln -sfn "desktop_peers_${TS}" "${RUNS_DIR}/desktop_peers_latest"

echo "Desktop peers run dir: ${RUN_DIR}"
echo "bin=${BIN}"
echo "config=${CONFIG}"

# Check if we have remote machine configured
USE_REMOTE=0
if [[ -n "${REMOTE_HOST}" && "${REMOTE_COUNT}" -gt 0 ]]; then
  if command -v sshpass >/dev/null 2>&1 || [[ -z "${REMOTE_PASS}" ]]; then
    USE_REMOTE=1
    echo "remote_host=${REMOTE_HOST}"
    echo "remote_bin=${REMOTE_BIN}"
    echo "remote_count=${REMOTE_COUNT}"
    
    # Create remote log directory
    if [[ -n "${REMOTE_PASS}" ]]; then
      sshpass -p "${REMOTE_PASS}" ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "mkdir -p ~/litep2p/logs" 2>/dev/null || true
    else
      ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "mkdir -p ~/litep2p/logs" 2>/dev/null || true
    fi
  else
    echo "WARNING: sshpass not found and REMOTE_PASS set - skipping remote peers" >&2
  fi
fi

# Calculate which peers go where
LOCAL_COUNT=$((COUNT - REMOTE_COUNT))
if [[ "${USE_REMOTE}" != "1" ]]; then
  LOCAL_COUNT="${COUNT}"
  REMOTE_COUNT=0
fi

echo "local_count=${LOCAL_COUNT} remote_count=${REMOTE_COUNT}"

# Start local peers (first LOCAL_COUNT peers)
i=1
while [[ $i -le $LOCAL_COUNT ]]; do
  PORT=$((BASE_PORT + i - 1))
  ID="${ID_PREFIX}${i}"
  LOG="${RUN_DIR}/${ID}.log"
  PIDF="${RUN_DIR}/${ID}.pid"

  nohup "${BIN}" \
    --config "${CONFIG}" \
    --id "${ID}" \
    --port "${PORT}" \
    --log-level "${LOG_LEVEL}" \
    --no-tui \
    --daemon \
    >"${LOG}" 2>&1 &
  echo $! >"${PIDF}"

  echo "started ${ID} port=${PORT} pid=$(cat "${PIDF}") log=${LOG} (local)"
  sleep 0.2
  i=$((i + 1))
done

# Start remote peers (remaining peers)
if [[ "${USE_REMOTE}" == "1" && "${REMOTE_COUNT}" -gt 0 ]]; then
  j=$((LOCAL_COUNT + 1))
  while [[ $j -le $COUNT ]]; do
    PORT=$((BASE_PORT + j - 1))
    ID="${ID_PREFIX}${j}"
    LOG="${RUN_DIR}/${ID}.log"
    PIDF="${RUN_DIR}/${ID}.pid"
    REMOTE_LOG="~/litep2p/logs/${ID}.log"

    # Start peer on remote machine via SSH
    SSH_CMD="cd ~/litep2p && nohup ${REMOTE_BIN} --config ${REMOTE_CONFIG} --id ${ID} --port ${PORT} --log-level ${LOG_LEVEL} --no-tui --daemon >${REMOTE_LOG} 2>&1 & echo \$!"
    
    if [[ -n "${REMOTE_PASS}" ]]; then
      REMOTE_PID=$(sshpass -p "${REMOTE_PASS}" ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "${SSH_CMD}")
    else
      REMOTE_PID=$(ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "${SSH_CMD}")
    fi

    # Store remote PID with host prefix for cleanup
    echo "remote:${REMOTE_HOST}:${REMOTE_PID}" >"${PIDF}"

    # Start background process to tail remote log to local log file
    if [[ -n "${REMOTE_PASS}" ]]; then
      (sshpass -p "${REMOTE_PASS}" ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "tail -f ${REMOTE_LOG} 2>/dev/null" >"${LOG}" 2>&1 &)
    else
      (ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "tail -f ${REMOTE_LOG} 2>/dev/null" >"${LOG}" 2>&1 &)
    fi

    echo "started ${ID} port=${PORT} pid=${REMOTE_PID} log=${LOG} (remote@${REMOTE_HOST})"
    sleep 0.2
    j=$((j + 1))
  done
fi

echo "OK"
