#!/usr/bin/env bash
set -euo pipefail

# Stop desktop peers started by start_desktop_peers.sh.
#
# Usage:
#   tools/harness/stop_desktop_peers.sh [run_dir]
#
# If run_dir is omitted, it will use ./tools/harness/runs/desktop_peers_latest.
#
# Supports remote peers: if pidfile contains "remote:<host>:<pid>", it will SSH to kill.
# Environment variables:
# - REMOTE_PASS (optional) SSH password for remote peers

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNS_DIR="${ROOT_DIR}/tools/harness/runs"

RUN_DIR="${1:-${RUNS_DIR}/desktop_peers_latest}"
REMOTE_PASS="${REMOTE_PASS:-}"

if [[ ! -d "${RUN_DIR}" ]]; then
  echo "ERROR: run dir not found: ${RUN_DIR}" >&2
  exit 1
fi

shopt -s nullglob
PIDFILES=("${RUN_DIR}"/*.pid)
shopt -u nullglob

if [[ ${#PIDFILES[@]} -eq 0 ]]; then
  echo "No pidfiles found under ${RUN_DIR}" >&2
  exit 1
fi

echo "Stopping peers from: ${RUN_DIR}"

for pf in "${PIDFILES[@]}"; do
  pid_content="$(cat "${pf}" 2>/dev/null || true)"
  if [[ -z "${pid_content}" ]]; then
    continue
  fi

  # Check if this is a remote peer (format: remote:<host>:<pid>)
  if [[ "${pid_content}" =~ ^remote:(.+):([0-9]+)$ ]]; then
    REMOTE_HOST="${BASH_REMATCH[1]}"
    REMOTE_PID="${BASH_REMATCH[2]}"
    echo "kill remote ${REMOTE_PID} on ${REMOTE_HOST} (from $(basename "${pf}"))"
    if [[ -n "${REMOTE_PASS}" ]]; then
      sshpass -p "${REMOTE_PASS}" ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "kill ${REMOTE_PID} 2>/dev/null || true" 2>/dev/null || true
    else
      ssh -o StrictHostKeyChecking=no "${REMOTE_HOST}" "kill ${REMOTE_PID} 2>/dev/null || true" 2>/dev/null || true
    fi
  else
    # Local peer
    pid="${pid_content}"
    if kill -0 "${pid}" >/dev/null 2>&1; then
      echo "kill ${pid} (from $(basename "${pf}"))"
      kill "${pid}" >/dev/null 2>&1 || true
    else
      echo "already dead: ${pid} (from $(basename "${pf}"))"
    fi
  fi

done

# Also kill any stray tail processes that were following remote logs
pkill -f "tail -f.*litep2p/logs" 2>/dev/null || true

echo "Done"
