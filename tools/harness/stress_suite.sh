#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# LiteP2P stress suite for self-hosted runners (VPS).
# - Builds desktop peer binary (linux)
# - Runs reconnect/restart harnesses against an isolated local signaling server
# - Applies networking chaos (tc netem + iptables), optionally restarts signaling periodically
# - Attempts to find limits (max message size under impairment, long churn)
# - Produces a log bundle directory that GitHub Actions can upload as an artifact

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-/tmp/litep2p_stress_suite_$(date +%Y%m%d_%H%M%S)}"
SIGNALING_PORT="${SIGNALING_PORT:-8769}"
RECONNECT_CYCLES="${RECONNECT_CYCLES:-8}"
LOG_LEVEL="${LOG_LEVEL:-info}"

UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
IS_LINUX=0
PLATFORM="linux"
if [[ "${UNAME_S}" == "Darwin"* ]]; then
  PLATFORM="mac"
else
  PLATFORM="linux"
  if [[ "${UNAME_S}" == "Linux"* ]]; then
    IS_LINUX=1
  fi
fi

# Allow overriding where we pick binaries from.
# Defaults:
#  - macOS:   desktop/build_mac/bin
#  - Linux:   desktop/build_linux_ci/bin (or desktop/build_linux/bin)
BIN_DIR="${BIN_DIR:-}"
if [[ -z "${BIN_DIR}" ]]; then
  if [[ "${PLATFORM}" == "mac" ]]; then
    if [[ -d "${ROOT_DIR}/desktop/build_mac/bin" ]]; then
      BIN_DIR="${ROOT_DIR}/desktop/build_mac/bin"
    else
      BIN_DIR="${ROOT_DIR}/desktop/build_mac_ci/bin"
    fi
  else
    if [[ -d "${ROOT_DIR}/desktop/build_linux_ci/bin" ]]; then
      BIN_DIR="${ROOT_DIR}/desktop/build_linux_ci/bin"
    else
      BIN_DIR="${ROOT_DIR}/desktop/build_linux/bin"
    fi
  fi
fi

PEER_BIN="${PEER_BIN:-${BIN_DIR}/litep2p_peer_${PLATFORM}}"
MESSAGE_SIZE_RUNNER_BIN="${MESSAGE_SIZE_RUNNER_BIN:-${BIN_DIR}/message_size_runner}"
FILE_TRANSFER_TEST_BIN="${FILE_TRANSFER_TEST_BIN:-${BIN_DIR}/file_transfer_test}"
WAN_INTEGRATION_RUNNER_BIN="${WAN_INTEGRATION_RUNNER_BIN:-${BIN_DIR}/wan_integration_runner}"

# Modes
DRY_RUN="${DRY_RUN:-0}"                # 1 => print actions, do not execute network/engine commands
QUICK="${QUICK:-0}"                    # 1 => shorter run (good sanity gate)
SKIP_BUILD="${SKIP_BUILD:-0}"          # 1 => assumes binaries already built

# Chaos controls
CHAOS_ENABLED="${CHAOS_ENABLED:-1}"
CHAOS_MODE="${CHAOS_MODE:-tc,iptables}"   # tc, iptables, or tc,iptables
CHAOS_IFACE="${CHAOS_IFACE:-}"            # auto-detect if empty (linux)
CHAOS_STEP_SEC="${CHAOS_STEP_SEC:-15}"
CHAOS_TOTAL_SEC="${CHAOS_TOTAL_SEC:-180}"

# iptables scoping/safety
IPTABLES_CHAIN="${IPTABLES_CHAIN:-LITEP2P_CHAOS}"
CHAOS_UDP_PORT_RANGE="${CHAOS_UDP_PORT_RANGE:-30000:32000}"
LOSS_PORTS="${LOSS_PORTS:-31001,31002}"

# Chaos tolerance
ALLOW_CHAOS_FAILURES="${ALLOW_CHAOS_FAILURES:-1}"     # 1 => chaos/probe failures are informational

# Optional CPU/memory/IO pressure (Linux only, requires stress-ng)
RESOURCE_CHAOS_ENABLED="${RESOURCE_CHAOS_ENABLED:-0}"
RESOURCE_CHAOS_PROFILE="${RESOURCE_CHAOS_PROFILE:-cpu,vm,io}"  # csv of cpu|vm|io
RESOURCE_CHAOS_DURATION_SEC="${RESOURCE_CHAOS_DURATION_SEC:-30}"
RESOURCE_CHAOS_CPU_WORKERS="${RESOURCE_CHAOS_CPU_WORKERS:-2}"
RESOURCE_CHAOS_VM_WORKERS="${RESOURCE_CHAOS_VM_WORKERS:-1}"
RESOURCE_CHAOS_VM_BYTES_PCT="${RESOURCE_CHAOS_VM_BYTES_PCT:-70}"
RESOURCE_CHAOS_IO_WORKERS="${RESOURCE_CHAOS_IO_WORKERS:-2}"

# tc netem profiles applied in a loop (space-separated). "clean" removes qdisc.
CHAOS_TC_PROFILES="${CHAOS_TC_PROFILES:-clean loss1 jitter50 loss5 jitter200 reorder10 blackout3 clean}"

# tc safety: avoid overwriting non-default root qdisc unless explicitly forced.
TC_SAFE_MODE="${TC_SAFE_MODE:-1}"
TC_CAN_APPLY=1

# iptables UDP loss injection (applies to the local peer ports used by reconnect_mechanism_test)
LOSS_PROB="${LOSS_PROB:-0.10}"
LOSS_DURATION_SEC="${LOSS_DURATION_SEC:-30}"

# Signaling chaos
SIGNALING_RESTART_EVERY_SEC="${SIGNALING_RESTART_EVERY_SEC:-0}"  # 0 disables

# Long churn / limit probing
LONG_CHURN_CYCLES="${LONG_CHURN_CYCLES:-0}"  # 0 disables (set e.g. 1000)
MSG_SIZE_MIN="${MSG_SIZE_MIN:-64}"
MSG_SIZE_MAX="${MSG_SIZE_MAX:-262144}"       # 256 KiB upper probe
MSG_SIZE_MODE="${MSG_SIZE_MODE:-exp}"        # exp|linear
MSG_SIZE_STEP="${MSG_SIZE_STEP:-2}"          # exp: multiply; linear: add bytes
MSG_SIZE_DEADLINE_SEC="${MSG_SIZE_DEADLINE_SEC:-180}"

# A quick smoke message-size list (should be conservative; the probe below finds the real limit).
MSG_SMOKE_SIZES="${MSG_SMOKE_SIZES:-64,128,256,512,1024,2048}"

SUDO=""
IPTABLES_ENABLED=0
TC_ENABLED=0
SIGNALING_PID=""
CHAOS_PID=""
SIGNALING_CHAOS_PID=""
RESOURCE_CHAOS_PID=""

if [[ "${IS_LINUX}" != "1" ]]; then
  # tc/iptables are Linux-only; keep suite runnable on macOS (local sanity).
  CHAOS_ENABLED=0
  CHAOS_MODE=""
fi

mkdir -p "${OUT_DIR}"

run_cmd() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] $*"
    return 0
  fi
  "$@"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_sudo() {
  if [[ "${EUID}" -eq 0 ]]; then
    SUDO=""
    return 0
  fi
  if have_cmd sudo && sudo -n true >/dev/null 2>&1; then
    SUDO="sudo -n"
    return 0
  fi
  SUDO=""
  return 1
}

detect_iface() {
  if [[ -n "${CHAOS_IFACE}" ]]; then
    echo "${CHAOS_IFACE}"
    return 0
  fi
  if ! have_cmd ip; then
    echo ""
    return 0
  fi
  # Best-effort: pick the interface used for default route.
  local dev
  dev="$(ip route show default 2>/dev/null | awk 'NR==1{print $5; exit}')"
  if [[ -z "${dev}" ]]; then
    dev="$(ip -6 route show default 2>/dev/null | awk 'NR==1{print $5; exit}')"
  fi
  if [[ -z "${dev}" ]]; then
    dev="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
  fi
  echo "${dev}"  # can be empty
}

write_summary_kv() {
  echo "$1=$2" >> "${OUT_DIR}/summary.env"
}

start_signaling() {
  echo "[suite] Starting isolated local signaling server on 127.0.0.1:${SIGNALING_PORT} ..."
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] start signaling server"
    return 0
  fi
  cd "${ROOT_DIR}"
  nohup env SIGNALING_HOST=127.0.0.1 SIGNALING_PORT="${SIGNALING_PORT}" LOG_LEVEL=INFO \
    python3 tools/signaling_server/server.py > "${OUT_DIR}/local_signaling.log" 2>&1 &
  SIGNALING_PID=$!

  # Readiness probe: attempt a websocket handshake to avoid race conditions.
  local ok=0
  for _i in $(seq 1 50); do
    python3 - <<PY >/dev/null 2>&1 && ok=1 && break || true
import asyncio
import websockets

async def main():
    uri = "ws://127.0.0.1:${SIGNALING_PORT}"
    try:
        async with websockets.connect(uri, open_timeout=0.2, close_timeout=0.2):
            return
    except Exception:
        raise

asyncio.run(main())
PY
    sleep 0.2
  done
  if [[ "${ok}" != "1" ]]; then
    echo "[suite] ERROR: signaling server did not become ready on 127.0.0.1:${SIGNALING_PORT}" >&2
    tail -n 50 "${OUT_DIR}/local_signaling.log" 2>/dev/null || true
    return 4
  fi
  write_summary_kv SIGNALING_PID "${SIGNALING_PID}"
}

stop_signaling() {
  if [[ -n "${SIGNALING_PID}" ]]; then
    kill "${SIGNALING_PID}" 2>/dev/null || true
    wait "${SIGNALING_PID}" 2>/dev/null || true
    SIGNALING_PID=""
  fi
  pkill -f "tools/signaling_server/[s]erver.py" 2>/dev/null || true
}

tc_clear() {
  local dev="$1"
  if [[ -z "${dev}" ]]; then
    return 0
  fi
  if [[ "${TC_ENABLED}" != "1" ]]; then
    return 0
  fi
  if have_cmd tc; then
    echo "[suite][chaos] WARN: removing root qdisc on ${dev} (restoring requires manual action)."
    ${SUDO} tc qdisc del dev "${dev}" root 2>/dev/null || true
  fi
}

tc_apply_profile() {
  local dev="$1"
  local profile="$2"
  if [[ -z "${dev}" ]]; then
    return 0
  fi
  if ! have_cmd tc; then
    return 0
  fi
  if [[ "${TC_CAN_APPLY}" != "1" ]]; then
    return 0
  fi

  # Snapshot existing qdisc once for observability/safety.
  if [[ ! -f "${OUT_DIR}/tc_before_${dev}.txt" ]]; then
    ${SUDO} tc qdisc show dev "${dev}" > "${OUT_DIR}/tc_before_${dev}.txt" 2>&1 || true
  fi

  case "${profile}" in
    clean)
      ${SUDO} tc qdisc del dev "${dev}" root 2>/dev/null || true
      ;;
    loss1)
      ${SUDO} tc qdisc replace dev "${dev}" root netem loss 1%
      ;;
    loss5)
      ${SUDO} tc qdisc replace dev "${dev}" root netem loss 5%
      ;;
    jitter50)
      ${SUDO} tc qdisc replace dev "${dev}" root netem delay 50ms 10ms distribution normal
      ;;
    jitter200)
      ${SUDO} tc qdisc replace dev "${dev}" root netem delay 200ms 50ms distribution normal
      ;;
    reorder10)
      ${SUDO} tc qdisc replace dev "${dev}" root netem reorder 10% 50%
      ;;
    blackout3)
      # "blackout" with tc isn't perfect. We'll do it with iptables separately if enabled.
      ${SUDO} tc qdisc replace dev "${dev}" root netem loss 100%
      ;;
    *)
      echo "[suite] WARN: unknown tc profile: ${profile}"
      return 0
      ;;
  esac
  TC_ENABLED=1
  echo "[suite][chaos] tc profile=${profile} dev=${dev}"
}

tc_prepare() {
  local dev="$1"
  if [[ -z "${dev}" ]]; then
    TC_CAN_APPLY=0
    return 0
  fi
  if ! have_cmd tc; then
    TC_CAN_APPLY=0
    return 0
  fi
  if [[ "${TC_SAFE_MODE}" != "1" ]]; then
    TC_CAN_APPLY=1
    return 0
  fi

  # Detect existing root qdisc kind (best-effort).
  local kind
  kind="$(${SUDO} tc qdisc show dev "${dev}" 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="qdisc") {print $(i+1); exit}}')"
  if [[ -z "${kind}" ]]; then
    TC_CAN_APPLY=1
    return 0
  fi

  case "${kind}" in
    pfifo_fast|fq_codel|noqueue)
      TC_CAN_APPLY=1
      ;;
    *)
      echo "[suite][chaos] WARN: existing root qdisc on ${dev} is '${kind}'. TC_SAFE_MODE=1 => skipping tc netem to avoid clobbering host shaping."
      echo "[suite][chaos]       Set TC_SAFE_MODE=0 to force tc netem (or run on a dedicated interface/namespace)."
      TC_CAN_APPLY=0
      ;;
  esac
}

iptables_clear_loss() {
  # Deprecated in favor of chain-based cleanup; keep as no-op for compatibility.
  return 0
}

iptables_apply_loss() {
  # Deprecated in favor of chain-based chaos rules.
  return 0
}

iptables_cmd() {
  # Prefer xtables lock wait to reduce flakiness under concurrency.
  if [[ -n "${SUDO}" ]]; then
    ${SUDO} iptables -w 5 "$@" 2>/dev/null || ${SUDO} iptables "$@"
  else
    iptables -w 5 "$@" 2>/dev/null || iptables "$@"
  fi
}

iptables_chain_setup() {
  if [[ "${IPTABLES_ENABLED}" == "1" ]]; then
    return 0
  fi
  if ! have_cmd iptables; then
    return 0
  fi
  local dev
  dev="$(detect_iface)"

  # Create chain if missing.
  if ! iptables_cmd -n -L "${IPTABLES_CHAIN}" >/dev/null 2>&1; then
    iptables_cmd -N "${IPTABLES_CHAIN}" || true
  fi

  # Ensure jump rules exist (scoped to UDP only; optionally scoped to interface).
  if [[ -n "${dev}" ]]; then
    iptables_cmd -C INPUT  -i "${dev}" -p udp -j "${IPTABLES_CHAIN}" >/dev/null 2>&1 || iptables_cmd -I INPUT  -i "${dev}" -p udp -j "${IPTABLES_CHAIN}"
    iptables_cmd -C OUTPUT -o "${dev}" -p udp -j "${IPTABLES_CHAIN}" >/dev/null 2>&1 || iptables_cmd -I OUTPUT -o "${dev}" -p udp -j "${IPTABLES_CHAIN}"
  else
    iptables_cmd -C INPUT  -p udp -j "${IPTABLES_CHAIN}" >/dev/null 2>&1 || iptables_cmd -I INPUT  -p udp -j "${IPTABLES_CHAIN}"
    iptables_cmd -C OUTPUT -p udp -j "${IPTABLES_CHAIN}" >/dev/null 2>&1 || iptables_cmd -I OUTPUT -p udp -j "${IPTABLES_CHAIN}"
  fi

  IPTABLES_ENABLED=1
}

iptables_chain_cleanup() {
  if [[ "${IPTABLES_ENABLED}" != "1" ]]; then
    return 0
  fi
  if ! have_cmd iptables; then
    return 0
  fi
  local dev
  dev="$(detect_iface)"

  # Flush our chain.
  iptables_cmd -F "${IPTABLES_CHAIN}" 2>/dev/null || true

  # Remove jump rules (delete all matching occurrences).
  if [[ -n "${dev}" ]]; then
    while iptables_cmd -D INPUT  -i "${dev}" -p udp -j "${IPTABLES_CHAIN}" 2>/dev/null; do :; done
    while iptables_cmd -D OUTPUT -o "${dev}" -p udp -j "${IPTABLES_CHAIN}" 2>/dev/null; do :; done
  fi
  while iptables_cmd -D INPUT  -p udp -j "${IPTABLES_CHAIN}" 2>/dev/null; do :; done
  while iptables_cmd -D OUTPUT -p udp -j "${IPTABLES_CHAIN}" 2>/dev/null; do :; done

  # Delete chain.
  iptables_cmd -X "${IPTABLES_CHAIN}" 2>/dev/null || true
  IPTABLES_ENABLED=0
}

iptables_chain_add_loss() {
  local prob="$1"
  local ports_csv="$2"
  iptables_chain_setup
  IFS=',' read -r -a _ports <<< "${ports_csv}"
  for p in "${_ports[@]}"; do
    [[ -z "${p}" ]] && continue
    # Inbound to our ports
    iptables_cmd -A "${IPTABLES_CHAIN}" -p udp --dport "${p}" -m statistic --mode random --probability "${prob}" -j DROP
    # Outbound from our ports
    iptables_cmd -A "${IPTABLES_CHAIN}" -p udp --sport "${p}" -m statistic --mode random --probability "${prob}" -j DROP
  done
}

iptables_chain_add_blackout() {
  local port_range="$1"  # e.g. 30000:32000
  local comment="LITEP2P_BLACKOUT"
  iptables_chain_setup

  # Scoped blackout: drop only UDP traffic related to the LiteP2P port range.
  # INPUT: packets destined to our ports (and optionally from peers in range).
  iptables_cmd -I "${IPTABLES_CHAIN}" 1 -p udp --dport "${port_range}" -m comment --comment "${comment}" -j DROP
  iptables_cmd -I "${IPTABLES_CHAIN}" 1 -p udp --sport "${port_range}" -m comment --comment "${comment}" -j DROP
  # OUTPUT: packets originating from our ports (and optionally targeting peers in range).
  iptables_cmd -I "${IPTABLES_CHAIN}" 1 -p udp --sport "${port_range}" -m comment --comment "${comment}" -j DROP
  iptables_cmd -I "${IPTABLES_CHAIN}" 1 -p udp --dport "${port_range}" -m comment --comment "${comment}" -j DROP
}

iptables_chain_remove_blackout() {
  local port_range="$1"
  local comment="LITEP2P_BLACKOUT"
  if ! have_cmd iptables; then
    return 0
  fi
  # Delete any blackout rules we inserted (loop to handle duplicates).
  while iptables_cmd -D "${IPTABLES_CHAIN}" -p udp --dport "${port_range}" -m comment --comment "${comment}" -j DROP 2>/dev/null; do :; done
  while iptables_cmd -D "${IPTABLES_CHAIN}" -p udp --sport "${port_range}" -m comment --comment "${comment}" -j DROP 2>/dev/null; do :; done
  while iptables_cmd -D "${IPTABLES_CHAIN}" -p udp --sport "${port_range}" -m comment --comment "${comment}" -j DROP 2>/dev/null; do :; done
  while iptables_cmd -D "${IPTABLES_CHAIN}" -p udp --dport "${port_range}" -m comment --comment "${comment}" -j DROP 2>/dev/null; do :; done
}

iptables_blackout_seconds() {
  local sec="$1"
  local dev
  dev="$(detect_iface)"
  echo "[suite][chaos] blackout via iptables for ${sec}s (udp ports ${CHAOS_UDP_PORT_RANGE}, iface=${dev:-any})"
  if ! have_cmd iptables; then
    return 0
  fi
  if [[ -z "${SUDO}" && "${EUID}" -ne 0 ]]; then
    echo "[suite] WARN: no sudo/root; skipping iptables blackout"
    return 0
  fi
  iptables_chain_add_blackout "${CHAOS_UDP_PORT_RANGE}" || true
  sleep "${sec}"
  iptables_chain_remove_blackout "${CHAOS_UDP_PORT_RANGE}" || true
}

chaos_loop() {
  local end_ts
  end_ts=$(( $(date +%s) + CHAOS_TOTAL_SEC ))

  local dev
  dev="$(detect_iface)"
  if [[ -z "${dev}" ]]; then
    echo "[suite] WARN: could not detect CHAOS_IFACE; tc chaos disabled"
  fi

  tc_prepare "${dev}" || true

  while (( $(date +%s) < end_ts )); do
    for prof in ${CHAOS_TC_PROFILES}; do
      if (( $(date +%s) >= end_ts )); then
        break
      fi

      if [[ "${CHAOS_MODE}" == *"tc"* ]] && [[ -n "${dev}" ]] && have_cmd tc; then
        if [[ "${DRY_RUN}" == "1" ]]; then
          echo "[dry-run] tc profile ${prof} on ${dev}"
        else
          tc_apply_profile "${dev}" "${prof}" || true
        fi
      fi

      if [[ "${CHAOS_MODE}" == *"iptables"* ]] && have_cmd iptables; then
        # One special case: blackout3 profile uses iptables for a hard partition.
        if [[ "${prof}" == "blackout3" ]]; then
          if [[ "${DRY_RUN}" == "1" ]]; then
            echo "[dry-run] iptables blackout 3s"
          else
            iptables_blackout_seconds 3 || true
          fi
        fi
      fi

      sleep "${CHAOS_STEP_SEC}"
    done
  done

  # restore
  if [[ "${DRY_RUN}" != "1" ]]; then
    tc_clear "${dev}" || true
  fi
}

signaling_restart_loop() {
  if [[ "${SIGNALING_RESTART_EVERY_SEC}" == "0" ]]; then
    return 0
  fi
  while true; do
    sleep "${SIGNALING_RESTART_EVERY_SEC}"
    echo "[suite][chaos] restarting local signaling server"
    if [[ "${DRY_RUN}" == "1" ]]; then
      continue
    fi
    stop_signaling
    start_signaling
  done
}

start_resource_chaos() {
  if [[ "${RESOURCE_CHAOS_ENABLED}" != "1" ]]; then
    return 0
  fi
  if [[ "${IS_LINUX}" != "1" ]]; then
    echo "[suite] RESOURCE_CHAOS_ENABLED=1 but not Linux; skipping"
    return 0
  fi
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] start stress-ng (${RESOURCE_CHAOS_PROFILE}) for ${RESOURCE_CHAOS_DURATION_SEC}s"
    return 0
  fi
  if ! have_cmd stress-ng; then
    echo "[suite] WARN: stress-ng not found; skipping resource chaos"
    return 0
  fi

  local args=(--timeout "${RESOURCE_CHAOS_DURATION_SEC}s" --metrics-brief)
  if [[ ",${RESOURCE_CHAOS_PROFILE}," == *",cpu,"* ]]; then
    args+=(--cpu "${RESOURCE_CHAOS_CPU_WORKERS}")
  fi
  if [[ ",${RESOURCE_CHAOS_PROFILE}," == *",vm,"* ]]; then
    args+=(--vm "${RESOURCE_CHAOS_VM_WORKERS}" --vm-bytes "${RESOURCE_CHAOS_VM_BYTES_PCT}%")
  fi
  if [[ ",${RESOURCE_CHAOS_PROFILE}," == *",io,"* ]]; then
    args+=(--io "${RESOURCE_CHAOS_IO_WORKERS}")
  fi

  echo "[suite][chaos] starting stress-ng resource pressure: ${args[*]}"
  (stress-ng "${args[@]}" > "${OUT_DIR}/resource_chaos.log" 2>&1) &
  RESOURCE_CHAOS_PID=$!
  write_summary_kv RESOURCE_CHAOS_PID "${RESOURCE_CHAOS_PID}"
}

stop_resource_chaos() {
  if [[ -n "${RESOURCE_CHAOS_PID}" ]]; then
    kill "${RESOURCE_CHAOS_PID}" 2>/dev/null || true
    wait "${RESOURCE_CHAOS_PID}" 2>/dev/null || true
    RESOURCE_CHAOS_PID=""
  fi
}

cleanup() {
  set +e
  # Remove iptables rules we add (best-effort).
  iptables_chain_cleanup || true
  stop_resource_chaos || true
  if [[ -n "${CHAOS_PID}" ]]; then
    kill "${CHAOS_PID}" 2>/dev/null || true
    wait "${CHAOS_PID}" 2>/dev/null || true
    CHAOS_PID=""
  fi
  if [[ -n "${SIGNALING_CHAOS_PID}" ]]; then
    kill "${SIGNALING_CHAOS_PID}" 2>/dev/null || true
    wait "${SIGNALING_CHAOS_PID}" 2>/dev/null || true
    SIGNALING_CHAOS_PID=""
  fi
  tc_clear "$(detect_iface)" || true
  stop_signaling || true
}
trap cleanup EXIT

echo "[suite] ROOT_DIR=${ROOT_DIR}"
echo "[suite] OUT_DIR=${OUT_DIR}"
write_summary_kv ROOT_DIR "${ROOT_DIR}"
write_summary_kv OUT_DIR "${OUT_DIR}"
write_summary_kv DRY_RUN "${DRY_RUN}"
write_summary_kv QUICK "${QUICK}"

detect_sudo || true
write_summary_kv SUDO "${SUDO:-none}"

echo "[suite] Ensuring python deps (websockets) ..."
if ! python3 -c "import websockets" >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    if [[ "${DRY_RUN}" == "1" ]]; then
      echo "[dry-run] apt-get install python3-websockets"
    else
      # Prefer OS packages to avoid PEP 668 'externally managed environment' errors.
      ${SUDO} apt-get update >/dev/null
      ${SUDO} apt-get install -y python3-websockets >/dev/null
    fi
  else
    echo "[suite] ERROR: python websockets module missing and apt-get not available." >&2
    echo "[suite]        Install it via your OS packages (e.g. python3-websockets) or provide a python environment that includes 'websockets'." >&2
    exit 2
  fi

  if ! python3 -c "import websockets" >/dev/null 2>&1; then
    echo "[suite] ERROR: failed to import 'websockets' after installation attempt." >&2
    exit 2
  fi
fi

PEER_TARGET="litep2p_peer_${PLATFORM}"
BUILD_DIR_CI="${ROOT_DIR}/desktop/build_${PLATFORM}_ci"

if [[ "${SKIP_BUILD}" != "1" ]]; then
  echo "[suite] Building desktop targets (${PLATFORM}) ..."
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] cmake -S desktop -B ${BUILD_DIR_CI} (Release)"
    echo "[dry-run] cmake --build ${BUILD_DIR_CI} --target ${PEER_TARGET} message_size_runner file_transfer_test wan_integration_runner"
  else
    mkdir -p "${BUILD_DIR_CI}"
    cd "${BUILD_DIR_CI}"
    cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_PROXY_MODULE=OFF .. >/dev/null
    cmake --build . --parallel 4 --target "${PEER_TARGET}" message_size_runner file_transfer_test wan_integration_runner >/dev/null

    # After building, prefer CI bin dir for subsequent runs.
    BIN_DIR="${BUILD_DIR_CI}/bin"
    PEER_BIN="${BIN_DIR}/${PEER_TARGET}"
    MESSAGE_SIZE_RUNNER_BIN="${BIN_DIR}/message_size_runner"
    FILE_TRANSFER_TEST_BIN="${BIN_DIR}/file_transfer_test"
    WAN_INTEGRATION_RUNNER_BIN="${BIN_DIR}/wan_integration_runner"
  fi
else
  echo "[suite] SKIP_BUILD=1; using existing BIN_DIR=${BIN_DIR}"
fi

echo "[suite] BIN_DIR=${BIN_DIR}"
echo "[suite] PEER_BIN=${PEER_BIN}"
write_summary_kv BIN_DIR "${BIN_DIR}"
write_summary_kv PEER_BIN "${PEER_BIN}"
write_summary_kv PLATFORM "${PLATFORM}"

if [[ "${DRY_RUN}" != "1" ]]; then
  if [[ ! -x "${PEER_BIN}" ]]; then
    echo "[suite] ERROR: PEER_BIN not found/executable: ${PEER_BIN}" >&2
    exit 3
  fi
  if [[ ! -x "${MESSAGE_SIZE_RUNNER_BIN}" ]]; then
    echo "[suite] ERROR: message_size_runner not found/executable: ${MESSAGE_SIZE_RUNNER_BIN}" >&2
    exit 3
  fi
  if [[ ! -x "${WAN_INTEGRATION_RUNNER_BIN}" ]]; then
    echo "[suite] ERROR: wan_integration_runner not found/executable: ${WAN_INTEGRATION_RUNNER_BIN}" >&2
    exit 3
  fi
fi

start_signaling

if [[ "${SIGNALING_RESTART_EVERY_SEC}" != "0" ]]; then
  echo "[suite] Signaling restart chaos enabled: every ${SIGNALING_RESTART_EVERY_SEC}s"
  if [[ "${DRY_RUN}" != "1" ]]; then
    signaling_restart_loop &
    SIGNALING_CHAOS_PID=$!
  else
    echo "[dry-run] signaling_restart_loop background"
  fi
fi

# Create per-peer config files with ISOLATED keystores to prevent Noise key corruption.
# Both A and B run from the same cwd, so "keystore" would be shared otherwise.
KEYSTORE_A="${OUT_DIR}/keystore_a"
KEYSTORE_B="${OUT_DIR}/keystore_b"
mkdir -p "${KEYSTORE_A}" "${KEYSTORE_B}"

cat > "${OUT_DIR}/config_a.json" <<JSON
{
  "network": {"default_server_port": 30001, "discovery_port": 30000},
  "global_discovery": {"enabled": false},
  "nat_traversal": {"enabled": false, "stun_enabled": false, "hole_punching_enabled": false, "turn_enabled": false},
  "signaling": {"enabled": true, "url": "ws://127.0.0.1:${SIGNALING_PORT}", "reconnect_interval_ms": 200},
  "storage": {"peer_db": {"enabled": false}},
  "peer_management": {"peer_expiration_timeout_ms": 15000, "heartbeat_interval_sec": 1, "timer_tick_interval_sec": 1, "max_message_size": 10485760},
  "security": {"noise_nk_protocol": {"enabled": true, "mandatory": true, "key_store_path": "${KEYSTORE_A}"}},
  "logging": {"level": "debug", "console_output": true}
}
JSON

cat > "${OUT_DIR}/config_b.json" <<JSON
{
  "network": {"default_server_port": 30001, "discovery_port": 30000},
  "global_discovery": {"enabled": false},
  "nat_traversal": {"enabled": false, "stun_enabled": false, "hole_punching_enabled": false, "turn_enabled": false},
  "signaling": {"enabled": true, "url": "ws://127.0.0.1:${SIGNALING_PORT}", "reconnect_interval_ms": 200},
  "storage": {"peer_db": {"enabled": false}},
  "peer_management": {"peer_expiration_timeout_ms": 15000, "heartbeat_interval_sec": 1, "timer_tick_interval_sec": 1, "max_message_size": 10485760},
  "security": {"noise_nk_protocol": {"enabled": true, "mandatory": true, "key_store_path": "${KEYSTORE_B}"}},
  "logging": {"level": "debug", "console_output": true}
}
JSON

if [[ "${QUICK}" == "1" ]]; then
  # Clamp chaos and cycles for a quick gate.
  RECONNECT_CYCLES=3
  CHAOS_TOTAL_SEC=30
  LOSS_DURATION_SEC=10
  LONG_CHURN_CYCLES=0
  MSG_SIZE_MAX=32768
fi

write_summary_kv RECONNECT_CYCLES "${RECONNECT_CYCLES}"
write_summary_kv CHAOS_ENABLED "${CHAOS_ENABLED}"
write_summary_kv CHAOS_MODE "${CHAOS_MODE}"
write_summary_kv CHAOS_TOTAL_SEC "${CHAOS_TOTAL_SEC}"
write_summary_kv LOSS_PROB "${LOSS_PROB}"
write_summary_kv LOSS_DURATION_SEC "${LOSS_DURATION_SEC}"
write_summary_kv SIGNALING_RESTART_EVERY_SEC "${SIGNALING_RESTART_EVERY_SEC}"
write_summary_kv LONG_CHURN_CYCLES "${LONG_CHURN_CYCLES}"
write_summary_kv MSG_SIZE_MAX "${MSG_SIZE_MAX}"
write_summary_kv ALLOW_CHAOS_FAILURES "${ALLOW_CHAOS_FAILURES}"
write_summary_kv RESOURCE_CHAOS_ENABLED "${RESOURCE_CHAOS_ENABLED}"

if [[ "${CHAOS_ENABLED}" == "1" ]]; then
  DEV="$(detect_iface)"
  write_summary_kv CHAOS_IFACE "${DEV}"
  if [[ -n "${DEV}" && "${DRY_RUN}" != "1" && "${IS_LINUX}" == "1" && $(command -v ip >/dev/null 2>&1; echo $?) -eq 0 ]]; then
    ip link show dev "${DEV}" > "${OUT_DIR}/mtu.txt" 2>&1 || true
    MTU_VAL="$(awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}' "${OUT_DIR}/mtu.txt" 2>/dev/null || true)"
    if [[ -n "${MTU_VAL}" ]]; then
      write_summary_kv MTU "${MTU_VAL}"
    fi
  fi
fi

echo "[suite] Running reconnect_mechanism_test (cycles=${RECONNECT_CYCLES}) ..."
PHASE_T0="$(date +%s)"
TS="$(date +%s)"
IDA="suiteA_${TS}"
IDB="suiteB_${TS}"
set +e
run_cmd python3 tools/reconnect_mechanism_test.py \
  --binary "${PEER_BIN}" \
  --config-a "${OUT_DIR}/config_a.json" \
  --config-b "${OUT_DIR}/config_b.json" \
  --id-a "${IDA}" --id-b "${IDB}" \
  --cycles "${RECONNECT_CYCLES}" \
  --restart both \
  --kill kill \
  --timeout 80 \
  --restart-pause 0.8 \
  > "${OUT_DIR}/reconnect_mechanism_baseline.log" 2>&1
BASELINE_EXIT=$?
set -e
PHASE_T1="$(date +%s)"
write_summary_kv reconnect_mechanism_baseline_duration_sec "$((PHASE_T1 - PHASE_T0))"
write_summary_kv reconnect_mechanism_baseline_exit "${BASELINE_EXIT}"

echo "[suite] Running restart_reconnect_test ..."
PHASE_T0="$(date +%s)"
set +e
run_cmd python3 tools/restart_reconnect_test.py \
  --binary "${PEER_BIN}" \
  --config-a "${OUT_DIR}/config_a.json" \
  --config-b "${OUT_DIR}/config_b.json" \
  --id-a "restartA_${TS}" --id-b "restartB_${TS}" \
  --port-a 31101 --port-b 31102 \
  --log-level "${LOG_LEVEL}" \
  --kill kill \
  --timeout 50 \
  > "${OUT_DIR}/restart_reconnect.log" 2>&1
RESTART_EXIT=$?
set -e
PHASE_T1="$(date +%s)"
write_summary_kv restart_reconnect_duration_sec "$((PHASE_T1 - PHASE_T0))"
write_summary_kv restart_reconnect_exit "${RESTART_EXIT}"

echo "[suite] Running file_transfer_test (chunking/resume) ..."
PHASE_T0="$(date +%s)"
if [[ "${DRY_RUN}" == "1" ]]; then
  echo "[dry-run] file_transfer_test"
  FILE_X=0
else
  set +e
  "${FILE_TRANSFER_TEST_BIN}" > "${OUT_DIR}/file_transfer_test.log" 2>&1
  FILE_X=$?
  set -e
fi
PHASE_T1="$(date +%s)"
write_summary_kv file_transfer_test_duration_sec "$((PHASE_T1 - PHASE_T0))"
write_summary_kv file_transfer_test_exit "${FILE_X}"

echo "[suite] Running message_size_runner (two-process loopback) ..."
PHASE_T0="$(date +%s)"
WORK_A="${OUT_DIR}/msgsize_a"
WORK_B="${OUT_DIR}/msgsize_b"
mkdir -p "${WORK_A}" "${WORK_B}"

cat > "${WORK_A}/config.json" <<JSON
{
  "global_discovery": {"enabled": false},
  "nat_traversal": {"enabled": false, "stun_enabled": false, "hole_punching_enabled": false, "turn_enabled": false},
  "signaling": {"enabled": false, "url": "ws://127.0.0.1:1", "reconnect_interval_ms": 60000},
  "storage": {"peer_db": {"enabled": false}},
  "peer_management": {"peer_expiration_timeout_ms": 15000, "heartbeat_interval_sec": 1, "timer_tick_interval_sec": 1, "max_message_size": 10485760},
  "security": {"noise_nk_protocol": {"enabled": true, "mandatory": true, "key_store_path": "keystore"}},
  "logging": {"level": "error", "console_output": true}
}
JSON

cp "${WORK_A}/config.json" "${WORK_B}/config.json"

PORT_A=31201
PORT_B=31202
IDA="msgA_$(date +%s)"
IDB="msgB_$(date +%s)"

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "[dry-run] message_size_runner loopback (skipped)"
  SENDER_CODE=0
else
  (
    cd "${WORK_B}"
    CONFIG_PATH="${WORK_B}/config.json" ROLE=receiver SELF_ID="${IDB}" SELF_PORT="${PORT_B}" \
      TARGET_ID="${IDA}" TARGET_NETID="127.0.0.1:${PORT_A}" DEADLINE_SEC=120 \
      OUT_JSON="${OUT_DIR}/message_size_receiver.json" \
      "${MESSAGE_SIZE_RUNNER_BIN}" > "${OUT_DIR}/message_size_receiver.log" 2>&1
  ) &
  RX_PID=$!

  sleep 1

  set +e
  (
    cd "${WORK_A}"
    CONFIG_PATH="${WORK_A}/config.json" ROLE=sender SELF_ID="${IDA}" SELF_PORT="${PORT_A}" \
      TARGET_ID="${IDB}" TARGET_NETID="127.0.0.1:${PORT_B}" \
      SIZES="${MSG_SMOKE_SIZES}" DEADLINE_SEC=120 \
      OUT_JSON="${OUT_DIR}/message_size_sender.json" \
      "${MESSAGE_SIZE_RUNNER_BIN}" > "${OUT_DIR}/message_size_sender.log" 2>&1
  )
  SENDER_CODE=$?
  set -e

  # Stop receiver promptly after sender is done.
  kill "${RX_PID}" 2>/dev/null || true
  wait "${RX_PID}" 2>/dev/null || true
fi
echo "[suite] message_size_runner sender exit=${SENDER_CODE}"
PHASE_T1="$(date +%s)"
write_summary_kv message_size_smoke_duration_sec "$((PHASE_T1 - PHASE_T0))"
write_summary_kv message_size_sender_exit "${SENDER_CODE}"

if [[ "${CHAOS_ENABLED}" == "1" ]]; then
  echo "[suite] Starting chaos loop (mode=${CHAOS_MODE}, total=${CHAOS_TOTAL_SEC}s) ..."
  if [[ "${DRY_RUN}" != "1" ]]; then
    chaos_loop &
    CHAOS_PID=$!
    write_summary_kv CHAOS_PID "${CHAOS_PID}"
  else
    echo "[dry-run] chaos_loop background"
  fi
fi

LOSS_EXIT="skipped"
TS2="$(date +%s)"
IDA2="lossA_${TS2}"
IDB2="lossB_${TS2}"

if [[ "${CHAOS_ENABLED}" == "1" ]]; then
  PHASE_T0="$(date +%s)"
  start_resource_chaos || true

  echo "[suite] Applying UDP packet loss via iptables (p=${LOSS_PROB}, duration=${LOSS_DURATION_SEC}s) ..."
  if [[ "${CHAOS_MODE}" != *"iptables"* ]]; then
    echo "[suite] iptables chaos disabled by CHAOS_MODE"
  else
    if [[ -z "${SUDO}" && "${EUID}" -ne 0 ]]; then
      echo "[suite] WARN: no sudo/root; skipping iptables loss injection"
    else
      if have_cmd iptables; then
        if [[ "${DRY_RUN}" == "1" ]]; then
          echo "[dry-run] iptables apply loss p=${LOSS_PROB}"
        else
          iptables_chain_add_loss "${LOSS_PROB}" "${LOSS_PORTS}"
          sleep "${LOSS_DURATION_SEC}"
          # Remove all loss rules by flushing chain (safer than exact-match deletions).
          iptables_cmd -F "${IPTABLES_CHAIN}" 2>/dev/null || true
        fi
      else
        echo "[suite] WARN: iptables not found; skipping loss injection"
      fi
    fi
  fi

  echo "[suite] Running reconnect_mechanism_test under impairment ..."
  LOSS_CYCLES=5
  LOSS_TIMEOUT=120
  if [[ "${QUICK}" == "1" ]]; then
    LOSS_CYCLES=2
    LOSS_TIMEOUT=80
  fi
  set +e
  run_cmd python3 tools/reconnect_mechanism_test.py \
    --binary "${PEER_BIN}" \
    --config-a "${OUT_DIR}/config_a.json" \
    --config-b "${OUT_DIR}/config_b.json" \
    --id-a "${IDA2}" --id-b "${IDB2}" \
    --port-a 31001 --port-b 31002 \
    --log-level "${LOG_LEVEL}" \
    --cycles "${LOSS_CYCLES}" \
    --restart both \
    --kill kill \
    --timeout "${LOSS_TIMEOUT}" \
    --restart-pause 0.8 \
    > "${OUT_DIR}/reconnect_mechanism_loss.log" 2>&1
  LOSS_EXIT=$?
  set -e
  stop_resource_chaos || true
  PHASE_T1="$(date +%s)"
  write_summary_kv reconnect_mechanism_loss_duration_sec "$((PHASE_T1 - PHASE_T0))"
else
  echo "[suite] CHAOS_ENABLED=0; skipping impairment reconnect test"
fi

write_summary_kv reconnect_mechanism_loss_exit "${LOSS_EXIT}"

echo "[suite] Probing max message size under current conditions (MSG_SIZE_MAX=${MSG_SIZE_MAX}) ..."
PHASE_T0="$(date +%s)"
SIZES=""
if [[ "${MSG_SIZE_MODE}" == "linear" ]]; then
  s=${MSG_SIZE_MIN}
  while (( s <= MSG_SIZE_MAX )); do
    if [[ -z "${SIZES}" ]]; then SIZES="${s}"; else SIZES="${SIZES},${s}"; fi
    s=$(( s + MSG_SIZE_STEP ))
  done
else
  s=${MSG_SIZE_MIN}
  while (( s <= MSG_SIZE_MAX )); do
    if [[ -z "${SIZES}" ]]; then SIZES="${s}"; else SIZES="${SIZES},${s}"; fi
    s=$(( s * MSG_SIZE_STEP ))
  done
fi

MS_WORK="${OUT_DIR}/msgsize_probe"
mkdir -p "${MS_WORK}/a" "${MS_WORK}/b"

# Use a minimal direct-connect config for the probe (no signaling), with a high max_message_size.
cat > "${MS_WORK}/a/config.json" <<JSON
{
  "global_discovery": {"enabled": false},
  "nat_traversal": {"enabled": false, "stun_enabled": false, "hole_punching_enabled": false, "turn_enabled": false},
  "signaling": {"enabled": false, "url": "ws://127.0.0.1:1", "reconnect_interval_ms": 60000},
  "storage": {"peer_db": {"enabled": false}},
  "peer_management": {"peer_expiration_timeout_ms": 15000, "heartbeat_interval_sec": 1, "timer_tick_interval_sec": 1, "max_message_size": 10485760},
  "security": {"noise_nk_protocol": {"enabled": true, "mandatory": true, "key_store_path": "keystore"}},
  "logging": {"level": "error", "console_output": true}
}
JSON

cp "${MS_WORK}/a/config.json" "${MS_WORK}/b/config.json"

PORT_PA=31301
PORT_PB=31302
IDA_P="probeA_${TS2}"
IDB_P="probeB_${TS2}"

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "[dry-run] message_size_runner probe sizes=${SIZES}"
  PROBE_SENDER_EXIT=0
else
  (
    cd "${MS_WORK}/b"
    CONFIG_PATH="${MS_WORK}/b/config.json" ROLE=receiver SELF_ID="${IDB_P}" SELF_PORT="${PORT_PB}" \
      TARGET_ID="${IDA_P}" TARGET_NETID="127.0.0.1:${PORT_PA}" DEADLINE_SEC="${MSG_SIZE_DEADLINE_SEC}" \
      OUT_JSON="${OUT_DIR}/msgsize_probe_receiver.json" \
      "${MESSAGE_SIZE_RUNNER_BIN}" > "${OUT_DIR}/msgsize_probe_receiver.log" 2>&1
  ) &
  PROBE_RX=$!

  sleep 1

  set +e
  (
    cd "${MS_WORK}/a"
    CONFIG_PATH="${MS_WORK}/a/config.json" ROLE=sender SELF_ID="${IDA_P}" SELF_PORT="${PORT_PA}" \
      TARGET_ID="${IDB_P}" TARGET_NETID="127.0.0.1:${PORT_PB}" \
      SIZES="${SIZES}" DEADLINE_SEC="${MSG_SIZE_DEADLINE_SEC}" \
      OUT_JSON="${OUT_DIR}/msgsize_probe_sender.json" \
      "${MESSAGE_SIZE_RUNNER_BIN}" > "${OUT_DIR}/msgsize_probe_sender.log" 2>&1
  )
  PROBE_SENDER_EXIT=$?
  set -e

  kill "${PROBE_RX}" 2>/dev/null || true
  wait "${PROBE_RX}" 2>/dev/null || true
fi
write_summary_kv msgsize_probe_sender_exit "${PROBE_SENDER_EXIT}"
PHASE_T1="$(date +%s)"
write_summary_kv msgsize_probe_duration_sec "$((PHASE_T1 - PHASE_T0))"

# Probe is allowed to "fail" (it is designed to find the limit). Record max_ok/failures if JSON exists.
if [[ -f "${OUT_DIR}/msgsize_probe_sender.json" ]]; then
  python3 - "${OUT_DIR}/msgsize_probe_sender.json" "${OUT_DIR}/summary.env" <<'PY' || true
import json,sys
path=sys.argv[1]
out=sys.argv[2]
try:
  with open(path, 'r') as f:
    data = json.load(f)
  result = data.get('result', '')
  max_ok = data.get('max_ok', -1)
  failures = data.get('failures', -1)
  with open(out, 'a') as f:
    if result:
      f.write(f"msgsize_probe_result={result}\n")
    f.write(f"msgsize_probe_max_ok={max_ok}\n")
    f.write(f"msgsize_probe_failures={failures}\n")
except Exception:
    pass
PY
fi

if [[ "${LONG_CHURN_CYCLES}" != "0" ]]; then
  echo "[suite] Running long churn (cycles=${LONG_CHURN_CYCLES}) ..."
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[dry-run] repro_peer_restart_churn.sh cycles=${LONG_CHURN_CYCLES}"
    CHURN_EXIT=0
  else
    set +e
    CHURN_OUT="$(LITEP2P_BIN="${PEER_BIN}" LITEP2P_CONFIG="${OUT_DIR}/config_a.json" CYCLES="${LONG_CHURN_CYCLES}" VERBOSE=0 \
      bash tools/repro_peer_restart_churn.sh 2>&1 | tee "${OUT_DIR}/long_churn.stdout")"
    CHURN_EXIT=${PIPESTATUS[0]}
    set -e
    # Extract run dir from stdout if present and link it into OUT_DIR.
    CHURN_RUN_DIR="$(echo "${CHURN_OUT}" | grep -Eo '^RUN_DIR=.*' | tail -1 | sed 's/^RUN_DIR=//')"
    if [[ -n "${CHURN_RUN_DIR}" && -d "${CHURN_RUN_DIR}" ]]; then
      ln -s "${CHURN_RUN_DIR}" "${OUT_DIR}/long_churn_run" 2>/dev/null || true
      write_summary_kv long_churn_run_dir "${CHURN_RUN_DIR}"
    fi
  fi
  write_summary_kv long_churn_exit "${CHURN_EXIT}"
fi

# Gate: baseline reconnect must pass; other phases are informational unless they hard-fail.
FINAL_EXIT=0
if [[ "${BASELINE_EXIT}" != "0" ]]; then FINAL_EXIT=2; fi
if [[ "${RESTART_EXIT}" != "0" ]]; then FINAL_EXIT=2; fi
# Chaos-related phases can be allowed to fail in exploratory runs.
if [[ "${ALLOW_CHAOS_FAILURES}" != "1" ]]; then
  if [[ "${CHAOS_ENABLED}" == "1" && "${LOSS_EXIT}" != "0" ]]; then FINAL_EXIT=2; fi
  # msgsize probe is also part of chaos/limit finding.
  if [[ "${PROBE_SENDER_EXIT:-0}" != "0" ]]; then FINAL_EXIT=2; fi
fi
# msgsize probe is informational (it often exits nonzero once you exceed the limit).
if [[ "${LONG_CHURN_CYCLES}" != "0" && "${CHURN_EXIT:-0}" != "0" ]]; then FINAL_EXIT=2; fi

# Export a JSON summary for downstream tooling.
if [[ "${DRY_RUN}" != "1" ]]; then
  python3 - "${OUT_DIR}/summary.env" "${OUT_DIR}/summary.json" <<'PY' || true
import json,sys
inp, outp = sys.argv[1], sys.argv[2]
d = {}
with open(inp,'r') as f:
    for line in f:
        line=line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k,v = line.split('=',1)
        d[k]=v
with open(outp,'w') as f:
    json.dump(d,f,indent=2,sort_keys=True)
    f.write('\n')
PY

  # Basic CSV for quick regression graphs.
  python3 - "${OUT_DIR}/summary.json" "${OUT_DIR}/results.csv" <<'PY' || true
import json,sys
sj, outp = sys.argv[1], sys.argv[2]
d = json.load(open(sj,'r'))

rows = [
  ("reconnect_baseline", d.get("reconnect_mechanism_baseline_exit"), d.get("reconnect_mechanism_baseline_duration_sec"), ""),
  ("restart_reconnect", d.get("restart_reconnect_exit"), d.get("restart_reconnect_duration_sec"), ""),
  ("file_transfer", d.get("file_transfer_test_exit"), d.get("file_transfer_test_duration_sec"), ""),
  ("msgsize_smoke", d.get("message_size_sender_exit"), d.get("message_size_smoke_duration_sec"), d.get("MSG_SMOKE_SIZES","")),
  ("reconnect_impairment", d.get("reconnect_mechanism_loss_exit"), d.get("reconnect_mechanism_loss_duration_sec"), ""),
  ("msgsize_probe", d.get("msgsize_probe_sender_exit"), d.get("msgsize_probe_duration_sec"), f"max_ok={d.get('msgsize_probe_max_ok','')};failures={d.get('msgsize_probe_failures','')}"),
]

with open(outp,'w') as f:
    f.write('phase,exit,duration_sec,extra\n')
    for phase, ex, dur, extra in rows:
        ex = '' if ex is None else str(ex)
        dur = '' if dur is None else str(dur)
        extra = (extra or '').replace('\n',' ').replace(',',';')
        f.write(f"{phase},{ex},{dur},{extra}\n")
PY
fi

write_summary_kv FINAL_EXIT "${FINAL_EXIT}"

echo "[suite] Done. Logs at: ${OUT_DIR} (exit=${FINAL_EXIT})"
ls -la "${OUT_DIR}" >/dev/null

exit "${FINAL_EXIT}"


