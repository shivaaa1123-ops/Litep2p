#!/usr/bin/env bash
set -euo pipefail

# One-command Android LTE<->WiFi style handoff repro + log capture.
#
# This script:
# - Clears logcat
# - Restarts the Android app
# - Toggles WiFi off -> on (simulates LTE->WiFi handoff behavior where availability may not go false)
# - Captures high-signal logs into timestamped files
# - Injects explicit MARK lines into device logs for easy timing correlation
#
# Requirements:
# - adb available on PATH
# - Device connected/authorized
#
# Optional environment variables:
# - ANDROID_PKG (default: com.zeengal.litep2p)
# - ANDROID_ACTIVITY (default: .MainActivity)
# - LOGCAT_TAGS (default: LiteP2P_Native:V Litep2p:V MainActivity:V LITEP2P_TEST:I)
# - AUTO_START_ENGINE (default: 1) launch the app with LITEP2P_AUTOSTART intent extra
# - ENGINE_COMMS_MODE (optional) sets spinner selection via LITEP2P_COMMS_MODE
# - ANDROID_PEER_ID (optional) persists peer id via LITEP2P_PEER_ID
# - ANDROID_PROXY_GATEWAY (optional) set proxy gateway checkbox via LITEP2P_PROXY_GATEWAY (0/1)
# - ANDROID_PROXY_CLIENT (optional) set proxy client checkbox via LITEP2P_PROXY_CLIENT (0/1)
# - LOOPS (default: 1) number of handoff cycles
# - TOGGLE_DATA (default: 1) toggle mobile data on/off during the loop (best-effort)
# - TOGGLE_AIRPLANE (default: 0) toggle airplane mode (requires permissions on some devices)
# - SCENARIOS (default: wifi) comma-separated scenarios to run each loop.
#   Supported: wifi,data,no_network. (wifi matches the original behavior)
# - STABILIZE_SECS (default: 0) extra settle time inserted between scenario steps
# - ANDROID_SERIAL / ADB_SERIAL (optional) target a specific device
# - START_DESKTOP (default: 1) start a desktop peer and capture logs (auto-disables if binary not found)
# - DESKTOP_BIN (optional) path to desktop peer binary
# - DESKTOP_CONFIG (default: repo config.json)
# - DESKTOP_PEER_ID (default: desktop-1)
# - DESKTOP_PORT (default: 31001)
# - DESKTOP_LOG_LEVEL (default: info)
# - DESKTOP_EXTRA_ARGS (optional) extra args appended to desktop peer command
# - DESKTOP_COUNT (default: 1) number of desktop peers to start (uses start_desktop_peers.sh when >1)
# - DESKTOP_ID_PREFIX (default: desktop-) prefix for auto peer IDs when DESKTOP_COUNT>1
# - DESKTOP_BASE_PORT (default: 31001) base port for auto peers when DESKTOP_COUNT>1
# - REMOTE_HOST (optional) SSH target for remote desktop peers (e.g., user@192.168.3.13)
# - REMOTE_PASS (optional) SSH password for remote host (uses sshpass)
# - REMOTE_BIN (default: ~/litep2p/litep2p_peer_linux) path to binary on remote machine
# - REMOTE_CONFIG (default: ~/litep2p/config.json) path to config on remote machine
# - REMOTE_COUNT (default: half of DESKTOP_COUNT) number of peers to run on remote machine
# - RESTART_APP_BEFORE_WIFI_DISABLE (default: 0) hard-restart app/engine before wifi_disable marker
# - RESTART_APP_BEFORE_WIFI_ENABLE (default: 0) hard-restart app/engine before wifi_enable marker
# - GENERATE_REPORTS (default: 1) run timeline + timing summarizers at the end
# - ENFORCE_SLA (default: 0) run SLA checker (fails the script if violated)
# - SLA_SECONDS (default: 8) SLA threshold when ENFORCE_SLA=1
# - SLA_REQUIRE_READY (default: 0) also require PeerFSM READY within SLA ("ready for messaging")
# - REQUIRE_ENGINE_START (default: 0) if 1, fail the run when engine start cannot be confirmed
# - WATCHDOG_ENABLE (default: 1) fail fast when logs stall (deadlock/crash/hang signal)
# - WATCHDOG_NO_LOG_SECS (default: 25) seconds without *any* new logcat lines before failing
# - WATCHDOG_NO_PROGRESS_SECS (default: 75) seconds without high-signal progress lines before failing
# - REQUIRE_TOGGLE_SUCCESS (default: 0) if 1, fail the run when Wi‑Fi/data/airplane toggles cannot be verified
# - WIFI_TOGGLE_RETRIES (default: 3) number of attempts for Wi‑Fi enable/disable
# - WIFI_TOGGLE_VERIFY_SECS (default: 18) seconds to wait for Wi‑Fi state to reflect desired value
# - WIFI_TOGGLE_CMD_SETTLE_SECS (default: 1) pause after issuing the Wi‑Fi toggle command before verification
# - WIFI_IP_VERIFY_SECS (default: 25) when enabling Wi‑Fi, time to wait for a non-link-local IPv4
# - DATA_TOGGLE_RETRIES (default: 3) number of attempts for mobile data enable/disable
# - DATA_TOGGLE_VERIFY_SECS (default: 12) seconds to wait for mobile_data setting to reflect desired value
# - DATA_TOGGLE_CMD_SETTLE_SECS (default: 1) pause after issuing the data toggle command before verification
# - AIRPLANE_TOGGLE_RETRIES (default: 3) number of attempts for airplane mode on/off
# - AIRPLANE_TOGGLE_VERIFY_SECS (default: 10) seconds to wait for airplane_mode_on to reflect desired value
# - AIRPLANE_TOGGLE_CMD_SETTLE_SECS (default: 1) pause after issuing the airplane toggle command before verification
#
# Hello message on peer READY (messaging after handshake):
# - SEND_HELLO_ON_READY (default: 1) send a hello message when a peer reaches READY state
# - HELLO_MESSAGE_CONTENT (default: "Hello from Android handoff test!") the message to send
# - HELLO_MESSAGE_MONITOR_INTERVAL_S (default: 2) how often to check for new READY peers
# - HELLO_MESSAGE_POST_READY_DELAY_S (default: 3) delay after READY before sending hello
#   This allows the network path to stabilize after handoff before sending data.
# - WAIT_FOR_UDP_CONFIRMATION (default: 0) if 1, wait for bidirectional UDP traffic before sending
#   This is more robust than just a delay, but requires heartbeat traffic to be visible in logs.
# - UDP_CONFIRMATION_TIMEOUT_S (default: 10) max time to wait for UDP confirmation
#
# Message delivery verification:
# - VERIFY_MESSAGE_DELIVERY (default: 1) verify ACK received after sending hello messages
# - MESSAGE_ACK_TIMEOUT_SECS (default: 8) how long to wait for ACK after sending
# - MESSAGE_ACK_RETRIES (default: 3) number of retries for ACK verification with exponential backoff
# - MESSAGE_ACK_RETRY_DELAY_S (default: 2) initial delay between ACK verification retries
# - REQUIRE_MESSAGE_DELIVERY (default: 0) if 1, fail the run when message delivery cannot be verified
#
# Socket restart verification:
# - WAIT_FOR_SOCKET_RESTART (default: 1) wait for socket restart confirmation after network change
# - SOCKET_RESTART_TIMEOUT_S (default: 15) max time to wait for socket restart confirmation
# - SOCKET_RESTART_SETTLE_S (default: 2) additional settle time after socket restart before sending
#
# Network transition safety:
# - NETWORK_TRANSITION_SAFETY_WINDOW_S (default: 3) delay before network transitions to flush in-flight messages
# - NETWORK_TRANSITION_IN_PROGRESS (file-based lock to prevent sending during transitions)
#
# Pre-flight checks:
# - RUN_PREFLIGHT_CHECKS (default: 1) verify connectivity before starting tests
# - PREFLIGHT_PING_TIMEOUT_S (default: 5) timeout for ping checks during pre-flight
#
# Test summary and metrics:
# - SHOW_TEST_SUMMARY (default: 1) show formatted test summary at end of run
# - ENHANCED_METRICS (default: 1) collect detailed connection/message/NAT metrics

ANDROID_PKG="${ANDROID_PKG:-com.zeengal.litep2p}"
ANDROID_ACTIVITY="${ANDROID_ACTIVITY:-.MainActivity}"
LOGCAT_TAGS="${LOGCAT_TAGS:-LiteP2P_Native:V Litep2p:V MainActivity:V LiteP2P_Network:V LITEP2P_TEST:I}"
AUTO_START_ENGINE="${AUTO_START_ENGINE:-1}"
ENGINE_COMMS_MODE="${ENGINE_COMMS_MODE:-}"
ANDROID_PEER_ID="${ANDROID_PEER_ID:-}"
ANDROID_PROXY_GATEWAY="${ANDROID_PROXY_GATEWAY:-}"
ANDROID_PROXY_CLIENT="${ANDROID_PROXY_CLIENT:-}"
LOOPS="${LOOPS:-1}"
TOGGLE_DATA="${TOGGLE_DATA:-1}"
TOGGLE_AIRPLANE="${TOGGLE_AIRPLANE:-0}"

SCENARIOS="${SCENARIOS:-wifi}"
STABILIZE_SECS="${STABILIZE_SECS:-0}"

# If 1, force a brief transport break (best-effort) to trigger real peer DISCONNECTED→CONNECTED.
# Implementation: while Wi‑Fi is OFF, temporarily disable mobile data for TRANSPORT_BREAK_SECS,
# then re-enable it so the phase can still proceed.
FORCE_TRANSPORT_BREAK="${FORCE_TRANSPORT_BREAK:-0}"
TRANSPORT_BREAK_SECS="${TRANSPORT_BREAK_SECS:-3}"

# Timing knobs (seconds). Defaults match the original hard-coded sleeps.
DATA_ENABLE_SECS="${DATA_ENABLE_SECS:-3}"
DATA_DISABLE_SECS="${DATA_DISABLE_SECS:-35}"
WIFI_DISABLE_SECS="${WIFI_DISABLE_SECS:-25}"
WIFI_ENABLE_SECS="${WIFI_ENABLE_SECS:-5}"
AIRPLANE_ENABLE_SECS="${AIRPLANE_ENABLE_SECS:-6}"
AIRPLANE_DISABLE_SECS="${AIRPLANE_DISABLE_SECS:-10}"

START_DESKTOP="${START_DESKTOP:-1}"
DESKTOP_BIN="${DESKTOP_BIN:-}"
DESKTOP_CONFIG="${DESKTOP_CONFIG:-}"
DESKTOP_PEER_ID="${DESKTOP_PEER_ID:-desktop-1}"
DESKTOP_PORT="${DESKTOP_PORT:-31001}"
DESKTOP_LOG_LEVEL="${DESKTOP_LOG_LEVEL:-info}"
DESKTOP_EXTRA_ARGS="${DESKTOP_EXTRA_ARGS:-}"

DESKTOP_COUNT="${DESKTOP_COUNT:-1}"
DESKTOP_ID_PREFIX="${DESKTOP_ID_PREFIX:-desktop-}"
DESKTOP_BASE_PORT="${DESKTOP_BASE_PORT:-31001}"

# Remote machine for desktop peers (avoids NAT hairpinning when all peers are behind same NAT)
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_PASS="${REMOTE_PASS:-}"
REMOTE_BIN="${REMOTE_BIN:-~/litep2p/litep2p_peer_linux}"
REMOTE_CONFIG="${REMOTE_CONFIG:-~/litep2p/config.json}"
REMOTE_COUNT="${REMOTE_COUNT:-}"

RESTART_APP_BEFORE_WIFI_DISABLE="${RESTART_APP_BEFORE_WIFI_DISABLE:-0}"
RESTART_APP_BEFORE_WIFI_ENABLE="${RESTART_APP_BEFORE_WIFI_ENABLE:-0}"

# Disable health checks during test loops to prevent disruptive app restarts
# Set to 1 to skip health checks (useful for handoff testing where brief unhealthy states are expected)
DISABLE_APP_HEALTH_CHECK="${DISABLE_APP_HEALTH_CHECK:-0}"

GENERATE_REPORTS="${GENERATE_REPORTS:-1}"
ENFORCE_SLA="${ENFORCE_SLA:-0}"
SLA_SECONDS="${SLA_SECONDS:-8}"
SLA_REQUIRE_READY="${SLA_REQUIRE_READY:-0}"
REQUIRE_ENGINE_START="${REQUIRE_ENGINE_START:-0}"

WATCHDOG_ENABLE="${WATCHDOG_ENABLE:-1}"
WATCHDOG_NO_LOG_SECS="${WATCHDOG_NO_LOG_SECS:-25}"
WATCHDOG_NO_PROGRESS_SECS="${WATCHDOG_NO_PROGRESS_SECS:-75}"

REQUIRE_TOGGLE_SUCCESS="${REQUIRE_TOGGLE_SUCCESS:-0}"

WIFI_TOGGLE_RETRIES="${WIFI_TOGGLE_RETRIES:-3}"
WIFI_TOGGLE_VERIFY_SECS="${WIFI_TOGGLE_VERIFY_SECS:-18}"
WIFI_TOGGLE_CMD_SETTLE_SECS="${WIFI_TOGGLE_CMD_SETTLE_SECS:-1}"
WIFI_IP_VERIFY_SECS="${WIFI_IP_VERIFY_SECS:-25}"

DATA_TOGGLE_RETRIES="${DATA_TOGGLE_RETRIES:-3}"
DATA_TOGGLE_VERIFY_SECS="${DATA_TOGGLE_VERIFY_SECS:-12}"
DATA_TOGGLE_CMD_SETTLE_SECS="${DATA_TOGGLE_CMD_SETTLE_SECS:-1}"

AIRPLANE_TOGGLE_RETRIES="${AIRPLANE_TOGGLE_RETRIES:-3}"
AIRPLANE_TOGGLE_VERIFY_SECS="${AIRPLANE_TOGGLE_VERIFY_SECS:-10}"
AIRPLANE_TOGGLE_CMD_SETTLE_SECS="${AIRPLANE_TOGGLE_CMD_SETTLE_SECS:-1}"

# Engine running detection:
# - We prefer PID-scoped matching (to avoid confusing previous app processes).
# - The default regexes include both legacy UI logs and native engine logs.
ENGINE_START_WAIT_TRIES="${ENGINE_START_WAIT_TRIES:-40}"
ENGINE_START_WAIT_SLEEP_S="${ENGINE_START_WAIT_SLEEP_S:-0.5}"

# Hello message configuration (sent after successful peer handshake/READY state)
# - SEND_HELLO_ON_READY (default: 1) send a hello message to peer when connection becomes READY
# - HELLO_MESSAGE_CONTENT (default: "Hello from Android handoff test!")
# - HELLO_MESSAGE_MONITOR_INTERVAL_S (default: 2) how often to check for new READY peers
SEND_HELLO_ON_READY="${SEND_HELLO_ON_READY:-1}"
HELLO_MESSAGE_CONTENT="${HELLO_MESSAGE_CONTENT:-Hello from Android handoff test!}"
HELLO_MESSAGE_MONITOR_INTERVAL_S="${HELLO_MESSAGE_MONITOR_INTERVAL_S:-2}"
HELLO_MESSAGE_POST_READY_DELAY_S="${HELLO_MESSAGE_POST_READY_DELAY_S:-5}"
WAIT_FOR_UDP_CONFIRMATION="${WAIT_FOR_UDP_CONFIRMATION:-1}"
UDP_CONFIRMATION_TIMEOUT_S="${UDP_CONFIRMATION_TIMEOUT_S:-15}"

# Message delivery verification configuration
VERIFY_MESSAGE_DELIVERY="${VERIFY_MESSAGE_DELIVERY:-1}"
MESSAGE_ACK_TIMEOUT_SECS="${MESSAGE_ACK_TIMEOUT_SECS:-8}"
MESSAGE_ACK_RETRIES="${MESSAGE_ACK_RETRIES:-3}"
MESSAGE_ACK_RETRY_DELAY_S="${MESSAGE_ACK_RETRY_DELAY_S:-2}"
REQUIRE_MESSAGE_DELIVERY="${REQUIRE_MESSAGE_DELIVERY:-0}"

# Socket restart verification configuration
WAIT_FOR_SOCKET_RESTART="${WAIT_FOR_SOCKET_RESTART:-1}"
SOCKET_RESTART_TIMEOUT_S="${SOCKET_RESTART_TIMEOUT_S:-15}"
SOCKET_RESTART_SETTLE_S="${SOCKET_RESTART_SETTLE_S:-2}"

# Network transition safety configuration
NETWORK_TRANSITION_SAFETY_WINDOW_S="${NETWORK_TRANSITION_SAFETY_WINDOW_S:-3}"
NETWORK_TRANSITION_LOCK_FILE=""

# Pre-flight checks configuration
RUN_PREFLIGHT_CHECKS="${RUN_PREFLIGHT_CHECKS:-1}"
PREFLIGHT_PING_TIMEOUT_S="${PREFLIGHT_PING_TIMEOUT_S:-5}"

# Test summary and enhanced metrics configuration
SHOW_TEST_SUMMARY="${SHOW_TEST_SUMMARY:-1}"
ENHANCED_METRICS="${ENHANCED_METRICS:-1}"

# If we're enforcing an SLA, ensure our phase windows are not shorter than the SLA itself.
# Timing analysis keys off MARK windows (wifi_disable -> wifi_enable). If that window is shorter
# than SLA_SECONDS, REGISTER_ACK could be within SLA but still be counted as "missing".
if [[ "${ENFORCE_SLA}" == "1" ]]; then
  SLA_SECONDS_INT="${SLA_SECONDS%%.*}"
  if [[ -n "${SLA_SECONDS_INT}" ]] && [[ "${SLA_SECONDS_INT}" =~ ^[0-9]+$ ]]; then
    if [[ "${WIFI_DISABLE_SECS}" =~ ^[0-9]+$ ]]; then
      if (( WIFI_DISABLE_SECS < SLA_SECONDS_INT + 1 )); then
        WIFI_DISABLE_SECS=$((SLA_SECONDS_INT + 1))
      fi
    fi
  fi
fi

ADB_BIN="${ADB_BIN:-adb}"
ADB_SERIAL="${ANDROID_SERIAL:-${ADB_SERIAL:-}}"
ADB_ARGS=()
if [[ -z "${ADB_SERIAL}" ]]; then
  ADB_DEVICES_OUT="$("${ADB_BIN}" devices 2>/dev/null || true)"
  ADB_DEVICE_COUNT="$(printf '%s\n' "${ADB_DEVICES_OUT}" | awk 'NR>1 && $2=="device" {c++} END {print c+0}')"
  if [[ "${ADB_DEVICE_COUNT}" == "1" ]]; then
    ADB_SERIAL="$(printf '%s\n' "${ADB_DEVICES_OUT}" | awk 'NR>1 && $2=="device" {print $1; exit}')"
  elif [[ "${ADB_DEVICE_COUNT}" == "0" ]]; then
    echo "ERROR: No authorized Android device found (adb devices shows 0 devices)." >&2
    exit 1
  else
    echo "ERROR: Multiple adb devices found (${ADB_DEVICE_COUNT}). Set ANDROID_SERIAL or ADB_SERIAL." >&2
    echo "adb devices:" >&2
    echo "${ADB_DEVICES_OUT}" >&2
    exit 1
  fi
fi

if [[ -n "${ADB_SERIAL}" ]]; then
  ADB_ARGS=(-s "${ADB_SERIAL}")
fi

adb_cmd() {
  "${ADB_BIN}" "${ADB_ARGS[@]}" "$@"
}

if ! adb_cmd get-state >/dev/null 2>&1; then
  echo "ERROR: No authorized Android device found (adb get-state failed)." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/tools/harness/runs"
mkdir -p "${OUT_DIR}"

if [[ -z "${DESKTOP_CONFIG}" ]]; then
  DESKTOP_CONFIG="${ROOT_DIR}/config.json"
fi

TS="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUT_DIR}/android_handoff_${TS}"
mkdir -p "${RUN_DIR}"

ANDROID_LOG="${RUN_DIR}/android_logcat_threadtime.txt"
ANDROID_LOG_DUMP="${RUN_DIR}/android_logcat_dump_threadtime.txt"
HOST_MARKS_LOG="${RUN_DIR}/host_marks.txt"
META="${RUN_DIR}/meta.txt"

ANDROID_LOG_HIGH_SIGNAL="${RUN_DIR}/android_logcat_high_signal.txt"
LOG_COUNTS="${RUN_DIR}/log_counts.txt"

DESKTOP_LOG="${RUN_DIR}/desktop_peer.log"

read -r -a LOGCAT_TAGS_ARR <<<"${LOGCAT_TAGS}"

LOGCAT_PID=""
LOGCAT_ADB_PID=""
LOGCAT_READER_PID=""
LOGCAT_FIFO=""
DESKTOP_PID=""
DESKTOP_PEERS_RUN_DIR=""
WATCHDOG_PID=""

kill_and_wait() {
  local pid="$1"
  local timeout_s="${2:-3}"
  if [[ -z "${pid}" ]]; then
    return 0
  fi

  kill "${pid}" >/dev/null 2>&1 || true
  local tries
  tries=$((timeout_s * 10))
  for _ in $(seq 1 "${tries}"); do
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  kill -9 "${pid}" >/dev/null 2>&1 || true
  return 0
}

# Safe grep count - avoids the issue where grep -c returns "0" on stdout but exit code 1,
# causing "|| echo 0" to add another "0" and produce "0\n0"
grep_count() {
  local pattern="$1"
  local file="$2"
  local count
  count=$(grep -c "${pattern}" "${file}" 2>/dev/null) || true
  echo "${count:-0}"
}

cleanup() {
  set +e
  # Stop logcat stream (both adb producer + reader) if running.
  if [[ -n "${LOGCAT_READER_PID}" ]]; then
    kill_and_wait "${LOGCAT_READER_PID}" 3
    wait "${LOGCAT_READER_PID}" >/dev/null 2>&1 || true
    LOGCAT_READER_PID=""
  fi
  if [[ -n "${LOGCAT_ADB_PID}" ]]; then
    kill_and_wait "${LOGCAT_ADB_PID}" 3
    wait "${LOGCAT_ADB_PID}" >/dev/null 2>&1 || true
    LOGCAT_ADB_PID=""
  fi
  LOGCAT_PID=""

  if [[ -n "${LOGCAT_FIFO}" ]]; then
    rm -f "${LOGCAT_FIFO}" >/dev/null 2>&1 || true
    LOGCAT_FIFO=""
  fi

  if [[ -n "${WATCHDOG_PID}" ]]; then
    kill_and_wait "${WATCHDOG_PID}" 2
    wait "${WATCHDOG_PID}" >/dev/null 2>&1 || true
    WATCHDOG_PID=""
  fi

  # Stop hello message monitor if running.
  if [[ -n "${HELLO_MONITOR_PID}" ]]; then
    kill_and_wait "${HELLO_MONITOR_PID}" 2
    wait "${HELLO_MONITOR_PID}" >/dev/null 2>&1 || true
    HELLO_MONITOR_PID=""
  fi

  # Clean up network transition lock file
  if [[ -n "${NETWORK_TRANSITION_LOCK_FILE}" ]] && [[ -f "${NETWORK_TRANSITION_LOCK_FILE}" ]]; then
    rm -f "${NETWORK_TRANSITION_LOCK_FILE}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${DESKTOP_PID}" ]]; then
    kill "${DESKTOP_PID}" >/dev/null 2>&1 || true
    wait "${DESKTOP_PID}" >/dev/null 2>&1 || true
    DESKTOP_PID=""
  fi

  if [[ -n "${DESKTOP_PEERS_RUN_DIR}" ]]; then
    REMOTE_PASS="${REMOTE_PASS}" "${ROOT_DIR}/tools/harness/stop_desktop_peers.sh" "${DESKTOP_PEERS_RUN_DIR}" >/dev/null 2>&1 || true
    DESKTOP_PEERS_RUN_DIR=""
  fi
}
trap cleanup EXIT

start_watchdog() {
  if [[ "${WATCHDOG_ENABLE}" != "1" ]]; then
    return 0
  fi

  local main_pid="$1"
  local last_progress_epoch
  last_progress_epoch="$(date +%s)"

  # Track last time the log file showed *any* activity. Prefer mtime (fast, robust),
  # and fall back to line-count deltas when mtime isn't available.
  local last_any_epoch
  last_any_epoch="${last_progress_epoch}"
  local last_seen_mtime
  last_seen_mtime="$(stat -f %m "${ANDROID_LOG}" 2>/dev/null || stat -c %Y "${ANDROID_LOG}" 2>/dev/null || echo 0)"
  local last_lines
  last_lines="$(log_line_count)"

  local progress_re
  progress_re="\\[PeerFSM\\]|SM: Signaling reconnect attempt|REGISTER_ACK|Network change detected|NATIVE: Network info update|Signaling: Connected successfully"

  (
    set +e
    while kill -0 "${main_pid}" >/dev/null 2>&1; do
      sleep 1

      local now
      now="$(date +%s)"

      # Fast path: detect *any* log activity via file mtime.
      local mtime_epoch
      mtime_epoch="$(stat -f %m "${ANDROID_LOG}" 2>/dev/null || stat -c %Y "${ANDROID_LOG}" 2>/dev/null || echo 0)"
      if [[ "${mtime_epoch}" =~ ^[0-9]+$ ]] && (( mtime_epoch > 0 )); then
        if [[ "${last_seen_mtime}" =~ ^[0-9]+$ ]] && (( mtime_epoch > last_seen_mtime )); then
          last_seen_mtime="${mtime_epoch}"
          last_any_epoch="${now}"
        fi
      else
        # Fall back to line-count growth if mtime isn't available.
        local cur_lines
        cur_lines="$(log_line_count)"
        if [[ -z "${cur_lines}" ]]; then
          cur_lines=0
        fi
        if (( cur_lines > last_lines )); then
          last_lines="${cur_lines}"
          last_any_epoch="${now}"
        fi
      fi

      # Progress detection: only scan a small tail window to avoid expensive full-file slicing.
      if tail -n 400 "${ANDROID_LOG}" 2>/dev/null | grep -qE "${progress_re}"; then
        last_progress_epoch="${now}"
      fi

      # No-logcat-lines watchdog.
      if (( now - last_any_epoch >= WATCHDOG_NO_LOG_SECS )); then
        mark "watchdog_fail kind=no_log secs=${WATCHDOG_NO_LOG_SECS}"
        kill -TERM "${main_pid}" >/dev/null 2>&1 || true
        exit 2
      fi

      # No-high-signal-progress watchdog.
      if (( now - last_progress_epoch >= WATCHDOG_NO_PROGRESS_SECS )); then
        mark "watchdog_fail kind=no_progress secs=${WATCHDOG_NO_PROGRESS_SECS}"
        kill -TERM "${main_pid}" >/dev/null 2>&1 || true
        exit 3
      fi
    done
  ) &
  WATCHDOG_PID=$!
}

mark() {
  adb_cmd shell log -t LITEP2P_TEST "MARK: $*" >/dev/null 2>&1 || true

  printf '[HOST %s] MARK: %s\n' "$(date +%Y-%m-%dT%H:%M:%S%z)" "$*" >>"${HOST_MARKS_LOG}" 2>/dev/null || true

  # Also write host-side marker into desktop log for easier correlation.
  if [[ -n "${DESKTOP_PID}" ]]; then
    printf '[HOST %s] MARK: %s\n' "$(date +%Y-%m-%dT%H:%M:%S%z)" "$*" >>"${DESKTOP_LOG}" 2>/dev/null || true
  fi
}

log_line_count() {
  if [[ -f "${ANDROID_LOG}" ]]; then
    wc -l <"${ANDROID_LOG}" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

# ============================================================================
# Hello Message on Peer READY
# ============================================================================
# Tracks peers that have transitioned to READY state and sends hello messages.
# Sends a hello message for EACH READY transition (not just once per peer).
# This ensures we send hello after both LAN/private IP connections and 
# WAN/public IP connections (after network handoff).

HELLO_SENT_LOG_FILE=""
HELLO_MONITOR_PID=""
HELLO_LAST_PROCESSED_LINE=0

# Message delivery tracking (for verification and metrics)
MESSAGE_DELIVERY_LOG_FILE=""
MESSAGES_SENT_COUNT=0
MESSAGES_ACKED_COUNT=0
MESSAGES_FAILED_COUNT=0
MESSAGE_LATENCIES=""

# Wait for bidirectional UDP confirmation
# Looks for recent UDP_SEND_SUCCESS and UDP_RECEIVE entries for the peer
# This is more robust than a time delay as it confirms the network path is working
# Now also checks for socket restart completion before looking for UDP traffic
wait_for_udp_confirmation() {
  local peer_id="$1"
  local since_line="$2"
  local timeout_s="${3:-${UDP_CONFIRMATION_TIMEOUT_S}}"
  
  if [[ "${WAIT_FOR_UDP_CONFIRMATION}" != "1" ]]; then
    return 0
  fi
  
  echo "    Waiting for bidirectional UDP confirmation for ${peer_id}..."
  mark "udp_confirmation_wait_start peer=${peer_id} timeout=${timeout_s}"
  
  local tries=$((timeout_s * 4))
  local udp_send_ok=0
  local udp_recv_ok=0
  local socket_ready=0
  
  for i in $(seq 1 "${tries}"); do
    if [[ -f "${ANDROID_LOG}" ]]; then
      # Check for both UDP send and receive since READY
      local recent_logs
      recent_logs="$(tail -n +"$((since_line + 1))" "${ANDROID_LOG}" 2>/dev/null || true)"
      
      # First verify socket is ready (socket restart completed or socket bound)
      if [[ "${socket_ready}" == "0" ]]; then
        if echo "${recent_logs}" | grep -qE "Socket restarted successfully|UDP_SOCKET_RESTART_COMPLETE|UDP: Socket restarted|UDP: Bound socket|UDP_SOCKET_BOUND"; then
          socket_ready=1
          echo "    Socket ready confirmed"
        fi
      fi
      
      # Check for UDP send success
      if echo "${recent_logs}" | grep -qE "UDP_SEND_SUCCESS.*${peer_id}|Sent message to peer.*${peer_id}|UDP: Sent.*to.*${peer_id}"; then
        udp_send_ok=1
      fi
      
      # Check for UDP receive
      if echo "${recent_logs}" | grep -qE "UDP_RECEIVE.*from.*${peer_id}|Received.*from.*${peer_id}|UDP_DEBUG: recvfrom|recvfrom received.*bytes from"; then
        udp_recv_ok=1
      fi
      
      # Also check for PING/PONG heartbeat exchange which confirms bidirectional UDP
      if echo "${recent_logs}" | grep -qE "PING.*${peer_id}|PONG.*${peer_id}|heartbeat.*${peer_id}|Heartbeat sent|Heartbeat received"; then
        udp_send_ok=1
        udp_recv_ok=1
      fi
      
      # Check for peer address update which indicates connectivity
      if echo "${recent_logs}" | grep -qE "address_changed.*${peer_id}|peer.*endpoint.*updated|Peer address updated"; then
        # Address update is a good sign, but still want to verify actual traffic
        if [[ "${udp_send_ok}" == "0" ]]; then
          echo "    Peer address updated, waiting for traffic confirmation..."
        fi
      fi
      
      if [[ "${udp_send_ok}" == "1" ]] && [[ "${udp_recv_ok}" == "1" ]]; then
        echo "    ✅ Bidirectional UDP confirmed for ${peer_id}"
        mark "udp_confirmation_success peer=${peer_id} socket_ready=${socket_ready}"
        return 0
      fi
    fi
    sleep 0.25
  done
  
  # Provide diagnostic info on timeout
  local diag_msg="send_ok=${udp_send_ok}, recv_ok=${udp_recv_ok}, socket_ready=${socket_ready}"
  echo "    ⚠️  UDP confirmation timeout for ${peer_id} (${diag_msg})"
  mark "udp_confirmation_timeout peer=${peer_id} udp_send_ok=${udp_send_ok} udp_recv_ok=${udp_recv_ok} socket_ready=${socket_ready}"
  return 1
}

# ============================================================================
# Socket Restart Verification
# ============================================================================
# Wait for socket restart confirmation after network change
# Looks for UDP_SOCKET_RESTART_COMPLETE or "Socket restarted successfully" in logs
wait_for_socket_restart() {
  local since_line="${1:-0}"
  local timeout_s="${2:-${SOCKET_RESTART_TIMEOUT_S}}"
  
  if [[ "${WAIT_FOR_SOCKET_RESTART}" != "1" ]]; then
    return 0
  fi
  
  echo "    Waiting for socket restart confirmation..."
  mark "socket_restart_wait_start since_line=${since_line} timeout=${timeout_s}"
  
  local tries=$((timeout_s * 4))
  local socket_restarted=0
  local restart_ts=""
  
  for i in $(seq 1 "${tries}"); do
    if [[ -f "${ANDROID_LOG}" ]]; then
      # Check for socket restart confirmation in logs
      local recent_logs
      recent_logs="$(tail -n +"$((since_line + 1))" "${ANDROID_LOG}" 2>/dev/null || true)"
      
      # Look for socket restart success indicators
      if echo "${recent_logs}" | grep -qE "UDP_SOCKET_RESTART_COMPLETE|Socket restarted successfully|UDP: Socket restarted|socket restart.*success"; then
        socket_restarted=1
        restart_ts="$(date +%Y-%m-%dT%H:%M:%S%z)"
        break
      fi
      
      # Also check for new socket binding which indicates restart
      if echo "${recent_logs}" | grep -qE "UDP: Bound socket to port|UDP: Socket bound on|UDP_SOCKET_BOUND"; then
        socket_restarted=1
        restart_ts="$(date +%Y-%m-%dT%H:%M:%S%z)"
        break
      fi
    fi
    sleep 0.25
  done
  
  if [[ "${socket_restarted}" == "1" ]]; then
    echo "    ✅ Socket restart confirmed at ${restart_ts}"
    mark "socket_restart_confirmed ts=${restart_ts}"
    
    # Additional settle time after socket restart
    if [[ "${SOCKET_RESTART_SETTLE_S}" -gt 0 ]]; then
      echo "    Waiting ${SOCKET_RESTART_SETTLE_S}s for socket to settle..."
      sleep "${SOCKET_RESTART_SETTLE_S}"
    fi
    return 0
  else
    echo "    ⚠️  Socket restart not confirmed within ${timeout_s}s"
    mark "socket_restart_timeout timeout=${timeout_s}"
    return 1
  fi
}

# ============================================================================
# Network Transition Lock
# ============================================================================
# File-based lock to prevent sending messages during network transitions
# This helps avoid message loss when the network path is changing

init_network_transition_lock() {
  NETWORK_TRANSITION_LOCK_FILE="${RUN_DIR}/network_transition.lock"
  rm -f "${NETWORK_TRANSITION_LOCK_FILE}" 2>/dev/null || true
}

acquire_network_transition_lock() {
  local reason="${1:-unknown}"
  if [[ -n "${NETWORK_TRANSITION_LOCK_FILE}" ]]; then
    echo "${reason}" > "${NETWORK_TRANSITION_LOCK_FILE}" 2>/dev/null || true
    mark "network_transition_lock_acquired reason=${reason}"
  fi
}

release_network_transition_lock() {
  if [[ -n "${NETWORK_TRANSITION_LOCK_FILE}" ]] && [[ -f "${NETWORK_TRANSITION_LOCK_FILE}" ]]; then
    rm -f "${NETWORK_TRANSITION_LOCK_FILE}" 2>/dev/null || true
    mark "network_transition_lock_released"
  fi
}

is_network_transition_in_progress() {
  if [[ -n "${NETWORK_TRANSITION_LOCK_FILE}" ]] && [[ -f "${NETWORK_TRANSITION_LOCK_FILE}" ]]; then
    return 0  # Lock exists, transition in progress
  fi
  return 1  # No lock, safe to send
}

# Wait for network transition to complete before sending
wait_for_network_stable() {
  local max_wait_s="${1:-30}"
  local tries=$((max_wait_s * 4))
  
  for i in $(seq 1 "${tries}"); do
    if ! is_network_transition_in_progress; then
      return 0
    fi
    sleep 0.25
  done
  
  echo "[WARN] Network transition still in progress after ${max_wait_s}s"
  return 1
}

# ============================================================================
# Pre-flight Checks
# ============================================================================
# Verify connectivity before starting tests

run_preflight_checks() {
  if [[ "${RUN_PREFLIGHT_CHECKS}" != "1" ]]; then
    return 0
  fi
  
  echo "==> Running pre-flight checks..."
  mark "preflight_checks_start"
  
  local preflight_passed=1
  
  # Check 1: ADB device is responsive
  echo "    Checking ADB connectivity..."
  if adb_cmd shell echo "ok" >/dev/null 2>&1; then
    echo "    ✅ ADB device responsive"
  else
    echo "    ❌ ADB device not responsive"
    preflight_passed=0
  fi
  
  # Check 2: App package exists on device
  echo "    Checking app installation..."
  if adb_cmd shell pm list packages 2>/dev/null | grep -q "${ANDROID_PKG}"; then
    echo "    ✅ App package ${ANDROID_PKG} found"
  else
    echo "    ❌ App package ${ANDROID_PKG} not found"
    preflight_passed=0
  fi
  
  # Check 3: Network connectivity on device
  echo "    Checking device network..."
  local net_state
  net_state="$(adb_cmd shell dumpsys connectivity 2>/dev/null | grep -E "NetworkAgentInfo.*CONNECTED" | head -1 || true)"
  if [[ -n "${net_state}" ]]; then
    echo "    ✅ Device has network connectivity"
  else
    echo "    ⚠️  Device network state unclear (may still work)"
  fi
  
  # Check 4: Desktop peer reachable (if enabled)
  if [[ "${START_DESKTOP}" == "1" ]]; then
    echo "    Checking desktop peer config..."
    if [[ -f "${DESKTOP_CONFIG}" ]]; then
      echo "    ✅ Desktop config exists: ${DESKTOP_CONFIG}"
    else
      echo "    ⚠️  Desktop config not found: ${DESKTOP_CONFIG}"
    fi
  fi
  
  # Check 5: Signaling server reachable (best effort)
  if [[ -f "${DESKTOP_CONFIG}" ]]; then
    local signaling_url
    signaling_url="$(grep -E '"signaling_url"|"websocket_url"' "${DESKTOP_CONFIG}" 2>/dev/null | head -1 | sed -E 's/.*"(wss?:\/\/[^"]+)".*/\1/' || true)"
    if [[ -n "${signaling_url}" ]]; then
      local signaling_host
      signaling_host="$(echo "${signaling_url}" | sed -E 's|wss?://([^:/]+).*|\1|')"
      echo "    Checking signaling server: ${signaling_host}..."
      if ping -c 1 -W "${PREFLIGHT_PING_TIMEOUT_S}" "${signaling_host}" >/dev/null 2>&1; then
        echo "    ✅ Signaling server reachable: ${signaling_host}"
      else
        echo "    ⚠️  Signaling server ping failed (may still work via different route)"
      fi
    fi
  fi
  
  mark "preflight_checks_complete passed=${preflight_passed}"
  
  if [[ "${preflight_passed}" == "0" ]]; then
    echo "    ❌ Pre-flight checks failed - some tests may not work"
    return 1
  fi
  
  echo "    ✅ Pre-flight checks passed"
  return 0
}

# Track socket restart events for metrics
SOCKET_RESTART_COUNT=0
SOCKET_RESTART_TIMES=""
LAST_SOCKET_RESTART_LINE=0

# ============================================================================
# Graceful Recovery and Error Handling
# ============================================================================
# Detect and recover from stuck states during testing

# Check if the app is still running and responsive
check_app_health() {
  local pid
  pid="$(get_app_pid)"
  
  if [[ -z "${pid}" ]]; then
    echo "[WARN] App not running - attempting recovery"
    mark "app_health_check failed=no_pid"
    return 1
  fi
  
  # Check if the app is responding to intents
  local test_result
  test_result="$(adb_cmd shell am start -n "${ANDROID_PKG}/${ANDROID_ACTIVITY}" -f 0x20000000 2>&1 || true)"
  if echo "${test_result}" | grep -qiE "error|exception|not found"; then
    echo "[WARN] App not responding to intents"
    mark "app_health_check failed=intent_error"
    return 1
  fi
  
  return 0
}

# Attempt to recover the app if it's in a bad state
recover_app_if_needed() {
  if check_app_health; then
    return 0
  fi
  
  echo "==> Attempting app recovery..."
  mark "app_recovery_start"
  
  # Force stop and restart the app
  adb_cmd shell am force-stop "${ANDROID_PKG}" || true
  sleep 2
  
  launch_app_and_wait_engine "recovery"
  
  # Give it time to re-establish connections
  sleep 5
  
  if check_app_health; then
    echo "    ✅ App recovered successfully"
    mark "app_recovery_success"
    return 0
  else
    echo "    ❌ App recovery failed"
    mark "app_recovery_failed"
    return 1
  fi
}

# Check for network stall (no activity for extended period)
check_network_stall() {
  local stall_threshold_s="${1:-30}"
  
  if [[ ! -f "${ANDROID_LOG}" ]]; then
    return 1
  fi
  
  # Check if there's been any network activity in recent logs
  local recent_activity
  recent_activity="$(tail -n 100 "${ANDROID_LOG}" 2>/dev/null | grep -cE "UDP_SEND|UDP_RECEIVE|Signaling|PeerFSM")" || recent_activity=0
  
  if [[ "${recent_activity}" -eq 0 ]]; then
    # Check file modification time
    local mtime_epoch
    mtime_epoch="$(stat -f %m "${ANDROID_LOG}" 2>/dev/null || stat -c %Y "${ANDROID_LOG}" 2>/dev/null || echo 0)"
    local now_epoch
    now_epoch="$(date +%s)"
    
    if [[ "${mtime_epoch}" =~ ^[0-9]+$ ]] && (( now_epoch - mtime_epoch >= stall_threshold_s )); then
      mark "network_stall_detected last_activity=$((now_epoch - mtime_epoch))s_ago"
      return 0  # Stall detected
    fi
  fi
  
  return 1  # No stall
}

# Attempt to recover from network stall
recover_from_network_stall() {
  echo "==> Network stall detected, attempting recovery..."
  mark "network_stall_recovery_start"
  
  # Try toggling airplane mode briefly to force network re-initialization
  echo "    Toggling airplane mode to force network reset..."
  adb_cmd shell settings put global airplane_mode_on 1 || true
  adb_cmd shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true >/dev/null 2>&1 || true
  sleep 2
  adb_cmd shell settings put global airplane_mode_on 0 || true
  adb_cmd shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false >/dev/null 2>&1 || true
  sleep 3
  
  # Re-enable WiFi if it was on
  adb_cmd shell svc wifi enable || true
  sleep 2
  
  mark "network_stall_recovery_complete"
}

init_hello_message_tracking() {
  if [[ "${SEND_HELLO_ON_READY}" != "1" ]]; then
    return 0
  fi
  HELLO_SENT_LOG_FILE="${RUN_DIR}/hello_sent_log.txt"
  MESSAGE_DELIVERY_LOG_FILE="${RUN_DIR}/message_delivery_log.txt"
  : >"${HELLO_SENT_LOG_FILE}"
  : >"${MESSAGE_DELIVERY_LOG_FILE}"
  HELLO_LAST_PROCESSED_LINE=0
  MESSAGES_SENT_COUNT=0
  MESSAGES_ACKED_COUNT=0
  MESSAGES_FAILED_COUNT=0
  MESSAGE_LATENCIES=""
}

# Send hello message to a peer via the Android app
# Uses adb am start with intent extras to trigger P2P.sendMessageTracked() in the app
send_hello_to_peer() {
  local peer_id="$1"
  local connection_info="${2:-}"
  local message="${3:-${HELLO_MESSAGE_CONTENT}}"
  
  local ts
  ts="$(date +%Y-%m-%dT%H:%M:%S%z)"
  local hello_count
  hello_count="$(wc -l <"${HELLO_SENT_LOG_FILE}" 2>/dev/null | tr -d ' ' || echo 0)"
  hello_count=$((hello_count + 1))
  
  mark "hello_message_send peer=${peer_id} count=${hello_count} connection=${connection_info} message_preview=${message:0:50}"
  
  # Use am start with intent extras to trigger message sending via MainActivity.onNewIntent()
  # This calls P2P.sendMessageTracked() which wraps the message in LP_APP envelope with ACK request
  # Flags: FLAG_ACTIVITY_SINGLE_TOP (0x20000000) ensures onNewIntent is called if activity exists
  #        FLAG_ACTIVITY_NEW_TASK (0x10000000) is required when starting from non-activity context
  # Combined flags: 0x30000000
  local adb_result
  # Use proper quoting to handle spaces in message and peer_id
  adb_result="$(adb_cmd shell "am start -n com.zeengal.litep2p/.MainActivity -f 0x30000000 --es LITEP2P_SEND_TO_PEER '${peer_id}' --es LITEP2P_SEND_MESSAGE '${message}'" 2>&1)" || true
  
  # Log the adb result for debugging
  if echo "${adb_result}" | grep -qi "error\|exception\|denied"; then
    echo "[WARN] adb am start may have failed: ${adb_result}" >&2
  fi
  
  # Log this hello send with timestamp and connection info
  printf '%s|%s|%s|%s\n' "${ts}" "${peer_id}" "${connection_info}" "${message}" \
    >>"${HELLO_SENT_LOG_FILE}" 2>/dev/null || true
  
  printf '[HOST %s] HELLO_SENT: peer=%s count=%d connection=%s message="%s"\n' \
    "${ts}" "${peer_id}" "${hello_count}" "${connection_info}" "${message}" \
    >>"${HOST_MARKS_LOG}" 2>/dev/null || true
  
  echo "==> Sent hello message #${hello_count} to peer: ${peer_id} (${connection_info})"
  
  # Verify message delivery if enabled
  if [[ "${VERIFY_MESSAGE_DELIVERY}" == "1" ]]; then
    local send_ts_epoch
    send_ts_epoch="$(date +%s%3N 2>/dev/null || date +%s)000"
    local since_line
    since_line="$(log_line_count)"
    
    verify_message_ack "${peer_id}" "${hello_count}" "${send_ts_epoch}" "${since_line}"
  fi
}

# Analyze why an ACK was not received and return a diagnostic reason
# This examines logs around the message send time to identify the root cause
analyze_ack_failure() {
  local peer_id="$1"
  local msg_num="$2"
  local since_line="$3"
  
  local failure_reason="UNKNOWN"
  local recent_logs=""
  
  if [[ -f "${ANDROID_LOG}" ]]; then
    # Get recent logs since message was sent (last ~200 lines or since since_line)
    recent_logs="$(tail -n +"$((since_line + 1))" "${ANDROID_LOG}" 2>/dev/null | tail -200 || true)"
  fi
  
  # Check for specific failure patterns in order of likelihood
  
  # 1. Check if peer is not in READY state
  if echo "${recent_logs}" | grep -qiE "PeerFSM.*${peer_id}.*DISCONNECTED|state.*not.*READY|peer.*not.*ready"; then
    failure_reason="PEER_NOT_READY"
  # 2. Check for network unavailable
  elif echo "${recent_logs}" | grep -qiE "Network is unreachable|no route to host|network.*unavailable"; then
    failure_reason="NETWORK_UNREACHABLE"
  # 3. Check for signaling disconnected
  elif echo "${recent_logs}" | grep -qiE "Signaling.*disconnect|signaling.*failed|websocket.*closed"; then
    failure_reason="SIGNALING_DOWN"
  # 4. Check for handshake issues
  elif echo "${recent_logs}" | grep -qiE "handshake.*failed|HANDSHAKE_FAILED|noise.*error"; then
    failure_reason="HANDSHAKE_FAILED"
  # 5. Check for send failure
  elif echo "${recent_logs}" | grep -qiE "send.*failed|failed.*send|send.*error|sendto.*failed"; then
    failure_reason="SEND_FAILED"
  # 6. Check for stale endpoint/connection
  elif echo "${recent_logs}" | grep -qiE "stale.*endpoint|endpoint.*expired|connection.*stale"; then
    failure_reason="STALE_ENDPOINT"
  # 7. Check for NAT/hole punch issues
  elif echo "${recent_logs}" | grep -qiE "hole.*punch.*failed|NAT.*failed|punch.*timeout"; then
    failure_reason="HOLEPUNCH_FAILED"
  # 8. Check if message was sent but no response
  elif echo "${recent_logs}" | grep -qE "ENCRYPTED_DATA|type=17|Sent.*${peer_id}"; then
    failure_reason="NO_RESPONSE_FROM_PEER"
  # 9. Check for connection in progress
  elif echo "${recent_logs}" | grep -qiE "CONNECTING|attempting.*connect|connection.*pending"; then
    failure_reason="CONNECTION_PENDING"
  # 10. Check for socket errors
  elif echo "${recent_logs}" | grep -qiE "socket.*error|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH"; then
    failure_reason="SOCKET_ERROR"
  # 11. Check for desktop peer not responding
  elif echo "${recent_logs}" | grep -qiE "no.*heartbeat|heartbeat.*timeout|peer.*timeout"; then
    failure_reason="PEER_TIMEOUT"
  fi
  
  # Log detailed context to a failure analysis file
  if [[ -n "${RUN_DIR}" ]] && [[ "${failure_reason}" != "UNKNOWN" ]]; then
    {
      echo "=== ACK Failure Analysis for message #${msg_num} to ${peer_id} ==="
      echo "Timestamp: $(date +%Y-%m-%dT%H:%M:%S%z)"
      echo "Failure Reason: ${failure_reason}"
      echo ""
      echo "--- Recent PeerFSM Events ---"
      echo "${recent_logs}" | grep -i "PeerFSM\|peer.*state" | tail -10 || true
      echo ""
      echo "--- Recent Network Events ---"
      echo "${recent_logs}" | grep -iE "network|WiFi|mobile|LTE|signaling" | tail -10 || true
      echo ""
      echo "--- Recent Error Logs ---"
      echo "${recent_logs}" | grep -iE "error|fail|timeout|refused" | tail -10 || true
      echo ""
      echo "=== End Analysis ==="
      echo ""
    } >> "${RUN_DIR}/ack_failure_analysis.txt" 2>/dev/null || true
  fi
  
  echo "${failure_reason}"
}

# Verify that a message was acknowledged (ACK received)
# Looks for APPLICATION_ACK (type=19) in the logs after sending
# Now includes retry logic with exponential backoff for improved reliability
verify_message_ack() {
  local peer_id="$1"
  local msg_num="$2"
  local send_ts_epoch="$3"
  local since_line="$4"
  
  MESSAGES_SENT_COUNT=$((MESSAGES_SENT_COUNT + 1))
  
  local ack_found=0
  local ack_ts=""
  local latency_ms=""
  local retry_attempt=0
  local current_timeout="${MESSAGE_ACK_TIMEOUT_SECS}"
  local current_delay="${MESSAGE_ACK_RETRY_DELAY_S}"
  
  # Retry loop with exponential backoff
  while [[ "${retry_attempt}" -lt "${MESSAGE_ACK_RETRIES}" ]]; do
    retry_attempt=$((retry_attempt + 1))
    local tries=$((current_timeout * 4))
    
    if [[ "${retry_attempt}" -gt 1 ]]; then
      echo "    Retrying ACK verification (attempt ${retry_attempt}/${MESSAGE_ACK_RETRIES}, timeout=${current_timeout}s)..."
      mark "message_ack_retry peer=${peer_id} msg_num=${msg_num} attempt=${retry_attempt} timeout=${current_timeout}"
    fi
    
    # Look for APPLICATION_ACK (type=19) in the Android logs
    for _ in $(seq 1 "${tries}"); do
      if [[ -f "${ANDROID_LOG}" ]]; then
        # Check for type=19 (APPLICATION_ACK) in recent logs
        if tail -n +"$((since_line + 1))" "${ANDROID_LOG}" 2>/dev/null | grep -qE "type=19|APPLICATION_ACK"; then
          ack_found=1
          ack_ts="$(date +%s%3N 2>/dev/null || date +%s)000"
          break 2  # Break out of both loops
        fi
      fi
      sleep 0.25
    done
    
    # If not found and we have more retries, wait with exponential backoff
    if [[ "${ack_found}" == "0" ]] && [[ "${retry_attempt}" -lt "${MESSAGE_ACK_RETRIES}" ]]; then
      sleep "${current_delay}"
      current_delay=$((current_delay * 2))  # Exponential backoff
      current_timeout=$((current_timeout + 2))  # Slightly longer timeout each retry
    fi
  done
  
  local result_status
  if [[ "${ack_found}" == "1" ]]; then
    MESSAGES_ACKED_COUNT=$((MESSAGES_ACKED_COUNT + 1))
    
    # Calculate latency
    if [[ -n "${ack_ts}" ]] && [[ -n "${send_ts_epoch}" ]]; then
      # Handle millisecond precision
      local send_ms="${send_ts_epoch}"
      local ack_ms="${ack_ts}"
      # Ensure we have numeric values
      if [[ "${send_ms}" =~ ^[0-9]+$ ]] && [[ "${ack_ms}" =~ ^[0-9]+$ ]]; then
        latency_ms=$((ack_ms - send_ms))
        # Sanity check - if latency is too large, we might have seconds vs milliseconds issue
        if [[ "${latency_ms}" -gt 60000 ]]; then
          # Probably seconds, not milliseconds
          latency_ms=$((latency_ms / 1000))
        fi
      fi
    fi
    
    if [[ -n "${latency_ms}" ]]; then
      MESSAGE_LATENCIES="${MESSAGE_LATENCIES}${latency_ms},"
    fi
    
    result_status="ACK_RECEIVED"
    mark "hello_message_ack peer=${peer_id} msg_num=${msg_num} latency_ms=${latency_ms:-unknown} retries=${retry_attempt}"
    echo "    ✅ ACK received for message #${msg_num} (latency: ${latency_ms:-?}ms, attempts: ${retry_attempt})"
  else
    MESSAGES_FAILED_COUNT=$((MESSAGES_FAILED_COUNT + 1))
    result_status="ACK_TIMEOUT"
    
    # Analyze why ACK failed and log detailed diagnostic info
    local failure_reason=""
    failure_reason="$(analyze_ack_failure "${peer_id}" "${msg_num}" "${since_line}")"
    
    mark "hello_message_ack_timeout peer=${peer_id} msg_num=${msg_num} timeout_secs=${MESSAGE_ACK_TIMEOUT_SECS} retries=${MESSAGE_ACK_RETRIES} reason=${failure_reason}"
    echo "    ⚠️  No ACK received for message #${msg_num} after ${MESSAGE_ACK_RETRIES} attempts"
    echo "    📊 Failure analysis: ${failure_reason}"
  fi
  
  # Log to delivery log file (now includes failure reason in the 7th field)
  printf '%s|%s|%d|%s|%s|%d|%s\n' \
    "$(date +%Y-%m-%dT%H:%M:%S%z)" \
    "${peer_id}" \
    "${msg_num}" \
    "${result_status}" \
    "${latency_ms:-}" \
    "${retry_attempt}" \
    "${failure_reason:-}" \
    >>"${MESSAGE_DELIVERY_LOG_FILE}" 2>/dev/null || true
  
  if [[ "${ack_found}" == "0" ]] && [[ "${REQUIRE_MESSAGE_DELIVERY}" == "1" ]]; then
    return 1
  fi
  return 0
}

# Calculate average latency from comma-separated values
calculate_average_latency() {
  local latencies="$1"
  if [[ -z "${latencies}" ]]; then
    echo ""
    return
  fi
  
  local sum=0
  local count=0
  local IFS=','
  for lat in ${latencies}; do
    if [[ -n "${lat}" ]] && [[ "${lat}" =~ ^[0-9]+$ ]]; then
      sum=$((sum + lat))
      count=$((count + 1))
    fi
  done
  
  if [[ "${count}" -gt 0 ]]; then
    echo $((sum / count))
  else
    echo ""
  fi
}

# Extract READY transitions from the log since a given line
# Returns each READY event with peer ID and connection info (for deduplication)
# Format: <line_number>|<peer_id>|<transition_info>
extract_ready_events_from_log() {
  local since_line="${1:-0}"
  
  if [[ ! -f "${ANDROID_LOG}" ]]; then
    return 0
  fi
  
  # Match: [PeerFSM] ... --> READY peer=<peer_id>
  # Example: [PeerFSM] CONNECTED --(HANDSHAKE_COMPLETE)--> READY peer=desktop-1
  # We include the full transition info to distinguish different READY events
  local line_num="${since_line}"
  tail -n +"$((since_line + 1))" "${ANDROID_LOG}" 2>/dev/null | while IFS= read -r line; do
    line_num=$((line_num + 1))
    if echo "${line}" | grep -qE '\[PeerFSM\].*-->[[:space:]]*READY[[:space:]]+peer='; then
      local peer_id
      peer_id="$(echo "${line}" | sed -E 's/.*peer=([^[:space:]]+).*/\1/')"
      # Extract connection info (e.g., LAN vs WAN, IP info if available)
      local connection_info="unknown"
      if echo "${line}" | grep -qi "LAN\|local\|192\.168\.\|10\.\|172\."; then
        connection_info="LAN"
      elif echo "${line}" | grep -qi "WAN\|public\|signaling"; then
        connection_info="WAN"
      else
        # Try to determine from context - check previous lines for IP info
        connection_info="connection_${line_num}"
      fi
      echo "${line_num}|${peer_id}|${connection_info}"
    fi
  done || true
}

# Process newly READY peers and send hello messages for EACH READY event
# Now includes socket restart verification and network transition safety checks
process_ready_peers_for_hello() {
  local since_line="${1:-0}"
  
  if [[ "${SEND_HELLO_ON_READY}" != "1" ]]; then
    return 0
  fi
  
  local events
  events="$(extract_ready_events_from_log "${since_line}")"
  
  if [[ -z "${events}" ]]; then
    return 0
  fi
  
  while IFS='|' read -r line_num peer_id connection_info; do
    if [[ -z "${peer_id}" ]]; then
      continue
    fi
    
    # Check if network transition is in progress - wait if so
    if is_network_transition_in_progress; then
      echo "[INFO] Network transition in progress, waiting before sending to ${peer_id}..."
      if ! wait_for_network_stable 30; then
        echo "[WARN] Network still transitioning, skipping hello to ${peer_id}"
        mark "hello_skipped_network_transition peer=${peer_id}"
        continue
      fi
    fi
    
    # Wait for socket restart confirmation if a network change was detected
    # This ensures the new socket is ready before we try to send
    local network_change_detected=0
    if [[ -f "${ANDROID_LOG}" ]]; then
      local recent_logs
      recent_logs="$(tail -n 200 "${ANDROID_LOG}" 2>/dev/null || true)"
      if echo "${recent_logs}" | grep -qE "Network change detected|Network info update|NATIVE: Network.*change"; then
        network_change_detected=1
      fi
    fi
    
    if [[ "${network_change_detected}" == "1" ]] && [[ "${WAIT_FOR_SOCKET_RESTART}" == "1" ]]; then
      echo "    Network change detected, verifying socket restart..."
      local socket_check_line="${LAST_SOCKET_RESTART_LINE}"
      if [[ "${socket_check_line}" -lt "$((line_num - 300))" ]]; then
        socket_check_line=$((line_num - 300))
      fi
      
      if wait_for_socket_restart "${socket_check_line}"; then
        SOCKET_RESTART_COUNT=$((SOCKET_RESTART_COUNT + 1))
        SOCKET_RESTART_TIMES="${SOCKET_RESTART_TIMES}$(date +%s),"
        LAST_SOCKET_RESTART_LINE="$(log_line_count)"
      else
        echo "[WARN] Socket restart not confirmed, proceeding anyway for ${peer_id}"
      fi
    fi
    
    # Wait for network to stabilize after READY before sending
    # This is critical after WiFi handoffs where the network path may still be settling
    if [[ "${HELLO_MESSAGE_POST_READY_DELAY_S}" -gt 0 ]]; then
      echo "    Waiting ${HELLO_MESSAGE_POST_READY_DELAY_S}s for network to stabilize..."
      sleep "${HELLO_MESSAGE_POST_READY_DELAY_S}"
      
      # After delay, verify peer is still READY (connection may have dropped during settle)
      local current_state
      current_state="$(tail -100 "${ANDROID_LOG}" 2>/dev/null | grep -E "\[PeerFSM\].*peer=${peer_id}" | tail -1 | sed -E 's/.*--> *([A-Z]+).*/\1/' || true)"
      if [[ "${current_state}" != "READY" ]] && [[ -n "${current_state}" ]]; then
        echo "[INFO] Skipping hello to ${peer_id}: state changed to ${current_state} during settle delay"
        mark "hello_skipped_state_change peer=${peer_id} new_state=${current_state}"
        continue
      fi
    fi
    
    # Wait for bidirectional UDP confirmation if enabled
    # This provides more reliable detection of a working network path than just a delay
    if [[ "${WAIT_FOR_UDP_CONFIRMATION}" == "1" ]]; then
      if ! wait_for_udp_confirmation "${peer_id}" "${since_line}"; then
        echo "[WARN] Proceeding with hello despite UDP confirmation failure for ${peer_id}"
        # Continue anyway - the message may still work, or the verification will catch the failure
      fi
    fi
    
    # Final check - make sure network is still stable
    if is_network_transition_in_progress; then
      echo "[INFO] Network transition started during wait, skipping hello to ${peer_id}"
      mark "hello_skipped_late_transition peer=${peer_id}"
      continue
    fi
    
    # Send hello for this READY event
    send_hello_to_peer "${peer_id}" "${connection_info}"
  done <<<"${events}"
}

# Background monitor that continuously checks for new READY peers
start_hello_message_monitor() {
  if [[ "${SEND_HELLO_ON_READY}" != "1" ]]; then
    return 0
  fi
  
  local main_pid="$1"
  
  (
    set +e
    local last_checked_line=0
    while kill -0 "${main_pid}" >/dev/null 2>&1; do
      sleep "${HELLO_MESSAGE_MONITOR_INTERVAL_S}"
      
      if [[ -f "${ANDROID_LOG}" ]]; then
        process_ready_peers_for_hello "${last_checked_line}"
        last_checked_line="$(wc -l <"${ANDROID_LOG}" 2>/dev/null | tr -d ' ' || echo 0)"
      fi
    done
  ) &
  HELLO_MONITOR_PID=$!
}

stop_hello_message_monitor() {
  if [[ -n "${HELLO_MONITOR_PID}" ]]; then
    kill "${HELLO_MONITOR_PID}" >/dev/null 2>&1 || true
    wait "${HELLO_MONITOR_PID}" >/dev/null 2>&1 || true
    HELLO_MONITOR_PID=""
  fi
}

# ============================================================================

wait_for_wifi_on() {
  # Best-effort: poll global setting wifi_on (0/1). Some OEMs may behave differently;
  # if we can't confirm, we still proceed.
  local desired="$1"   # 0 or 1
  local timeout_s="${2:-12}"
  local tries
  tries=$((timeout_s * 2))

  for _ in $(seq 1 "${tries}"); do
    local cur
    cur="$(adb_cmd shell settings get global wifi_on 2>/dev/null | tr -d '\r' | tail -n 1 || true)"
    if [[ "${cur}" == "${desired}" ]]; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

get_airplane_mode_on() {
  adb_cmd shell settings get global airplane_mode_on 2>/dev/null | tr -d '\r' | tail -n 1 || true
}

wait_for_airplane_mode_on() {
  local desired="$1"   # 0 or 1
  local timeout_s="${2:-10}"
  local tries
  tries=$((timeout_s * 2))

  for _ in $(seq 1 "${tries}"); do
    local cur
    cur="$(get_airplane_mode_on)"
    if [[ "${cur}" == "${desired}" ]]; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

toggle_wifi_verified() {
  # Args: desired(0/1) loop_idx scenario_tag
  local desired="$1"
  local loop_idx="$2"
  local scenario_tag="$3"

  local action
  if [[ "${desired}" == "1" ]]; then
    action="enable"
  else
    action="disable"
  fi

  # Safety window before network transition - allow in-flight messages to complete
  if [[ "${NETWORK_TRANSITION_SAFETY_WINDOW_S}" -gt 0 ]]; then
    echo "    [Safety] Waiting ${NETWORK_TRANSITION_SAFETY_WINDOW_S}s before WiFi ${action}..."
    mark "network_safety_window_start action=wifi_${action} loop=${loop_idx} duration=${NETWORK_TRANSITION_SAFETY_WINDOW_S}"
    sleep "${NETWORK_TRANSITION_SAFETY_WINDOW_S}"
  fi

  # Acquire transition lock to prevent message sending during network change
  acquire_network_transition_lock "wifi_${action}"

  local attempt
  for attempt in $(seq 1 "${WIFI_TOGGLE_RETRIES}"); do
    mark "wifi_${action}_cmd_attempt loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt}"
    adb_cmd shell svc wifi "${action}" || true
    sleep "${WIFI_TOGGLE_CMD_SETTLE_SECS}"

    if wait_for_wifi_on "${desired}" "${WIFI_TOGGLE_VERIFY_SECS}"; then
      # Preserve legacy MARK names used by reporting.
      if [[ "${desired}" == "1" ]]; then
        local iface
        iface="$(pick_wifi_iface)"
        if wait_for_wifi_ipv4 "${iface}" "${WIFI_IP_VERIFY_SECS}"; then
          mark "wifi_enable loop=${loop_idx} scenario=${scenario_tag} iface=${iface}"
          mark "wifi_${action}_verified loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt} iface=${iface}"
        else
          mark "wifi_enable loop=${loop_idx} scenario=${scenario_tag} confirmed=1 connected=0 iface=${iface}"
          mark "wifi_${action}_verified loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt} iface=${iface} ip=0"
        fi
      else
        mark "wifi_disable loop=${loop_idx} scenario=${scenario_tag}"
        mark "wifi_${action}_verified loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt}"
      fi
      
      # Release lock after successful toggle
      release_network_transition_lock
      return 0
    fi
  done

  # Could not verify - release lock anyway
  release_network_transition_lock

  if [[ "${desired}" == "1" ]]; then
    mark "wifi_enable loop=${loop_idx} scenario=${scenario_tag} confirmed=0 connected=0"
  else
    mark "wifi_disable loop=${loop_idx} scenario=${scenario_tag} confirmed=0"
  fi
  mark "wifi_${action}_verify_failed loop=${loop_idx} scenario=${scenario_tag} retries=${WIFI_TOGGLE_RETRIES}"

  if [[ "${REQUIRE_TOGGLE_SUCCESS}" == "1" ]]; then
    return 1
  fi
  return 0
}

toggle_mobile_data_verified() {
  # Args: desired(0/1) loop_idx scenario_tag
  local desired="$1"
  local loop_idx="$2"
  local scenario_tag="$3"

  local action
  if [[ "${desired}" == "1" ]]; then
    action="enable"
  else
    action="disable"
  fi

  # Safety window before network transition - allow in-flight messages to complete
  if [[ "${NETWORK_TRANSITION_SAFETY_WINDOW_S}" -gt 0 ]]; then
    echo "    [Safety] Waiting ${NETWORK_TRANSITION_SAFETY_WINDOW_S}s before data ${action}..."
    mark "network_safety_window_start action=data_${action} loop=${loop_idx} duration=${NETWORK_TRANSITION_SAFETY_WINDOW_S}"
    sleep "${NETWORK_TRANSITION_SAFETY_WINDOW_S}"
  fi

  # Acquire transition lock to prevent message sending during network change
  acquire_network_transition_lock "data_${action}"

  local attempt
  for attempt in $(seq 1 "${DATA_TOGGLE_RETRIES}"); do
    mark "data_${action}_cmd loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt}"
    adb_cmd shell svc data "${action}" || true
    sleep "${DATA_TOGGLE_CMD_SETTLE_SECS}"
    if wait_for_mobile_data_on "${desired}" "${DATA_TOGGLE_VERIFY_SECS}"; then
      # Preserve legacy MARK names where used.
      if [[ "${desired}" == "1" ]]; then
        mark "data_enable loop=${loop_idx} scenario=${scenario_tag}"
      else
        mark "data_disable loop=${loop_idx} scenario=${scenario_tag}"
      fi
      mark "data_${action}_verified loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt}"
      
      # Release lock after successful toggle
      release_network_transition_lock
      return 0
    fi
  done

  # Release lock after failed toggle attempts
  release_network_transition_lock

  if [[ "${desired}" == "1" ]]; then
    mark "data_enable loop=${loop_idx} scenario=${scenario_tag} confirmed=0"
  else
    mark "data_disable loop=${loop_idx} scenario=${scenario_tag} confirmed=0"
  fi
  mark "data_${action}_verify_failed loop=${loop_idx} scenario=${scenario_tag} retries=${DATA_TOGGLE_RETRIES}"

  if [[ "${REQUIRE_TOGGLE_SUCCESS}" == "1" ]]; then
    return 1
  fi
  return 0
}

toggle_airplane_verified() {
  # Args: desired(0/1) loop_idx scenario_tag
  local desired="$1"
  local loop_idx="$2"
  local scenario_tag="$3"

  local action
  if [[ "${desired}" == "1" ]]; then
    action="enable"
  else
    action="disable"
  fi

  # Safety window before network transition - allow in-flight messages to complete
  if [[ "${NETWORK_TRANSITION_SAFETY_WINDOW_S}" -gt 0 ]]; then
    echo "    [Safety] Waiting ${NETWORK_TRANSITION_SAFETY_WINDOW_S}s before airplane ${action}..."
    mark "network_safety_window_start action=airplane_${action} loop=${loop_idx} duration=${NETWORK_TRANSITION_SAFETY_WINDOW_S}"
    sleep "${NETWORK_TRANSITION_SAFETY_WINDOW_S}"
  fi

  # Acquire transition lock to prevent message sending during network change
  acquire_network_transition_lock "airplane_${action}"

  local attempt
  for attempt in $(seq 1 "${AIRPLANE_TOGGLE_RETRIES}"); do
    mark "airplane_${action}_cmd loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt}"
    adb_cmd shell settings put global airplane_mode_on "${desired}" || true
    adb_cmd shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez state "$([[ "${desired}" == "1" ]] && echo true || echo false)" >/dev/null 2>&1 || true
    sleep "${AIRPLANE_TOGGLE_CMD_SETTLE_SECS}"
    if wait_for_airplane_mode_on "${desired}" "${AIRPLANE_TOGGLE_VERIFY_SECS}"; then
      if [[ "${desired}" == "1" ]]; then
        mark "no_network_enable loop=${loop_idx} scenario=${scenario_tag}"
      else
        mark "no_network_disable loop=${loop_idx} scenario=${scenario_tag}"
      fi
      mark "airplane_${action}_verified loop=${loop_idx} scenario=${scenario_tag} attempt=${attempt}"
      
      # Release lock after successful toggle
      release_network_transition_lock
      return 0
    fi
  done

  # Release lock after failed toggle attempts
  release_network_transition_lock

  if [[ "${desired}" == "1" ]]; then
    mark "no_network_enable loop=${loop_idx} scenario=${scenario_tag} confirmed=0"
  else
    mark "no_network_disable loop=${loop_idx} scenario=${scenario_tag} confirmed=0"
  fi
  mark "airplane_${action}_verify_failed loop=${loop_idx} scenario=${scenario_tag} retries=${AIRPLANE_TOGGLE_RETRIES}"

  if [[ "${REQUIRE_TOGGLE_SUCCESS}" == "1" ]]; then
    return 1
  fi
  return 0
}

wait_for_mobile_data_on() {
  # Best-effort: poll settings global mobile_data (0/1). Some OEMs may not expose this;
  # if we can't confirm, proceed.
  local desired="$1"   # 0 or 1
  local timeout_s="${2:-12}"
  local tries
  tries=$((timeout_s * 2))

  for _ in $(seq 1 "${tries}"); do
    local cur
    cur="$(adb_cmd shell settings get global mobile_data 2>/dev/null | tr -d '\r' | tail -n 1 || true)"
    if [[ "${cur}" == "${desired}" ]]; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

pick_wifi_iface() {
  # Most devices expose Wi‑Fi as wlan0; keep a small fallback list.
  local c
  for c in wlan0 wlan1 wifi0; do
    if adb_cmd shell ip link show "${c}" >/dev/null 2>&1; then
      echo "${c}"
      return 0
    fi
  done
  echo "wlan0"
  return 0
}

wait_for_wifi_ipv4() {
  # Best-effort: wait until the Wi‑Fi interface has a non-link-local IPv4.
  local iface="$1"
  local timeout_s="${2:-25}"
  local tries
  tries=$((timeout_s * 4))

  local i
  for i in $(seq 1 "${tries}"); do
    local ip
    ip="$(adb_cmd shell ip -4 -o addr show "${iface}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 | tr -d '\r' || true)"
    if [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "${ip}" != 169.254.* ]]; then
      return 0
    fi

    ip="$(adb_cmd shell getprop "dhcp.${iface}.ipaddress" 2>/dev/null | tr -d '\r' || true)"
    if [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "${ip}" != 169.254.* ]]; then
      return 0
    fi

    sleep 0.25
  done

  return 1
}

wait_for_log_regex_since() {
  local since_line="$1"
  local regex="$2"
  local tries="${3:-40}"
  local sleep_s="${4:-0.5}"

  local found=0
  for _ in $(seq 1 "${tries}"); do
    if [[ -f "${ANDROID_LOG}" ]]; then
      if tail -n +"$((since_line + 1))" "${ANDROID_LOG}" 2>/dev/null | grep -qE "${regex}"; then
        found=1
        break
      fi
    fi
    sleep "${sleep_s}"
  done
  if [[ "${found}" == "1" ]]; then
    return 0
  fi
  return 1
}

get_app_pid() {
  # Returns the first PID for the package, or empty.
  adb_cmd shell pidof "${ANDROID_PKG}" 2>/dev/null | tr -d '\r' | awk '{print $1}' | head -n 1 || true
}

wait_for_app_pid() {
  local timeout_s="${1:-10}"
  local tries
  tries=$((timeout_s * 10))
  local pid=""
  for _ in $(seq 1 "${tries}"); do
    pid="$(get_app_pid)"
    if [[ -n "${pid}" ]]; then
      echo "${pid}"
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_log_regex_since_pid() {
  local since_line="$1"
  local pid="$2"
  local regex="$3"
  local tries="${4:-40}"
  local sleep_s="${5:-0.5}"

  # threadtime: "MM-DD HH:MM:SS.mmm  PID  TID  L TAG: msg"
  local pid_prefix
  pid_prefix="^[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3} +${pid} +[0-9]+ +[VDIWEF] "

  local found=0
  for _ in $(seq 1 "${tries}"); do
    if [[ -f "${ANDROID_LOG}" ]]; then
      if tail -n +"$((since_line + 1))" "${ANDROID_LOG}" 2>/dev/null | grep -qE "${pid_prefix}.*(${regex})"; then
        found=1
        break
      fi
    fi
    sleep "${sleep_s}"
  done
  if [[ "${found}" == "1" ]]; then
    return 0
  fi
  return 1
}

wait_for_engine_running_since() {
  local since_line="$1"
  local pid="$2"

  # Multiple acceptable signatures. Keep these broad but engine-specific.
  local ui_re
  ui_re="startEngine called|onEngineStartComplete|Setting engineState to STARTING"
  local native_re
  # Proof-of-life signatures for the native engine. We accept either:
  #   - Any LiteP2P_Native line with common high-signal substrings, OR
  #   - The engine event-loop (EM_NATIVE) activity which appears as soon as the native core is alive.
  native_re="(LiteP2P_Native:.*(NATIVE: Network info update|SM: Network change detected|STUN: === Starting NAT Detection|SM: Signaling reconnect attempt|Signaling: Connected successfully|\\[PeerFSM\\]|Discovery: Found peer|SM: Event type|SM: Signaling message received)|Litep2p : EM_NATIVE:)"

  if [[ -n "${pid}" ]]; then
    if wait_for_log_regex_since_pid "${since_line}" "${pid}" "${ui_re}" "${ENGINE_START_WAIT_TRIES}" "${ENGINE_START_WAIT_SLEEP_S}"; then
      echo "ui"
      return 0
    fi
    # Native logs are sometimes emitted from a different PID than the app PID (multi-process
    # variants / OEM ROMs). Prefer an unscoped native match first.
    if wait_for_log_regex_since "${since_line}" "${native_re}" "${ENGINE_START_WAIT_TRIES}" "${ENGINE_START_WAIT_SLEEP_S}"; then
      echo "native_unscoped"
      return 0
    fi

    # If PID scoping works on this device/build, accept it too.
    if wait_for_log_regex_since_pid "${since_line}" "${pid}" "${native_re}" "${ENGINE_START_WAIT_TRIES}" "${ENGINE_START_WAIT_SLEEP_S}"; then
      echo "native_pid"
      return 0
    fi

    # Final fallback: broaden to UI or native signatures without PID scoping.
    if wait_for_log_regex_since "${since_line}" "${ui_re}|${native_re}" "${ENGINE_START_WAIT_TRIES}" "${ENGINE_START_WAIT_SLEEP_S}"; then
      echo "unscoped_fallback"
      return 0
    fi
  else
    # PID unknown: fall back to global matching (best-effort).
    if wait_for_log_regex_since "${since_line}" "${ui_re}|${native_re}" "${ENGINE_START_WAIT_TRIES}" "${ENGINE_START_WAIT_SLEEP_S}"; then
      echo "unscoped"
      return 0
    fi
  fi

  return 1
}

launch_app_and_wait_engine() {
  local reason="$1"

  echo "==> Restarting app: ${ANDROID_PKG}/${ANDROID_ACTIVITY} (reason: ${reason})"
  adb_cmd shell am force-stop "${ANDROID_PKG}" || true
  # Record baseline *after* force-stopping so that any tail noise from a previous
  # engine instance doesn't shift our since_line past the real startup signatures.
  local since
  since="$(log_line_count)"
  AM_START_ARGS=(am start -n "${ANDROID_PKG}/${ANDROID_ACTIVITY}")
  if [[ "${AUTO_START_ENGINE}" == "1" ]]; then
    AM_START_ARGS+=(--ez LITEP2P_AUTOSTART true)
  fi
  if [[ -n "${ENGINE_COMMS_MODE}" ]]; then
    AM_START_ARGS+=(--es LITEP2P_COMMS_MODE "${ENGINE_COMMS_MODE}")
  fi
  if [[ -n "${ANDROID_PEER_ID}" ]]; then
    AM_START_ARGS+=(--es LITEP2P_PEER_ID "${ANDROID_PEER_ID}")
  fi
  if [[ -n "${ANDROID_PROXY_GATEWAY}" ]]; then
    if [[ "${ANDROID_PROXY_GATEWAY}" == "1" ]]; then
      AM_START_ARGS+=(--ez LITEP2P_PROXY_GATEWAY true)
    else
      AM_START_ARGS+=(--ez LITEP2P_PROXY_GATEWAY false)
    fi
  fi
  if [[ -n "${ANDROID_PROXY_CLIENT}" ]]; then
    if [[ "${ANDROID_PROXY_CLIENT}" == "1" ]]; then
      AM_START_ARGS+=(--ez LITEP2P_PROXY_CLIENT true)
    else
      AM_START_ARGS+=(--ez LITEP2P_PROXY_CLIENT false)
    fi
  fi

  mark "app_launch reason=${reason} autostart=${AUTO_START_ENGINE}"
  adb_cmd shell "${AM_START_ARGS[@]}"
  sleep 2

  local pid=""
  if pid="$(wait_for_app_pid 10 2>/dev/null || true)"; then
    if [[ -n "${pid}" ]]; then
      mark "app_pid reason=${reason} pid=${pid}"
    fi
  fi

  # NOTE: We intentionally do NOT block on detecting engine autostart logs.
  # The engine has been observed to start reliably even when log-based detection is brittle.
  if [[ "${AUTO_START_ENGINE}" == "1" ]]; then
    mark "engine_autostart_assumed reason=${reason} pid=${pid:-unknown}"
    return 0
  fi

  # For older APKs without intent-extras autostart, try a best-effort UI tap.
  mark "ui_press_start_attempt reason=${reason}"
  if try_press_start_button; then
    mark "ui_press_start_sent reason=${reason}"
  else
    mark "ui_press_start_failed reason=${reason}"
  fi
  return 0
}

try_press_start_button() {
  # Best-effort fallback for older APKs without intent-extras autostart:
  # use uiautomator to find the Start button and tap it.
  local dump_on_device="/sdcard/litep2p_window_dump.xml"
  local dump_local="${RUN_DIR}/window_dump.xml"

  adb_cmd shell uiautomator dump "${dump_on_device}" >/dev/null 2>&1 || return 1
  adb_cmd pull "${dump_on_device}" "${dump_local}" >/dev/null 2>&1 || true
  if [[ ! -f "${dump_local}" ]]; then
    return 1
  fi

  local line=""
  # Prefer stable resource-id if present.
  line="$(grep -m 1 "resource-id=\"${ANDROID_PKG}:id/startButton\"" "${dump_local}" 2>/dev/null || true)"
  if [[ -z "${line}" ]]; then
    # Fallback: match visible label.
    line="$(grep -im 1 'text="start"' "${dump_local}" 2>/dev/null || true)"
  fi
  if [[ -z "${line}" ]]; then
    return 1
  fi

  # Extract bounds for the matched node. uiautomator often emits a single huge line,
  # so we first cut the XML at the match and then grab the *first* bounds attribute.
  local cut
  if [[ "${line}" == *"resource-id=\"${ANDROID_PKG}:id/startButton\""* ]]; then
    cut="${line#*resource-id=\"${ANDROID_PKG}:id/startButton\"}"
  else
    # Text match fallback (case-insensitive): cut at the first occurrence of text="...start..."
    cut="$(printf '%s' "${line}" | perl -pe 's/.*?text="[^"]*start[^"]*"/text="start"/i')"
  fi

  local bounds_str
  bounds_str="$(printf '%s\n' "${cut}" | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | head -n 1 || true)"
  if [[ -z "${bounds_str}" ]]; then
    return 1
  fi

  local x1 y1 x2 y2
  read -r x1 y1 x2 y2 <<<"$(printf '%s\n' "${bounds_str}" | sed -E 's/bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]"/\1 \2 \3 \4/')"
  if [[ -z "${x1}" || -z "${y1}" || -z "${x2}" || -z "${y2}" ]]; then
    return 1
  fi

  local x y
  x=$(( (x1 + x2) / 2 ))
  y=$(( (y1 + y2) / 2 ))
  adb_cmd shell input tap "${x}" "${y}" >/dev/null 2>&1 || return 1
  return 0
}

pick_desktop_bin() {
  if [[ -n "${DESKTOP_BIN}" ]]; then
    echo "${DESKTOP_BIN}"
    return 0
  fi

  local c
  for c in \
    "${ROOT_DIR}/desktop/build_mac/bin/litep2p_peer_mac" \
    "${ROOT_DIR}/desktop/build_linux/bin/litep2p_peer_linux" \
    "${ROOT_DIR}/desktop/build_linux_docker/bin/litep2p_peer_linux" \
    "${ROOT_DIR}/build/litep2p_peer"; do
    if [[ -x "${c}" ]]; then
      echo "${c}"
      return 0
    fi
  done

  return 1
}

start_desktop_peer() {
  if [[ "${START_DESKTOP}" != "1" ]]; then
    return 0
  fi

  if [[ "${DESKTOP_COUNT}" -gt 1 ]]; then
    if [[ ! -f "${DESKTOP_CONFIG}" ]]; then
      echo "==> Desktop peers: skipped (config not found at ${DESKTOP_CONFIG})." | tee -a "${META}"
      START_DESKTOP=0
      return 0
    fi

    echo "==> Starting ${DESKTOP_COUNT} desktop peers" | tee -a "${META}"
    local peer_out
    peer_out="$(
      cd "${ROOT_DIR}" && \
      COUNT="${DESKTOP_COUNT}" \
      ID_PREFIX="${DESKTOP_ID_PREFIX}" \
      BASE_PORT="${DESKTOP_BASE_PORT}" \
      DESKTOP_BIN="${DESKTOP_BIN}" \
      CONFIG="${DESKTOP_CONFIG}" \
      LOG_LEVEL="${DESKTOP_LOG_LEVEL}" \
      RUNS_DIR="${RUN_DIR}" \
      REMOTE_HOST="${REMOTE_HOST}" \
      REMOTE_PASS="${REMOTE_PASS}" \
      REMOTE_BIN="${REMOTE_BIN}" \
      REMOTE_CONFIG="${REMOTE_CONFIG}" \
      REMOTE_COUNT="${REMOTE_COUNT}" \
      "${ROOT_DIR}/tools/harness/start_desktop_peers.sh"
    )" || {
      echo "==> Desktop peers: failed to start." | tee -a "${META}"
      START_DESKTOP=0
      return 0
    }
    echo "${peer_out}" >>"${META}" 2>/dev/null || true

    DESKTOP_PEERS_RUN_DIR="$(printf '%s\n' "${peer_out}" | awk -F': ' '/Desktop peers run dir:/ {print $2; exit}')"
    if [[ -n "${DESKTOP_PEERS_RUN_DIR}" ]]; then
      mark "desktop_peers_started count=${DESKTOP_COUNT} run_dir=${DESKTOP_PEERS_RUN_DIR}"
    else
      mark "desktop_peers_started count=${DESKTOP_COUNT}"
    fi
    return 0
  fi

  local bin
  if ! bin="$(pick_desktop_bin)"; then
    echo "==> Desktop peer: skipped (binary not found)." | tee -a "${META}"
    echo "    Build it first (macOS): cd desktop && ./build_mac.sh" | tee -a "${META}"
    START_DESKTOP=0
    return 0
  fi

  if [[ ! -f "${DESKTOP_CONFIG}" ]]; then
    echo "==> Desktop peer: skipped (config not found at ${DESKTOP_CONFIG})." | tee -a "${META}"
    START_DESKTOP=0
    return 0
  fi

  local -a DESKTOP_EXTRA_ARGS_ARR=()
  if [[ -n "${DESKTOP_EXTRA_ARGS}" ]]; then
    read -r -a DESKTOP_EXTRA_ARGS_ARR <<<"${DESKTOP_EXTRA_ARGS}"
  fi

  echo "==> Starting desktop peer -> ${DESKTOP_LOG}" | tee -a "${META}"
  echo "    bin=${bin}" | tee -a "${META}"
  echo "    id=${DESKTOP_PEER_ID} port=${DESKTOP_PORT} log_level=${DESKTOP_LOG_LEVEL}" | tee -a "${META}"

  : >"${DESKTOP_LOG}"
  local -a cmd=(
    "${bin}"
    --config "${DESKTOP_CONFIG}"
    --id "${DESKTOP_PEER_ID}"
    --port "${DESKTOP_PORT}"
    --log-level "${DESKTOP_LOG_LEVEL}"
    --no-tui
    --daemon
  )
  if [[ -n "${DESKTOP_EXTRA_ARGS}" ]]; then
    cmd+=("${DESKTOP_EXTRA_ARGS_ARR[@]}")
  fi

  "${cmd[@]}" >"${DESKTOP_LOG}" 2>&1 &
  DESKTOP_PID=$!
}

echo "==> Run dir: ${RUN_DIR}"

echo "==> Capturing device info"
{
  echo "host_ts=${TS}"
  echo "android_pkg=${ANDROID_PKG}"
  echo "android_activity=${ANDROID_ACTIVITY}"
  echo "logcat_tags=${LOGCAT_TAGS}"
  echo "loops=${LOOPS}"
  echo "toggle_data=${TOGGLE_DATA}"
  echo "toggle_airplane=${TOGGLE_AIRPLANE}"
  echo "adb_serial=${ADB_SERIAL:-<default>}"
  echo
  adb_cmd devices -l || true
  echo
  adb_cmd shell getprop ro.build.fingerprint || true
  adb_cmd shell getprop ro.product.model || true
  adb_cmd shell getprop ro.build.version.release || true
  adb_cmd shell getprop ro.build.version.sdk || true
} >"${META}"

echo "==> Clearing logcat"
adb_cmd logcat -c

echo "==> Starting logcat stream -> ${ANDROID_LOG}"
: >"${ANDROID_LOG}"
: >"${HOST_MARKS_LOG}"
LOGCAT_FIFO="${RUN_DIR}/logcat_stream.fifo"
rm -f "${LOGCAT_FIFO}" >/dev/null 2>&1 || true
mkfifo "${LOGCAT_FIFO}"

set +u
# Use a FIFO so we can reliably stop both sides of the pipeline without leaving adb logcat running.
adb_cmd logcat -v threadtime -s "${LOGCAT_TAGS_ARR[@]}" >"${LOGCAT_FIFO}" &
LOGCAT_ADB_PID=$!

# Force line buffering so polling the file for markers/events is reliable.
awk '{print; fflush();}' <"${LOGCAT_FIFO}" >"${ANDROID_LOG}" &
LOGCAT_READER_PID=$!

# Back-compat alias (kept for any older debugging paths that mention LOGCAT_PID).
LOGCAT_PID="${LOGCAT_READER_PID}"
set -u

# Initialize network transition lock
init_network_transition_lock

start_watchdog "$$"

# Run pre-flight checks before starting tests
run_preflight_checks || {
  echo "[WARN] Pre-flight checks had issues - continuing anyway"
}

mark "run_start"

start_desktop_peer
if [[ -n "${DESKTOP_PID}" ]]; then
  mark "desktop_peer_started pid=${DESKTOP_PID}"
fi

if [[ -n "${DESKTOP_PEERS_RUN_DIR}" ]]; then
  echo "==> Desktop peers logs: ${DESKTOP_PEERS_RUN_DIR}" | tee -a "${META}"
fi

launch_app_and_wait_engine "initial"

# Initialize and start hello message monitoring for peer READY events
init_hello_message_tracking
if [[ "${SEND_HELLO_ON_READY}" == "1" ]]; then
  echo "==> Starting hello message monitor (will send hello on peer READY)"
  mark "hello_monitor_start"
  start_hello_message_monitor "$$"
fi

echo "==> Device snapshot (connectivity)"
adb_cmd shell dumpsys connectivity | head -n 120 >>"${META}" 2>/dev/null || true

read -r -a SCENARIOS_ARR <<<"${SCENARIOS//,/ }"

run_scenario_wifi() {
  local loop_idx="$1"
  local scenario_tag="$2"

  if [[ "${TOGGLE_DATA}" == "1" ]]; then
    echo "==> Mobile data enable (prefer LTE)"
    toggle_mobile_data_verified 1 "${loop_idx}" "${scenario_tag}"
    sleep "${DATA_ENABLE_SECS}"
  fi

  if [[ "${RESTART_APP_BEFORE_WIFI_DISABLE}" == "1" ]]; then
    mark "app_restart_before_wifi_disable loop=${loop_idx} scenario=${scenario_tag}"
    launch_app_and_wait_engine "before_wifi_disable loop=${loop_idx} scenario=${scenario_tag}" || true
  fi

  echo "==> WiFi disable (simulate LTE)"
  mark "wifi_disable_cmd loop=${loop_idx} scenario=${scenario_tag}"
  toggle_wifi_verified 0 "${loop_idx}" "${scenario_tag}"

  if [[ "${FORCE_TRANSPORT_BREAK}" == "1" ]]; then
    echo "==> Forcing transport break (data OFF -> ON) for ${TRANSPORT_BREAK_SECS}s"
    mark "transport_break_start loop=${loop_idx} scenario=${scenario_tag} secs=${TRANSPORT_BREAK_SECS}"
    mark "transport_break_data_disable loop=${loop_idx} scenario=${scenario_tag}"
    adb_cmd shell svc data disable || true
    sleep "${TRANSPORT_BREAK_SECS}"
    mark "transport_break_data_enable loop=${loop_idx} scenario=${scenario_tag}"
    adb_cmd shell svc data enable || true
    sleep 1
    mark "transport_break_end loop=${loop_idx} scenario=${scenario_tag}"
  fi

  sleep "${WIFI_DISABLE_SECS}"
  mark "wifi_disable_end loop=${loop_idx} scenario=${scenario_tag}"

  if [[ "${RESTART_APP_BEFORE_WIFI_ENABLE}" == "1" ]]; then
    mark "app_restart_before_wifi_enable loop=${loop_idx} scenario=${scenario_tag}"
    launch_app_and_wait_engine "before_wifi_enable loop=${loop_idx} scenario=${scenario_tag}" || true
  fi

  echo "==> WiFi enable (handoff to WiFi)"
  mark "wifi_enable_cmd loop=${loop_idx} scenario=${scenario_tag}"
  toggle_wifi_verified 1 "${loop_idx}" "${scenario_tag}"

  sleep "${WIFI_ENABLE_SECS}"

  if [[ "${TOGGLE_DATA}" == "1" ]]; then
    echo "==> Mobile data disable (prefer WiFi)"
    toggle_mobile_data_verified 0 "${loop_idx}" "${scenario_tag}"
    sleep "${DATA_DISABLE_SECS}"
  fi
}



run_scenario_data() {
  local loop_idx="$1"
  local scenario_tag="$2"
  echo "==> Mobile data disable (simulate data loss)"
  toggle_mobile_data_verified 0 "${loop_idx}" "${scenario_tag}"
  sleep "${DATA_DISABLE_SECS}"
  mark "data_disable_end loop=${loop_idx} scenario=${scenario_tag}"

  echo "==> Mobile data enable (simulate recovery)"
  toggle_mobile_data_verified 1 "${loop_idx}" "${scenario_tag}"
  sleep "${DATA_ENABLE_SECS}"
}

run_scenario_no_network() {
  local loop_idx="$1"
  local scenario_tag="$2"

  echo "==> Airplane mode ON (simulate full network loss)"
  mark "no_network_enable_cmd loop=${loop_idx} scenario=${scenario_tag}"
  toggle_airplane_verified 1 "${loop_idx}" "${scenario_tag}"
  sleep "${AIRPLANE_ENABLE_SECS}"

  echo "==> Airplane mode OFF (recovery)"
  mark "no_network_disable_cmd loop=${loop_idx} scenario=${scenario_tag}"
  toggle_airplane_verified 0 "${loop_idx}" "${scenario_tag}"
  sleep "${AIRPLANE_DISABLE_SECS}"
}

for i in $(seq 1 "${LOOPS}"); do
  echo
  echo "==> LOOP ${i}/${LOOPS}"
  mark "loop_${i}_start"

  # Health check at the start of each loop (can be disabled for handoff testing)
  if [[ "${DISABLE_APP_HEALTH_CHECK}" != "1" ]]; then
    if ! check_app_health; then
      echo "[WARN] App health check failed at loop ${i}, attempting recovery..."
      recover_app_if_needed || {
        echo "[ERROR] App recovery failed, continuing anyway..."
        mark "loop_${i}_app_recovery_failed"
      }
    fi
  fi

  # Check for network stall and recover if needed
  if check_network_stall 30; then
    recover_from_network_stall
  fi

  # Back-compat: TOGGLE_AIRPLANE=1 historically ran airplane on/off each loop.
  # If the user requested it, keep doing it even if SCENARIOS doesn't include no_network.
  if [[ "${TOGGLE_AIRPLANE}" == "1" ]]; then
    run_scenario_no_network "${i}" "airplane"
    if [[ "${STABILIZE_SECS}" != "0" ]]; then
      sleep "${STABILIZE_SECS}"
    fi
  fi

  for scenario in "${SCENARIOS_ARR[@]}"; do
    scenario="$(printf '%s' "${scenario}" | tr -d '[:space:]')"
    if [[ -z "${scenario}" ]]; then
      continue
    fi

    # Normalize scenarios to canonical keys so MARKs are consistent across aliases.
    scenario_key="${scenario}"
    case "${scenario}" in
      no_network|nonetwork|all_off|alloff)
        scenario_key="no_network"
        ;;
      lte|4g|mobile|cellular)
        # LTE/4G/mobile/cellular are aliases for the wifi scenario which tests WiFi→LTE handoff
        scenario_key="wifi"
        ;;
    esac

    mark "scenario_start loop=${i} scenario=${scenario_key}"
    case "${scenario_key}" in
      wifi)
        run_scenario_wifi "${i}" "wifi"
        ;;
      data)
        run_scenario_data "${i}" "data"
        ;;
      no_network)
        run_scenario_no_network "${i}" "no_network"
        ;;
      *)
        echo "WARNING: Unknown scenario '${scenario}' (skipping)" >&2
        mark "scenario_skip loop=${i} scenario=${scenario_key}"
        ;;
    esac
    mark "scenario_end loop=${i} scenario=${scenario_key}"
    if [[ "${STABILIZE_SECS}" != "0" ]]; then
      sleep "${STABILIZE_SECS}"
    fi
  done

  adb_cmd shell dumpsys connectivity | head -n 80 >>"${META}" 2>/dev/null || true
  mark "loop_${i}_end"
done

mark "run_done"

echo "==> Stopping logcat stream"
cleanup

echo "==> Dumping remaining logcat -> ${ANDROID_LOG_DUMP}"
adb_cmd logcat -d -v threadtime -s "${LOGCAT_TAGS_ARR[@]}" >"${ANDROID_LOG_DUMP}" || true

echo "==> Generating high-signal log -> ${ANDROID_LOG_HIGH_SIGNAL}"
grep -E "MARK:|startEngine called|stopEngine called|onEngineStartComplete|onEngineStopComplete|Setting engineState to (STARTING|STOPPING)|Network change detected|Network info update|Signaling:|Signaling reconnect attempt|REGISTER(_ACK)?\b|PEER_LIST|PEER_(JOINED|UPDATED)|\[PeerFSM\]|CONNECT_(REQUEST|SUCCESS|FAILED)|HANDSHAKE_FAILED|Hole punch|NAT:|STUN:|EXCEPTION|FATAL|CRASH" "${ANDROID_LOG}" \
  >"${ANDROID_LOG_HIGH_SIGNAL}" 2>/dev/null || true

echo "==> Generating event counts -> ${LOG_COUNTS}"
{
  echo "# Event counts (best-effort)"
  echo "run_dir=${RUN_DIR}"
  echo "timestamp=$(date +%Y-%m-%dT%H:%M:%S%z)"
  echo
  
  # ============================================================================
  # Basic Event Counts
  # ============================================================================
  echo "=== BASIC EVENT COUNTS ==="
  echo "MARK lines: $(grep_count "MARK:" "${ANDROID_LOG}")"
  echo "REGISTER_ACK: $(grep_count "REGISTER_ACK" "${ANDROID_LOG}")"
  echo "PeerFSM CONNECTED: $(grep_count "\[PeerFSM\].*-->[[:space:]]*CONNECTED" "${ANDROID_LOG}")"
  echo "PeerFSM READY: $(grep_count "\[PeerFSM\].*-->[[:space:]]*READY" "${ANDROID_LOG}")"
  echo "PeerFSM DISCONNECTED: $(grep_count "\[PeerFSM\].*-->[[:space:]]*DISCONNECTED" "${ANDROID_LOG}")"
  echo "Network change detected: $(grep_count "Network change detected" "${ANDROID_LOG}")"
  echo "Signaling reconnect attempt: $(grep_count "Signaling reconnect attempt" "${ANDROID_LOG}")"
  echo
  
  # ============================================================================
  # Enhanced Metrics (if enabled)
  # ============================================================================
  if [[ "${ENHANCED_METRICS}" == "1" ]]; then
    echo "=== CONNECTION METRICS ==="
    local connect_requested
    connect_requested="$(grep_count "CONNECT_REQUESTED\|CONNECT_REQUEST" "${ANDROID_LOG}")"
    local connect_success
    connect_success="$(grep_count "CONNECT_SUCCESS" "${ANDROID_LOG}")"
    local connect_failed
    connect_failed="$(grep_count "CONNECT_FAILED\|HANDSHAKE_FAILED" "${ANDROID_LOG}")"
    local handshake_complete
    handshake_complete="$(grep_count "HANDSHAKE_COMPLETE" "${ANDROID_LOG}")"
    
    echo "Connection attempts: ${connect_requested}"
    echo "Connection successes: ${connect_success}"
    echo "Connection failures: ${connect_failed}"
    echo "Handshakes completed: ${handshake_complete}"
    
    if [[ "${connect_requested}" -gt 0 ]]; then
      local success_rate
      success_rate=$((connect_success * 100 / connect_requested))
      echo "Connection success rate: ${success_rate}%"
    fi
    echo
    
    echo "=== NAT/STUN METRICS ==="
    local stun_attempts
    stun_attempts="$(grep_count "STUN:.*Starting NAT Detection\|STUN: Test I" "${ANDROID_LOG}")"
    local stun_success
    stun_success="$(grep_count "STUN:.*Success\|Detected NAT type" "${ANDROID_LOG}")"
    local hole_punch_attempts
    hole_punch_attempts="$(grep_count "Hole punch attempt" "${ANDROID_LOG}")"
    local hole_punch_success
    hole_punch_success="$(grep_count "Hole punching succeeded" "${ANDROID_LOG}")"
    local nat_type
    nat_type="$(grep "NAT: Detected NAT type" "${ANDROID_LOG}" 2>/dev/null | tail -1 | sed -E 's/.*NAT type ([^ ]+).*/\1/' || echo "unknown")"
    
    echo "STUN detection attempts: ${stun_attempts}"
    echo "STUN successes: ${stun_success}"
    echo "Hole punch attempts: ${hole_punch_attempts}"
    echo "Hole punch successes: ${hole_punch_success}"
    if [[ "${hole_punch_attempts}" -gt 0 ]]; then
      local hp_rate
      hp_rate=$((hole_punch_success * 100 / hole_punch_attempts))
      echo "Hole punch success rate: ${hp_rate}%"
    fi
    echo "Last detected NAT type: ${nat_type}"
    echo
    
    echo "=== SIGNALING METRICS ==="
    local signaling_connects
    signaling_connects="$(grep_count "Signaling: Connected successfully" "${ANDROID_LOG}")"
    local signaling_reconnects
    signaling_reconnects="$(grep_count "Signaling reconnect attempt" "${ANDROID_LOG}")"
    local peer_joined
    peer_joined="$(grep_count "PEER_JOINED" "${ANDROID_LOG}")"
    local peer_updated
    peer_updated="$(grep_count "PEER_UPDATED" "${ANDROID_LOG}")"
    
    echo "Signaling connections: ${signaling_connects}"
    echo "Signaling reconnect attempts: ${signaling_reconnects}"
    echo "Peers joined: ${peer_joined}"
    echo "Peers updated: ${peer_updated}"
    echo
    
    echo "=== DISCOVERY METRICS ==="
    local discovery_found
    discovery_found="$(grep_count "Discovery: Found peer" "${ANDROID_LOG}")"
    local lan_discoveries
    lan_discoveries="$(grep_count "Discovery:.*192\.168\.\|Discovery:.*10\.\|Discovery:.*172\." "${ANDROID_LOG}")"
    
    echo "Peers discovered: ${discovery_found}"
    echo "LAN discoveries: ${lan_discoveries}"
    echo
  fi
  
  # ============================================================================
  # Message Delivery Metrics
  # ============================================================================
  echo "=== MESSAGE DELIVERY METRICS ==="
  if [[ "${SEND_HELLO_ON_READY}" == "1" ]] && [[ -f "${HELLO_SENT_LOG_FILE}" ]]; then
    local msgs_sent
    msgs_sent="$(wc -l <"${HELLO_SENT_LOG_FILE}" 2>/dev/null | tr -d ' ' || echo 0)"
    echo "Hello messages sent: ${msgs_sent}"
    
    if [[ "${VERIFY_MESSAGE_DELIVERY}" == "1" ]] && [[ -f "${MESSAGE_DELIVERY_LOG_FILE}" ]]; then
      local msgs_acked
      msgs_acked="$(grep_count "ACK_RECEIVED" "${MESSAGE_DELIVERY_LOG_FILE}")"
      local msgs_timeout
      msgs_timeout="$(grep_count "ACK_TIMEOUT" "${MESSAGE_DELIVERY_LOG_FILE}")"
      
      echo "Messages acknowledged: ${msgs_acked}"
      echo "Messages timed out: ${msgs_timeout}"
      
      if [[ "${msgs_sent}" -gt 0 ]]; then
        local delivery_rate
        delivery_rate=$((msgs_acked * 100 / msgs_sent))
        echo "Message delivery rate: ${delivery_rate}%"
      fi
      
      # Calculate average latency from delivery log
      local latencies
      latencies="$(awk -F'|' '$4=="ACK_RECEIVED" && $5!="" {print $5}' "${MESSAGE_DELIVERY_LOG_FILE}" 2>/dev/null | tr '\n' ',' || true)"
      local avg_latency
      avg_latency="$(calculate_average_latency "${latencies}")"
      if [[ -n "${avg_latency}" ]]; then
        echo "Average message latency: ${avg_latency}ms"
      fi
      
      # Calculate retry statistics
      local total_retries
      total_retries="$(awk -F'|' 'NF>=6 && $6!="" {sum+=$6} END{print sum+0}' "${MESSAGE_DELIVERY_LOG_FILE}" 2>/dev/null || echo 0)"
      local avg_retries
      if [[ "${msgs_sent}" -gt 0 ]]; then
        avg_retries=$((total_retries / msgs_sent))
      else
        avg_retries=0
      fi
      echo "Total ACK verification retries: ${total_retries}"
      echo "Average retries per message: ${avg_retries}"
      
      echo
      echo "Message delivery details:"
      cat "${MESSAGE_DELIVERY_LOG_FILE}" 2>/dev/null | while IFS='|' read -r ts peer num status latency retries; do
        if [[ -n "${latency}" ]]; then
          echo "  - ${ts}: peer=${peer} msg#${num} ${status} (${latency}ms, ${retries:-1} attempts)"
        else
          echo "  - ${ts}: peer=${peer} msg#${num} ${status} (${retries:-1} attempts)"
        fi
      done || true
      
      # Display ACK failure reasons summary
      if [[ "${msgs_timeout}" -gt 0 ]]; then
        echo
        echo "ACK failure reasons:"
        # Count failures by reason from the 7th field
        local reasons
        reasons="$(awk -F'|' '$4=="ACK_TIMEOUT" && NF>=7 && $7!="" {print $7}' "${MESSAGE_DELIVERY_LOG_FILE}" 2>/dev/null | sort | uniq -c | sort -rn || true)"
        if [[ -n "${reasons}" ]]; then
          echo "${reasons}" | while read -r count reason; do
            echo "  - ${reason}: ${count} occurrence(s)"
          done
        else
          echo "  (No failure reasons recorded - check ack_failure_analysis.txt for details)"
        fi
        
        # Reference the detailed analysis file
        if [[ -f "${RUN_DIR}/ack_failure_analysis.txt" ]]; then
          echo
          echo "Detailed failure analysis saved to: ${RUN_DIR}/ack_failure_analysis.txt"
        fi
      fi
    fi
    
    echo
    echo "Hello message send log:"
    cat "${HELLO_SENT_LOG_FILE}" 2>/dev/null | while IFS='|' read -r ts peer conn msg; do
      echo "  - ${ts}: peer=${peer} connection=${conn}"
    done || true
  else
    echo "Hello messages: disabled or no log"
  fi
  echo
  
  # ============================================================================
  # Socket Restart Metrics
  # ============================================================================
  echo "=== SOCKET RESTART METRICS ==="
  local socket_restarts
  socket_restarts="$(grep_count "Socket restarted successfully\|UDP_SOCKET_RESTART_COMPLETE\|UDP: Socket restarted" "${ANDROID_LOG}")"
  local socket_binds
  socket_binds="$(grep_count "UDP: Bound socket\|UDP_SOCKET_BOUND" "${ANDROID_LOG}")"
  echo "Socket restart confirmations: ${socket_restarts}"
  echo "Socket bind events: ${socket_binds}"
  
  # Check for socket restart failures
  local socket_failures
  socket_failures="$(grep_count "socket restart failed\|UDP_SOCKET_RESTART_FAILED\|Failed to restart socket" "${ANDROID_LOG}")"
  if [[ "${socket_failures}" -gt 0 ]]; then
    echo "⚠️  Socket restart failures: ${socket_failures}"
  fi
  echo
  
  # ============================================================================
  # Desktop Peer Metrics (if available)
  # ============================================================================
  if [[ -f "${DESKTOP_LOG}" ]]; then
    echo "=== DESKTOP PEER METRICS ==="
    local desktop_encrypted_recv
    desktop_encrypted_recv="$(grep_count "ENCRYPTED_DATA\|type=17" "${DESKTOP_LOG}")"
    local desktop_app_data_recv
    desktop_app_data_recv="$(grep_count "APPLICATION_DATA\|type=18" "${DESKTOP_LOG}")"
    local desktop_handshake_complete
    desktop_handshake_complete="$(grep_count "PeerFSM.*READY\|keys derived" "${DESKTOP_LOG}")"
    
    echo "Messages received (ENCRYPTED_DATA): ${desktop_encrypted_recv}"
    echo "Application data received: ${desktop_app_data_recv}"
    echo "Handshakes completed: ${desktop_handshake_complete}"
    echo
  fi
  
  # ============================================================================
  # NAT Mapping / WiFi Handoff Diagnostic
  # ============================================================================
  if [[ -f "${ANDROID_LOG}" ]] && [[ -f "${MESSAGE_DELIVERY_LOG_FILE}" ]] && [[ -f "${HELLO_SENT_LOG_FILE}" ]]; then
    echo "=== NAT MAPPING DIAGNOSTIC ==="
    
    # Check for stale ephemeral mapping pattern
    local ephemeral_redirects
    ephemeral_redirects="$(grep_count "ephemeral mapping" "${ANDROID_LOG}")"
    local handshake_relays
    handshake_relays="$(grep_count "HANDSHAKE_RELAY" "${ANDROID_LOG}")"
    local handshake_failed_then_success
    handshake_failed_then_success="$(grep_count "HANDSHAKE_FAILED.*CONNECTED" "${ANDROID_LOG}")"
    
    echo "Ephemeral mapping uses: ${ephemeral_redirects}"
    echo "Handshake relays used: ${handshake_relays}"
    echo "Handshake retry patterns (FAILED->retry->SUCCESS): ${handshake_failed_then_success}"
    
    # Analyze failure pattern by network type
    local wifi_enable_msgs_failed=0
    local wifi_disable_msgs_failed=0
    if [[ -f "${HOST_MARKS}" ]]; then
      # Look at message send times and correlate with network events
      while IFS='|' read -r msg_ts peer msg_num status latency; do
        if [[ "${status}" == "ACK_TIMEOUT" ]]; then
          # Check if this was after WiFi enable or disable
          local msg_epoch
          msg_epoch="$(date -j -f "%Y-%m-%dT%H:%M:%S%z" "${msg_ts}" +%s 2>/dev/null || date +%s)"
          local last_wifi_enable
          last_wifi_enable="$(grep "wifi_enable_verified\|wifi_enable loop" "${HOST_MARKS}" 2>/dev/null | \
                              awk -v ts="${msg_epoch}" 'BEGIN{last=0} {
                                match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}/); 
                                if (RSTART > 0) {
                                  mark_ts = substr($0, RSTART, RLENGTH);
                                  "date -j -f %Y-%m-%dT%H:%M:%S " mark_ts " +%s 2>/dev/null" | getline mark_epoch;
                                  close("date -j -f %Y-%m-%dT%H:%M:%S " mark_ts " +%s 2>/dev/null");
                                  if (mark_epoch < ts && mark_epoch > last) last = mark_epoch;
                                }
                              } END {print last}' 2>/dev/null || echo 0)"
          local last_wifi_disable
          last_wifi_disable="$(grep "wifi_disable_verified\|wifi_disable loop" "${HOST_MARKS}" 2>/dev/null | \
                               awk -v ts="${msg_epoch}" 'BEGIN{last=0} {
                                 match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}/); 
                                 if (RSTART > 0) {
                                   mark_ts = substr($0, RSTART, RLENGTH);
                                   "date -j -f %Y-%m-%dT%H:%M:%S " mark_ts " +%s 2>/dev/null" | getline mark_epoch;
                                   close("date -j -f %Y-%m-%dT%H:%M:%S " mark_ts " +%s 2>/dev/null");
                                   if (mark_epoch < ts && mark_epoch > last) last = mark_epoch;
                                 }
                               } END {print last}' 2>/dev/null || echo 0)"
          if [[ "${last_wifi_enable:-0}" -gt "${last_wifi_disable:-0}" ]]; then
            wifi_enable_msgs_failed=$((wifi_enable_msgs_failed + 1))
          else
            wifi_disable_msgs_failed=$((wifi_disable_msgs_failed + 1))
          fi
        fi
      done < "${MESSAGE_DELIVERY_LOG_FILE}" 2>/dev/null || true
    fi
    
    echo "Messages failed after WiFi enable: ${wifi_enable_msgs_failed}"
    echo "Messages failed after WiFi disable: ${wifi_disable_msgs_failed}"
    
    # Additional WAN vs LAN path analysis
    local msgs_sent_to_wan=0
    local msgs_sent_to_lan=0
    if [[ -f "${ANDROID_LOG}" ]]; then
      msgs_sent_to_wan="$(grep_count "UDP_SEND_SUCCESS.*110\.\|UDP_SEND_SUCCESS.*[0-9]\.[0-9]*\.[0-9]*\.[0-9]*:31001" "${ANDROID_LOG}")"
      msgs_sent_to_lan="$(grep_count "UDP_SEND_SUCCESS.*192\.168\.\|UDP_SEND_SUCCESS.*10\.\|UDP_SEND_SUCCESS.*172\." "${ANDROID_LOG}")"
    fi
    echo "UDP packets sent to WAN IPs: ${msgs_sent_to_wan}"
    echo "UDP packets sent to LAN IPs: ${msgs_sent_to_lan}"
    
    # Provide diagnosis
    echo
    echo "--- DIAGNOSIS ---"
    if [[ "${wifi_enable_msgs_failed}" -gt "${wifi_disable_msgs_failed}" ]]; then
      echo "⚠️  LIKELY ISSUE: LAN path not used after WiFi reconnect"
      echo "   Messages fail predominantly after WiFi is re-enabled."
      echo
      echo "   DETECTED BEHAVIOR:"
      echo "   - Android sends to WAN IP (external) even when on same LAN as desktop"
      echo "   - Desktop is reachable via LAN (192.168.x.x) but Android uses WAN path"
      echo "   - Router NAT mapping is stale after WiFi reconnect, so packets are lost"
      echo
      echo "   ROOT CAUSE:"
      echo "   The P2P library does not update its preferred endpoint to use LAN IP after"
      echo "   WiFi reconnect, even though LAN discovery is working. It continues to use"
      echo "   the WAN/ephemeral mapping from the previous network configuration."
      echo
      echo "   REQUIRED P2P LIBRARY FIX:"
      echo "   1. After network interface change, detect if peer is on same LAN via discovery"
      echo "   2. Update preferred endpoint to LAN IP when discovered on same network"
      echo "   3. Clear stale WAN/ephemeral mappings after network change"
      echo "   4. Re-establish hole punch only if LAN path fails"
      echo
      echo "   WORKAROUND:"
      echo "   - Increase delay to allow more heartbeats (may help occasionally)"
      echo "   - Current settings: HELLO_MESSAGE_POST_READY_DELAY_S=${HELLO_MESSAGE_POST_READY_DELAY_S}s"
    elif [[ "${handshake_relays}" -gt 0 ]]; then
      echo "ℹ️  Handshake relay is being used, which indicates direct UDP path issues."
      echo "   The signaling server is relaying handshake messages because hole punching failed."
    else
      echo "✅ No specific NAT mapping issues detected in this run."
    fi
    echo
  fi
  
  echo "=== TOP MARKS ==="
  grep -E "MARK:" "${ANDROID_LOG}" 2>/dev/null | tail -n 80 || true
} >"${LOG_COUNTS}" 2>/dev/null || true

SLA_EXIT=0
SLA_REPORT="${RUN_DIR}/sla_report.txt"
TIMELINE_MD="${RUN_DIR}/timeline.md"
TIMING_MD="${RUN_DIR}/timing_summary.md"

if [[ "${GENERATE_REPORTS}" == "1" ]]; then
  echo "==> Generating timeline -> ${TIMELINE_MD}"
  python3 "${ROOT_DIR}/tools/harness/parse_android_handoff_timeline.py" \
    --run-dir "${RUN_DIR}" \
    --out "${TIMELINE_MD}" \
    >/dev/null 2>&1 || true

  echo "==> Generating timing summary -> ${TIMING_MD}"
  python3 "${ROOT_DIR}/tools/harness/summarize_android_handoff_timings.py" \
    --run-dir "${RUN_DIR}" \
    --out "${TIMING_MD}" \
    >/dev/null 2>&1 || true
fi

if [[ "${ENFORCE_SLA}" == "1" ]]; then
  echo "==> Enforcing SLA <= ${SLA_SECONDS}s"
  SLA_ARGS=()
  if [[ "${SLA_REQUIRE_READY}" == "1" ]]; then
    SLA_ARGS+=(--require-ready)
  fi
  if [[ ${#SLA_ARGS[@]} -gt 0 ]]; then
    python3 "${ROOT_DIR}/tools/harness/check_android_handoff_sla.py" \
      --run-dir "${RUN_DIR}" \
      --sla-seconds "${SLA_SECONDS}" \
      "${SLA_ARGS[@]}" \
      >"${SLA_REPORT}" 2>&1 || SLA_EXIT=$?
  else
    python3 "${ROOT_DIR}/tools/harness/check_android_handoff_sla.py" \
      --run-dir "${RUN_DIR}" \
      --sla-seconds "${SLA_SECONDS}" \
      >"${SLA_REPORT}" 2>&1 || SLA_EXIT=$?
  fi
fi

echo
echo "==> High-signal excerpts (tail):"
grep -E "MARK:|startEngine called|onEngineStartComplete|Setting engineState to STARTING|Network change detected|Network info update|Signaling:|Signaling reconnect attempt|REGISTER_ACK|PEER_LIST|PEER_JOINED|PEER_UPDATED|CONNECT_REQUEST|Discovery: Found peer|CONNECT_SUCCESS|CONNECT_FAILED|HANDSHAKE_FAILED|Hole punch|NAT:|STUN:" "${ANDROID_LOG}" \
  | tail -n 250 || true

echo
echo "==> Saved:"
echo "- ${ANDROID_LOG}"
echo "- ${ANDROID_LOG_DUMP}"
echo "- ${ANDROID_LOG_HIGH_SIGNAL}"
echo "- ${LOG_COUNTS}"
echo "- ${HOST_MARKS_LOG}"
echo "- ${META}"

if [[ -n "${HELLO_SENT_LOG_FILE}" ]] && [[ -f "${HELLO_SENT_LOG_FILE}" ]]; then
  echo "- ${HELLO_SENT_LOG_FILE}"
fi

if [[ -f "${SLA_REPORT}" ]]; then
  echo "- ${SLA_REPORT}"
fi

if [[ -f "${TIMELINE_MD}" ]]; then
  echo "- ${TIMELINE_MD}"
fi
if [[ -f "${TIMING_MD}" ]]; then
  echo "- ${TIMING_MD}"
  if [[ -f "${TIMING_MD}.json" ]]; then
    echo "- ${TIMING_MD}.json"
  fi
fi

if [[ "${SLA_EXIT}" != "0" ]]; then
  echo
  echo "==> SLA violated (exit=${SLA_EXIT})." >&2
  if [[ -f "${SLA_REPORT}" ]]; then
    echo "--- SLA report ---" >&2
    cat "${SLA_REPORT}" >&2 || true
    echo "--- end SLA report ---" >&2
  else
    echo "See timing summary + high-signal log." >&2
  fi
  exit "${SLA_EXIT}"
fi

# ============================================================================
# TEST SUMMARY DASHBOARD
# ============================================================================
if [[ "${SHOW_TEST_SUMMARY}" == "1" ]]; then
  echo
  echo "╔══════════════════════════════════════════════════════════════════════════════╗"
  echo "║                           P2P HANDOFF TEST SUMMARY                           ║"
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  
  # Helper function for status indicators
  status_icon() {
    if [[ "$1" == "pass" ]]; then
      printf "✅"
    elif [[ "$1" == "warn" ]]; then
      printf "⚠️ "
    elif [[ "$1" == "fail" ]]; then
      printf "❌"
    else
      printf "ℹ️ "
    fi
  }
  
  # Calculate metrics for summary
  summary_loops="${LOOPS}"
  summary_scenarios="${SCENARIOS}"
  
  # Connection metrics
  sum_peer_ready="$(grep_count "\[PeerFSM\].*-->[[:space:]]*READY" "${ANDROID_LOG}")"
  sum_peer_connected="$(grep_count "\[PeerFSM\].*-->[[:space:]]*CONNECTED" "${ANDROID_LOG}")"
  sum_peer_disconnected="$(grep_count "\[PeerFSM\].*-->[[:space:]]*DISCONNECTED" "${ANDROID_LOG}")"
  sum_register_ack="$(grep_count "REGISTER_ACK" "${ANDROID_LOG}")"
  sum_network_changes="$(grep_count "Network change detected" "${ANDROID_LOG}")"
  
  # Connection status
  conn_status="pass"
  if [[ "${sum_peer_ready}" -eq 0 ]]; then
    conn_status="fail"
  elif [[ "${sum_peer_ready}" -lt "${summary_loops}" ]]; then
    conn_status="warn"
  fi
  
  printf "║ %-76s ║\n" "$(status_icon ${conn_status}) Connection Established: ${sum_peer_ready} READY state(s)"
  printf "║ %-76s ║\n" "   └─ Connected: ${sum_peer_connected}, Disconnected: ${sum_peer_disconnected}"
  
  # Signaling status
  sig_status="pass"
  if [[ "${sum_register_ack}" -eq 0 ]]; then
    sig_status="fail"
  fi
  printf "║ %-76s ║\n" "$(status_icon ${sig_status}) Signaling Registration: ${sum_register_ack} REGISTER_ACK(s)"
  
  # Network handoff status
  handoff_status="info"
  if [[ "${sum_network_changes}" -gt 0 ]]; then
    handoff_status="pass"
  fi
  printf "║ %-76s ║\n" "$(status_icon ${handoff_status}) Network Handoffs Detected: ${sum_network_changes}"
  
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  
  # Message delivery metrics
  if [[ "${SEND_HELLO_ON_READY}" == "1" ]]; then
    sum_msgs_sent=0
    sum_msgs_acked=0
    sum_msgs_failed=0
    sum_avg_latency=""
    
    if [[ -f "${HELLO_SENT_LOG_FILE}" ]]; then
      sum_msgs_sent="$(wc -l <"${HELLO_SENT_LOG_FILE}" 2>/dev/null | tr -d ' ' || echo 0)"
    fi
    
    if [[ -f "${MESSAGE_DELIVERY_LOG_FILE}" ]]; then
      sum_msgs_acked="$(grep_count "ACK_RECEIVED" "${MESSAGE_DELIVERY_LOG_FILE}")"
      sum_msgs_failed="$(grep_count "ACK_TIMEOUT" "${MESSAGE_DELIVERY_LOG_FILE}")"
      
      # Calculate average latency
      latencies="$(awk -F'|' '$4=="ACK_RECEIVED" && $5!="" {print $5}' "${MESSAGE_DELIVERY_LOG_FILE}" 2>/dev/null | tr '\n' ',' || true)"
      sum_avg_latency="$(calculate_average_latency "${latencies}")"
    fi
    
    msg_status="pass"
    delivery_rate=0
    if [[ "${sum_msgs_sent}" -gt 0 ]]; then
      delivery_rate=$((sum_msgs_acked * 100 / sum_msgs_sent))
      if [[ "${delivery_rate}" -lt 100 ]]; then
        msg_status="warn"
      fi
      if [[ "${delivery_rate}" -lt 50 ]]; then
        msg_status="fail"
      fi
    elif [[ "${sum_peer_ready}" -gt 0 ]]; then
      msg_status="warn"  # Ready but no messages sent
    fi
    
    printf "║ %-76s ║\n" "$(status_icon ${msg_status}) Messages Sent: ${sum_msgs_sent}"
    printf "║ %-76s ║\n" "   └─ Delivered: ${sum_msgs_acked} (${delivery_rate}%), Failed: ${sum_msgs_failed}"
    
    if [[ -n "${sum_avg_latency}" ]]; then
      lat_status="pass"
      if [[ "${sum_avg_latency}" -gt 500 ]]; then
        lat_status="warn"
      fi
      if [[ "${sum_avg_latency}" -gt 2000 ]]; then
        lat_status="fail"
      fi
      printf "║ %-76s ║\n" "$(status_icon ${lat_status}) Average Message Latency: ${sum_avg_latency}ms"
    fi
  else
    printf "║ %-76s ║\n" "ℹ️  Message Testing: Disabled (SEND_HELLO_ON_READY=0)"
  fi
  
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  
  # NAT/Connectivity metrics
  sum_hole_punch_success="$(grep_count "Hole punching succeeded" "${ANDROID_LOG}")"
  sum_hole_punch_attempts="$(grep_count "Hole punch attempt" "${ANDROID_LOG}")"
  sum_nat_type="$(grep "NAT: Detected NAT type" "${ANDROID_LOG}" 2>/dev/null | tail -1 | sed -E 's/.*NAT type ([^ ]+).*/\1/' || echo "unknown")"
  
  nat_status="pass"
  if [[ "${sum_hole_punch_attempts}" -gt 0 ]]; then
    hp_rate=$((sum_hole_punch_success * 100 / sum_hole_punch_attempts))
    if [[ "${hp_rate}" -lt 100 ]]; then
      nat_status="warn"
    fi
    if [[ "${hp_rate}" -lt 50 ]]; then
      nat_status="fail"
    fi
    printf "║ %-76s ║\n" "$(status_icon ${nat_status}) NAT Traversal: ${sum_hole_punch_success}/${sum_hole_punch_attempts} hole punches (${hp_rate}%)"
  else
    printf "║ %-76s ║\n" "ℹ️  NAT Traversal: No hole punch attempts recorded"
  fi
  printf "║ %-76s ║\n" "   └─ Detected NAT Type: ${sum_nat_type}"
  
  # Desktop peer metrics (if available)
  if [[ -f "${DESKTOP_LOG}" ]]; then
    desktop_msgs_recv="$(grep_count "ENCRYPTED_DATA\|type=17" "${DESKTOP_LOG}")"
    desktop_status="pass"
    if [[ "${desktop_msgs_recv}" -eq 0 ]] && [[ "${sum_msgs_sent}" -gt 0 ]]; then
      desktop_status="warn"
    fi
    printf "║ %-76s ║\n" "$(status_icon ${desktop_status}) Desktop Peer Messages Received: ${desktop_msgs_recv}"
  fi
  
  # Socket restart metrics
  sum_socket_restarts="$(grep_count "Socket restarted successfully\|UDP_SOCKET_RESTART_COMPLETE\|UDP: Socket restarted" "${ANDROID_LOG}")"
  sum_socket_failures="$(grep_count "socket restart failed\|UDP_SOCKET_RESTART_FAILED" "${ANDROID_LOG}")"
  
  socket_status="pass"
  if [[ "${sum_socket_failures}" -gt 0 ]]; then
    socket_status="fail"
  elif [[ "${sum_network_changes}" -gt 0 ]] && [[ "${sum_socket_restarts}" -eq 0 ]]; then
    socket_status="warn"  # Network changed but no socket restarts detected
  fi
  
  printf "║ %-76s ║\n" "$(status_icon ${socket_status}) Socket Restarts: ${sum_socket_restarts} confirmed"
  if [[ "${sum_socket_failures}" -gt 0 ]]; then
    printf "║ %-76s ║\n" "   └─ ⚠️  Failures: ${sum_socket_failures}"
  fi
  
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  
  # SLA compliance
  if [[ "${ENFORCE_SLA}" == "1" ]]; then
    sla_status="pass"
    if [[ "${SLA_EXIT}" != "0" ]]; then
      sla_status="fail"
    fi
    printf "║ %-76s ║\n" "$(status_icon ${sla_status}) SLA Compliance (<${SLA_SECONDS}s): $([[ ${SLA_EXIT} == 0 ]] && echo 'PASS' || echo 'FAIL')"
  fi
  
  # Overall result
  echo "╠══════════════════════════════════════════════════════════════════════════════╣"
  
  overall_result="PASS"
  overall_status="pass"
  
  # Determine overall result
  if [[ "${sum_peer_ready}" -eq 0 ]]; then
    overall_result="FAIL"
    overall_status="fail"
  elif [[ "${SLA_EXIT}" != "0" ]]; then
    overall_result="FAIL"
    overall_status="fail"
  elif [[ "${SEND_HELLO_ON_READY}" == "1" ]] && [[ "${sum_msgs_sent}" -gt 0 ]]; then
    if [[ -f "${MESSAGE_DELIVERY_LOG_FILE}" ]]; then
      acked="$(grep_count "ACK_RECEIVED" "${MESSAGE_DELIVERY_LOG_FILE}")"
      if [[ "${acked}" -lt "${sum_msgs_sent}" ]]; then
        if [[ "${REQUIRE_MESSAGE_DELIVERY}" == "1" ]]; then
          overall_result="FAIL"
          overall_status="fail"
        else
          overall_result="PASS (with warnings)"
          overall_status="warn"
        fi
      fi
    fi
  fi
  
  printf "║ %-76s ║\n" ""
  printf "║ %-76s ║\n" "                    OVERALL RESULT: $(status_icon ${overall_status}) ${overall_result}"
  printf "║ %-76s ║\n" ""
  printf "║ %-76s ║\n" "   Test Duration: ${LOOPS} loop(s), Scenarios: ${SCENARIOS}"
  printf "║ %-76s ║\n" "   Run Directory: ${RUN_DIR##*/}"
  
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
  echo
  
  # Save summary to file
  TEST_SUMMARY_FILE="${RUN_DIR}/test_summary.txt"
  {
    echo "P2P HANDOFF TEST SUMMARY"
    echo "========================"
    echo "Timestamp: $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo "Run Directory: ${RUN_DIR}"
    echo ""
    echo "=== CONNECTION ==="
    echo "READY states: ${sum_peer_ready}"
    echo "CONNECTED transitions: ${sum_peer_connected}"
    echo "DISCONNECTED transitions: ${sum_peer_disconnected}"
    echo "REGISTER_ACKs: ${sum_register_ack}"
    echo "Network changes: ${sum_network_changes}"
    echo ""
    echo "=== MESSAGING ==="
    if [[ "${SEND_HELLO_ON_READY}" == "1" ]]; then
      echo "Messages sent: ${sum_msgs_sent:-0}"
      echo "Messages acknowledged: ${sum_msgs_acked:-0}"
      echo "Messages failed: ${sum_msgs_failed:-0}"
      echo "Delivery rate: ${delivery_rate:-0}%"
      echo "Average latency: ${sum_avg_latency:-N/A}ms"
    else
      echo "Message testing: Disabled"
    fi
    echo ""
    echo "=== NAT TRAVERSAL ==="
    echo "Hole punch attempts: ${sum_hole_punch_attempts}"
    echo "Hole punch successes: ${sum_hole_punch_success}"
    echo "NAT type: ${sum_nat_type}"
    echo ""
    echo "=== RESULT ==="
    echo "Overall: ${overall_result}"
    echo "SLA Exit Code: ${SLA_EXIT}"
  } >"${TEST_SUMMARY_FILE}" 2>/dev/null || true
  
  echo "- ${TEST_SUMMARY_FILE}"
fi


