#!/usr/bin/env bash
set -euo pipefail

# Keep the script quiet: disable job control/async job termination notifications.
# Otherwise bash may emit lines like `Killed: 9 <cmd>` when we intentionally
# SIGKILL peers during churn, which can flood stderr and get the run killed.
set +m 2>/dev/null || true
set +b 2>/dev/null || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DEFAULT="$ROOT_DIR/desktop/build_mac/bin/litep2p_peer_mac"
BIN="${LITEP2P_BIN:-$BIN_DEFAULT}"

CONFIG_DEFAULT="$ROOT_DIR/tools/config_local_no_signaling.json"
CONFIG="${LITEP2P_CONFIG:-$CONFIG_DEFAULT}"

if [[ ! -f "$CONFIG" ]]; then
  echo "ERROR: config file not found: $CONFIG" >&2
  echo "Set LITEP2P_CONFIG to a valid config (e.g. $ROOT_DIR/config.json)" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "ERROR: peer binary not found/executable at: $BIN" >&2
  echo "Build it first (macOS): cd desktop && ./build_mac.sh" >&2
  exit 1
fi

RUNS_DIR="$ROOT_DIR/desktop_sim_runs"
RUN_DIR="$RUNS_DIR/churn_repro_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RUN_DIR"

# Create per-peer configs so each process has its own Noise keystore (and optional peer_db),
# matching real-world behavior (each device/app has isolated storage). Without this, multiple peers
# will overwrite the same keystore file and encrypted messaging will fail/flap nondeterministically.
CONFIG_A="$RUN_DIR/config_peer_a.json"
CONFIG_B="$RUN_DIR/config_peer_b.json"
KEYSTORE_A="$RUN_DIR/keystore_a"
KEYSTORE_B="$RUN_DIR/keystore_b"
mkdir -p "$KEYSTORE_A" "$KEYSTORE_B"

python3 - "$CONFIG" "$CONFIG_A" "$KEYSTORE_A" <<'PY'
import json, sys
src, dst, ks = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(src, "r", encoding="utf-8"))
sec = data.setdefault("security", {})
nk = sec.setdefault("noise_nk_protocol", {})
nk["enabled"] = bool(nk.get("enabled", True))
nk["mandatory"] = bool(nk.get("mandatory", True))
nk["key_store_path"] = ks
storage = data.setdefault("storage", {})
peer_db = storage.setdefault("peer_db", {})
peer_db["enabled"] = False
json.dump(data, open(dst, "w", encoding="utf-8"), indent=2)
PY

python3 - "$CONFIG" "$CONFIG_B" "$KEYSTORE_B" <<'PY'
import json, sys
src, dst, ks = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(src, "r", encoding="utf-8"))
sec = data.setdefault("security", {})
nk = sec.setdefault("noise_nk_protocol", {})
nk["enabled"] = bool(nk.get("enabled", True))
nk["mandatory"] = bool(nk.get("mandatory", True))
nk["key_store_path"] = ks
storage = data.setdefault("storage", {})
peer_db = storage.setdefault("peer_db", {})
peer_db["enabled"] = False
json.dump(data, open(dst, "w", encoding="utf-8"), indent=2)
PY

# Fixed IDs so we can restart with the exact same identity.
PEER_A_ID="${PEER_A_ID:-11111111-1111-1111-1111-111111111111}"
PEER_B_ID="${PEER_B_ID:-22222222-2222-2222-2222-222222222222}"

# Ports must be stable across restarts if you want to mimic a "same peer" reboot.
PEER_A_PORT="${PEER_A_PORT:-31101}"
PEER_B_PORT="${PEER_B_PORT:-31102}"

CYCLES="${CYCLES:-200}"
MSG_TIMEOUT_SEC="${MSG_TIMEOUT_SEC:-3}"
CONNECT_TIMEOUT_SEC="${CONNECT_TIMEOUT_SEC:-3}"
DISCOVERY_TIMEOUT_SEC="${DISCOVERY_TIMEOUT_SEC:-6}"
HANDSHAKE_TIMEOUT_SEC="${HANDSHAKE_TIMEOUT_SEC:-25}"
SLEEP_BETWEEN_SEC="${SLEEP_BETWEEN_SEC:-0.2}"
VERBOSE="${VERBOSE:-0}"
PROGRESS_EVERY="${PROGRESS_EVERY:-25}"
DISCOVERY_RETRIES="${DISCOVERY_RETRIES:-2}"
SEND_RETRIES="${SEND_RETRIES:-5}"
CONNECT_RETRIES="${CONNECT_RETRIES:-4}"
ENABLE_DUPLICATE_ID="${ENABLE_DUPLICATE_ID:-0}"

A_FIFO="$RUN_DIR/peer_a.in"
B_FIFO="$RUN_DIR/peer_b.in"
mkfifo "$A_FIFO" "$B_FIFO"

A_LOG="$RUN_DIR/peer_a.log"
B_LOG="$RUN_DIR/peer_b.log"

SUMMARY="$RUN_DIR/summary.txt"

# Open each FIFO read+write so:
# - the peer can open it for reading without blocking
# - the peer never sees EOF when we write one command and close
# NOTE: macOS ships bash 3.2 by default, so we avoid bash 4+ dynamic FD syntax.
exec 3<>"$A_FIFO"
exec 4<>"$B_FIFO"
A_FD=3
B_FD=4

A_PID=""
B_PID=""

cleanup() {
  set +e
  if [[ -n "${A_PID:-}" ]]; then kill "$A_PID" 2>/dev/null || true; fi
  if [[ -n "${B_PID:-}" ]]; then kill "$B_PID" 2>/dev/null || true; fi
  sleep 0.2
  if [[ -n "${A_PID:-}" ]]; then kill -9 "$A_PID" 2>/dev/null || true; fi
  if [[ -n "${B_PID:-}" ]]; then kill -9 "$B_PID" 2>/dev/null || true; fi
  wait 2>/dev/null || true
}
trap cleanup EXIT

log_summary() {
  echo "$*" >>"$SUMMARY"
  if [[ "$VERBOSE" == "1" ]]; then
    echo "$*"
  fi
}

log_progress() {
  local cycle="$1"
  if (( cycle % PROGRESS_EVERY == 0 )); then
    log_summary "PROGRESS cycle=$cycle"
    if [[ "$VERBOSE" != "1" ]]; then
      # Minimal stdout heartbeat so you know it's alive.
      echo "progress: cycle $cycle (run: $RUN_DIR)"
    fi
  fi
}

start_peer_a() {
  "$BIN" --no-tui --log-level none --config "$CONFIG_A" --id "$PEER_A_ID" --port "$PEER_A_PORT" <"$A_FIFO" >>"$A_LOG" 2>&1 &
  A_PID=$!
  log_summary "START A pid=$A_PID id=$PEER_A_ID port=$PEER_A_PORT"
}

start_peer_b() {
  "$BIN" --no-tui --log-level none --config "$CONFIG_B" --id "$PEER_B_ID" --port "$PEER_B_PORT" <"$B_FIFO" >>"$B_LOG" 2>&1 &
  B_PID=$!
  log_summary "START B pid=$B_PID id=$PEER_B_ID port=$PEER_B_PORT"
}

send_a() { printf '%s\n' "$*" >&"$A_FD"; }
send_b() { printf '%s\n' "$*" >&"$B_FD"; }

now_ms() {
  # macOS: date doesn't support %N reliably; use python if available, else seconds.
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import time
print(int(time.time()*1000))
PY
  else
    echo "$(date +%s)000"
  fi
}

wait_for_pattern_since_line() {
  local file="$1"
  local start_line="$2"
  local pattern="$3"
  local timeout_sec="$4"

  local deadline=$(( $(date +%s) + timeout_sec ))
  while (( $(date +%s) <= deadline )); do
    if [[ -f "$file" ]]; then
      # tail -n +N is supported on macOS.
      if tail -n +"$((start_line + 1))" "$file" 2>/dev/null | grep -Eq "$pattern"; then
        return 0
      fi
    fi
    sleep 0.05
  done
  return 1
}

line_count() {
  if [[ -f "$1" ]]; then
    wc -l <"$1" | tr -d ' '
  else
    echo 0
  fi
}

is_pid_alive() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

assert_connected_and_messaging() {
  local cycle="$1"

  if ! is_pid_alive "$A_PID"; then
    log_summary "FAIL cycle=$cycle reason=A_not_running"
    return 1
  fi
  if ! is_pid_alive "$B_PID"; then
    log_summary "FAIL cycle=$cycle reason=B_not_running"
    return 1
  fi

  # Refresh peers list to keep mapping warm.
  # IMPORTANT: right after a restart, a peer may momentarily have an empty peer list.
  # We wait for each side to *see* the other peer before trying connect/send.
  local a0 b0
  a0="$(line_count "$A_LOG")"
  b0="$(line_count "$B_LOG")"
  send_a "peers"
  send_b "peers"

  local attempt
  for ((attempt=1; attempt<=DISCOVERY_RETRIES; attempt++)); do
    if wait_for_pattern_since_line "$A_LOG" "$a0" "\\b${PEER_B_ID}\\b" "$DISCOVERY_TIMEOUT_SEC"; then
      break
    fi
    if ! is_pid_alive "$A_PID"; then
      log_summary "FAIL cycle=$cycle reason=A_died_while_waiting_for_discovery"
      return 1
    fi
    log_summary "WARN cycle=$cycle reason=A_missing_peer_in_list attempt=$attempt/$DISCOVERY_RETRIES"
    send_a "peers"
  done
  if ! wait_for_pattern_since_line "$A_LOG" "$a0" "\\b${PEER_B_ID}\\b" 0; then
    log_summary "FAIL cycle=$cycle reason=A_missing_peer_in_list"
    return 1
  fi

  for ((attempt=1; attempt<=DISCOVERY_RETRIES; attempt++)); do
    if wait_for_pattern_since_line "$B_LOG" "$b0" "\\b${PEER_A_ID}\\b" "$DISCOVERY_TIMEOUT_SEC"; then
      break
    fi
    if ! is_pid_alive "$B_PID"; then
      log_summary "FAIL cycle=$cycle reason=B_died_while_waiting_for_discovery"
      return 1
    fi
    log_summary "WARN cycle=$cycle reason=B_missing_peer_in_list attempt=$attempt/$DISCOVERY_RETRIES"
    send_b "peers"
  done
  if ! wait_for_pattern_since_line "$B_LOG" "$b0" "\\b${PEER_A_ID}\\b" 0; then
    log_summary "FAIL cycle=$cycle reason=B_missing_peer_in_list"
    return 1
  fi

  # Best-effort connect (id->addr mapping is discovery-driven).
  local a_conn0 b_conn0
  a_conn0="$(line_count "$A_LOG")"
  b_conn0="$(line_count "$B_LOG")"

  # Under loss/jitter, connect/handshake may take longer; retry connect commands a few times.
  local ctry
  for ((ctry=1; ctry<=CONNECT_RETRIES; ctry++)); do
    send_a "connect $PEER_B_ID"
    send_b "connect $PEER_A_ID"

    # Look for either side reporting a successful connect.
    if wait_for_pattern_since_line "$A_LOG" "$a_conn0" "Connected:" "$CONNECT_TIMEOUT_SEC" \
      && wait_for_pattern_since_line "$B_LOG" "$b_conn0" "Connected:" "$CONNECT_TIMEOUT_SEC"; then
      break
    fi

    log_summary "WARN cycle=$cycle reason=connect_not_confirmed attempt=$ctry/$CONNECT_RETRIES"
    if ! is_pid_alive "$A_PID" || ! is_pid_alive "$B_PID"; then
      log_summary "FAIL cycle=$cycle reason=peer_died_during_connect_wait"
      return 1
    fi
    # Refresh peer list + try again.
    send_a "peers"
    send_b "peers"
  done

  if ! wait_for_pattern_since_line "$A_LOG" "$a_conn0" "Connected:" 0 \
    || ! wait_for_pattern_since_line "$B_LOG" "$b_conn0" "Connected:" 0; then
    log_summary "FAIL cycle=$cycle reason=connect_not_confirmed"
    return 1
  fi

  # STRICT: ensure Noise handshake is READY on both sides before sending app messages.
  # Sending ENCRYPTED_DATA before both sides are READY causes expected decrypt failures/flaps.
  if ! wait_for_pattern_since_line "$A_LOG" "$a_conn0" "SecureSession: Handshake complete for ${PEER_B_ID}" "$HANDSHAKE_TIMEOUT_SEC"; then
    log_summary "FAIL cycle=$cycle reason=a_handshake_timeout"
    return 1
  fi
  if ! wait_for_pattern_since_line "$B_LOG" "$b_conn0" "SecureSession: Handshake complete for ${PEER_A_ID}" "$HANDSHAKE_TIMEOUT_SEC"; then
    log_summary "FAIL cycle=$cycle reason=b_handshake_timeout"
    return 1
  fi

  # Send messages both ways and assert receipt.
  local msg_a msg_b
  msg_a="cycle=${cycle} from=A t=$(now_ms)"
  msg_b="cycle=${cycle} from=B t=$(now_ms)"

  a0="$(line_count "$A_LOG")"
  b0="$(line_count "$B_LOG")"

  # UDP can drop packets under iptables/tc loss. Retry a few times before declaring failure.
  local attempt ok_a ok_b
  ok_a=0
  ok_b=0
  for ((attempt=1; attempt<=SEND_RETRIES; attempt++)); do
    send_a "send $PEER_B_ID $msg_a"
    if wait_for_pattern_since_line "$B_LOG" "$b0" "$msg_a" "$MSG_TIMEOUT_SEC"; then
      ok_a=1
      break
    fi
    log_summary "WARN cycle=$cycle reason=B_missing_msg_a attempt=$attempt/$SEND_RETRIES"
    # Re-drive connect in case the session got reset due to decrypt failure.
    send_a "connect $PEER_B_ID"
    send_b "connect $PEER_A_ID"
  done

  for ((attempt=1; attempt<=SEND_RETRIES; attempt++)); do
    send_b "send $PEER_A_ID $msg_b"
    if wait_for_pattern_since_line "$A_LOG" "$a0" "$msg_b" "$MSG_TIMEOUT_SEC"; then
      ok_b=1
      break
    fi
    log_summary "WARN cycle=$cycle reason=A_missing_msg_b attempt=$attempt/$SEND_RETRIES"
    send_a "connect $PEER_B_ID"
    send_b "connect $PEER_A_ID"
  done

  if [[ "$ok_a" != "1" ]]; then
    log_summary "FAIL cycle=$cycle reason=B_missing_msg_a"
    return 1
  fi
  if [[ "$ok_b" != "1" ]]; then
    log_summary "FAIL cycle=$cycle reason=A_missing_msg_b"
    return 1
  fi

  return 0
}

restart_b_graceful() {
  log_summary "ACTION restart_b_graceful"
  send_b "quit"
  sleep 0.2
  kill "$B_PID" 2>/dev/null || true
  wait "$B_PID" 2>/dev/null || true
  start_peer_b
}

restart_b_term() {
  log_summary "ACTION restart_b_term"
  kill -TERM "$B_PID" 2>/dev/null || true
  sleep 0.2
  wait "$B_PID" 2>/dev/null || true
  start_peer_b
}

restart_b_kill() {
  log_summary "ACTION restart_b_kill"
  kill -KILL "$B_PID" 2>/dev/null || true
  sleep 0.2
  wait "$B_PID" 2>/dev/null || true
  start_peer_b
}

restart_a_graceful() {
  log_summary "ACTION restart_a_graceful"
  send_a "quit"
  sleep 0.2
  kill "$A_PID" 2>/dev/null || true
  wait "$A_PID" 2>/dev/null || true
  start_peer_a
}

restart_a_kill() {
  log_summary "ACTION restart_a_kill"
  kill -KILL "$A_PID" 2>/dev/null || true
  sleep 0.2
  wait "$A_PID" 2>/dev/null || true
  start_peer_a
}

# Start a duplicate instance with the same ID on a different port *without* stopping the original.
# This is intentionally "bad" and often reveals state confusion around (peer_id -> network_id).
duplicate_b_then_kill_one() {
  local dup_port=$((PEER_B_PORT + 1000 + (RANDOM % 200)))
  log_summary "ACTION duplicate_b_then_kill_one dup_port=$dup_port"

  local dup_log="$RUN_DIR/peer_b_dup_${dup_port}.log"

  # IMPORTANT:
  # - Run the duplicate as a daemon so it doesn't depend on stdin (we don't control it).
  # - Do NOT replace the main B instance, because our harness talks to B via $B_FIFO.
  "$BIN" --daemon --no-tui --log-level none --config "$CONFIG" --id "$PEER_B_ID" --port "$dup_port" >>"$dup_log" 2>&1 &
  local dup_pid=$!

  # Let it announce itself.
  sleep 1

  if (( RANDOM % 2 == 0 )); then
    # Kill the original without disconnecting, restart it with the same ID+port, and then kill the duplicate.
    log_summary "ACTION duplicate_b_then_kill_one killing=original pid=$B_PID"
    kill -KILL "$B_PID" 2>/dev/null || true
    wait "$B_PID" 2>/dev/null || true
    start_peer_b

    sleep 1
    log_summary "ACTION duplicate_b_then_kill_one killing=duplicate pid=$dup_pid"
    kill -KILL "$dup_pid" 2>/dev/null || true
    wait "$dup_pid" 2>/dev/null || true
  else
    # Kill the duplicate only.
    log_summary "ACTION duplicate_b_then_kill_one killing=duplicate pid=$dup_pid"
    kill -KILL "$dup_pid" 2>/dev/null || true
    wait "$dup_pid" 2>/dev/null || true
  fi
}

echo "RUN_DIR=$RUN_DIR"

# Avoid flooding the terminal with bash job termination notices when we SIGKILL
# peers on purpose. Keep them in the run artifacts instead.
HARNESS_STDERR="$RUN_DIR/harness.stderr"
exec 2>>"$HARNESS_STDERR"

log_summary "RUN_DIR=$RUN_DIR"
log_summary "BIN=$BIN"
log_summary "CONFIG=$CONFIG"
log_summary "A=$PEER_A_ID:$PEER_A_PORT"
log_summary "B=$PEER_B_ID:$PEER_B_PORT"
log_summary "cycles=$CYCLES msg_timeout=$MSG_TIMEOUT_SEC discovery_timeout=$DISCOVERY_TIMEOUT_SEC"

start_peer_a
start_peer_b

# Give discovery/signaling a moment.
sleep 2

for ((i=1; i<=CYCLES; i++)); do
  log_summary "--- cycle $i ---"

  log_progress "$i"

  if ! assert_connected_and_messaging "$i"; then
    log_summary "STOPPING early at cycle=$i (see logs)"
    echo "FAIL (run: $RUN_DIR). See $SUMMARY" >&2
    exit 2
  fi

  # Randomly choose a churn pattern.
  # If ENABLE_DUPLICATE_ID=0, avoid the duplicate-id scenario (it intentionally violates invariants).
  mod=7
  if [[ "${ENABLE_DUPLICATE_ID}" != "1" ]]; then
    mod=6
  fi

  case $((RANDOM % mod)) in
    0) restart_b_graceful ;;
    1) restart_b_term ;;
    2) restart_b_kill ;;
    3) restart_a_graceful ;;
    4) restart_a_kill ;;
    5)
      if [[ "${ENABLE_DUPLICATE_ID}" == "1" ]]; then
        duplicate_b_then_kill_one
      else
        log_summary "ACTION noop (no restart)"
      fi
      ;;
    6) log_summary "ACTION noop (no restart)" ;;
  esac

  sleep "$SLEEP_BETWEEN_SEC"
done

log_summary "DONE. Logs in: $RUN_DIR"
echo "DONE. Logs in: $RUN_DIR"

# If we somehow completed without early-exiting, still fail the process if summary includes FAIL.
if grep -q "^FAIL " "$SUMMARY"; then
  echo "FAIL (run: $RUN_DIR). See $SUMMARY" >&2
  exit 2
fi
