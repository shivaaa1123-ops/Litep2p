#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="$ROOT_DIR/desktop/build_mac/bin"

if [[ ! -x "$BIN_DIR/proxy_netbench" ]]; then
  echo "ERROR: $BIN_DIR/proxy_netbench not found or not executable. Build desktop first." >&2
  exit 2
fi

PORT_A=31001
PORT_B=31002
PORT_C=31003

PEER_A=peer_a
PEER_B=peer_b
PEER_C=peer_c

LOG_DIR="$ROOT_DIR/desktop_sim_runs/proxy_chain_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

LOG_A="$LOG_DIR/a.log"
LOG_B="$LOG_DIR/b.log"
LOG_C="$LOG_DIR/c.log"

cleanup() {
  # Best-effort cleanup
  [[ -n "${PID_A:-}" ]] && kill "$PID_A" 2>/dev/null || true
  [[ -n "${PID_B:-}" ]] && kill "$PID_B" 2>/dev/null || true
  [[ -n "${PID_C:-}" ]] && kill "$PID_C" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_line() {
  local file="$1"
  local pattern="$2"
  local timeout_s="$3"

  local deadline=$(( $(date +%s) + timeout_s ))
  while (( $(date +%s) < deadline )); do
    if [[ -f "$file" ]] && grep -qE "$pattern" "$file"; then
      return 0
    fi
    sleep 0.1
  done

  echo "ERROR: Timed out waiting for '$pattern' in $file" >&2
  echo "--- tail $file ---" >&2
  tail -n 80 "$file" 2>/dev/null || true
  return 1
}

echo "Logs: $LOG_DIR"

# 1) Start final hop C (echo + logging)
"$BIN_DIR/proxy_netbench" \
  --mode final \
  --id "$PEER_C" \
  --port "$PORT_C" \
  --connect "$PEER_B" \
  --final-echo 1 \
  --log-level info \
  >"$LOG_C" 2>&1 &
PID_C=$!

# 2) Start gateway B (connect downstream to C)
"$BIN_DIR/proxy_netbench" \
  --mode gateway \
  --id "$PEER_B" \
  --port "$PORT_B" \
  --connect "$PEER_A" \
  --connect "$PEER_C" \
  --log-level info \
  >"$LOG_B" 2>&1 &
PID_B=$!

wait_for_line "$LOG_C" "^FINAL_READY" 20
wait_for_line "$LOG_B" "^GATEWAY_READY" 20

# Wait for the intended handshakes to complete (best-effort, but makes this much less flaky).
wait_for_line "$LOG_B" "^GATEWAY_CONNECTED id=${PEER_C} " 30
wait_for_line "$LOG_B" "^GATEWAY_CONNECTED id=${PEER_A} " 30
wait_for_line "$LOG_C" "^FINAL_CONNECTED id=${PEER_B} " 30

sleep 0.5

# 3) Run client A: connect to B, open proxied stream to C, and measure RTT
set +e
"$BIN_DIR/proxy_netbench" \
  --mode rtt \
  --id "$PEER_A" \
  --port "$PORT_A" \
  --gateway "$PEER_B" \
  --final "$PEER_C" \
  --count 20 \
  --interval-ms 50 \
  --timeout-ms 2000 \
  --log-level info \
  >"$LOG_A" 2>&1
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "ERROR: Peer A RTT run failed (exit=$RC). See logs." >&2
  exit 1
fi

# 4) Assertions
# Final hop must see messages coming FROM peer_b (gateway), not from peer_a.
if ! grep -qE "^FINAL_RX from=${PEER_B} " "$LOG_C"; then
  echo "ERROR: Final hop did not observe traffic from gateway (${PEER_B})." >&2
  echo "--- tail $LOG_C ---" >&2
  tail -n 120 "$LOG_C" >&2
  exit 1
fi

if grep -qE "^FINAL_RX from=${PEER_A} " "$LOG_C"; then
  echo "ERROR: Final hop observed traffic directly from client (${PEER_A}); expected it to be masked by gateway (${PEER_B})." >&2
  echo "--- tail $LOG_C ---" >&2
  tail -n 120 "$LOG_C" >&2
  exit 1
fi

echo "PASS: A -> C via B works, and C sees sender as B (proxy gateway)."
echo "- A log: $LOG_A"
echo "- B log: $LOG_B"
echo "- C log: $LOG_C"
