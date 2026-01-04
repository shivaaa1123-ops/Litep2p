#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# LiteP2P stress suite for self-hosted runners (VPS).
# - Builds desktop peer binary (linux)
# - Runs reconnect/restart harnesses against an isolated local signaling server
# - Optionally applies UDP packet loss via iptables (does NOT affect ssh/signaling TCP)
# - Produces a log bundle directory that GitHub Actions can upload as an artifact

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-/tmp/litep2p_stress_suite_$(date +%Y%m%d_%H%M%S)}"
SIGNALING_PORT="${SIGNALING_PORT:-8769}"
LOSS_PROB="${LOSS_PROB:-0.10}"          # 10% UDP drop
LOSS_DURATION_SEC="${LOSS_DURATION_SEC:-30}"
RECONNECT_CYCLES="${RECONNECT_CYCLES:-8}"
LOG_LEVEL="${LOG_LEVEL:-info}"

mkdir -p "${OUT_DIR}"

cleanup() {
  set +e
  # Remove iptables rules we add (best-effort).
  iptables -D INPUT  -p udp --dport 31001 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP 2>/dev/null || true
  iptables -D INPUT  -p udp --dport 31002 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP 2>/dev/null || true
  iptables -D OUTPUT -p udp --sport 31001 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP 2>/dev/null || true
  iptables -D OUTPUT -p udp --sport 31002 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP 2>/dev/null || true
  pkill -f "tools/signaling_server/[s]erver.py" 2>/dev/null || true
}
trap cleanup EXIT

echo "[suite] ROOT_DIR=${ROOT_DIR}"
echo "[suite] OUT_DIR=${OUT_DIR}"

echo "[suite] Ensuring python deps (websockets) ..."
python3 -m pip --version >/dev/null 2>&1 || apt-get update && apt-get install -y python3-pip >/dev/null
python3 -m pip install --quiet websockets >/dev/null

echo "[suite] Building desktop peer (linux) ..."
cd "${ROOT_DIR}/desktop"
mkdir -p build_linux_ci
cd build_linux_ci
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_PROXY_MODULE=OFF .. >/dev/null
cmake --build . --parallel 4 --target litep2p_peer_linux >/dev/null

PEER_BIN="${ROOT_DIR}/desktop/build_linux_ci/bin/litep2p_peer_linux"
echo "[suite] PEER_BIN=${PEER_BIN}"

echo "[suite] Starting isolated local signaling server on 127.0.0.1:${SIGNALING_PORT} ..."
cd "${ROOT_DIR}"
nohup env SIGNALING_HOST=127.0.0.1 SIGNALING_PORT="${SIGNALING_PORT}" LOG_LEVEL=INFO \
  python3 tools/signaling_server/server.py > "${OUT_DIR}/local_signaling.log" 2>&1 &
sleep 1

cat > "${OUT_DIR}/config_local_signaling.json" <<JSON
{
  "network": {"default_server_port": 30001, "discovery_port": 30000},
  "global_discovery": {"enabled": false},
  "nat_traversal": {"enabled": false, "stun_enabled": false, "hole_punching_enabled": false, "turn_enabled": false},
  "signaling": {"enabled": true, "url": "ws://127.0.0.1:${SIGNALING_PORT}", "reconnect_interval_ms": 200},
  "storage": {"peer_db": {"enabled": false}},
  "peer_management": {"peer_expiration_timeout_ms": 15000, "heartbeat_interval_sec": 1, "timer_tick_interval_sec": 1},
  "security": {"noise_nk_protocol": {"enabled": true, "mandatory": true, "key_store_path": "keystore"}},
  "logging": {"level": "debug", "console_output": true}
}
JSON

echo "[suite] Running reconnect_mechanism_test (cycles=${RECONNECT_CYCLES}) ..."
TS="$(date +%s)"
IDA="suiteA_${TS}"
IDB="suiteB_${TS}"
python3 tools/reconnect_mechanism_test.py \
  --binary "${PEER_BIN}" \
  --config "${OUT_DIR}/config_local_signaling.json" \
  --id-a "${IDA}" --id-b "${IDB}" \
  --cycles "${RECONNECT_CYCLES}" \
  --restart both \
  --kill kill \
  --timeout 80 \
  --restart-pause 0.8 \
  > "${OUT_DIR}/reconnect_mechanism_baseline.log" 2>&1

echo "[suite] Running restart_reconnect_test ..."
python3 tools/restart_reconnect_test.py \
  --binary "${PEER_BIN}" \
  --config "${OUT_DIR}/config_local_signaling.json" \
  --id-a "restartA_${TS}" --id-b "restartB_${TS}" \
  --port-a 31101 --port-b 31102 \
  --log-level "${LOG_LEVEL}" \
  --kill kill \
  --timeout 50 \
  > "${OUT_DIR}/restart_reconnect.log" 2>&1

echo "[suite] Running file_transfer_test (chunking/resume) ..."
cd "${ROOT_DIR}/desktop/build_linux_ci"
./bin/file_transfer_test > "${OUT_DIR}/file_transfer_test.log" 2>&1 || true

echo "[suite] Running message_size_runner (two-process loopback) ..."
WORK_A="${OUT_DIR}/msgsize_a"
WORK_B="${OUT_DIR}/msgsize_b"
mkdir -p "${WORK_A}" "${WORK_B}"

cat > "${WORK_A}/config.json" <<JSON
{
  "global_discovery": {"enabled": false},
  "nat_traversal": {"enabled": false, "stun_enabled": false, "hole_punching_enabled": false, "turn_enabled": false},
  "signaling": {"enabled": false, "url": "ws://127.0.0.1:1", "reconnect_interval_ms": 60000},
  "storage": {"peer_db": {"enabled": false}},
  "peer_management": {"peer_expiration_timeout_ms": 15000, "heartbeat_interval_sec": 1, "timer_tick_interval_sec": 1},
  "security": {"noise_nk_protocol": {"enabled": true, "mandatory": true, "key_store_path": "keystore"}},
  "logging": {"level": "error", "console_output": true}
}
JSON

cp "${WORK_A}/config.json" "${WORK_B}/config.json"

PORT_A=31201
PORT_B=31202
IDA="msgA_$(date +%s)"
IDB="msgB_$(date +%s)"

cd "${ROOT_DIR}/desktop/build_linux_ci"

(
  cd "${WORK_B}"
  CONFIG_PATH="${WORK_B}/config.json" ROLE=receiver SELF_ID="${IDB}" SELF_PORT="${PORT_B}" \
    TARGET_ID="${IDA}" TARGET_NETID="127.0.0.1:${PORT_A}" DEADLINE_SEC=120 \
    OUT_JSON="${OUT_DIR}/message_size_receiver.json" \
    "${ROOT_DIR}/desktop/build_linux_ci/bin/message_size_runner" > "${OUT_DIR}/message_size_receiver.log" 2>&1
) &
RX_PID=$!

sleep 1

(
  cd "${WORK_A}"
  CONFIG_PATH="${WORK_A}/config.json" ROLE=sender SELF_ID="${IDA}" SELF_PORT="${PORT_A}" \
    TARGET_ID="${IDB}" TARGET_NETID="127.0.0.1:${PORT_B}" \
    SIZES="64,128,256,512,1024,2048,4096,8192,16384,32768" DEADLINE_SEC=120 \
    OUT_JSON="${OUT_DIR}/message_size_sender.json" \
    "${ROOT_DIR}/desktop/build_linux_ci/bin/message_size_runner" > "${OUT_DIR}/message_size_sender.log" 2>&1
)
SENDER_CODE=$?

wait "${RX_PID}" || true
echo "[suite] message_size_runner sender exit=${SENDER_CODE}"

echo "[suite] Applying UDP packet loss via iptables (p=${LOSS_PROB}, duration=${LOSS_DURATION_SEC}s) ..."
iptables -A INPUT  -p udp --dport 31001 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP
iptables -A INPUT  -p udp --dport 31002 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP
iptables -A OUTPUT -p udp --sport 31001 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP
iptables -A OUTPUT -p udp --sport 31002 -m statistic --mode random --probability "${LOSS_PROB}" -j DROP

sleep "${LOSS_DURATION_SEC}"

echo "[suite] Running reconnect_mechanism_test under loss ..."
TS2="$(date +%s)"
IDA2="lossA_${TS2}"
IDB2="lossB_${TS2}"
python3 tools/reconnect_mechanism_test.py \
  --binary "${PEER_BIN}" \
  --config "${OUT_DIR}/config_local_signaling.json" \
  --id-a "${IDA2}" --id-b "${IDB2}" \
  --cycles 5 \
  --restart both \
  --kill kill \
  --timeout 120 \
  --restart-pause 0.8 \
  > "${OUT_DIR}/reconnect_mechanism_loss.log" 2>&1

echo "[suite] OK. Logs at: ${OUT_DIR}"
ls -la "${OUT_DIR}" >/dev/null


