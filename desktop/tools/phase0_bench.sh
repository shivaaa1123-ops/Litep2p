#!/usr/bin/env bash
# phase0_bench.sh — Network OS Phase 0 baseline benchmark harness.
# NOT production code. Measures idle cost + latency + startup on the desktop
# build and writes a JSON baseline under docs/network-os/.
#
# Usage: desktop/tools/phase0_bench.sh [OUT_JSON]
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
OUT="${1:-$REPO/docs/network-os/baseline-$(date +%Y-%m-%d).json}"

# Hermetic config: no signaling, no NAT, discovery off, fixed ports.
CFG="$REPO/desktop/tools/phase0_bench_config.json"
cat > "$CFG" <<'EOF'
{
  "network": { "default_server_port": 30001, "discovery_port": 30000, "listen_backlog": 5, "select_max_retries": 3 },
  "communication": {
    "default_protocol": "UDP",
    "udp": { "enabled": true, "port": 30001, "buffer_size": 65535, "timeout_ms": 5000, "select_timeout_sec": 1 },
    "tcp": { "enabled": false, "port": 30001, "nodelay": true, "buffer_size": 4096, "connect_timeout_sec": 5, "select_timeout_sec": 1 },
    "quic": { "enabled": false, "port": 30001, "buffer_size": 1048576 }
  },
  "peer_management": {
    "peer_timeout_sec": 30, "timer_tick_interval_sec": 10, "ping_interval_sec": 10,
    "heartbeat_interval_sec": 10, "peer_expiration_timeout_ms": 30000,
    "max_queued_messages": 100, "max_message_size": 10485760, "max_handshake_retries": 3
  },
  "discovery": { "message_prefix": "LITEP2P_DISCOVERY", "max_message_size": 1024, "broadcast_interval_sec": 2, "enabled": false },
  "security": {
    "noise_nk_protocol": { "enabled": true, "mandatory": true, "key_store_path": "keystore", "key_rotation_interval_hours": 24 },
    "selective_encryption_enabled": true
  },
  "nat_traversal": { "enabled": false, "mode": "off", "stun_enabled": false, "hole_punching_enabled": false, "turn_enabled": false },
  "signaling": { "enabled": false, "url": "ws://127.0.0.1:8765", "reconnect_interval_ms": 5000 },
  "logging": { "level": "warn", "format": "text", "console_output": false }
}
EOF

echo "== Phase 0 baseline benchmark =="
echo "repo: $REPO   out: $OUT"
OS_UNAME="$(uname -s)"
OS_ARCH="$(uname -m)"
tmpdir="$(mktemp -d /tmp/p0bench.XXXXXX)"

# ---------------------------------------------------------------------------
# 1. Startup time (daemon peer reaches running state)
# ---------------------------------------------------------------------------
startup_ms=""
if [ -x "$BIN/litep2p_peer_mac" ]; then
    start_s=$(date +%s.%N)
    "$BIN/litep2p_peer_mac" --no-tui --daemon --id bench-startup --config "$CFG" \
        > "$tmpdir/startup.log" 2>&1 &
    pid=$!
    ready=0
    for i in $(seq 1 60); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        if grep -q "engine started\|RUNNING" "$tmpdir/startup.log" 2>/dev/null; then ready=1; break; fi
        sleep 0.2
    done
    end_s=$(date +%s.%N)
    startup_ms=$(awk -v a="$start_s" -v b="$end_s" 'BEGIN{ printf "%.0f", (b-a)*1000 }')
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    echo "startup_ms=$startup_ms"
fi


# ---------------------------------------------------------------------------
# 2. Idle cost (daemon peer; RSS KB + thread count sampled over ~50s)
# ---------------------------------------------------------------------------
idle_cpu="0"; idle_rss_kb="0"; idle_threads="0"
if [ -x "$BIN/litep2p_peer_mac" ]; then
    "$BIN/litep2p_peer_mac" --no-tui --daemon --id bench-idle --config "$CFG" \
        > "$tmpdir/idle.log" 2>&1 &
    pid=$!
    sleep 3
    if kill -0 "$pid" 2>/dev/null; then
        rss_samples=""; thr_samples=""
        for i in $(seq 1 5); do
            if [[ "$OS_UNAME" == "Darwin" ]]; then
                rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
                thr=$(ps -M -p "$pid" 2>/dev/null | wc -l | tr -d ' ')
            else
                rss=$(awk '/VmRSS/{print $2}' /proc/$pid/status 2>/dev/null)
                thr=$(ps -L -p "$pid" 2>/dev/null | wc -l | tr -d ' ')
            fi
            [ -n "$rss" ] && rss_samples="$rss_samples $rss"
            [ -n "$thr" ] && thr_samples="$thr_samples $thr"
            sleep 10
        done
        # CPU: user+sys ticks over a 10s window (Linux only; macOS reports 0)
        if [[ "$OS_UNAME" != "Darwin" ]]; then
            t1=$(awk '{print $14+$15}' /proc/$pid/stat 2>/dev/null)
            sleep 10
            t2=$(awk '{print $14+$15}' /proc/$pid/stat 2>/dev/null)
            idle_cpu=$(awk -v a="$t1" -v b="$t2" 'BEGIN{ if (a>0) printf "%.2f", (b-a)/100.0*100.0; else print 0 }')
        fi
        idle_rss_kb=$(echo $rss_samples | tr ' ' '\n' | awk '{s+=$1;n++} END{ if (n>0) printf "%.0f", s/n; else print 0 }')
        idle_threads=$(echo $thr_samples | tr ' ' '\n' | awk '{s+=$1;n++} END{ if (n>0) printf "%.0f", s/n; else print 0 }')
    fi
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    echo "idle_cpu_pct=$idle_cpu rss_kb=$idle_rss_kb threads=$idle_threads"
fi

# ---------------------------------------------------------------------------
# 3. Latency (loopback, UDP + Noise): receiver + sender pair, p50/p95 for 1KB/8KB
# ---------------------------------------------------------------------------
lat_json="{\"result\":\"skipped\"}"
if [ -x "$BIN/message_latency_runner" ]; then
    RECV_ID="p0recv"; SEND_ID="p0send"
    RECV_PORT=32011; SEND_PORT=32012
    ROLE=receiver CONFIG_PATH="$CFG" SELF_ID="$RECV_ID" SELF_PORT=$RECV_PORT \
        "$BIN/message_latency_runner" > "$tmpdir/recv.log" 2>&1 &
    recv_pid=$!
    sleep 1
    ROLE=sender CONFIG_PATH="$CFG" SELF_ID="$SEND_ID" SELF_PORT=$SEND_PORT \
        TARGET_ID="$RECV_ID" TARGET_NETID="127.0.0.1:$RECV_PORT" \
        SIZES=1024,8192 ITERATIONS=20 OUT_JSON="$tmpdir/lat.json" \
        "$BIN/message_latency_runner" > "$tmpdir/send.log" 2>&1
    send_rc=$?
    wait "$recv_pid" 2>/dev/null
    if [ -f "$tmpdir/lat.json" ]; then
        lat_json="$(cat "$tmpdir/lat.json")"
    fi
    echo "latency rc=$send_rc: $lat_json"
fi

# ---------------------------------------------------------------------------
# 4. AAR sizes (with vs without QUIC) + lib sizes
# ---------------------------------------------------------------------------
aar_json="{}"
aar_root="$REPO/litep2p-core/build/outputs/aar"
if [ -d "$aar_root" ]; then
    aar_json="{"
    first=1
    for f in "$aar_root"/*.aar; do
        [ -e "$f" ] || continue
        sz=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null)
        [ -z "$sz" ] && continue
        [ "$first" -eq 0 ] && aar_json="$aar_json,"
        aar_json="$aar_json\"$(basename "$f")\":$sz"
        first=0
    done
    aar_json="$aar_json}"
fi

# ---------------------------------------------------------------------------
# 5. Emit JSON
# ---------------------------------------------------------------------------
{
    echo "{"
    echo "  \"date\": \"$(date +%Y-%m-%d)\","
    echo "  \"env\": { \"os\": \"$OS_UNAME\", \"arch\": \"$OS_ARCH\", \"branch\": \"$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null)\" },"
    echo "  \"startup_ms\": ${startup_ms:-null},"
    echo "  \"idle\": { \"cpu_pct\": $idle_cpu, \"rss_kb\": ${idle_rss_kb:-0}, \"threads\": ${idle_threads:-0} },"
    echo "  \"latency\": $lat_json,"
    echo "  \"aar_sizes_bytes\": $aar_json"
    echo "}"
} > "$OUT"

echo "Wrote $OUT"
rm -rf "$tmpdir"
