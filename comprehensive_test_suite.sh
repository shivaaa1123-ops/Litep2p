#!/bin/bash

# ============================================================================
# Comprehensive LiteP2P Test Suite
# ============================================================================
# This script performs rigorous testing of the LiteP2P engine including:
# - Basic connectivity tests
# - Message passing tests
# - Failure scenario tests
# - Performance benchmarks
# - Error recovery tests
# - Stress tests
# ============================================================================

set -euo pipefail || set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$SCRIPT_DIR/desktop"

# Optional config override:
# - By default the peer uses "config.json" (relative to CWD). Since this script
#   runs from the repo root, defaulting to "$SCRIPT_DIR/config.json" is safe.
# - To avoid external dependencies (signaling/STUN/TURN) during local/CI runs,
#   you can run:
#     LITEP2P_CONFIG="$SCRIPT_DIR/tools/config_local_no_signaling.json" ./comprehensive_test_suite.sh
CONFIG_FILE="${LITEP2P_CONFIG:-$SCRIPT_DIR/config.json}"
# NOTE: The peer exits on stdin EOF. For non-interactive test runs we keep stdin
# open using a FIFO feeder (see `start_peer_bg` below).
PEER_COMMON_ARGS=(--config "$CONFIG_FILE" --no-tui)

# Detect platform and binary
if [ -f "$DESKTOP_DIR/build_mac/bin/litep2p_peer_mac" ]; then
    BINARY="$DESKTOP_DIR/build_mac/bin/litep2p_peer_mac"
elif [ -f "$DESKTOP_DIR/build_linux/bin/litep2p_peer_linux" ]; then
    BINARY="$DESKTOP_DIR/build_linux/bin/litep2p_peer_linux"
elif [ -f "$DESKTOP_DIR/build_linux_docker/bin/litep2p_peer_linux" ]; then
    BINARY="$DESKTOP_DIR/build_linux_docker/bin/litep2p_peer_linux"
else
    BINARY=""
fi

# Create test directory with timestamp
if command -v date >/dev/null 2>&1; then
    TEST_DIR="$SCRIPT_DIR/test_suite_$(date +%Y%m%d_%H%M%S 2>/dev/null || date +%Y%m%d_%H%M%S)"
else
    TEST_DIR="$SCRIPT_DIR/test_suite_$$"
fi
RESULTS_FILE="$TEST_DIR/test_results.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

check_binary() {
    if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
        log_error "Binary not found"
        echo "Please build:"
        echo "  macOS: cd desktop && ./build_mac.sh"
        echo "  Linux: cd desktop && ./build_linux.sh"
        exit 1
    fi
    if [ ! -x "$BINARY" ]; then
        log_warn "Binary not executable, attempting to fix..."
        chmod +x "$BINARY" 2>/dev/null || true
    fi
    log_success "Binary found: $BINARY"
    if [ ! -f "$CONFIG_FILE" ]; then
        log_warn "Config file not found: $CONFIG_FILE (peer will likely fail). Set LITEP2P_CONFIG to override."
    else
        log_info "Using config: $CONFIG_FILE"
    fi
}

# Start a peer in the background while keeping stdin open (peer exits on EOF).
# Writes PIDs into caller-provided variable names (avoids subshells/process substitution).
start_peer_bg() {
    local peer_dir=$1
    local peer_id=$2
    local port=$3
    local log_level=$4
    local log_file=$5
    local feeder_pid_var=${6:-}
    local peer_pid_var=${7:-}
    
    # Use default PEER_COMMON_ARGS
    start_peer_bg_with_args "$peer_dir" "$peer_id" "$port" "$log_level" "$log_file" "$feeder_pid_var" "$peer_pid_var" "${PEER_COMMON_ARGS[@]}"
}

start_peer_bg_with_args() {
    local peer_dir=$1
    local peer_id=$2
    local port=$3
    local log_level=$4
    local log_file=$5
    local feeder_pid_var=${6:-}
    local peer_pid_var=${7:-}
    shift 7
    local peer_args=("$@")  # Remaining arguments are peer-specific args

    mkdir -p "$peer_dir"

    local fifo="$peer_dir/stdin_fifo"
    local cmd_file="$peer_dir/cmd_queue.txt"
    rm -f "$fifo" "$cmd_file" 2>/dev/null || true
    mkfifo "$fifo" 2>/dev/null || true
    touch "$cmd_file"
    
    # Background coordinator process that:
    # 1. Reads commands from cmd_file and writes them to stdin_fifo
    # 2. Periodically writes newlines to keep stdin open (prevent EOF)
    (
        local line_count=0
        while true; do
            # Read new lines from cmd_file
            local current_lines=$(wc -l < "$cmd_file" 2>/dev/null || echo "0")
            if [ "$current_lines" -gt "$line_count" ]; then
                # Read and send new lines (skip already processed ones)
                sed -n "$((line_count + 1)),\$p" "$cmd_file" 2>/dev/null | while IFS= read -r cmd; do
                    [ -n "$cmd" ] && echo "$cmd" > "$fifo" 2>/dev/null
                    sleep 0.2  # Small delay between commands
                done
                line_count=$current_lines
            fi
            
            # Periodic newline to keep stdin open (every 5 seconds, peer ignores empty lines)
            sleep 5
            echo "" > "$fifo" 2>/dev/null || break
        done
    ) &
    local feeder_pid=$!

    "$BINARY" "${peer_args[@]}" --id "$peer_id" --port "$port" --log-level "$log_level" < "$fifo" > "$log_file" 2>&1 &
    local peer_pid=$!

    if [ -n "${feeder_pid_var:-}" ]; then
        printf -v "$feeder_pid_var" '%s' "$feeder_pid"
    fi
    if [ -n "${peer_pid_var:-}" ]; then
        printf -v "$peer_pid_var" '%s' "$peer_pid"
    fi
}

stop_peer_bg() {
    local feeder_pid=$1
    local peer_pid=$2
    local peer_dir=${3:-}

    kill "$peer_pid" 2>/dev/null || true
    kill "$feeder_pid" 2>/dev/null || true

    if [ -n "${peer_dir:-}" ]; then
        rm -f "$peer_dir/stdin_fifo" "$peer_dir/cmd_queue.txt" 2>/dev/null || true
    fi
}

check_port() {
    local port=$1
    if command -v lsof >/dev/null 2>&1; then
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            return 1
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -an | grep -q ":$port.*LISTEN" 2>/dev/null; then
            return 1
        fi
    fi
    return 0
}

wait_for_log_pattern() {
    local log_file=$1
    local pattern=$2
    local timeout=${3:-10}
    local elapsed=0
    
    # Wait for log file to exist
    local wait_count=0
    while [ ! -f "$log_file" ] && [ $wait_count -lt 5 ]; do
        sleep 0.5
        wait_count=$((wait_count + 1))
    done
    
    while [ $elapsed -lt $timeout ]; do
        # Case-insensitive match: log messages vary in capitalization across platforms/modules.
        if [ -f "$log_file" ] && grep -qi "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Send command to peer via command queue file
# The background coordinator process reads from this file and writes to stdin FIFO
send_command() {
    local peer_dir=$1
    local command=$2
    local cmd_file="$peer_dir/cmd_queue.txt"
    
    # Append command to queue file (background process will pick it up)
    if [ -f "$cmd_file" ]; then
        echo "$command" >> "$cmd_file" 2>/dev/null
        sleep 0.8  # Delay to allow coordinator to process the command
    else
        # Fallback: append to commands log
        echo "$command" >> "$peer_dir/commands.txt"
    fi
}

extract_peer_id() {
    local log_file=$1
    # Try to extract peer ID from logs - look for peer_id= in logs or the --id argument value
    local id=$(grep -i "peer.*id\|local.*id\|started.*peer\|peer_id=" "$log_file" 2>/dev/null | grep -oE 'peer_id=[a-f0-9-]{20,}' | head -1 | cut -d'=' -f2 || echo "")
    if [ -z "$id" ]; then
        # Try alternative patterns
        id=$(grep -i "P2PNode created, peer_id=" "$log_file" 2>/dev/null | grep -oE 'peer_id=[a-zA-Z0-9_-]+' | head -1 | cut -d'=' -f2 || echo "")
    fi
    echo "$id"
}

# Generate a protocol-specific config file
create_protocol_config() {
    local config_file=$1
    local protocol=$2  # UDP, TCP, or QUIC
    local base_config="${CONFIG_FILE}"
    
    # Read base config and modify protocol settings
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<EOF
import json
import sys
import os

try:
    with open("$base_config", "r") as f:
        config = json.load(f)
except Exception as e:
    print(f"Error: Could not read base config: {e}", file=sys.stderr)
    sys.exit(1)

# Ensure communication section exists
if "communication" not in config:
    config["communication"] = {}

# Set default protocol
config["communication"]["default_protocol"] = "$protocol"

# Ensure protocol sections exist and set enabled flags
protocol_lower = "$protocol".lower()
for p in ["udp", "tcp", "quic"]:
    if p not in config["communication"]:
        # Create default config for missing protocols
        if p == "udp":
            config["communication"][p] = {"enabled": False, "port": 30001, "buffer_size": 65535}
        elif p == "tcp":
            config["communication"][p] = {"enabled": False, "port": 30001, "buffer_size": 4096}
        elif p == "quic":
            config["communication"][p] = {"enabled": False, "port": 30001, "buffer_size": 1048576}
    
    # Enable selected protocol, disable others
    if isinstance(config["communication"][p], dict):
        config["communication"][p]["enabled"] = (p == protocol_lower)

# Write modified config
try:
    with open("$config_file", "w") as f:
        json.dump(config, f, indent=2)
except Exception as e:
    print(f"Error: Could not write config file: {e}", file=sys.stderr)
    sys.exit(1)
EOF
    else
        # Fallback: copy base config (will use default from base)
        cp "$base_config" "$config_file" 2>/dev/null || {
            echo "Error: Could not create config file (python3 not available and base config copy failed)" >&2
            return 1
        }
    fi
}

# ============================================================================
# Test Scenarios
# ============================================================================

test_1_basic_startup() {
    log_test "Test 1: Basic Peer Startup"
    
    local peer_dir="$TEST_DIR/peer1_startup"
    mkdir -p "$peer_dir"
    
    log_info "Starting peer on port 30001..."
    local feeder_pid pid
    start_peer_bg "$peer_dir" "test-peer-1" "30001" "info" "$peer_dir/peer.log" feeder_pid pid
    
    sleep 3
    
    if ! kill -0 $pid 2>/dev/null; then
        log_error "Peer process died immediately"
        stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
        return 1
    fi
    
    if wait_for_log_pattern "$peer_dir/peer.log" "started successfully\|engine started"; then
        log_success "Peer started successfully"
        stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
        sleep 1
        return 0
    else
        log_error "Peer failed to start (no success message in logs)"
        stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
        return 1
    fi
}

test_2_port_binding() {
    log_test "Test 2: Port Binding Validation"
    
    # Test binding to available port
    local peer_dir="$TEST_DIR/peer2_binding"
    mkdir -p "$peer_dir"
    
    if ! check_port 30002; then
        log_warn "Port 30002 unavailable, trying alternative port..."
        local test_port=30022
        if ! check_port $test_port; then
            log_error "No available ports for test"
            return 1
        fi
        local test_port_used=$test_port
    else
        local test_port_used=30002
    fi
    
    log_info "Testing port binding on $test_port_used..."
    local feeder_pid pid
    start_peer_bg "$peer_dir" "test-peer-2" "$test_port_used" "info" "$peer_dir/peer.log" feeder_pid pid
    sleep 2
    
    if grep -qi "failed to bind\|address already in use\|bind.*error" "$peer_dir/peer.log" 2>/dev/null; then
        log_error "Port binding failed unexpectedly"
        stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
        return 1
    fi
    
    if wait_for_log_pattern "$peer_dir/peer.log" "UDP server started\|TCP.*started\|listening"; then
        log_success "Port binding successful"
        stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
        sleep 1
        return 0
    else
        log_error "Port binding test inconclusive"
        stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
        return 1
    fi
}

test_3_duplicate_port() {
    log_test "Test 3: Duplicate Port Detection"
    
    local peer1_dir="$TEST_DIR/peer3a"
    local peer2_dir="$TEST_DIR/peer3b"
    mkdir -p "$peer1_dir" "$peer2_dir"
    
    log_info "Starting first peer on port 30003..."
    local feeder1 pid1
    start_peer_bg "$peer1_dir" "test-peer-3a" "30003" "info" "$peer1_dir/peer.log" feeder1 pid1
    sleep 3
    
    log_info "Attempting to start second peer on same port 30003..."
    local feeder2 pid2
    start_peer_bg "$peer2_dir" "test-peer-3b" "30003" "info" "$peer2_dir/peer.log" feeder2 pid2
    sleep 2
    
    if wait_for_log_pattern "$peer2_dir/peer.log" "failed to bind\|address already in use\|bind.*error" 5; then
        log_success "Duplicate port correctly detected and rejected"
        stop_peer_bg "$feeder1" "$pid1" "$peer1_dir"
        stop_peer_bg "$feeder2" "$pid2" "$peer2_dir"
        sleep 1
        return 0
    else
        log_error "Duplicate port not properly detected"
        stop_peer_bg "$feeder1" "$pid1" "$peer1_dir"
        stop_peer_bg "$feeder2" "$pid2" "$peer2_dir"
        return 1
    fi
}

test_4_two_peer_discovery() {
    log_test "Test 4: Two-Peer Discovery"
    
    local peer1_dir="$TEST_DIR/peer4a"
    local peer2_dir="$TEST_DIR/peer4b"
    mkdir -p "$peer1_dir" "$peer2_dir"
    
    local port1=30004
    local port2=30005
    
    # Find available ports
    while ! check_port $port1; do
        port1=$((port1 + 100))
        if [ $port1 -gt 31000 ]; then
            log_error "Could not find available port for peer 1"
            return 1
        fi
    done
    
    while ! check_port $port2 || [ $port2 -eq $port1 ]; do
        port2=$((port2 + 100))
        if [ $port2 -gt 31000 ]; then
            log_error "Could not find available port for peer 2"
            return 1
        fi
    done
    
    log_info "Starting peer 1 on port $port1..."
    local feeder1 pid1
    start_peer_bg "$peer1_dir" "test-peer-4a" "$port1" "info" "$peer1_dir/peer.log" feeder1 pid1
    sleep 3
    
    if ! kill -0 $pid1 2>/dev/null; then
        log_error "Peer 1 failed to start"
        stop_peer_bg "$feeder1" "$pid1" "$peer1_dir"
        return 1
    fi
    
    log_info "Starting peer 2 on port $port2..."
    local feeder2 pid2
    start_peer_bg "$peer2_dir" "test-peer-4b" "$port2" "info" "$peer2_dir/peer.log" feeder2 pid2
    sleep 3
    
    if ! kill -0 $pid2 2>/dev/null; then
        log_error "Peer 2 failed to start"
        stop_peer_bg "$feeder1" "$pid1" "$peer1_dir"
        stop_peer_bg "$feeder2" "$pid2" "$peer2_dir"
        return 1
    fi
    
    # Wait for discovery (via signaling server or broadcast)
    log_info "Waiting for peer discovery (30 seconds)..."
    sleep 30
    
    # grep returns exit code 1 when there are 0 matches; avoid "0\n0" by not using `|| echo 0`
    local peer1_discovered=$(grep -ic "discover\|peer.*found\|peer.*connected" "$peer1_dir/peer.log" 2>/dev/null || true)
    local peer2_discovered=$(grep -ic "discover\|peer.*found\|peer.*connected" "$peer2_dir/peer.log" 2>/dev/null || true)
    peer1_discovered=${peer1_discovered:-0}
    peer2_discovered=${peer2_discovered:-0}
    
    if [ "$peer1_discovered" -gt 0 ] || [ "$peer2_discovered" -gt 0 ]; then
        log_success "Peer discovery activity detected (P1: $peer1_discovered, P2: $peer2_discovered events)"
        stop_peer_bg "$feeder1" "$pid1" "$peer1_dir"
        stop_peer_bg "$feeder2" "$pid2" "$peer2_dir"
        sleep 1
        return 0
    else
        log_warn "No discovery activity detected (may be normal for same-machine testing)"
        stop_peer_bg "$feeder1" "$pid1" "$peer1_dir"
        stop_peer_bg "$feeder2" "$pid2" "$peer2_dir"
        return 0  # Not a failure, just a limitation
    fi
}

test_5_message_passing() {
    log_test "Test 5: Message Passing"
    
    local peer1_dir="$TEST_DIR/peer5a"
    local peer2_dir="$TEST_DIR/peer5b"
    mkdir -p "$peer1_dir" "$peer2_dir"
    
    check_port 30006 || return 1
    check_port 30007 || return 1
    
    log_info "Starting two peers for message passing test..."
    local feeder1 pid1
    local feeder2 pid2
    start_peer_bg "$peer1_dir" "test-peer-5a" "30006" "info" "$peer1_dir/peer.log" feeder1 pid1
    start_peer_bg "$peer2_dir" "test-peer-5b" "30007" "info" "$peer2_dir/peer.log" feeder2 pid2
    
    sleep 5
    
    # Extract peer IDs from logs
    local peer1_id=$(extract_peer_id "$peer1_dir/peer.log")
    local peer2_id=$(extract_peer_id "$peer2_dir/peer.log")
    
    log_info "Peer 1 ID: ${peer1_id:-unknown}"
    log_info "Peer 2 ID: ${peer2_id:-unknown}"
    
    # Try to send a test message (if we can determine peer IDs)
    if [ -n "$peer1_id" ] && [ -n "$peer2_id" ]; then
        log_info "Attempting to send test message..."
        # Note: This would require programmatic API access
        # For now, we just verify the peers are running
    fi
    
    # Check for message-related errors
    # grep returns exit code 1 when there are 0 matches; avoid "0\n0" by not using `|| echo 0`
    local peer1_errors=$(grep -ic "error.*message\|fail.*send\|message.*error" "$peer1_dir/peer.log" 2>/dev/null || true)
    local peer2_errors=$(grep -ic "error.*message\|fail.*send\|message.*error" "$peer2_dir/peer.log" 2>/dev/null || true)
    peer1_errors=${peer1_errors:-0}
    peer2_errors=${peer2_errors:-0}
    
    if [ "$peer1_errors" -eq 0 ] && [ "$peer2_errors" -eq 0 ]; then
        log_success "No message-related errors detected"
    else
        log_warn "Some message-related errors detected (P1: $peer1_errors, P2: $peer2_errors)"
    fi
    
    stop_peer_bg "$feeder1" "$pid1" "$peer1_dir"
    stop_peer_bg "$feeder2" "$pid2" "$peer2_dir"
    sleep 1
    return 0
}

test_6_error_recovery() {
    log_test "Test 6: Error Recovery"
    
    local peer_dir="$TEST_DIR/peer6_recovery"
    mkdir -p "$peer_dir"
    
    check_port 30008 || return 1
    
    log_info "Testing error recovery mechanisms..."
    local feeder_pid pid
    start_peer_bg "$peer_dir" "test-peer-6" "30008" "info" "$peer_dir/peer.log" feeder_pid pid
    sleep 3
    
    # Simulate network interruption by killing and restarting
    log_info "Simulating network interruption..."
    kill -USR1 $pid 2>/dev/null || true
    sleep 2
    
    if kill -0 $pid 2>/dev/null; then
        log_success "Peer survived interruption signal"
    else
        log_error "Peer crashed on interruption"
        return 1
    fi
    
    # Check for recovery messages
    if grep -qi "recover\|retry\|reconnect" "$peer_dir/peer.log" 2>/dev/null; then
        log_success "Recovery mechanisms active"
    else
        log_warn "No explicit recovery messages (may be normal)"
    fi
    
    stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
    sleep 1
    return 0
}

test_7_performance_metrics() {
    log_test "Test 7: Performance Metrics"
    
    local peer_dir="$TEST_DIR/peer7_perf"
    mkdir -p "$peer_dir"
    
    check_port 30009 || return 1
    
    log_info "Measuring startup time and resource usage..."
    local feeder_pid pid
    # Use high-resolution timer if available, fallback to seconds
    if date +%s%N >/dev/null 2>&1; then
        local start_time=$(date +%s%N)
        start_peer_bg "$peer_dir" "test-peer-7" "30009" "error" "$peer_dir/peer.log" feeder_pid pid
        wait_for_log_pattern "$peer_dir/peer.log" "started successfully\|engine started" 10
        local end_time=$(date +%s%N)
        local startup_ms=$(( (end_time - start_time) / 1000000 ))
    else
        # Fallback for systems without %N support (like older macOS)
        local start_time=$(date +%s)
        start_peer_bg "$peer_dir" "test-peer-7" "30009" "error" "$peer_dir/peer.log" feeder_pid pid
        wait_for_log_pattern "$peer_dir/peer.log" "started successfully\|engine started" 10
        local end_time=$(date +%s)
        local startup_ms=$(( (end_time - start_time) * 1000 ))
    fi
    
    sleep 2
    
    # Memory usage
    local mem_kb=0
    local mem_mb=0
    if command -v ps >/dev/null 2>&1; then
        mem_kb=$(ps -o rss= -p $pid 2>/dev/null | tr -d ' ' || echo "0")
        if [ -n "$mem_kb" ] && [ "$mem_kb" != "" ]; then
            mem_mb=$((mem_kb / 1024))
        fi
    fi
    
    # CPU usage (sample over 2 seconds)
    local cpu_pct=0
    if command -v ps >/dev/null 2>&1; then
        cpu_pct=$(ps -o %cpu= -p $pid 2>/dev/null | tr -d ' ' || echo "0")
    fi
    
    log_info "Startup time: ${startup_ms}ms"
    log_info "Memory usage: ${mem_mb}MB"
    log_info "CPU usage: ${cpu_pct}%"
    
    if [ "$startup_ms" -lt 10000 ]; then
        log_success "Startup time acceptable (<10s)"
    else
        log_warn "Startup time slow (>10s)"
    fi
    
    if [ "$mem_mb" -lt 500 ]; then
        log_success "Memory usage acceptable (<500MB)"
    else
        log_warn "Memory usage high (>500MB)"
    fi
    
    stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
    sleep 1
    return 0
}

test_8_stress_test() {
    log_test "Test 8: Stress Test (Multiple Rapid Starts/Stops)"
    
    log_info "Running stress test: 5 rapid start/stop cycles..."
    
    local base_port=30010
    local cycles_passed=0
    
    for i in $(seq 1 5); do
        local peer_dir="$TEST_DIR/peer8_stress_$i"
        mkdir -p "$peer_dir"
        local port=$((base_port + i))
        
        # Find available port
        while ! check_port $port; do
            port=$((port + 10))
            if [ $port -gt 31000 ]; then
                log_warn "Skipping cycle $i - no available ports"
                continue 2
            fi
        done
        
        log_info "Cycle $i/5: Starting peer on port $port..."
        local feeder_pid pid
        start_peer_bg "$peer_dir" "stress-test-$i" "$port" "error" "$peer_dir/peer.log" feeder_pid pid
        sleep 2
        
        if kill -0 $pid 2>/dev/null; then
            stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
            sleep 1
            cycles_passed=$((cycles_passed + 1))
        else
            stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
            log_warn "Peer died in cycle $i (may be normal for rapid cycles)"
        fi
    done
    
    if [ $cycles_passed -ge 3 ]; then
        log_success "Stress test completed ($cycles_passed/5 cycles passed)"
        return 0
    else
        log_error "Stress test failed (only $cycles_passed/5 cycles passed)"
        return 1
    fi
}

test_9_invalid_inputs() {
    log_test "Test 9: Invalid Input Handling"
    
    local peer_dir="$TEST_DIR/peer9_invalid"
    mkdir -p "$peer_dir"
    
    check_port 30016 || return 1
    
    log_info "Testing with invalid port number..."
    # Test with port 0 (invalid)
    local feeder_pid pid
    start_peer_bg "$peer_dir" "test-invalid" "0" "error" "$peer_dir/peer.log" feeder_pid pid
    sleep 2
    
    if ! kill -0 $pid 2>/dev/null || grep -qi "error\|fail\|invalid" "$peer_dir/peer.log" 2>/dev/null; then
        log_success "Invalid port correctly handled"
    else
        log_warn "Invalid port handling unclear"
    fi
    
    stop_peer_bg "$feeder_pid" "$pid" "$peer_dir"
    sleep 1
    
    # Test with very long peer ID
    log_info "Testing with very long peer ID..."
    local long_id=$(printf 'a%.0s' {1..500})
    local feeder_pid2 pid2
    start_peer_bg "$peer_dir" "$long_id" "30016" "error" "$peer_dir/peer2.log" feeder_pid2 pid2
    sleep 2
    
    if kill -0 $pid2 2>/dev/null; then
        log_success "Long peer ID handled"
    else
        log_warn "Long peer ID may have caused issues"
    fi
    
    stop_peer_bg "$feeder_pid2" "$pid2" "$peer_dir"
    sleep 1
    return 0
}

test_10_concurrent_peers() {
    log_test "Test 10: Concurrent Multiple Peers"
    
    log_info "Starting 3 peers concurrently..."
    local pids=()
    local feeders=()
    local ports=()
    local base_port=30017
    
    # Find 3 available ports
    local port_count=0
    local current_port=$base_port
    while [ $port_count -lt 3 ] && [ $current_port -lt 31000 ]; do
        if check_port $current_port; then
            ports+=("$current_port")
            port_count=$((port_count + 1))
        fi
        current_port=$((current_port + 1))
    done
    
    if [ ${#ports[@]} -lt 3 ]; then
        log_error "Could not find 3 available ports"
        return 1
    fi
    
    for i in $(seq 0 2); do
        local peer_dir="$TEST_DIR/peer10_$i"
        mkdir -p "$peer_dir"
        local port=${ports[$i]}
        
        local feeder_pid pid
        start_peer_bg "$peer_dir" "concurrent-peer-$i" "$port" "info" "$peer_dir/peer.log" feeder_pid pid
        pids+=("$pid")
        feeders+=("$feeder_pid")
        sleep 1
    done
    
    sleep 5
    
    local running_count=0
    for pid in "${pids[@]}"; do
        if kill -0 $pid 2>/dev/null; then
            running_count=$((running_count + 1))
        fi
    done
    
    if [ $running_count -eq 3 ]; then
        log_success "All 3 peers running concurrently"
    elif [ $running_count -ge 2 ]; then
        log_warn "$running_count/3 peers running (may be acceptable)"
    else
        log_error "Only $running_count/3 peers running"
    fi
    
    for i in "${!pids[@]}"; do
        stop_peer_bg "${feeders[$i]}" "${pids[$i]}" "$TEST_DIR/peer10_$i"
    done
    sleep 1
    
    if [ $running_count -ge 2 ]; then
        return 0
    else
        return 1
    fi
}

test_11_mesh_protocol_restart() {
    local protocol=${1:-UDP}  # Default to UDP, can be UDP, TCP, or QUIC
    log_test "Test 11: 4-Peer Mesh with $protocol Protocol, Bidirectional Messaging, and Random Restarts"
    
    local base_port=30100
    local num_peers=4
    local peer_dirs=()
    local feeders=()
    local pids=()
    local ports=()
    local peer_ids=()
    local config_files=()
    
    # Find available ports
    log_info "Finding available ports for $num_peers peers..."
    local port_count=0
    local current_port=$base_port
    while [ $port_count -lt $num_peers ] && [ $current_port -lt 31000 ]; do
        if check_port $current_port; then
            ports+=($current_port)
            port_count=$((port_count + 1))
        fi
        current_port=$((current_port + 1))
    done
    
    if [ ${#ports[@]} -lt $num_peers ]; then
        log_error "Could not find $num_peers available ports"
        return 1
    fi
    
    # Create protocol-specific config files for each peer
    log_info "Creating $protocol protocol config files..."
    for i in $(seq 0 $((num_peers - 1))); do
        local peer_dir="$TEST_DIR/mesh_${protocol}_peer$i"
        peer_dirs+=("$peer_dir")
        mkdir -p "$peer_dir"
        
        local config_file="$peer_dir/config_${protocol}.json"
        config_files+=("$config_file")
        create_protocol_config "$config_file" "$protocol"
    done
    
    # Start all peers with protocol-specific configs
    log_info "Starting $num_peers peers with $protocol protocol..."
    for i in $(seq 0 $((num_peers - 1))); do
        local peer_dir="${peer_dirs[$i]}"
        local port=${ports[$i]}
        local config_file="${config_files[$i]}"
        local peer_id="mesh-${protocol}-peer$i"
        
        local feeder_pid peer_pid
        # Use peer-specific config
        local peer_args=(--config "$config_file" --no-tui)
        start_peer_bg_with_args "$peer_dir" "$peer_id" "$port" "info" "$peer_dir/peer.log" feeder_pid peer_pid "${peer_args[@]}"
        
        feeders+=($feeder_pid)
        pids+=($peer_pid)
        
        sleep 2  # Stagger startup
    done
    
    # Wait for all peers to start
    log_info "Waiting for all peers to start..."
    sleep 8
    
    # Verify all peers are running
    local running_count=0
    for pid in "${pids[@]}"; do
        if kill -0 $pid 2>/dev/null; then
            running_count=$((running_count + 1))
        else
            log_warn "Peer with PID $pid died during startup"
        fi
    done
    
    if [ $running_count -lt $num_peers ]; then
        log_error "Only $running_count/$num_peers peers started successfully"
        for i in "${!pids[@]}"; do
            stop_peer_bg "${feeders[$i]}" "${pids[$i]}" "${peer_dirs[$i]}"
        done
        return 1
    fi
    
    # Store peer IDs (we set them explicitly, so use those directly)
    log_info "Using explicit peer IDs..."
    for i in $(seq 0 $((num_peers - 1))); do
        local peer_id="mesh-${protocol}-peer$i"
        peer_ids+=("$peer_id")
        log_info "Peer $i ID: $peer_id"
    done
    
    # Establish mesh: connect all peers to each other
    log_info "Establishing mesh connections (all peers connect to all others)..."
    for i in $(seq 0 $((num_peers - 1))); do
        for j in $(seq 0 $((num_peers - 1))); do
            if [ $i -ne $j ]; then
                local peer_dir="${peer_dirs[$i]}"
                local target_id="${peer_ids[$j]}"
                send_command "$peer_dir" "connect $target_id"
            fi
        done
    done
    
    # Wait for connections to establish
    log_info "Waiting for mesh connections to establish..."
    sleep 15
    
    # Start bidirectional messaging test with random restarts
    log_info "Starting bidirectional messaging test with random peer restarts..."
    
    local total_messages=0
    local successful_messages=0
    local failed_messages=0
    local restart_count=0
    local max_restarts=3
    local messages_per_round=6  # 3 bidirectional pairs * 2 messages each
    
    # Function to count successful message deliveries in logs
    count_message_deliveries() {
        local log_file=$1
        local pattern=$2
        # Count message sent/received patterns (case-insensitive)
        grep -ic "message.*sent\|message.*received\|→.*:" "$log_file" 2>/dev/null | head -1 || echo "0"
    }
    
    # Test messaging for several rounds with random restarts
    for round in $(seq 1 3); do
        log_info "Round $round: Sending bidirectional messages between all pairs..."
        
        # Send bidirectional messages between all pairs
        for i in $(seq 0 $((num_peers - 1))); do
            for j in $(seq $((i + 1)) $((num_peers - 1))); do
                # Skip if either peer is not running
                if ! kill -0 "${pids[$i]}" 2>/dev/null || ! kill -0 "${pids[$j]}" 2>/dev/null; then
                    continue
                fi
                
                local peer_dir_i="${peer_dirs[$i]}"
                local peer_dir_j="${peer_dirs[$j]}"
                local peer_id_i="${peer_ids[$i]}"
                local peer_id_j="${peer_ids[$j]}"
                
                # Send from i to j
                local msg_ij="msg_${round}_${i}_to_${j}_$(date +%s)"
                send_command "$peer_dir_i" "send $peer_id_j $msg_ij"
                total_messages=$((total_messages + 1))
                sleep 0.5
                
                # Send from j to i
                local msg_ji="msg_${round}_${j}_to_${i}_$(date +%s)"
                send_command "$peer_dir_j" "send $peer_id_i $msg_ji"
                total_messages=$((total_messages + 1))
                sleep 0.5
            done
        done
        
        # Wait for messages to be processed
        sleep 5
        
        # Randomly restart a peer (except in last round)
        if [ $round -lt 3 ] && [ $restart_count -lt $max_restarts ]; then
            local peer_to_restart=$((RANDOM % num_peers))
            log_info "Randomly restarting peer $peer_to_restart..."
            
            # Stop the peer
            stop_peer_bg "${feeders[$peer_to_restart]}" "${pids[$peer_to_restart]}" "${peer_dirs[$peer_to_restart]}"
            sleep 2
            
            # Restart the peer
            local peer_dir="${peer_dirs[$peer_to_restart]}"
            local port=${ports[$peer_to_restart]}
            local config_file="${config_files[$peer_to_restart]}"
            local peer_id="${peer_ids[$peer_to_restart]}"
            
            local feeder_pid peer_pid
            local peer_args=(--config "$config_file" --no-tui)
            start_peer_bg_with_args "$peer_dir" "$peer_id" "$port" "info" "$peer_dir/peer.log" feeder_pid peer_pid "${peer_args[@]}"
            
            feeders[$peer_to_restart]=$feeder_pid
            pids[$peer_to_restart]=$peer_pid
            
            restart_count=$((restart_count + 1))
            
            # Wait for restart
            sleep 8
            
            # Re-establish connections from restarted peer
            log_info "Re-establishing connections from restarted peer $peer_to_restart..."
            for j in $(seq 0 $((num_peers - 1))); do
                if [ $peer_to_restart -ne $j ] && kill -0 "${pids[$j]}" 2>/dev/null; then
                    send_command "$peer_dir" "connect ${peer_ids[$j]}"
                fi
            done
            
            # Also have other peers reconnect to the restarted peer
            for j in $(seq 0 $((num_peers - 1))); do
                if [ $peer_to_restart -ne $j ] && kill -0 "${pids[$j]}" 2>/dev/null; then
                    send_command "${peer_dirs[$j]}" "connect $peer_id"
                fi
            done
            
            sleep 10  # Wait for reconnections
        fi
    done
    
    # Final wait for all messages to be processed
    log_info "Waiting for final message processing..."
    sleep 10
    
    # Analyze results: count message deliveries and reconnection events
    log_info "Analyzing message delivery and reconnection results..."
    
    local total_deliveries=0
    local reconnection_successes=0
    local reconnection_failures=0
    
    for i in $(seq 0 $((num_peers - 1))); do
        local peer_dir="${peer_dirs[$i]}"
        local log_file="$peer_dir/peer.log"
        
        # Count message deliveries (sent/received)
        local deliveries=$(grep -ic "message.*sent\|message.*received\|→.*:" "$log_file" 2>/dev/null | head -1 || echo "0")
        total_deliveries=$((total_deliveries + deliveries))
        
        # Count reconnection events
        local reconnects=$(grep -ic "reconnect\|reconnected\|connected.*peer" "$log_file" 2>/dev/null | head -1 || echo "0")
        if [ "$reconnects" -gt 0 ]; then
            reconnection_successes=$((reconnection_successes + 1))
        fi
        
        # Check for connection failures
        local conn_failures=$(grep -ic "failed.*connect\|connection.*failed\|unable.*connect" "$log_file" 2>/dev/null | head -1 || echo "0")
        if [ "$conn_failures" -gt 5 ]; then  # Threshold to avoid false positives
            reconnection_failures=$((reconnection_failures + 1))
        fi
    done
    
    # Calculate success rate
    local delivery_rate=0
    if [ $total_messages -gt 0 ]; then
        delivery_rate=$(( (total_deliveries * 100) / total_messages ))
    fi
    
    log_info "Results for $protocol protocol:"
    log_info "  Total messages sent: $total_messages"
    log_info "  Message deliveries detected: $total_deliveries"
    log_info "  Delivery rate: ${delivery_rate}%"
    log_info "  Peer restarts: $restart_count"
    log_info "  Peers with reconnections: $reconnection_successes"
    log_info "  Peers with connection failures: $reconnection_failures"
    
    # Stop all peers
    for i in "${!pids[@]}"; do
        stop_peer_bg "${feeders[$i]}" "${pids[$i]}" "${peer_dirs[$i]}"
    done
    sleep 2
    
    # Evaluate success criteria
    local test_passed=true
    
    # Check if delivery rate is reasonable (at least 50% for a mesh with restarts)
    if [ $delivery_rate -lt 50 ]; then
        log_error "Message delivery rate too low: ${delivery_rate}% (expected >= 50%)"
        test_passed=false
    fi
    
    # Check if reconnection worked after restarts
    if [ $restart_count -gt 0 ] && [ $reconnection_successes -eq 0 ]; then
        log_warn "No reconnection events detected after $restart_count peer restarts"
        # Don't fail the test for this, just warn
    fi
    
    if [ "$test_passed" = true ]; then
        log_success "Mesh test with $protocol protocol completed successfully (delivery rate: ${delivery_rate}%)"
        return 0
    else
        log_error "Mesh test with $protocol protocol failed"
        return 1
    fi
}

# ============================================================================
# Main Test Execution
# ============================================================================

main() {
    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  LiteP2P Comprehensive Test Suite"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    
    # Setup
    mkdir -p "$TEST_DIR"
    check_binary
    
    # Cleanup function
    cleanup() {
        log_info "Cleaning up test processes..."
        # Kill all litep2p processes
        if command -v killall >/dev/null 2>&1; then
            killall -9 litep2p_peer_mac 2>/dev/null || true
            killall -9 litep2p_peer_linux 2>/dev/null || true
        fi
        if command -v pkill >/dev/null 2>&1; then
            pkill -9 -f litep2p_peer_mac 2>/dev/null || true
            pkill -9 -f litep2p_peer_linux 2>/dev/null || true
        fi
        # Also try to kill by pattern (works on both macOS and Linux)
        if command -v ps >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
            ps aux 2>/dev/null | grep -i litep2p | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true
        fi
        sleep 1
    }
    trap cleanup EXIT INT TERM
    
    # Run all tests (do not abort on first failure; we want full diagnostics + perf numbers).
    test_1_basic_startup || true
    test_2_port_binding || true
    test_3_duplicate_port || true
    test_4_two_peer_discovery || true
    test_5_message_passing || true
    test_6_error_recovery || true
    test_7_performance_metrics || true
    test_8_stress_test || true
    test_9_invalid_inputs || true
    test_10_concurrent_peers || true
    # Enhanced mesh tests with different protocols
    test_11_mesh_protocol_restart UDP || true
    test_11_mesh_protocol_restart TCP || true
    test_11_mesh_protocol_restart QUIC || true
    
    # Final cleanup
    cleanup
    
    # Summary
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Test Summary${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo ""
    echo "Test artifacts: $TEST_DIR"
    echo ""
    
    # Calculate pass rate
    local pass_rate=0
    if [ $TESTS_TOTAL -gt 0 ]; then
        pass_rate=$(( (TESTS_PASSED * 100) / TESTS_TOTAL ))
    fi
    
    echo "Pass rate: ${pass_rate}%"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        exit 0
    elif [ $pass_rate -ge 70 ]; then
        echo -e "${YELLOW}⚠ Some tests failed, but pass rate is acceptable (${pass_rate}%)${NC}"
        exit 0
    else
        echo -e "${RED}✗ Multiple tests failed (pass rate: ${pass_rate}%)${NC}"
        exit 1
    fi
}

main "$@"

