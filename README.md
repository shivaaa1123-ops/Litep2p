# LiteP2P

**A Production-Ready, High-Performance Peer-to-Peer Networking Engine**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C++-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

LiteP2P is a lightweight, modular, and highly optimized peer-to-peer networking engine designed for production deployment. It provides reliable connectivity across NATs, secure encrypted communication, efficient resource usage, and robust error recovery mechanisms.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Production Readiness](#production-readiness)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

LiteP2P is built with a **modular architecture** consisting of:

- **Core P2P Layers** (5 layers): Foundation, Infrastructure (Crypto + Reactor), and Core Services (Transport + Security)
- **Plugin System**: Optional modules for discovery, routing, optimization, file transfer, and more
- **Cross-Platform Support**: Android (via JNI), Linux, and macOS
- **Production Tested**: Verified across 5 global VPS nodes with comprehensive stress testing

### Key Design Principles

1. **Modularity**: Core layers are independent; plugins are optional
2. **Performance**: Event-driven architecture, zero-copy where possible, efficient memory management
3. **Reliability**: Robust error recovery, adaptive reconnection policies, watchdog mechanisms
4. **Security**: End-to-end encryption via Noise Protocol, secure key management
5. **Battery Efficiency**: Aggressive optimization for mobile devices
6. **Production Ready**: Comprehensive testing, telemetry, and monitoring

---

## Architecture

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            APPLICATION LAYER                                 │
│                      (Android App / Desktop CLI / Your App)                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PLUGIN LAYER (Optional)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Session    │  │  Discovery   │  │   Routing    │  │ Optimization │   │
│  │  Management  │  │   (LAN/WAN)  │  │ (NAT/TURN)   │  │  (Battery)   │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                      │
│  │File Transfer │  │    Proxy     │  │     JNI      │                      │
│  │   Manager    │  │   (Relay)    │  │  (Android)   │                      │
│  └──────────────┘  └──────────────┘  └──────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CORE P2P LAYERS (Required)                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Layer 3: Core Services                             │  │
│  │  ┌──────────────────┐           ┌──────────────────┐                │  │
│  │  │    Transport     │           │    Security      │                │  │
│  │  │  (UDP/TCP/QUIC)  │           │  (Noise Protocol)│                │  │
│  │  │  - Connection    │           │  - Handshake     │                │  │
│  │  │  - Multi-socket  │           │  - Encryption    │                │  │
│  │  │  - Batch mgmt    │           │  - Key Store     │                │  │
│  │  └──────────────────┘           └──────────────────┘                │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                        │                                     │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Layer 2: Infrastructure                            │  │
│  │  ┌──────────────────┐           ┌──────────────────┐                │  │
│  │  │    Crypto        │           │     Reactor      │                │  │
│  │  │  - AES           │           │  - Event Loop    │                │  │
│  │  │  - Noise Keys    │           │  - Thread Pool   │                │  │
│  │  │  - Key Store     │           │  - Timers        │                │  │
│  │  └──────────────────┘           └──────────────────┘                │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                        │                                     │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Layer 1: Foundation                                │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │  │
│  │  │  Config Manager  │  │     Logger       │  │   Telemetry      │  │  │
│  │  │  - JSON Config   │  │  - Async Logging │  │  - Metrics       │  │  │
│  │  │  - Dynamic Config│  │  - File/Console  │  │  - Counters      │  │  │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SYSTEM LAYER                                       │
│                    (OS Sockets, Threads, File System)                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Detailed Component Architecture

```
                    ┌─────────────────────────────────────┐
                    │      SessionManager (Orchestrator)  │
                    │  - Peer Lifecycle Management        │
                    │  - Event Processing                 │
                    │  - State Machine Coordination       │
                    └──────────────┬──────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│ PeerLifecycle │         │ MessageHandler│         │ Maintenance   │
│   Manager     │         │               │         │   Manager     │
│ - Discovery   │         │ - Inbound Msg │         │ - Watchdogs   │
│ - Connect     │         │ - Routing     │         │ - Timeouts    │
│ - FSM Events  │         │ - Security    │         │ - Cleanup     │
└───────────────┘         └───────────────┘         └───────────────┘
        │                          │                          │
        └──────────────────────────┼──────────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────┐         ┌───────────────┐         ┌───────────────┐
│  EventManager │         │  NATTraversal │         │ PeerState     │
│  - Queue      │         │  - STUN       │         │   Machine     │
│  - Threads    │         │  - Hole Punch │         │  - States     │
│  - Timers     │         │  - TURN       │         │  - Transitions│
└───────────────┘         └───────────────┘         └───────────────┘
```

### Data Flow Architecture

```
┌─────────────┐
│   Peer A    │
└──────┬──────┘
       │
       │ 1. Discovery (Broadcast / Signaling)
       ▼
┌─────────────────────────────────────┐
│   Signaling Server (WebSocket)      │  ◄─── Peer Registry
│   - Peer Registration               │
│   - Peer List Distribution          │
│   - Connection Coordination         │
└─────────────────────────────────────┘
       │
       │ 2. Peer List
       ▼
┌─────────────┐
│   Peer B    │
└──────┬──────┘
       │
       │ 3. NAT Traversal
       │    - STUN (NAT Detection)
       │    - Hole Punching
       │    - TURN (Fallback)
       ▼
┌─────────────────────────────────────┐
│   Direct UDP Connection Established │
└──────┬──────────────────────────────┘
       │
       │ 4. Security Handshake
       │    - Noise Protocol NK
       │    - Key Exchange
       │    - Session Establishment
       ▼
┌─────────────────────────────────────┐
│   Encrypted Session (READY)         │
│   - Application Messages            │
│   - File Transfers                  │
│   - Heartbeats                      │
└─────────────────────────────────────┘
```

---

## Features

### 1. Peer Discovery

**Description:** Multi-strategy peer discovery system supporting both local network (LAN) and wide-area network (WAN) discovery.

**Implementation:**
- **LAN Discovery**: UDP broadcast-based discovery on local network
- **WAN Discovery**: WebSocket signaling server for global peer discovery
- **Hybrid Mode**: Combines both strategies for optimal coverage

**Reliability:**
- ✅ Automatic retry on discovery failures
- ✅ Deduplication of discovered peers
- ✅ LRU cache for peer information (configurable size: default 100 peers)
- ✅ Network change detection triggers discovery refresh
- ✅ Verified peer timeout (default: 300 seconds)

**Optimization:**
- Broadcast interval configurable (default: 5 seconds)
- Efficient packet format (max 1024 bytes)
- Network interface selection for optimal routing
- TTL-based filtering to prevent broadcast storms

**Configuration:**
```json
{
  "discovery": {
    "message_prefix": "LITEP2P_DISCOVERY",
    "max_message_size": 1024,
    "broadcast_interval_sec": 5
  },
  "global_discovery": {
    "enabled": true,
    "discovery_strategy": "broadcast",
    "local_network_scan": true,
    "announce_self": true,
    "announce_interval_ms": 30000
  }
}
```

---

### 2. NAT Traversal

**Description:** Comprehensive NAT traversal system supporting STUN, UDP hole punching, UPnP, and TURN relay.

**Implementation:**
- **STUN Detection**: RFC 5389/5780 compliant NAT type detection
- **Hole Punching**: Multi-threaded hole punching with configurable retries
- **UPnP Support**: Automatic port mapping with lease management
- **TURN Relay**: Fallback relay server for symmetric NATs

**Reliability:**
- ✅ Exponential backoff for hole punching retries (configurable: default 10 attempts)
- ✅ Thread pool for concurrent hole punching (default: 10 threads)
- ✅ Heartbeat mechanism to maintain NAT bindings (default: 15 seconds)
- ✅ Automatic cleanup of stale mappings (default: 60 seconds)
- ✅ TURN fallback automatically triggered for symmetric NATs
- ✅ Multi-STUN server support for redundancy

**Optimization:**
- On-demand hole punching (only when needed)
- Parallel hole punching for multiple peers
- NAT type caching to avoid repeated STUN queries
- Connection pooling for TURN relay

**NAT Types Supported:**
- Open (no NAT)
- Full Cone NAT
- Restricted Cone NAT
- Port-Restricted Cone NAT
- Symmetric NAT (requires TURN)

**Configuration:**
```json
{
  "nat_traversal": {
    "enabled": true,
    "mode": "auto",
    "stun_enabled": true,
    "stun_servers": [
      {"hostname": "stun.l.google.com", "port": 19302},
      {"hostname": "stun1.l.google.com", "port": 19302}
    ],
    "hole_punching_enabled": true,
    "hole_punch_max_attempts": 10,
    "hole_punch_retry_backoff_ms": 100,
    "hole_punch_thread_pool_size": 10,
    "heartbeat_interval_sec": 15,
    "turn_enabled": true,
    "turn_config": {
      "server_ip": "your-turn-server",
      "server_port": 3478,
      "username": "litep2p",
      "password": "your-password"
    }
  }
}
```

---

### 3. Security (Noise Protocol)

**Description:** End-to-end encryption using Noise Protocol Framework (NK pattern) for secure peer communication.

**Implementation:**
- **Noise NK Pattern**: One-way authenticated handshake
- **Key Management**: Persistent key store with rotation support
- **Session Management**: Secure session establishment and management
- **Forward Secrecy**: Ephemeral keys for each session

**Reliability:**
- ✅ Automatic key rotation (configurable: default 24 hours)
- ✅ Session resumption for faster reconnection
- ✅ Handshake retry mechanism (max 3 retries)
- ✅ Stale session detection and cleanup
- ✅ Key validation on handshake
- ✅ Secure key storage (file-based with permissions)

**Optimization:**
- Zero-copy encryption where possible
- Session caching to avoid repeated handshakes
- Selective encryption mode (WiFi vs Cellular)
- Batch encryption for multiple messages

**Security Features:**
- Perfect Forward Secrecy (PFS)
- Authenticated encryption
- Replay protection
- Key derivation from static + ephemeral keys

**Configuration:**
```json
{
  "security": {
    "noise_nk_protocol": {
      "enabled": true,
      "mandatory": true,
      "key_store_path": "keystore",
      "key_rotation_interval_hours": 24
    },
    "selective_encryption_enabled": true
  }
}
```

---

### 4. Session Management

**Description:** Comprehensive peer session lifecycle management with state machine, event processing, and connection orchestration.

**Implementation:**
- **Peer State Machine**: Deterministic FSM for peer state transitions
- **Event Manager**: Thread-safe event queue with worker threads
- **Connection Orchestration**: Coordinates discovery, NAT traversal, and security
- **Message Routing**: Efficient message routing to peers

**Reliability:**
- ✅ Watchdog mechanisms for stuck connections (15s for CONNECTING, 20s for HANDSHAKING)
- ✅ Automatic state recovery on failures
- ✅ Deadlock prevention (mutex design patterns)
- ✅ Event queue overflow protection
- ✅ Graceful shutdown with cleanup
- ✅ Peer expiration timeout (default: 30 seconds)

**Optimization:**
- Event batching to reduce context switches
- Thread pool for event processing (configurable: default 4 workers)
- Lock-free data structures where possible
- Efficient peer lookup (O(1) hash map)

**Peer States:**
- `UNKNOWN`: Not yet discovered
- `DISCOVERED`: Discovered but not connected
- `CONNECTING`: Connection attempt in progress
- `CONNECTED`: Transport connected, security pending
- `HANDSHAKING`: Security handshake in progress
- `READY`: Fully connected and ready for messages
- `DEGRADED`: Temporarily unstable but usable
- `DISCONNECTED`: Gracefully disconnected
- `FAILED`: Terminal failure (retry exhausted)

**Configuration:**
```json
{
  "session_manager": {
    "num_workers": 4,
    "cache_size": 100,
    "cache_lifetime_sec": 3600,
    "session_timeout_ms": 30000,
    "max_concurrent_sessions": 100
  },
  "event_manager": {
    "queue_wait_timeout_ms": 100,
    "timer_tick_interval_ms": 500,
    "thread_sleep_ms": 100
  }
}
```

---

### 5. Reconnection Policy

**Description:** Adaptive reconnection policy with exponential backoff, circuit breaker pattern, and network-aware strategies.

**Implementation:**
- **Adaptive Backoff**: Exponential backoff with jitter
- **Circuit Breaker**: Prevents connection storms
- **Network Awareness**: Different policies for WiFi vs Cellular
- **Battery Awareness**: Aggressive mode for low battery

**Reliability:**
- ✅ Exponential backoff with configurable base delay
- ✅ Circuit breaker pattern (opens after N failures)
- ✅ Automatic recovery attempt after cooldown period
- ✅ Network type change detection triggers reconnection
- ✅ Battery level consideration (reduced activity on low battery)

**Optimization:**
- Aggressive mode for desktop/servers (faster reconnection)
- Conservative mode for mobile (battery savings)
- Jitter to prevent thundering herd
- Connection attempt throttling

**Modes:**
- **Aggressive**: Fast reconnection (desktop/servers)
- **Balanced**: Default mode (mobile/tablets)
- **Conservative**: Battery-first (low battery scenarios)

**Configuration:**
```json
{
  "reconnect_policy": {
    "mode": "balanced",
    "base_backoff_ms": 500,
    "max_backoff_ms": 30000,
    "circuit_breaker_threshold": 5,
    "circuit_breaker_cooldown_ms": 60000
  }
}
```

---

### 6. File Transfer

**Description:** Reliable file transfer system with chunking, resume capability, congestion control, and multi-path routing.

**Implementation:**
- **32KB Chunking**: Efficient transfer in 32KB chunks
- **Resume Support**: Checkpoint-based resume capability
- **CRC32 Validation**: Per-chunk integrity verification
- **Congestion Control**: Adaptive rate limiting
- **Multi-path Routing**: Optimal path selection (latency/throughput)

**Reliability:**
- ✅ Chunk-level retry mechanism
- ✅ Checkpoint persistence for resume
- ✅ CRC32 validation per chunk
- ✅ Atomic file finalization (temp file + rename)
- ✅ Transfer timeout handling
- ✅ Error recovery with retry

**Optimization:**
- Sliding window (default: 16 chunks in flight)
- Adaptive rate limiting (initial: 1 Mbps, min: 64 Kbps)
- Priority queuing (LOW, NORMAL, HIGH)
- Concurrent transfers (default: 100 max)
- Path selection based on latency/throughput/cost

**Features:**
- Resume from interruption
- Progress tracking (percentage, speed, ETA)
- Transfer prioritization
- Concurrent transfer management
- Multi-path aggregation

**Configuration:**
```json
{
  "file_transfer": {
    "chunk_size_bytes": 32768,
    "max_concurrent_transfers": 100,
    "max_chunks_in_flight": 16,
    "initial_rate_limit_kbps": 1024,
    "min_rate_limit_kbps": 64
  }
}
```

---

### 7. Battery Optimization

**Description:** Aggressive battery optimization for mobile devices with network-aware strategies and adaptive scaling.

**Implementation:**
- **Network-Aware Optimization**: Different strategies for WiFi vs Cellular
- **Message Batching**: Reduces radio wakeups
- **Adaptive Scaling**: CPU/network usage scaling based on conditions
- **Power Profiles**: AGGRESSIVE, BALANCED, PERFORMANCE modes

**Reliability:**
- ✅ Graceful degradation on low battery
- ✅ Network type change adaptation
- ✅ Battery level monitoring integration
- ✅ Prevents battery drain in background

**Optimization:**
- **WiFi Mode**: Aggressive sync (ping every 5s, minimal batching)
- **Cellular Mode**: Conservative sync (ping every 30s, aggressive batching)
- **Low Battery**: WiFi-only mode, reduced activity
- **Message Batching**: 50-200ms delay, up to 50 messages/batch
- **Buffer Pooling**: Reusable buffer allocations (default: 32 buffers)

**Profiles:**
- **AGGRESSIVE**: Max battery savings (ping 30s, batch 200ms, WiFi-only)
- **BALANCED**: Default (ping 10s, batch 50ms, all networks)
- **PERFORMANCE**: Min battery savings (ping 3s, batch 5ms, all networks)

**Configuration:**
```json
{
  "battery_optimizer": {
    "enabled": true,
    "aggressive_mode": false,
    "power_save_threshold": 20,
    "level_critical": 10,
    "level_low": 20,
    "level_medium": 80
  },
  "performance": {
    "buffer_pool_size": 16,
    "message_batcher_enabled": true
  }
}
```

---

### 8. Telemetry & Monitoring

**Description:** Built-in telemetry system for metrics collection, performance monitoring, and debugging.

**Implementation:**
- **Metrics Types**: Counters, Gauges, Histograms
- **Periodic Flushing**: Configurable flush interval
- **JSON Export**: Structured metrics export
- **Performance Tracking**: State transition durations, connection metrics

**Reliability:**
- ✅ Thread-safe metrics collection
- ✅ Periodic flush to prevent data loss
- ✅ Configurable flush intervals
- ✅ File-based persistence

**Optimization:**
- Low-overhead metric collection
- Batch metric updates
- Optional peer ID inclusion for debugging
- Configurable retention policies

**Metrics Collected:**
- Connection events (success, failure, suppressed)
- Handshake events (success, failure)
- Message counts (RX/TX, bytes, application messages)
- Peer state counts (connecting, handshaking, ready)
- Network changes
- State transition durations (histograms)

**Configuration:**
```json
{
  "monitoring": {
    "telemetry": {
      "enabled": true,
      "log_interval_sec": 30,
      "file_path": "/tmp/litep2p_telemetry.json",
      "include_peer_ids": false
    }
  }
}
```

---

### 9. Signaling Server Integration

**Description:** WebSocket-based signaling server for WAN peer discovery and connection coordination.

**Implementation:**
- **WebSocket Client**: Persistent connection to signaling server
- **Peer Registration**: Automatic peer registration with network ID
- **Peer List Distribution**: Receives peer list from server
- **Connection Coordination**: Exchanges connection requests between peers

**Reliability:**
- ✅ Automatic reconnection on disconnect
- ✅ Heartbeat mechanism (default: 30 seconds)
- ✅ Peer list bootstrap on startup
- ✅ Network ID update on change
- ✅ Connection retry with exponential backoff

**Optimization:**
- Persistent WebSocket connection (avoids connection overhead)
- Efficient message format (JSON)
- Throttled peer list requests
- Batch peer updates

**Configuration:**
```json
{
  "signaling": {
    "enabled": true,
    "url": "ws://your-signaling-server:8765",
    "reconnect_delay_ms": 2000,
    "heartbeat_interval_sec": 30
  }
}
```

---

### 10. Local Peer Database

**Description:** Optional SQLite-based persistent storage for peer information and connection history.

**Implementation:**
- **SQLite Storage**: Lightweight database for peer persistence
- **Peer Information**: Stores peer ID, network ID, last seen, connection history
- **Bootstrap Support**: Fast reconnection on startup using stored peers
- **Automatic Pruning**: Removes stale peers after configurable timeout

**Reliability:**
- ✅ Transaction-based writes (ACID)
- ✅ Automatic database initialization
- ✅ Stale peer cleanup (configurable: default 30 days)
- ✅ Connection history tracking

**Optimization:**
- Indexed queries for fast lookup
- Batch operations for efficiency
- Configurable database size limits
- Optional feature (can be disabled)

**Configuration:**
```json
{
  "storage": {
    "peer_db": {
      "enabled": true,
      "path": "litep2p_peers.sqlite",
      "reconnect_candidate_limit": 50,
      "prune_after_days": 30
    }
  }
}
```

---

## Installation

### Prerequisites

**Linux/macOS:**
- CMake 3.16 or higher
- C++17 compatible compiler (GCC 7+, Clang 5+)
- OpenSSL development libraries
- libsodium (for Noise Protocol)
- nlohmann/json (header-only, included via CMake)
- pkg-config

**Android:**
- Android NDK r21 or higher
- CMake 3.16+
- Gradle (for Android build)

### Build Instructions

#### Linux

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cmake \
  libssl-dev \
  libsodium-dev \
  nlohmann-json3-dev \
  pkg-config

# Clone repository
git clone https://github.com/shivaaa1123-ops/Litep2p.git
cd Litep2p

# Build (Desktop version)
cd desktop
mkdir -p build_linux && cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Binary will be at: desktop/build_linux/bin/litep2p_peer_linux
```

#### macOS

```bash
# Install dependencies (Homebrew)
brew install cmake openssl libsodium pkg-config

# Clone and build
git clone https://github.com/shivaaa1123-ops/Litep2p.git
cd Litep2p/desktop

# Build script
chmod +x build_mac.sh
./build_mac.sh

# Binary will be at: desktop/build_mac/bin/litep2p_peer_mac
```

#### Android

```bash
# Using Gradle (from project root)
./gradlew assembleDebug

# Or using CMake directly
cd app/src/main/cpp/modules
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

---

## Configuration

LiteP2P uses JSON-based configuration. See `config.example.json` for a complete example.

### Quick Start Configuration

```json
{
  "communication": {
    "default_protocol": "UDP",
    "udp": {
      "enabled": true,
      "port": 30001,
      "buffer_size": 65535
    }
  },
  "security": {
    "noise_nk_protocol": {
      "enabled": true,
      "mandatory": true,
      "key_store_path": "keystore"
    }
  },
  "signaling": {
    "enabled": true,
    "url": "ws://your-signaling-server:8765"
  },
  "nat_traversal": {
    "enabled": true,
    "stun_enabled": true,
    "hole_punching_enabled": true
  },
  "logging": {
    "level": "info",
    "console_output": true
  }
}
```

### Configuration File Location

- **Desktop**: `config.json` in current directory, or specified via `--config` flag
- **Android**: Assets folder or specified path in code
- **Production**: `/etc/litep2p/config.json` (recommended)

---

## Usage

### Desktop CLI

```bash
# Start peer on port 30001
./litep2p_peer_linux --port 30001 --id MY_PEER_ID

# With custom config
./litep2p_peer_linux --config /path/to/config.json --port 30001

# Daemon mode (no interactive CLI)
./litep2p_peer_linux --daemon --port 30001

# Log level control
./litep2p_peer_linux --log-level debug --port 30001
```

**Interactive Commands:**
```
peers                - List all discovered peers
send <peer_id> <msg> - Send message to peer
status <peer_id>     - Get detailed peer status
help                 - Show available commands
quit                 - Exit application
```

### Android Integration

```kotlin
// Initialize engine
val engine = LiteP2PEngine()

// Configure
val config = LiteP2PConfig.Builder()
    .setPort(30001)
    .setPeerId("android-peer-123")
    .setSignalingUrl("ws://your-server:8765")
    .enableNATTraversal(true)
    .enableNoiseProtocol(true)
    .build()

// Start engine
engine.start(config, object : PeerUpdateCallback {
    override fun onPeerUpdate(peers: List<Peer>) {
        // Handle peer list updates
    }
})

// Send message
engine.sendMessageToPeer(peerId, "Hello, P2P!")

// Receive messages
engine.setMessageReceivedCallback { peerId, message ->
    Log.d("LiteP2P", "Received from $peerId: $message")
}

// Stop engine
engine.stop()
```

### Programmatic API (C++)

```cpp
#include "p2p_node.h"

// Create node
P2PNode node;

// Start with callback
node.start(30001, [](const std::vector<Peer>& peers) {
    // Handle peer updates
}, "UDP", "my-peer-id");

// Send message
node.sendMessageToPeer("target-peer-id", "Hello, P2P!");

// Receive messages
node.setMessageReceivedCallback([](const std::string& peer_id, 
                                    const std::string& message) {
    std::cout << "Received: " << message << std::endl;
});

// Stop
node.stop();
```

---

## Production Readiness

LiteP2P has been extensively tested and verified for production deployment:

### Test Coverage

- ✅ **Cross-VPS Connectivity**: Tested across 5 global nodes (Australia, India, Europe, Singapore, USA)
- ✅ **Multi-Peer Mesh**: Verified 5-node mesh formation
- ✅ **Reconnection Resilience**: 3/3 churn cycles successful
- ✅ **Network Handoff**: Android LTE↔WiFi transitions tested
- ✅ **Stress Testing**: High-volume message passing, peer restarts, network chaos
- ✅ **Deadlock Prevention**: Critical bugs fixed and verified

### Production Checklist

- ✅ Cross-VPS WAN connectivity
- ✅ NAT traversal (STUN/Hole punching/TURN)
- ✅ End-to-end encryption (Noise Protocol)
- ✅ Reconnection resilience
- ✅ Network change handling
- ✅ Error recovery mechanisms
- ✅ Telemetry and monitoring
- ✅ Battery optimization
- ✅ Memory leak prevention
- ✅ Thread safety

See `PRODUCTION_READINESS_TEST.md` for comprehensive test results and procedures.

---

## Testing

### Unit Tests

```bash
cd desktop/build_linux
make session_manager_test
./bin/session_manager_test
```

### Integration Tests

```bash
# Cross-VPS connectivity test
cd tools/harness
bash stress_suite.sh

# Android handoff test
bash android_wifi_handoff_repro.sh

# Churn test
bash repro_peer_restart_churn.sh
```

### Test Scripts

- `tools/harness/stress_suite.sh`: Comprehensive stress test suite
- `tools/reconnect_mechanism_test.py`: Reconnection resilience test
- `tools/repro_peer_restart_churn.sh`: Peer restart churn test
- `tools/harness/android_wifi_handoff_repro.sh`: Network handoff test

---

## Performance Characteristics

### Latency

- **LAN**: < 10ms (direct connection)
- **WAN**: 50-200ms (depending on geography)
- **With TURN**: +20-50ms overhead

### Throughput

- **UDP**: Up to 100+ Mbps (limited by network)
- **File Transfer**: Up to 50+ Mbps (with congestion control)
- **Message Rate**: 1000+ messages/second (batched)

### Resource Usage

- **Memory**: ~10-50 MB (depending on peer count)
- **CPU**: < 5% idle, 10-20% active (single core)
- **Battery**: Optimized for mobile (aggressive mode: < 1% per hour idle)

---

## Troubleshooting

### Connection Issues

**Problem**: Peers not discovering each other
- **Solution**: Verify signaling server is reachable, check firewall rules, ensure discovery is enabled

**Problem**: NAT traversal failing
- **Solution**: Check STUN server connectivity, verify hole punching is enabled, consider TURN server for symmetric NATs

**Problem**: Handshake failures
- **Solution**: Verify Noise Protocol is enabled, check key store permissions, review handshake timeout settings

### Performance Issues

**Problem**: High CPU usage
- **Solution**: Reduce event thread pool workers, increase batching delay, disable debug logging

**Problem**: High memory usage
- **Solution**: Reduce peer cache size, limit concurrent sessions, enable peer database pruning

**Problem**: Battery drain
- **Solution**: Enable aggressive battery optimization, use WiFi-only mode, increase ping intervals

---

## Contributing

Contributions are welcome! Please see the contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Noise Protocol Framework for secure communication
- STUN protocol (RFC 5389/5780) for NAT traversal
- SQLite for peer persistence
- nlohmann/json for configuration parsing

---

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/shivaaa1123-ops/Litep2p/issues
- Documentation: See `PRODUCTION_READINESS_TEST.md` for detailed test procedures

---

**Version**: 1.0.0  
**Last Updated**: January 2026  
**Status**: Production Ready ✅

