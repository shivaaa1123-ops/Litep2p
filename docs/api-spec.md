# LiteP2P Public API Specification

**Version:** 0.3.0-draft
**Status:** Proposal — pending review
**Audience:** Engine maintainers, library integrators

---

## 1. Overview

LiteP2P is a lightweight, efficient, rigid, and reliable peer-to-peer networking
engine written in C++17. It handles the network layer — discovery, connectivity
(LAN direct, WAN hole-punch, relay), encrypted sessions (Noise NK), message
transport, file transfer, and NAT/network recovery — so that application layers
can be built on top of it without dealing with P2P complexity.

The engine is distributed as a **library**:

| Platform | Artifact |
|---|---|
| Android | AAR (`litep2p-core`) containing the native `.so` + Kotlin API |
| Linux/macOS | Static/shared library + C header (`liblitep2p`) |

The Android app in this repository is a **development/test harness** only. It is
not part of the library surface and must not leak into the library's public API.

### 1.1 Design goals

- **Stable ABI.** A single C header (`litep2p.h`) is the contract. C++ internals
  may change freely; the C ABI changes only with a major version bump.
- **Zero UI/framework dependencies in the core.** No Android framework types,
  no LiveData, no JNI types in the engine proper. JNI is a binding layer.
- **Callback-driven.** The engine pushes events (peers, messages, telemetry,
  logs, lifecycle) to registered listeners. Consumers choose their own threading.
- **Binary-safe messaging.** Messages are byte buffers with explicit lengths.
- **Observable.** Telemetry (counters, gauges, latency histograms, RAM/CPU,
  connection paths) is a first-class API, not a log-parsing side channel.
- **Small surface.** Fewer than 40 public functions. Everything else is internal.

### 1.2 Non-goals (v1)

- Application-layer protocols (chat, sync, etc.) — those belong to consumers.
- Multi-engine instances per process (single engine per process; handle-based
  API leaves the door open for multi-instance later).
- Public C++ API. C++ headers are internal; integrators use the C ABI or the
  Kotlin wrapper.

---

## 2. Target architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Consumer app / harness (:app)                              │
│  - Dev UI, testing tools, message tracing, ACK envelopes    │
└──────────────────────────┬──────────────────────────────────┘
                           │ depends on
┌──────────────────────────▼──────────────────────────────────┐
│  :litep2p-core (Android library module)                     │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Kotlin API: LiteP2PEngine, LiteP2PConfig, listeners   │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ JNI binding layer (jni_bridge.cpp)                    │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ C ABI: litep2p.h  ← THE PUBLIC CONTRACT               │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ C++ engine: SessionManager + modules                  │  │
│  │ (core, transport, crypto, discovery, session,         │  │
│  │  file_transfer, routing, proxy, optimization)         │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

The desktop build (`desktop/`) consumes the same C ABI instead of wrapping
`SessionManager` directly, so both platforms validate the same contract.

### 2.1 Module split (Gradle)

- `:litep2p-core` — `com.android.library`; owns `cpp/` (engine + JNI), publishes
  the Kotlin API. No AndroidX UI dependencies. Only `androidx.annotation`.
- `:app` — `com.android.application`; the dev harness. Depends on
  `:litep2p-core`. Owns all UI, `MessageTraceStore`, ACK-envelope logic,
  `TelemetryStore` rendering, and the Material 3 console.

---

## 3. C ABI — `litep2p.h`

### 3.1 Conventions

- All functions are `extern "C"`, prefixed `litep2p_`.
- Opaque handle: `litep2p_engine_t` (pointer to internal engine object).
- All fallible operations return `litep2p_result_t` (int32 error code) unless
  stated otherwise.
- Strings are UTF-8, NUL-terminated. Byte buffers carry explicit lengths.
- Memory returned by the engine is documented per-function (caller-owned vs.
  engine-owned with `litep2p_free`).
- The API is thread-safe unless documented otherwise.

### 3.2 Error codes

```c
typedef enum litep2p_result {
    LITEP2P_OK                  = 0,
    LITEP2P_ERR_INVALID_ARG     = -1,
    LITEP2P_ERR_INVALID_STATE   = -2,   // e.g. send before start
    LITEP2P_ERR_BUSY            = -3,   // start/stop already in progress
    LITEP2P_ERR_NOT_FOUND       = -4,   // unknown peer / transfer id
    LITEP2P_ERR_IO              = -5,
    LITEP2P_ERR_TIMEOUT         = -6,
    LITEP2P_ERR_UNSUPPORTED     = -7,   // feature compiled out
    LITEP2P_ERR_INTERNAL        = -99,
} litep2p_result_t;

const char* litep2p_result_string(litep2p_result_t result);
```

### 3.3 Versioning

```c
#define LITEP2P_VERSION_MAJOR 0
#define LITEP2P_VERSION_MINOR 3
#define LITEP2P_VERSION_PATCH 0

uint32_t litep2p_version(void);          // packed major<<16 | minor<<8 | patch
const char* litep2p_version_string(void); // "0.3.0"
```

ABI stability rules: additive changes bump MINOR; breaking changes bump MAJOR.
Structs passed across the ABI are always passed by pointer with a `struct_size`
field for forward compatibility.

### 3.4 Configuration

```c
typedef struct litep2p_config {
    uint32_t struct_size;        // = sizeof(litep2p_config); set by caller

    const char* peer_id;         // stable identity; NULL = engine generates one
    const char* comms_mode;      // "TCP" | "UDP" | "AUTO"
    int listen_port;             // 0 = engine default
    const char* files_dir;       // writable dir for config.json, keystore, peer DB
                                 // (Android: Context.getFilesDir().absolutePath)
    const char* config_path;     // optional explicit config.json path; NULL = auto-discover

    // Feature toggles (must match compile-time modules; runtime-disable where supported)
    int enable_encryption;       // Noise NK sessions (default 1)
    int enable_discovery;        // LAN discovery (default 1)
    int enable_file_transfer;    // (default 1)

    // Telemetry
    int telemetry_enabled;       // default 1
    int telemetry_interval_ms;   // default 30000

    // Threading
    int single_thread_mode;      // default 0 (multi-thread); 1 = reduced thread count
} litep2p_config_t;

void litep2p_config_init(litep2p_config_t* config); // fills defaults, sets struct_size
```

### 3.5 Lifecycle

```c
litep2p_result_t litep2p_engine_create(const litep2p_config_t* config,
                                       litep2p_engine_t* out_engine);
litep2p_result_t litep2p_engine_start(litep2p_engine_t engine);   // async; completion via event
litep2p_result_t litep2p_engine_stop(litep2p_engine_t engine);    // async; completion via event
litep2p_result_t litep2p_engine_destroy(litep2p_engine_t engine); // stops if running; frees handle

// Engine state: STOPPED | STARTING | RUNNING | STOPPING
typedef enum litep2p_state {
    LITEP2P_STATE_STOPPED  = 0,
    LITEP2P_STATE_STARTING = 1,
    LITEP2P_STATE_RUNNING  = 2,
    LITEP2P_STATE_STOPPING = 3,
} litep2p_state_t;

litep2p_state_t litep2p_engine_get_state(litep2p_engine_t engine);
litep2p_result_t litep2p_engine_get_peer_id(litep2p_engine_t engine,
                                            char* buf, uint32_t buf_len);
```

State transitions are guarded: `start` from STOPPED only, `stop` from RUNNING
only; otherwise `LITEP2P_ERR_BUSY` / `LITEP2P_ERR_INVALID_STATE` (mirrors the
existing lifecycle guard in `jni_bridge.cpp`).



### 3.6 Events and callbacks

All callbacks receive the `user_data` pointer supplied at registration and may
be invoked from engine threads. Consumers must not block; the engine does not
guarantee callback ordering across categories.

```c
typedef struct litep2p_peer_info {
    char peer_id[128];
    char ip[64];
    int port;
    int connected;               // 0/1
    char network_id[128];
    char connection_path[32];    // "LAN_DIRECT" | "WAN_HOLE_PUNCH" | "TURN_RELAY"
                                 // | "SIGNALING_RELAY" | "UNKNOWN"
    char fsm_state[32];          // best-effort peer FSM state string
} litep2p_peer_info_t;

typedef struct litep2p_callbacks {
    uint32_t struct_size;
    void* user_data;

    // Lifecycle
    void (*on_engine_started)(void* user_data);
    void (*on_engine_stopped)(void* user_data);

    // Peers — full snapshot each time (simplest correct model; matches current
    // onPeersUpdated(Array<PeerInfo>) contract)
    void (*on_peers_changed)(void* user_data,
                             const litep2p_peer_info_t* peers, uint32_t count);

    // Messaging — buffer valid only for the duration of the call
    void (*on_message_received)(void* user_data, const char* peer_id,
                                const uint8_t* data, uint32_t len);

    // Logging — level: 0=DEBUG 1=INFO 2=WARN 3=ERROR
    void (*on_log)(void* user_data, int level, const char* line);

    // Telemetry — single-line JSON snapshot (see §6)
    void (*on_telemetry)(void* user_data, const char* json);
} litep2p_callbacks_t;

litep2p_result_t litep2p_engine_set_callbacks(litep2p_engine_t engine,
                                              const litep2p_callbacks_t* callbacks);
```

### 3.7 Peer operations

```c
litep2p_result_t litep2p_connect(litep2p_engine_t engine, const char* peer_id);
litep2p_result_t litep2p_add_peer(litep2p_engine_t engine, const char* peer_id,
                                  const char* network_id);
litep2p_result_t litep2p_disconnect(litep2p_engine_t engine, const char* peer_id);

litep2p_result_t litep2p_peer_is_connected(litep2p_engine_t engine,
                                           const char* peer_id, int* out_connected);
litep2p_result_t litep2p_peer_get_connection_path(litep2p_engine_t engine,
                                                  const char* peer_id,
                                                  char* buf, uint32_t buf_len);
```

### 3.8 Messaging

```c
// Asynchronous send. Delivery semantics are engine-defined (best-effort over
// the active transport). Returns LITEP2P_OK when the message was accepted for
// sending, not when delivered.
litep2p_result_t litep2p_send(litep2p_engine_t engine, const char* peer_id,
                              const uint8_t* data, uint32_t len);
```

Application-level concerns (ACKs, envelopes, retries at the app layer) are
**out of scope** for the engine API. The engine guarantees ordered, encrypted,
binary-safe delivery over an established session; reliability features
(reconnect, path failover) are engine-internal.

### 3.9 Security (Noise NK)

```c
// Local static public key, hex-encoded. buf_len >= 65.
litep2p_result_t litep2p_get_local_public_key(litep2p_engine_t engine,
                                              char* buf, uint32_t buf_len);
litep2p_result_t litep2p_register_peer_key(litep2p_engine_t engine,
                                           const char* peer_id,
                                           const char* public_key_hex);
litep2p_result_t litep2p_has_peer_key(litep2p_engine_t engine,
                                      const char* peer_id, int* out_has_key);
```

### 3.10 File transfer (optional module)

```c
typedef struct litep2p_transfer_callbacks {
    uint32_t struct_size;
    void* user_data;
    void (*on_progress)(void* user_data, const char* transfer_id, float progress,
                        float bytes_per_sec);
    void (*on_completed)(void* user_data, const char* transfer_id, int success,
                         const char* error);
} litep2p_transfer_callbacks_t;

litep2p_result_t litep2p_send_file(litep2p_engine_t engine, const char* peer_id,
                                   const char* file_path, int priority,
                                   const litep2p_transfer_callbacks_t* callbacks,
                                   char* out_transfer_id, uint32_t buf_len);
litep2p_result_t litep2p_pause_transfer(litep2p_engine_t engine, const char* transfer_id);
litep2p_result_t litep2p_resume_transfer(litep2p_engine_t engine, const char* transfer_id);
litep2p_result_t litep2p_cancel_transfer(litep2p_engine_t engine, const char* transfer_id);
```

Returns `LITEP2P_ERR_UNSUPPORTED` when compiled without
`LITEP2P_ENABLE_FILE_TRANSFER`.

### 3.11 Proxy / relay (optional module)

```c
// role: "off" | "gateway" | "exit" | "client" | "both"
litep2p_result_t litep2p_set_proxy_role(litep2p_engine_t engine, const char* role);
```

### 3.12 Environment hints (mobile integration)

```c
litep2p_result_t litep2p_set_network_info(litep2p_engine_t engine,
                                          int is_wifi, int network_available);
litep2p_result_t litep2p_set_battery_level(litep2p_engine_t engine,
                                           int percent, int is_charging);
// mode: "auto" | "aggressive" | "balanced" | "power_saver"
litep2p_result_t litep2p_set_reconnect_mode(litep2p_engine_t engine, const char* mode);
```

### 3.13 Telemetry and diagnostics

```c
// Force an immediate snapshot; delivered via on_telemetry callback and/or
// returned as a malloc'd JSON string the caller must free with litep2p_free.
litep2p_result_t litep2p_telemetry_snapshot(litep2p_engine_t engine, char** out_json);
void litep2p_free(void* ptr);

// Logging level: 0=DEBUG 1=INFO 2=WARN 3=ERROR
litep2p_result_t litep2p_set_log_level(litep2p_engine_t engine, int level);

---

## 4. Kotlin API (Android)

The Kotlin wrapper lives in `:litep2p-core`, package `com.zeengal.litep2p.core`.
It is the recommended API for Android consumers; it wraps the C ABI via JNI and
adds type safety, listener registration, and lifecycle safety. No Android
framework types appear except `filesDir: String` supplied by the integrator.

```kotlin
public class LiteP2PConfig private constructor(...) {
    public class Builder {
        fun peerId(id: String?): Builder
        fun commsMode(mode: CommsMode): Builder          // TCP | UDP | AUTO
        fun listenPort(port: Int): Builder
        fun filesDir(path: String): Builder              // required on Android
        fun configPath(path: String?): Builder
        fun encryptionEnabled(enabled: Boolean): Builder
        fun discoveryEnabled(enabled: Boolean): Builder
        fun fileTransferEnabled(enabled: Boolean): Builder
        fun telemetryEnabled(enabled: Boolean): Builder
        fun telemetryIntervalMs(intervalMs: Int): Builder
        fun singleThreadMode(enabled: Boolean): Builder
        fun build(): LiteP2PConfig
    }
}

public enum class EngineState { STOPPED, STARTING, RUNNING, STOPPING }

public data class PeerInfo(
    val id: String,
    val ip: String,
    val port: Int,
    val connected: Boolean,
    val networkId: String,
    val connectionPath: ConnectionPath,
    val fsmState: String,
)

public enum class ConnectionPath {
    LAN_DIRECT, WAN_HOLE_PUNCH, TURN_RELAY, SIGNALING_RELAY, UNKNOWN
}

public interface LiteP2PListener {
    fun onEngineStarted() {}
    fun onEngineStopped() {}
    fun onPeersChanged(peers: List<PeerInfo>) {}
    fun onMessageReceived(peerId: String, data: ByteArray) {}
    fun onLog(level: LogLevel, line: String) {}
    fun onTelemetry(json: String) {}
}

public class LiteP2PEngine(config: LiteP2PConfig) : AutoCloseable {
    fun start(): EngineResult          // async; completion via onEngineStarted
    fun stop(): EngineResult           // async; completion via onEngineStopped
    val state: EngineState
    val peerId: String

    fun addListener(listener: LiteP2PListener)
    fun removeListener(listener: LiteP2PListener)

    fun connect(peerId: String): EngineResult
    fun addPeer(peerId: String, networkId: String): EngineResult
    fun disconnect(peerId: String): EngineResult
    fun isPeerConnected(peerId: String): Boolean
    fun send(peerId: String, data: ByteArray): EngineResult

    // Security
    fun localPublicKeyHex(): String
    fun registerPeerKey(peerId: String, publicKeyHex: String): EngineResult

    // Environment hints
    fun setNetworkInfo(isWifi: Boolean, networkAvailable: Boolean)
    fun setBatteryLevel(percent: Int, isCharging: Boolean)
    fun setReconnectMode(mode: ReconnectMode)
    fun setLogLevel(level: LogLevel)

    // Diagnostics
    fun telemetrySnapshot(): String    // JSON, see §6

    override fun close()               // stops engine, releases native handle

    companion object {
        val version: String
    }
}

public enum class EngineResult { OK, INVALID_ARG, INVALID_STATE, BUSY,
                                 NOT_FOUND, IO, TIMEOUT, UNSUPPORTED, INTERNAL }
```

### 4.1 Threading contract (Kotlin)

- Listener callbacks are dispatched on an internal engine thread. The wrapper
  does **not** post to the main thread; that is the consumer's choice.
- The harness (`:app`) adapts listeners to `LiveData` — exactly what
  `hook/p2p.kt` does today, but moved out of the library.
- `LiteP2PEngine` is safe to call from any thread.

### 4.2 Migration of current harness code

| Today (in `:app`, mixed) | After split |
|---|---|
| `EngineNative.kt` (JNI externs) | Internal to `:litep2p-core` |
| `hook/p2p.kt` engine calls | `LiteP2PEngine` API |
| `hook/p2p.kt` LiveData + message history | Harness-side adapter in `:app` |
| `sendMessageTracked` ACK envelopes | Harness-only feature in `:app` |
| `LiteP2PLogger` (JNI log sink) | `onLog` listener; harness renders it |
| `TelemetryStore` | Harness-side consumer of `onTelemetry` |

---

## 5. Identity and addressing

- `peer_id` is a stable UTF-8 string (current format retained). It is the
  primary key for connections, keys, and telemetry attribution.
- If `config.peer_id` is null, the engine generates one and reports it via
  `litep2p_engine_get_peer_id` / `LiteP2PEngine.peerId`.
- Discovery populates `network_id` (LAN identity) used for rendezvous.


---

## 6. Telemetry contract

Telemetry snapshots are single-line JSON, produced by the existing `Telemetry`
class. The schema is versioned by the `schema` field and evolves additively.

```json
{
  "schema": 1,
  "engine_id": "…",
  "ts_ms": 1723000000000,
  "uptime_ms": 123456,
  "reason": "periodic|snapshot|shutdown",
  "counters": { "messages_sent": 10, "…": 0 },
  "gauges":   { "peers_connected": 2, "rss_bytes": 12345678, "…": 0 },
  "hists_ms": { "connect_latency": { "count": 3, "sum": 450, "min": 100, "max": 200 } },
  "connection_summary": {
    "total_peers": 3, "connected": 2, "lan_direct": 1,
    "wan_hole_punch": 1, "turn_relay": 0, "signaling_relay": 0, "unknown": 0
  },
  "peers": [
    { "peer_id": "…", "connection_path": "LAN_DIRECT",
      "is_connected": true, "connected_at_ms": 1723000000000 }
  ]
}
```

### 6.1 Required resource gauges (for the "lightweight" goal)

The engine must report, at minimum, on every flush:

| Gauge | Source | Notes |
|---|---|---|
| `rss_bytes` | `/proc/self/status` (VmRSS) on Android/Linux; `task_info` on macOS | actual RAM footprint |
| `thread_count` | `/proc/self/status` (Threads) | validates single-thread mode |
| `peers_connected` | session manager | |
| `cpu_pct_estimate` | sampled jiffies delta (best-effort) | optional where unavailable |

These give the harness (and any integrator) a direct answer to "how much RAM is
the engine consuming" without external profiling.

---

## 7. Reliability requirements (acceptance criteria for "rigid and reliable")

The library is considered release-ready when:

1. **Lifecycle rigidity:** start/stop races, double-start, stop-while-starting,
   and destroy-while-running are all handled without crashes or deadlocks
   (state machine in §3.5; existing guard already enforces this — it becomes
   part of the contract and is unit-tested).
2. **JNI safety:** no pending-exception leaks across the JNI boundary (the
   `ExceptionClear` discipline in the current bridge becomes a binding-layer
   rule with tests).
3. **Reconnection:** peer FSM recovers across NAT rebinding, Wi-Fi↔cellular
   switches, and interface changes, driven by `set_network_info` hints.
4. **Bounded resources:** memory and thread counts stay within documented
   budgets per mode (multi-thread vs single-thread), verified via §6.1 gauges.
5. **Clean shutdown:** `stop` completes within a documented deadline; all
   sockets, threads, and file handles are released; `destroy` is idempotent.

---

## 8. Migration plan

**Phase 1 — Extract the C ABI (no behavior change)**
- Add `litep2p.h` + `litep2p_c_api.cpp` implementing §3 on top of the existing
  `SessionManager` singleton.
- Desktop `P2PNode` switches to the C ABI to prove platform neutrality.
- Existing JNI bridge keeps working unchanged.

**Phase 2 — Module split**
- Create `:litep2p-core` library module; move `cpp/`, JNI bridge, and a new
  Kotlin API (§4) into it.
- `:app` keeps only harness code; `hook/p2p.kt` becomes a thin adapter over
  `LiteP2PEngine`.
- Both flavors (`multiThread`/`singleThread`) keep building.

**Phase 3 — Re-point JNI onto the C ABI**
- JNI bridge calls `litep2p_*` functions instead of `SessionManager` directly.
- Delete direct C++ coupling between binding and engine internals.

**Phase 4 — Hardening and packaging**
- Add ABI conformance tests, lifecycle race tests, and telemetry gauge tests.
- Publish `:litep2p-core` as an AAR (Maven local first); document integration
  guide for external projects.

Each phase ends with a green build of both flavors and the harness fully
functional (start/stop, peers, messages, logs, telemetry).

---

## 9. Open questions

1. Should `litep2p_send` expose a completion callback (accepted/delivered/failed)
   at the engine level, or remain fire-and-forget with app-layer ACKs?
2. Multi-instance support: needed for any known consumer, or defer?
3. Should the C ABI expose file-transfer *receive* initiation, or is receive
   always accept-by-callback?
4. Preferred distribution: AAR only, or also a plain `.so` + header tarball for
   NDK-only integrators?

```
