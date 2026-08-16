# LiteP2P SDK Reference

**Version:** 0.3.0 (matches `LITEP2P_VERSION_*` in `litep2p.h` and `LiteP2P.version`)
**Status:** Implemented and exercised by the in-repo harness (`:app`) and desktop C ABI tests
**Audience:** Application developers integrating the LiteP2P peer-to-peer SDK
**Primary API for Android:** Kotlin (`com.zeengal.litep2p.core`) — wraps the C ABI via JNI
**C API contract:** `litep2p-core/src/main/cpp/include/litep2p.h`

---

## Table of contents

1. [Overview](#1-overview)
2. [Quickstart — Android integration](#2-quickstart--android-integration)
3. [Architecture](#3-architecture)
4. [C ABI reference (`litep2p.h`)](#4-c-abi-reference-litep2ph)
5. [Kotlin API reference (Android)](#5-kotlin-api-reference-android)
6. [Messaging model](#6-messaging-model)
7. [Overlay / multi-hop routing model](#7-overlay--multi-hop-routing-model)
8. [Telemetry contract](#8-telemetry-contract)
9. [`config.json` reference](#9-configjson-reference)
10. [Identity and addressing](#10-identity-and-addressing)
11. [Threading and lifecycle contract](#11-threading-and-lifecycle-contract)
12. [Reliability and operations guidance](#12-reliability-and-operations-guidance)
13. [Chat application integration guide](#13-chat-application-integration-guide)
14. [Worked examples](#14-worked-examples)
15. [Error code quick reference](#15-error-code-quick-reference)

---

## 1. Overview

LiteP2P is a lightweight, efficient, rigid, and reliable peer-to-peer networking
engine written in C++17. It handles the entire network layer — discovery,
connectivity (LAN direct, WAN hole-punch, TURN relay, signaling relay),
encrypted sessions (Noise NK), message transport, file transfer, multi-hop
overlay routing, and NAT/network recovery — so application layers (chat,
sync, file sharing, censorship-resistant messaging) can be built on top of it
without dealing with P2P complexity.

The engine is distributed as a **library**:

| Platform | Artifact |
|---|---|
| Android | AAR (`:litep2p-core`) containing native `.so` + Kotlin API — the published artifact |
| Linux/macOS | In-repo desktop build (`desktop/`) consuming the same C header — development/test target, not published |

The Android app in this repository (`:app`) is a **development/test harness**
only. It is not part of the library surface and must not leak into the
library's public API.

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
- **Small surface.** The public API is intentionally small; everything else is
  engine-internal.

### 1.2 Non-goals

- Application-layer protocols (chat, sync, etc.) — those belong to consumers.
  LiteP2P moves bytes between peers; it does not define chat semantics.
- Multiple engine instances per process. Exactly **one engine per process**,
  enforced by the API (process-wide singleton, no handles).
- Engine-level delivery notifications. `litep2p_send` is **fire-and-forget**;
  applications needing delivery confirmation use the app-layer ACK envelope
  protocol (see [§6 Messaging model](#6-messaging-model)).
- Public C++ API. C++ headers are internal; integrators use the C ABI or the
  Kotlin wrapper.

---

## 2. Quickstart — Android integration

### 2.1 Add the dependency

`:litep2p-core` ships with a **configured `maven-publish` setup** — the
recommended path is **Option C** (Maven Local publication, zero external
accounts). Maven Central requires only adding credentials + signing (see below).

**Option C — Maven local publication (recommended).** The SDK coordinates are
`com.zeengal:litep2p-core:<version>` (version is single-sourced from
`LITEP2P_VERSION` in `gradle.properties`, currently `0.3.0`). Publish and depend:

```bash
cd /path/to/Litep2p
./gradlew :litep2p-core:assembleMultiThreadRelease              # optional dry check
./gradlew :litep2p-core:publishMultiThreadReleasePublicationToMavenLocal
# Installed to ~/.m2/repository/com/zeengal/litep2p-core/<version>/ with
#   litep2p-core-<version>.aar          (native .so + Kotlin API)
#   litep2p-core-<version>-sources.jar
#   litep2p-core-<version>-javadoc.jar  (Dokka KDoc)
#   litep2p-core-<version>.pom          (license, SCM, developer metadata)
```

```kotlin
// settings.gradle.kts (root of your chat app)
dependencyResolutionManagement {
    repositories {
        mavenLocal()
        google()
        mavenCentral()
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.zeengal:litep2p-core:0.3.0")
}
```

Notes:

- A separate publication exists for the single-thread flavor:
  `./gradlew :litep2p-core:publishSingleThreadReleasePublicationToMavenLocal` →
  coordinate `com.zeengal:litep2p-core-singleThread:0.3.0`.
- **For Maven Central:** add `mavenCentral()` to the `publishing.repositories`
  block in `litep2p-core/build.gradle.kts`, add the `signing` plugin, and supply
  a GPG key + Sonatype credentials (`~/.gradle/gradle.properties`). The POM
  already carries license/SCM/developer metadata required by Central.
- **Automated CI:** `.github/workflows/build-and-publish.yml` builds both
  flavors (all ABIs) + runs the JVM unit tests and the desktop C ABI suite on
  standard runners for every push/PR, and on a `v<version>` tag produces the
  Maven artifacts and attaches them to a GitHub Release.

**Option A — vendor the module into your project.** Copy the `litep2p-core/`
directory (it contains the Kotlin API + JNI + native engine) into your project
and include it:

```kotlin
// settings.gradle.kts (root of your chat app)
include(":app")
include(":litep2p-core")

// app/build.gradle.kts
dependencies {
    implementation(project(":litep2p-core"))
}
```

You also need the module's plugins (and the `LITEP2P_VERSION` property) in your
root build files — see `litep2p-core/build.gradle.kts` and
`gradle.properties`.

**Option B — local AAR file (no source coupling, no Maven).** Build the
release AAR and depend on it directly:

```bash
cd /path/to/Litep2p
./gradlew :litep2p-core:assembleMultiThreadRelease
# AAR at: litep2p-core/build/outputs/aar/litep2p-core-multiThread-release.aar
```

```kotlin
// app/build.gradle.kts
dependencies {
    implementation(files("libs/litep2p-core-multiThread-release.aar"))
}
```

> **Important:** the AAR ships native libraries for `arm64-v8a`, `armeabi-v7a`
> and `x86_64` (see `litep2p-core/build.gradle.kts`, `ndk.abiFilters`). The
> 32-bit `x86` ABI is not packaged because its vendored libsodium is not
> `-fPIC`; `x86_64` covers all modern emulators. The NDK is pinned to
> `26.1.10909125` for reproducible builds.

### 2.2 Minimal startup sequence

```kotlin
import com.zeengal.litep2p.core.*

// 1. Register your event listener BEFORE starting the engine so no events are missed.
LiteP2P.addListener(object : LiteP2PListener {
    override fun onEngineStarted() { /* engine is up */ }
    override fun onPeersChanged(peers: List<PeerInfo>) { /* render peer list */ }
    override fun onMessageReceived(peerId: String, data: ByteArray) { /* chat line arrived */ }
    override fun onLog(level: LogLevel, line: String) { /* optional */ }
    override fun onTelemetry(json: String) { /* optional */ }
})

// 2. Configure and initialize (once per process).
val config = LiteP2PConfig.Builder()
    .filesDir(context.filesDir.absolutePath)   // REQUIRED on Android
    .peerId("my-stable-peer-id")               // optional; engine generates one if omitted
    .commsMode(CommsMode.UDP)                  // optional; default UDP
    .build()

LiteP2P.init(config)   // EngineResult.OK on success

// 3. Start the engine (completion also reported via onEngineStarted).
LiteP2P.start()        // EngineResult.OK = start accepted

// 4. When done:
LiteP2P.stop()         // async; completion via onEngineStopped
LiteP2P.shutdown()     // release all native state; idempotent
```

### 2.3 Threading rule of thumb

`LiteP2P` is safe to call from any thread. All listener callbacks arrive on
**internal engine threads** — do not block in them, and post UI updates to the
main thread yourself (e.g. with `Handler(Looper.getMainLooper())` or a
`MutableLiveData`/`Flow` bridge). See [§11](#11-threading-and-lifecycle-contract).

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Consumer app (:app) — your chat application                │
│  - Your UI, your app protocol, your persistence              │
└──────────────────────────┬──────────────────────────────────┘
                           │ depends on
┌──────────────────────────▼──────────────────────────────────┐
│  :litep2p-core (Android library module / AAR)               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Kotlin API: LiteP2P, LiteP2PConfig, LiteP2PListener,   │  │
│  │ PeerInfo, enums                                        │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ JNI binding layer (jni_bridge.cpp)                    │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ C ABI: litep2p.h   ← THE PUBLIC CONTRACT              │  │
│  ├───────────────────────────────────────────────────────┤  │
│  │ C++ engine: SessionManager + modules                  │  │
│  │ (core, transport, crypto, discovery, session,         │  │
│  │  file_transfer, routing, overlay, proxy, optimization)│  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

- `:litep2p-core` — `com.android.library`; owns `cpp/` (engine + JNI) and
  publishes the Kotlin API. No AndroidX UI dependencies.
- `:app` — `com.android.application`; the dev harness. Depends on
  `:litep2p-core`.
- `desktop/` — CMake build that compiles the same C++ engine and
  `litep2p_c_api.cpp` so desktop C tests exercise the identical public contract
  as Android.


---

## 4. C ABI reference (`litep2p.h`)

The C header `litep2p-core/src/main/cpp/include/litep2p.h` is the **public
contract**. The Kotlin API is a thin wrapper over it. If you integrate from a
non-Android platform (desktop, server, embedded), this section is your API.

### 4.1 Conventions

- All functions are `extern "C"`, prefixed `litep2p_`.
- Process-wide singleton: **no handles**. Initialize once with `litep2p_init`,
  tear down with `litep2p_shutdown`. Calling `litep2p_init` twice while the
  engine is not `STOPPED` returns `LITEP2P_ERR_INVALID_STATE`.
- All fallible operations return `litep2p_result_t` (int32 error code) unless
  stated otherwise.
- Strings are UTF-8, NUL-terminated. Byte buffers carry explicit lengths.
- Memory returned by the engine is documented per-function (caller-owned vs.
  engine-owned with `litep2p_free`).
- The API is thread-safe unless documented otherwise.
- Callbacks may be invoked from engine threads; **consumers must not block in
  them**.

### 4.2 Error codes

```c
typedef enum litep2p_result {
    LITEP2P_OK                =   0,
    LITEP2P_ERR_INVALID_ARG   =  -1,
    LITEP2P_ERR_INVALID_STATE =  -2,  /* e.g. send before start */
    LITEP2P_ERR_BUSY          =  -3,  /* start/stop already in progress */
    LITEP2P_ERR_NOT_FOUND     =  -4,  /* unknown peer / transfer id */
    LITEP2P_ERR_IO            =  -5,
    LITEP2P_ERR_TIMEOUT       =  -6,
    LITEP2P_ERR_UNSUPPORTED   =  -7,  /* feature compiled out / not wired yet */
    LITEP2P_ERR_NO_ROUTE      =  -8,  /* overlay: no relay path available */
    LITEP2P_ERR_INTERNAL      = -99,
} litep2p_result_t;

const char* litep2p_result_string(litep2p_result_t result);
```

`litep2p_result_string` returns a human-readable name for every code (e.g.
`"NO_ROUTE"`), or `"UNKNOWN"` for unrecognized values.

### 4.3 Versioning

```c
#define LITEP2P_VERSION_MAJOR 0
#define LITEP2P_VERSION_MINOR 3
#define LITEP2P_VERSION_PATCH 0

uint32_t litep2p_version(void);           /* packed major<<16 | minor<<8 | patch */
const char* litep2p_version_string(void); /* "0.3.0" */
```

ABI stability rules: additive changes bump MINOR; breaking changes bump MAJOR.
Structs passed across the ABI always carry a `struct_size` field set by the
caller for forward/backward compatibility.

### 4.4 Configuration (`litep2p_config_t`)

```c
typedef struct litep2p_config {
    uint32_t struct_size;        /* = sizeof(litep2p_config); set by caller */

    const char* peer_id;         /* stable identity; NULL = engine generates one */
    const char* comms_mode;      /* "TCP" | "UDP" | "QUIC" | "ALL" | "AUTO" */
    int listen_port;             /* 0 = engine default (30001) */
    const char* files_dir;       /* writable dir for config.json, keystore, peer DB
                                  * (Android: Context.getFilesDir().absolutePath) */
    const char* config_path;     /* optional explicit config.json path; NULL = auto-discover */

    /* Feature toggles (runtime-disable where supported). */
    int enable_encryption;       /* Noise NK sessions (default 1) */
    int enable_discovery;        /* LAN discovery (default 1) */
    int enable_file_transfer;    /* (default 1; compile-time module, runtime no-op) */

    /* Telemetry. */
    int telemetry_enabled;       /* default 1 */
    int telemetry_interval_ms;   /* default 30000 */

    /* Threading. */
    int single_thread_mode;      /* default 0 (multi-thread); 1 = reduced threads */
} litep2p_config_t;

/* Populate with safe defaults; always sets struct_size. */
void litep2p_config_init(litep2p_config_t* config);
```

Notes:

- `comms_mode`: `"TCP"`, `"UDP"`, `"QUIC"`, `"ALL"` (listen on all three
  transports simultaneously), or `"AUTO"` (engine choice). The Kotlin
  `CommsMode` enum mirrors these values.
- `files_dir` is where the engine discovers `config.json`, reads/writes the
  Noise keystore, and (when enabled) the peer DB. On Android it must be a
  writable app-private directory.
- `enable_file_transfer` is accepted but currently a no-op at runtime — the
  file-transfer module is compile-time only.
- `single_thread_mode` is a **compile-time hint** in the current build: the
  actual thread mode is selected by the `singleThread`/`multiThread` Gradle
  flavor (`SINGLE_THREAD_MODE` CMake toggle).

### 4.5 Lifecycle

```c
typedef enum litep2p_state {
    LITEP2P_STATE_STOPPED  = 0,
    LITEP2P_STATE_STARTING = 1,
    LITEP2P_STATE_RUNNING  = 2,
    LITEP2P_STATE_STOPPING = 3,
} litep2p_state_t;

/* Initialize the (single) engine. Must be called before litep2p_start(). */
litep2p_result_t litep2p_init(const litep2p_config_t* config);

/* Start asynchronously; completion via on_engine_started. */
litep2p_result_t litep2p_start(void);

/* Stop asynchronously; completion via on_engine_stopped. */
litep2p_result_t litep2p_stop(void);

/* Stop (if running) and release all engine state. Idempotent. */
litep2p_result_t litep2p_shutdown(void);

litep2p_state_t litep2p_get_state(void);

/* Copy the local peer id into buf (NUL-terminated). Returns the number of bytes
 * written (excluding NUL) on success, or a negative error code. */
litep2p_result_t litep2p_get_peer_id(char* buf, uint32_t buf_len);
```

Behavioral contract:

| Call | Result while `STOPPED` | Result while `STARTING`/`RUNNING`/`STOPPING` |
|---|---|---|
| `litep2p_init` | `OK` (replaces stored config) | `INVALID_STATE` (call `litep2p_shutdown` first) |
| `litep2p_start` | `OK` (accepted) | `BUSY` if `STARTING`/`STOPPING`, else `INVALID_STATE`; `INVALID_STATE` if never `init`'d |
| `litep2p_stop` | `OK` (idempotent no-op) | `OK` if `STOPPING` (no-op), `BUSY` if `STARTING`, else accepted async stop |
| `litep2p_shutdown` | `OK` (idempotent) | Stops first (synchronous wait), then releases state |

- `litep2p_start` resolves the local peer id (generating a persistent device id
  when none was configured), applies `files_dir`-based config
  (`config.json`, keystore, peer DB), and starts all subsystems.
- Both `litep2p_stop` and `litep2p_shutdown` are idempotent and safe to call
  multiple times.
- After `litep2p_shutdown`, `litep2p_init` may be invoked again.

### 4.6 Events and callbacks

All callbacks receive the `user_data` pointer supplied at registration and may
be invoked from engine threads. The engine copies the callback struct, so the
caller's memory is not retained. Register callbacks **before** `litep2p_start`
to receive lifecycle/peer/message events; you may re-register at any time.

```c
typedef struct litep2p_peer_info {
    char peer_id[128];
    char ip[64];
    int port;
    int connected;               /* 0/1 */
    int latency;                 /* measured RTT in ms, -1 when unknown */
    char network_id[128];
    char connection_path[32];    /* "LAN_DIRECT" | "WAN_HOLE_PUNCH" | "TURN_RELAY"
                                  * | "SIGNALING_RELAY" | "UNKNOWN" */
    char fsm_state[32];          /* best-effort peer FSM state string */
} litep2p_peer_info_t;

typedef struct litep2p_callbacks {
    uint32_t struct_size;        /* = sizeof(litep2p_callbacks) */
    void* user_data;

    /* Lifecycle. */
    void (*on_engine_started)(void* user_data);
    void (*on_engine_stopped)(void* user_data);

    /* Peers — full snapshot each time. */
    void (*on_peers_changed)(void* user_data,
                             const litep2p_peer_info_t* peers, uint32_t count);

    /* Messaging — buffer valid only for the duration of the call. */
    void (*on_message_received)(void* user_data, const char* peer_id,
                                const uint8_t* data, uint32_t len);

    /* Logging — level: 0=DEBUG 1=INFO 2=WARN 3=ERROR. */
    void (*on_log)(void* user_data, int level, const char* line);

    /* Telemetry — single-line JSON snapshot (see §8). */
    void (*on_telemetry)(void* user_data, const char* json);

    /* Overlay reliable-send completion: frame_id + delivered (1/0). Fires for
     * want_ack overlay sends when the destination ACKs (delivered=1) or the
     * bounded retry budget is exhausted (delivered=0). */
    void (*on_overlay_delivery)(void* user_data, const char* frame_id, int delivered);
} litep2p_callbacks_t;

litep2p_result_t litep2p_set_callbacks(const litep2p_callbacks_t* callbacks);
```

Notes:

- `on_peers_changed` delivers a **full snapshot** on every change — replace any
  previously cached list; peers absent from the snapshot are gone.
- The `on_message_received` buffer is valid only for the duration of the call;
  copy it if you need it later.
- The engine does not guarantee callback ordering across categories.

### 4.7 Peer operations

```c
/* Initiate a connection to a peer (by peer_id). OK = accepted, not connected. */
litep2p_result_t litep2p_connect(const char* peer_id);

/* Register a peer for rendezvous (discovery bootstrap / out-of-band invite). */
litep2p_result_t litep2p_add_peer(const char* peer_id, const char* network_id);

/* Disconnect a specific peer. The engine closes transport connections
 * best-effort, drives the peer FSM to DISCONNECTED, and suppresses automatic
 * reconnection until the peer is explicitly re-connected (litep2p_connect) or
 * establishes an inbound connection. NOT_FOUND when the peer is unknown to the
 * engine. */
litep2p_result_t litep2p_disconnect(const char* peer_id);

/* Query whether a peer session is fully established. */
litep2p_result_t litep2p_peer_is_connected(const char* peer_id, int* out_connected);

/* Query a peer's current connection path ("LAN_DIRECT", "TURN", ...). */
litep2p_result_t litep2p_peer_get_connection_path(const char* peer_id,
                                                  char* buf, uint32_t buf_len);
```

- `litep2p_connect` accepts the request into the connection path; actual
  connectivity is reported asynchronously through `on_peers_changed`.
- `network_id` is the peer's advertised LAN endpoint used for rendezvous
  (usually `"ip:port"`). It can be empty when unknown.
- All peer functions return `LITEP2P_ERR_INVALID_STATE` before `litep2p_start`.

### 4.8 Messaging

```c
/* Fire-and-forget send. Returns LITEP2P_OK when the message was accepted into
 * the send path, not when (or whether) it was delivered. There is no
 * engine-level delivery notification by design; applications that need
 * delivery confirmation implement app-layer ACKs (see §6). */
litep2p_result_t litep2p_send(const char* peer_id, const uint8_t* data, uint32_t len);
```

- Messages are opaque byte buffers (binary-safe). `len == 0` is rejected with
  `INVALID_ARG`.
- Within an established session the engine provides ordered, encrypted,
  binary-safe delivery. Reliability features (reconnect, path failover) are
  engine-internal.
- There is no per-peer backpressure API; the send queue is bounded by
  `peer_management.max_queued_messages` in `config.json` (default 100).
- The engine recognizes the **LP_APP / LP_APP_ACK envelope protocol** for
  application-level delivery confirmation — see [§6 Messaging model](#6-messaging-model).

### 4.9 Security (Noise NK)

```c
/* Local static public key, hex-encoded. buf_len must be >= 65. */
litep2p_result_t litep2p_get_local_public_key(char* buf, uint32_t buf_len);

/* Register a peer's Noise NK static public key (64 hex chars). */
litep2p_result_t litep2p_register_peer_key(const char* peer_id,
                                           const char* public_key_hex);

/* Check whether a peer key is registered. */
litep2p_result_t litep2p_has_peer_key(const char* peer_id, int* out_has_key);
```

- Sessions use the Noise **NK** handshake: the initiator must know the
  responder's static public key (registered via `litep2p_register_peer_key`)
  before the handshake can complete.
- The local static key is persisted under `files_dir` (`keystore/`); it stays
  stable across restarts.
- `litep2p_get_local_public_key` returns `UNSUPPORTED` when the Noise module is
  unavailable or the key has not been initialized yet.

### 4.10 File transfer (optional module)

File transfer uses an **offer/accept** model: nothing is written to disk until
the receiver explicitly accepts an incoming offer.

```c
typedef struct litep2p_file_offer {
    char transfer_id[64];
    char peer_id[128];
    char file_name[256];
    uint64_t size_bytes;
} litep2p_file_offer_t;

typedef struct litep2p_transfer_callbacks {
    uint32_t struct_size;        /* = sizeof(litep2p_transfer_callbacks) */
    void* user_data;
    /* Sender side: progress/completion of an outgoing transfer. */
    void (*on_progress)(void* user_data, const char* transfer_id, float progress,
                        float bytes_per_sec);
    void (*on_completed)(void* user_data, const char* transfer_id, int success,
                         const char* error);
    /* Receiver side: an incoming transfer offer; accept with
     * litep2p_accept_file_transfer(save_path) or decline it. */
    void (*on_file_transfer_offered)(void* user_data,
                                     const litep2p_file_offer_t* offer);
} litep2p_transfer_callbacks_t;

litep2p_result_t litep2p_set_transfer_callbacks(const litep2p_transfer_callbacks_t* callbacks);

litep2p_result_t litep2p_send_file(const char* peer_id, const char* file_path,
                                   int priority, char* out_transfer_id, uint32_t buf_len);
litep2p_result_t litep2p_accept_file_transfer(const char* transfer_id,
                                              const char* save_path);
litep2p_result_t litep2p_decline_file_transfer(const char* transfer_id);
litep2p_result_t litep2p_pause_transfer(const char* transfer_id);
litep2p_result_t litep2p_resume_transfer(const char* transfer_id);
litep2p_result_t litep2p_cancel_transfer(const char* transfer_id);
```

- `litep2p_send_file` returns `NOT_FOUND` when the target peer is not connected
  or the offer could not be created; on success `out_transfer_id` receives the
  transfer id.
- Accept/decline/pause/resume/cancel return `NOT_FOUND` for unknown transfer ids.
- The file-transfer module is compile-time enabled; functions return
  `UNSUPPORTED` only when the module is compiled out. Query availability with
  `litep2p_get_feature_flags()` / `LiteP2P.capabilities`.
- The Kotlin wrapper exposes the full offer/accept model — see
  [§5.6 File transfer (Kotlin)](#56-file-transfer-kotlin).

### 4.11 Proxy / relay (optional module)

```c
/* role: "off" | "gateway" | "exit" | "client" | "both" */
litep2p_result_t litep2p_set_proxy_role(const char* role);
```

- Safe to call while running; roles change live.
- `"off"`/`"0"`/`"false"` disables both roles; `"exit"` is accepted as an alias
  for `"gateway"`. Any other value returns `INVALID_ARG`.
- Returns `UNSUPPORTED` when the proxy module is compiled out or no proxy
  endpoint exists.

### 4.12 Overlay / multi-hop routing (censorship-resistance layer)

The overlay routes application messages through N sealed relay hops (onion-lite
LPX2). Payloads are signed with the local Ed25519 key and verified by the
destination. Static knobs live under the `overlay` object in `config.json`
(`relay_enabled`, `default_hops`, `relay_peers`, `padding_bucket`,
`obfuscate_transport`, `cover_interval_ms`, `pex_interval_ms`,
`require_origin_auth`); runtime operations live here.

```c
/* Opt in/out of forwarding frames and holding mailboxes for other peers.
 * Origin/destination roles need no opt-in. */
litep2p_result_t litep2p_set_overlay_relay_enabled(int enabled);

/* Send `data` through the overlay to `peer_id` (the peer's Noise NK static key
 * must be registered first — see litep2p_register_peer_key).
 *   want_ack    = request reliable delivery (ACK/fail via on_overlay_delivery)
 *   via_mailbox = hold at the terminal relay until the peer collects it
 * On success fills out_frame_id (32 hex chars) and returns LITEP2P_OK.
 * Errors: NOT_FOUND (no peer key), NO_ROUTE (no relay path), BUSY,
 *         INVALID_ARG (payload too large), INVALID_STATE, INTERNAL. */
litep2p_result_t litep2p_send_overlay(const char* peer_id,
                                      const uint8_t* data, uint32_t len,
                                      int want_ack, int via_mailbox,
                                      char* out_frame_id, uint32_t buf_len);

/* Ask `relay_peer_id` to hand over any mailboxes it holds for us. */
litep2p_result_t litep2p_overlay_pickup_mailbox(const char* relay_peer_id);

/* Add a relay candidate (bootstrap list, QR code, etc.). persistent=1 keeps
 * it regardless of advertisement freshness. */
litep2p_result_t litep2p_overlay_register_relay(const char* peer_id,
                                                int capacity, int max_hops,
                                                int persistent);

/* Register a peer's Ed25519 signing public key (64 hex chars) as the trust
 * anchor for origin authentication. Once registered, overlay payloads
 * claiming to be from `peer_id` must be signed by this exact key. */
litep2p_result_t litep2p_overlay_register_peer_signing_key(const char* peer_id,
                                                           const char* public_key_hex);

/* Overlay counters as single-line JSON (malloc'd; free with litep2p_free). */
litep2p_result_t litep2p_overlay_stats(char** out_json);
```

- **Message size:** the maximum application payload per overlay send is
  **640 bytes** (larger payloads return `INVALID_ARG`). The internal wire frame
  cap is 1100 bytes. For chat, keep overlay messages short; use
  `litep2p_send` for larger payloads.
- **Setup prerequisites:** register the destination's Noise NK key
  (`litep2p_register_peer_key`) and at least one relay candidate
  (`litep2p_overlay_register_relay` or `overlay.relay_peers` in `config.json`).
- **Delivery notification:** when `want_ack=1`, `on_overlay_delivery` fires
  with the frame id and `delivered=1/0` once the destination ACKs or the
  bounded retry budget is exhausted.
- **Offline delivery:** when `via_mailbox=1`, the terminal relay holds the
  frame until the destination calls `litep2p_overlay_pickup_mailbox`.
- All overlay functions return `UNSUPPORTED` when the overlay module is
  compiled out.

### 4.13 Environment hints (mobile integration)

```c
/* Network state hint — drives signaling/NAT recovery in the native engine. */
litep2p_result_t litep2p_set_network_info(int is_wifi, int network_available);

/* Battery hint — drives reconnect/keepalive aggressiveness. */
litep2p_result_t litep2p_set_battery_level(int percent, int is_charging);

/* Reconnect aggressiveness: "auto" | "aggressive" | "balanced" | "power_saver". */
litep2p_result_t litep2p_set_reconnect_mode(const char* mode);
```

- These hints let the engine adapt to Wi-Fi↔cellular switches, Doze/battery
  saver, and flaky networks without the application re-implementing policy.
- `litep2p_set_reconnect_mode` validates the mode string and returns
  `INVALID_ARG` for unknown values.
- Call them whenever the Android `ConnectivityManager` / `BatteryManager`
  reports a change (see [§13](#13-chat-application-integration-guide)).

### 4.14 Telemetry and diagnostics

```c
/* Force an immediate snapshot; delivered via the on_telemetry callback AND
 * returned as a malloc'd JSON string the caller must free with litep2p_free. */
litep2p_result_t litep2p_telemetry_snapshot(char** out_json);

/* Free memory returned by the engine (e.g. litep2p_telemetry_snapshot). */
void litep2p_free(void* ptr);

/* Logging level: 0=DEBUG 1=INFO 2=WARN 3=ERROR. */
litep2p_result_t litep2p_set_log_level(int level);
```

- `litep2p_telemetry_snapshot` returns single-line JSON with
  `"reason":"c_api"` (see [§8 Telemetry contract](#8-telemetry-contract)).
- `litep2p_set_log_level` returns `INVALID_ARG` for values outside 0–3.

### 4.15 Feature detection (compile-time module availability)

```c
/* Flags returned by litep2p_get_feature_flags(). */
#define LITEP2P_FEATURE_FILE_TRANSFER (1u << 0)
#define LITEP2P_FEATURE_OVERLAY       (1u << 1)
#define LITEP2P_FEATURE_PROXY         (1u << 2)
#define LITEP2P_FEATURE_ENCRYPTION    (1u << 3)
#define LITEP2P_FEATURE_DISCOVERY     (1u << 4)
#define LITEP2P_FEATURE_TELEMETRY     (1u << 5)

/* Bitmask of LITEP2P_FEATURE_* for this build. */
uint32_t litep2p_get_feature_flags(void);
```

- The flags reflect the **build configuration** (module compiled in or out) and
  are fixed for the lifetime of the process. Safe to call before
  `litep2p_init`.
- Use them to degrade gracefully when a subsystem is not available instead of
  discovering `LITEP2P_ERR_UNSUPPORTED` at call time.
- See [§5.7 Feature detection (Kotlin)](#57-feature-detection-kotlin) for the
  Kotlin wrapper.

---

## 5. Kotlin API reference (Android)

The Kotlin wrapper lives in `:litep2p-core`, package `com.zeengal.litep2p.core`.
It is the recommended API for Android consumers; it wraps the C ABI via JNI and
adds type safety, listener registration, and lifecycle safety. The only
Android-specific input is the `filesDir` path you supply.

All public types:

- `LiteP2PConfig` (+ `LiteP2PConfig.Builder`)
- `LiteP2P` (process-wide singleton `object`)
- `LiteP2PListener` (event observer interface)
- `PeerInfo`, `EngineState`, `EngineResult`, `CommsMode`, `ConnectionPath`,
  `LogLevel`, `ReconnectMode`
- `LiteP2PCapabilities` (feature detection), `FileTransferOffer`,
  `FileTransferPriority`
- Reactive types: `LiteP2PMessage`, `LiteP2PMessageAck`, `LiteP2POverlayDelivery`,
  `LiteP2PLogLine`, `LiteP2PTransferEvent`

### 5.1 `LiteP2PConfig`

Immutable engine configuration. Construct via `Builder`.

```kotlin
class LiteP2PConfig private constructor(
    val peerId: String?,          // null = engine generates one
    val commsMode: CommsMode,     // default UDP
    val listenPort: Int,          // 0 = engine default (30001)
    val filesDir: String,         // REQUIRED on Android
    val configPath: String?,      // null = auto-discover config.json under filesDir
    val encryptionEnabled: Boolean,   // default true
    val discoveryEnabled: Boolean,    // default true
    val fileTransferEnabled: Boolean, // default true
    val telemetryEnabled: Boolean,    // default true
    val telemetryIntervalMs: Int,     // default 30000
    val singleThreadMode: Boolean     // default false; compile-time hint (see below)
)
```

Builder:

```kotlin
LiteP2PConfig.Builder()
    .peerId(id: String?)               // stable identity; null = engine-generated
    .commsMode(mode: CommsMode)        // TCP | UDP | QUIC | ALL | AUTO
    .listenPort(port: Int)             // 0 = engine default
    .filesDir(path: String)            // required: Context.getFilesDir().absolutePath
    .configPath(path: String?)         // explicit config.json path; null = auto
    .encryptionEnabled(enabled: Boolean)
    .discoveryEnabled(enabled: Boolean)
    .fileTransferEnabled(enabled: Boolean)
    .telemetryEnabled(enabled: Boolean)
    .telemetryIntervalMs(intervalMs: Int)
    .singleThreadMode(enabled: Boolean)
    .build(): LiteP2PConfig
```

Rules:

- `build()` throws `IllegalArgumentException` if `filesDir` is blank.
- `singleThreadMode` is currently a **compile-time hint**: the actual thread
  mode is decided by the `singleThread`/`multiThread` Gradle flavor
  (`SINGLE_THREAD_MODE` CMake toggle), not by this flag.
- Rebuilding + re-calling `LiteP2P.init(config)` while the engine is stopped
  simply replaces the stored configuration.

### 5.2 `LiteP2P` — lifecycle, peers, messaging, security

```kotlin
object LiteP2P {

    // Version string, e.g. "0.3.0". Single-sourced from gradle.properties
    // LITEP2P_VERSION via BuildConfig; matches litep2p_version_string().
    val version: String

    // Current engine lifecycle state.
    val state: EngineState

    // Resolved local peer id (engine-generated when none configured).
    // Falls back to the configured id (or "") before the engine has started.
    val peerId: String

    // --- Lifecycle ---------------------------------------------------------
    fun init(config: LiteP2PConfig): EngineResult   // once per process
    fun start(): EngineResult                       // async; completion via onEngineStarted
    fun stop(): EngineResult                        // async; completion via onEngineStopped
    fun shutdown(): EngineResult                    // stops if running; releases native state; idempotent

    // --- Listeners ---------------------------------------------------------
    fun addListener(listener: LiteP2PListener)      // idempotent
    fun removeListener(listener: LiteP2PListener)

    // --- Peers -------------------------------------------------------------
    fun connect(peerId: String): EngineResult
    fun addPeer(peerId: String, networkId: String): EngineResult
    fun disconnect(peerId: String): EngineResult    // NOT_FOUND for unknown peers
    fun isPeerConnected(peerId: String): Boolean

    // --- Messaging ---------------------------------------------------------
    fun send(peerId: String, data: ByteArray): EngineResult  // fire-and-forget

    // --- Security (Noise NK) ------------------------------------------------
    fun localPublicKeyHex(): String                 // "" when unavailable
    fun registerPeerKey(peerId: String, publicKeyHex: String): EngineResult

    // --- Feature detection (see §5.7) ---------------------------------------
    val capabilities: LiteP2PCapabilities          // compile-time module flags
    fun supportsFileTransfer(): Boolean
    fun supportsOverlay(): Boolean
    fun supportsProxy(): Boolean
    fun supportsEncryption(): Boolean

    // --- Reactive state (see §5.8) ------------------------------------------
    val stateFlow: StateFlow<EngineState>          // observable lifecycle

    // --- File transfer (see §5.6) -------------------------------------------
    fun sendFile(peerId: String, filePath: String,
                 priority: FileTransferPriority = FileTransferPriority.NORMAL): String?
    fun acceptFileTransfer(transferId: String, savePath: String): EngineResult
    fun declineFileTransfer(transferId: String): EngineResult
    fun pauseTransfer(transferId: String): EngineResult
    fun resumeTransfer(transferId: String): EngineResult
    fun cancelTransfer(transferId: String): EngineResult
}
```

Method notes:

- `init` returns `INVALID_STATE` if the engine is `RUNNING` or `STARTING`.
- `start` returns `INVALID_STATE` if `init` was not called, `BUSY` if the
  engine is not `STOPPED`. The native call blocks until the engine is up (or
  fails); completion is also reported via `LiteP2PListener.onEngineStarted`.
- `stop` returns `OK` when already `STOPPED`/`STOPPING` (idempotent no-op).
- `shutdown` stops the engine if needed, releases all native state, and resets
  the wrapper so a later `init` starts clean.
- `send` rejects blank peer ids and empty payloads with `INVALID_ARG`.
- `disconnect` requests a session teardown with the peer: transport connections
  are closed best-effort, the peer FSM is driven to DISCONNECTED, and automatic
  reconnection is suppressed until an explicit `connect` or an inbound
  connection. Returns `OK` when the peer is known, `NOT_FOUND` when the peer is
  unknown to the engine. The updated peer state arrives asynchronously via
  `onPeersChanged`.
- `isPeerConnected` returns `false` for blank ids or when the engine is not up.
- Blank `peerId` (or empty hex) arguments are rejected with `INVALID_ARG`.

### 5.3 `LiteP2P` — proxy, overlay, environment hints, diagnostics

```kotlin
object LiteP2P {

    // --- Proxy / relay ------------------------------------------------------
    // Maps the booleans onto the C ABI role string:
    //   (true, true) -> "both" | (true, false) -> "gateway"
    //   (false, true) -> "client" | (false, false) -> "off"
    // Safe to call while running; roles change live.
    fun configureProxy(enableGateway: Boolean, enableClient: Boolean): EngineResult

    // --- Overlay / multi-hop routing (censorship-resistance) -----------------
    // Send data through the onion-lite overlay. Prerequisites: register the
    // destination's Noise NK key (registerPeerKey) and at least one relay
    // (registerRelay or overlay.relay_peers in config.json).
    // @param wantAck    request bounded reliable delivery — completion arrives
    //                   via LiteP2PListener.onOverlayDelivery with this frame id
    // @param viaMailbox hold at the terminal relay until the peer collects it
    // @return the 32-char frame id, or null on failure
    fun sendOverlay(peerId: String, data: ByteArray,
                    wantAck: Boolean = false, viaMailbox: Boolean = false): String?

    // Collect any mailboxes a relay is holding for this device.
    fun pickupMailbox(relayPeerId: String): EngineResult

    // Add a relay candidate. persistent=true keeps it regardless of
    // advertisement freshness. Defaults: capacity 32, maxHops 4, persistent true.
    fun registerRelay(peerId: String,
                      capacity: Int = 32, maxHops: Int = 4,
                      persistent: Boolean = true): EngineResult

    // Register a peer's Ed25519 signing public key (64 hex chars) as the trust
    // anchor for origin authentication. Overlay payloads claiming to come from
    // the peer must then be signed by this exact key or they are dropped.
    fun registerPeerSigningKey(peerId: String, publicKeyHex: String): EngineResult

    // Opt in/out of forwarding frames and holding mailboxes for other peers.
    fun setOverlayRelayEnabled(enabled: Boolean): EngineResult

    // Overlay counters as single-line JSON, or "" when unavailable.
    fun overlayStats(): String

    // --- Environment hints ---------------------------------------------------
    fun setNetworkInfo(isWifi: Boolean, networkAvailable: Boolean): EngineResult
    fun setBatteryLevel(percent: Int, isCharging: Boolean): EngineResult
    fun setReconnectMode(mode: ReconnectMode): EngineResult

    // --- Diagnostics ---------------------------------------------------------
    // Logging level: DEBUG | INFO | WARN | ERROR.
    fun setLogLevel(level: LogLevel): EngineResult

    // Pull-based telemetry snapshot as single-line JSON ("" when telemetry is
    // disabled or the engine is not initialized). Periodic snapshots also
    // arrive via LiteP2PListener.onTelemetry.
    fun telemetrySnapshot(): String
}
```

Notes:

- `sendOverlay` returns `null` for blank peer ids or empty payloads. The
  maximum payload is **640 bytes** per overlay send.
- `pickupMailbox` / `registerRelay` / `registerPeerSigningKey` return
  `INVALID_ARG` for blank peer ids.
- `telemetrySnapshot` returns `""` when telemetry is disabled or the engine is
  not initialized; the manual snapshot's JSON uses `"reason":"c_api"`.

### 5.4 `LiteP2PListener`

All methods have default no-op implementations, so you override only what you
need. Callbacks are dispatched on internal engine threads — do not block.

```kotlin
interface LiteP2PListener {

    // Engine startup completed (asynchronous result of LiteP2P.start).
    fun onEngineStarted() {}

    // Engine shutdown completed (asynchronous result of LiteP2P.stop).
    fun onEngineStopped() {}

    // Full peer snapshot; replaces any previous list.
    fun onPeersChanged(peers: List<PeerInfo>) {}

    // A message arrived from peerId. data is valid only for the call duration.
    fun onMessageReceived(peerId: String, data: ByteArray) {}

    // Engine log line. level is best-effort.
    fun onLog(level: LogLevel, line: String) {}

    // Telemetry snapshot as single-line JSON (see §8).
    fun onTelemetry(json: String) {}

    // Application-level ACK received for a previously sent message. Supports
    // the LP_APP / LP_APP_ACK envelope protocol (§6): the sender embeds a
    // msg_id and the receiver echoes it back, letting the sender measure
    // delivery latency. Engines that do not run the envelope protocol never
    // fire this callback.
    // @param messageId The original message id.
    // @param sentTsMs  Sender-provided send timestamp (epoch ms), or 0.
    // @param recvTsMs  Receiver-provided receive timestamp (epoch ms), or 0.
    fun onMessageAcked(messageId: String, sentTsMs: Long, recvTsMs: Long) {}

    // Overlay reliable-send completion. Fires for overlay sends requested with
    // wantAck = true: delivered=true when the destination ACKed, false when the
    // bounded retry budget was exhausted. frameId matches the value returned by
    // LiteP2P.sendOverlay.
    fun onOverlayDelivery(frameId: String, delivered: Boolean) {}

    // --- File transfer (offer/accept model) --------------------------------
    // An incoming file-transfer offer arrived. Nothing is written to disk
    // until the receiver calls LiteP2P.acceptFileTransfer(savePath) or
    // LiteP2P.declineFileTransfer().
    fun onFileTransferOffered(offer: FileTransferOffer) {}

    // Progress update for a transfer: progressPercent is 0..100, bytesPerSec
    // the current throughput in bytes/second.
    fun onTransferProgress(transferId: String, progressPercent: Float, bytesPerSec: Float) {}

    // A transfer finished. success=false also covers cancelled transfers;
    // error carries a human-readable reason when available.
    fun onTransferCompleted(transferId: String, success: Boolean, error: String?) {}
}
```

### 5.5 Types and enums

```kotlin
// Engine lifecycle state (mirrors litep2p_state_t).
enum class EngineState(val code: Int) {
    STOPPED(0), STARTING(1), RUNNING(2), STOPPING(3);
    companion object { fun fromCode(code: Int): EngineState }
}

// Result codes (mirror litep2p_result_t values exactly).
enum class EngineResult(val code: Int) {
    OK(0), INVALID_ARG(-1), INVALID_STATE(-2), BUSY(-3), NOT_FOUND(-4),
    IO(-5), TIMEOUT(-6), UNSUPPORTED(-7), NO_ROUTE(-8), INTERNAL(-99);
    companion object { fun fromCode(code: Int): EngineResult } // unknown -> INTERNAL
}

// Transport selection.
enum class CommsMode(val wire: String) {
    TCP("TCP"), UDP("UDP"), QUIC("QUIC"), ALL("ALL"), AUTO("AUTO");
    companion object {
        fun fromWire(wire: String?): CommsMode  // unknown/"HETEROGENEOUS" -> ALL; else UDP
    }
}

// How a peer connection was established.
enum class ConnectionPath {
    LAN_DIRECT, WAN_HOLE_PUNCH, TURN_RELAY, SIGNALING_RELAY, UNKNOWN;
    companion object { fun fromWire(wire: String?): ConnectionPath }
}

// Logging verbosity (0=DEBUG 1=INFO 2=WARN 3=ERROR).
enum class LogLevel(val level: Int) {
    DEBUG(0), INFO(1), WARN(2), ERROR(3);
    companion object { fun fromLevel(level: Int): LogLevel } // unknown -> INFO
}

// Reconnect aggressiveness.
enum class ReconnectMode(val wire: String) {
    AUTO("auto"), AGGRESSIVE("aggressive"), BALANCED("balanced"), POWER_SAVER("power_saver")
}
```

`PeerInfo` — snapshot of a single peer:

```kotlin
data class PeerInfo(
    val id: String,                 // stable peer identity
    val ip: String,                 // latest advertised/active endpoint IP
    val port: Int,                  // endpoint port
    val latency: Int,               // measured RTT in ms, or -1 when unknown
    val connected: Boolean,         // true when the session is fully established
    val networkId: String,          // LAN identity used for rendezvous
    val fsmState: String,           // best-effort peer FSM state
    val connectionType: String      // raw path string ("LAN"/"TURN"/"SIGNALING"/...)
) {
    // Typed connection path derived from connectionType.
    val connectionPath: ConnectionPath
}
```

> ⚠️ **JNI stability note:** `PeerInfo`'s primary constructor signature is part
> of the JNI contract (`(String,String,Int,Int,Boolean,String,String,String)`).
> Do not reorder or change its parameters in your own forks.

### 5.6 File transfer (Kotlin)

The Kotlin wrapper exposes the full offer/accept model:

```kotlin
// Sender: send a file to a connected peer. Returns the transfer id or null
// on failure (peer not connected / module unavailable).
val transferId: String? = LiteP2P.sendFile(
    peerId = "bob",
    filePath = "/data/user/0/com.example/cache/photo.jpg",
    priority = FileTransferPriority.HIGH       // LOW | NORMAL | HIGH
)

// Receiver: accept an incoming offer (onFileTransferOffered) or decline it.
val result = LiteP2P.acceptFileTransfer(offer.transferId, savePath)
LiteP2P.declineFileTransfer(offer.transferId)

// Both sides can manage a transfer by id.
LiteP2P.pauseTransfer(transferId)
LiteP2P.resumeTransfer(transferId)
LiteP2P.cancelTransfer(transferId)
```

- `FileTransferPriority` maps to the C ABI integer (`LOW=0`, `NORMAL=1`,
  `HIGH=2`); `<=0` → LOW, `>=2` → HIGH in the engine.
- The receiver is notified via `LiteP2PListener.onFileTransferOffered` /
  `transfersFlow`; **nothing is written to disk** until `acceptFileTransfer`.
- Progress (`0..100` + bytes/sec) and completion arrive via
  `onTransferProgress` / `onTransferCompleted` for **both** sender and receiver.
- `sendFile` is only accepted for an **established session**; send on a peer
  that is not connected returns null. Check `LiteP2P.supportsFileTransfer()`
  first when the module may be compiled out.

### 5.7 Feature detection (Kotlin)

```kotlin
// Compile-time capabilities of the native build. Safe to query at any time,
// including before LiteP2P.init.
val caps: LiteP2PCapabilities = LiteP2P.capabilities

if (caps.fileTransfer) LiteP2P.sendFile(...)
if (caps.overlay)      LiteP2P.sendOverlay(...)
if (caps.proxy)        LiteP2P.configureProxy(...)

// Individual helpers (equivalent to reading the booleans above):
LiteP2P.supportsFileTransfer()
LiteP2P.supportsOverlay()
LiteP2P.supportsProxy()
LiteP2P.supportsEncryption()
```

- `LiteP2PCapabilities` decodes the C ABI `LITEP2P_FEATURE_*` bitmask and is
  fixed for the process lifetime (build-time module availability).
- Degrade gracefully with these flags instead of relying on
  `EngineResult.UNSUPPORTED` at call time.

### 5.8 Reactive API (coroutines / Flow)

Requires `kotlinx-coroutines-core` (already exposed transitively by
`:litep2p-core`). All streams are **hot** — subscribe before starting the
engine to avoid missing early events.

```kotlin
// Observable lifecycle state (StateFlow; replays the current value).
LiteP2P.stateFlow.collect { state -> /* STOPPED..RUNNING.. */ }

// Full peer snapshots (replays the latest).
LiteP2P.peersFlow.collect { peers -> /* render roster */ }

// Received messages (bounded buffer; drops oldest under pressure).
LiteP2P.messagesFlow.collect { msg -> String(msg.data, Charsets.UTF_8) }

// LP_APP delivery confirmations, overlay completions, telemetry, logs.
LiteP2P.messageAcksFlow.collect { ack -> /* "delivered in ${ack.recvTsMs - ack.sentTsMs}ms" */ }
LiteP2P.overlayDeliveriesFlow.collect { d -> /* frameId + delivered */ }
LiteP2P.telemetryFlow.collect { json -> /* snapshot */ }
LiteP2P.logsFlow.collect { line -> /* level + line */ }

// File-transfer events as a single sealed stream.
LiteP2P.transfersFlow.collect { event ->
    when (event) {
        is LiteP2PTransferEvent.Offered   -> LiteP2P.acceptFileTransfer(event.offer.transferId, savePath)
        is LiteP2PTransferEvent.Progress  -> progressBar.value = event.progressPercent
        is LiteP2PTransferEvent.Completed -> /* done */ 
    }
}

// Suspend lifecycle helpers (run the blocking native calls on Dispatchers.IO
// and suspend until the requested state is reached, or TIMEOUT).
val startResult: EngineResult = LiteP2P.startAndAwait()   // suspends until RUNNING
val stopResult:  EngineResult = LiteP2P.stopAndAwait()    // suspends until STOPPED
```

Notes:

- Events are dispatched on **engine threads**; collect with the dispatcher you
  prefer (e.g. `Flow.flowOn(Dispatchers.Default)` or `lifecycleScope.launch`).
- Buffer policy: `peersFlow` and `telemetryFlow` replay the latest value
  (`replay = 1`); the others buffer a bounded number of events and drop the
  oldest under pressure. For lossless handling use the
  `LiteP2PListener` callbacks directly.
- `startAndAwait` / `stopAndAwait` return the immediate `EngineResult` when the
  request itself failed, `EngineResult.TIMEOUT` when the engine did not reach
  the target state within the timeout (default 15 s), else `EngineResult.OK`.

---

## 6. Messaging model

### 6.1 Fire-and-forget

`LiteP2P.send(peerId, data)` / `litep2p_send(...)` are **fire-and-forget**:
`EngineResult.OK` / `LITEP2P_OK` means the message was **accepted into the send
path**, not that it was delivered. There is no engine-level delivery callback.

What the engine *does* guarantee within an established session:

- Ordered delivery on the same session.
- Encrypted transport (Noise NK when enabled).
- Binary-safe payloads (arbitrary bytes with explicit length).
- Automatic reconnection and path failover (LAN → WAN hole-punch → TURN →
  signaling) so a session survives network changes.

What it does *not* guarantee:

- Delivery confirmation (you implement this at the app layer).
- Exactly-once semantics (you deduplicate by message id at the app layer).

### 6.2 App-layer ACK envelope protocol (`LP_APP` / `LP_APP_ACK`)

To measure/confirm delivery without engine-level support, LiteP2P recognizes a
simple JSON envelope protocol on the wire. **This is the recommended pattern
for chat delivery status.**

**Sending** — wrap your payload in an `LP_APP` envelope:

```json
{
  "type": "LP_APP",
  "msg_id": "<your-unique-id>",
  "requires_ack": true,
  "sent_ts_ms": 1723000000000,
  "body": "<your chat message, UTF-8>"
}
```

**Receiving** — the engine automatically:

1. Parses the envelope.
2. If `requires_ack` is true, immediately sends an `LP_APP_ACK` back to the
   sender with the original `msg_id`, the echoed `sent_ts_ms`, and a fresh
   `recv_ts_ms`.
3. Forwards **only the `body` field** to `LiteP2PListener.onMessageReceived` /
   `on_message_received` (so your chat code sees clean text, not the envelope).

**ACK receipt** — when the sender receives the `LP_APP_ACK`, the engine fires
`LiteP2PListener.onMessageAcked(messageId, sentTsMs, recvTsMs)` on Android
(and `sendMessageAckToUI` on the JNI/desktop path). Delivery latency =
`recvTsMs - sentTsMs`.

> **Key point:** any peer (LiteP2P or not) can participate by emitting the same
> JSON envelopes. If a peer sends plain bytes without the envelope, they are
> forwarded verbatim to `onMessageReceived` and no ACK is generated.

### 6.3 Sizing and backpressure

- Plain `send` payloads are bounded by `peer_management.max_message_size`
  (default 10 MB in `config.json`).
- The per-peer send queue is bounded by `peer_management.max_queued_messages`
  (default 100). When full, the engine drops or applies backpressure — keep
  chat messages small and rate-limit heavy bursts.
- Overlay sends have their own smaller cap (640 bytes; see §7).

---

## 7. Overlay / multi-hop routing model

The overlay (LPX2) routes application messages through **N sealed relay hops**
(onion-lite). It is designed for censorship-resistant chat: no single relay can
link a message to its origin, and messages can be delivered offline via
mailboxes.

- **Hops:** configurable via `overlay.default_hops` (0–3) in `config.json`.
- **Sealing:** each hop can only unwrap one layer. Every payload is signed
  with the origin's Ed25519 key. On receipt, if a signing key is registered for
  the claimed origin, the signature must match or the frame is dropped; with
  `overlay.require_origin_auth` set, unsigned frames are dropped even when no
  key is registered.
- **Relay opt-in:** forwarding frames / holding mailboxes is **off by default**.
  A peer becomes a relay by calling `LiteP2P.setOverlayRelayEnabled(true)` or
  setting `overlay.relay_enabled` in `config.json`.
- **Bootstrap relays:** list persistent candidates in `overlay.relay_peers`
  (array of peer ids) in `config.json`, or register at runtime with
  `LiteP2P.registerRelay(...)`.
- **Delivery notification:** `sendOverlay(..., wantAck = true)` returns a
  32-char frame id; completion arrives via
  `LiteP2PListener.onOverlayDelivery(frameId, delivered)`.
- **Offline delivery:** `sendOverlay(..., viaMailbox = true)` holds the frame
  at the terminal relay until the destination calls
  `LiteP2P.pickupMailbox(relayPeerId)`.
- **Payload limit:** max **640 bytes** per overlay message — suitable for short
  chat texts and presence, not for large media (use `LiteP2P.send` for those).

Security model:

- Every participant has an Ed25519 signing keypair (used to sign overlay
  payloads) plus the Noise NK static keypair (used for the encrypted transport
  between hops).
- Origin authentication is **opt-in**: set `overlay.require_origin_auth=true`
  and register destination signing keys with
  `LiteP2P.registerPeerSigningKey(peerId, publicKeyHex)` to drop unsigned
  payloads.
- Traffic-analysis resistance is **opt-in**: `overlay.padding_bucket`,
  `overlay.obfuscate_transport`, and `overlay.cover_interval_ms` add padding,
  per-link obfuscation, and cover traffic.

---

## 8. Telemetry contract

Telemetry snapshots are **single-line JSON**. They are pushed periodically via
`LiteP2PListener.onTelemetry` (interval governed by
`monitoring.telemetry.flush_interval_ms` in `config.json`, default 30000 ms,
2000 ms in the shipped Android assets config) and on shutdown, and pulled on
demand via `LiteP2P.telemetrySnapshot()` / `litep2p_telemetry_snapshot`.
`LiteP2PConfig.telemetryIntervalMs` / `litep2p_config.telemetry_interval_ms`
(default 30000) is accepted and forwarded through the ABI.

### 8.1 Schema (as emitted by the engine)

```json
{
  "ts_ms": 1723000000000,
  "uptime_ms": 123456,
  "engine_id": "<peer-id>",
  "reason": "periodic|snapshot|shutdown|c_api",
  "include_peer_ids": true,
  "counters": { "messages_sent": 10, "..." : 0 },
  "gauges":   { "peers_connected": 2, "rss_bytes": 12345678, "..." : 0 },
  "hists_ms": { "connect_latency": { "count": 3, "sum": 450, "min": 100, "max": 200 } },
  "peers": [
    { "peer_id": "...", "connection_path": "LAN_DIRECT",
      "is_connected": true, "connected_at_ms": 1723000000000 }
  ],
  "connection_summary": {
    "total_peers": 3, "connected": 2,
    "lan_direct": 1, "wan_hole_punch": 1, "turn_relay": 0,
    "signaling_relay": 0, "unknown": 0
  }
}
```

Field notes:

- `reason` values: `"periodic"` (scheduled flush), `"snapshot"`,
  `"shutdown"`, and `"c_api"` (manual `telemetrySnapshot()`/`litep2p_telemetry_snapshot`).
- `include_peer_ids` reflects `monitoring.telemetry.include_peer_ids` in
  `config.json`. When false, the `peers` array is still present but
  `peer_id` is redacted (`""`). The `connection_summary` counts remain intact.
- There is **no `schema` version field**; the field set is stable and evolves
  additively. Applications should treat unknown keys as optional.
- Histogram entries use `count`/`sum`/`min`/`max` (ms); empty histograms are
  emitted with all zeros.

### 8.2 Common counters

Connection/session: `connect_requested_total`, `connect_success_total`,
`connect_failed_total`, `connect_suppressed_total`, `disconnect_detected_total`,
`handshake_required_total`, `handshake_success_total`,
`handshake_failed_total`, `network_change_total`, `engine_start_total`,
`engine_stop_total`, `noise_session_reset_total`, `noise_decrypt_fail_total`.

Messaging: `rx_app_messages_total`, `rx_app_bytes_total`, `rx_bytes_total`,
`rx_events_total`, `rx_app_acks_total`, `tx_app_acks_total`.

Overlay: `overlay_tx_total`, `overlay_relayed_total`, `overlay_delivered_total`,
`overlay_ack_tx_total`, `overlay_cover_tx_total`, `overlay_cover_rx_total`,
`overlay_auth_fail_total`, `overlay_mailbox_stored_total`,
`overlay_mailbox_picked_total`.

### 8.3 Gauges (resource usage)

`peers_total`, `peers_connected`, `peers_state_connecting`,
`peers_state_handshaking`, `peers_state_ready`, `pending_messages_total`,
`signaling_connected`, `signaling_registered`, `network_available`,
`network_is_wifi`, `rss_bytes` (RAM footprint), `thread_count`,
`cpu_pct_estimate` (best-effort sampled jiffies).

---

## 9. `config.json` reference

On startup the engine discovers `config.json` in the directory given by
`filesDir` (or `configPath` if provided) and applies it **on top of** the
programmatic configuration. The repo-root `config.json` is the desktop
reference; `app/src/main/assets/config.json` is the Android default (copied to
app-private storage on first launch).

Most keys are engine tuning knobs and safe to leave at defaults. The keys a
chat application is most likely to care about:

| Section / key | Default | Purpose |
|---|---|---|
| `network.default_server_port` | `30001` | Main listener port |
| `network.discovery_port` | `30000` | LAN broadcast discovery port |
| `communication.default_protocol` | `"UDP"` | `"TCP"`, `"UDP"`, `"QUIC"` |
| `communication.tcp/udp/quic.enabled` | `true` | Per-transport toggles |
| `communication.*.port` | `30001` | Per-transport listen ports |
| `peer_management.max_message_size` | `10485760` (10 MB) | Largest accepted message |
| `peer_management.max_queued_messages` | `100` | Per-peer send queue bound |
| `peer_management.peer_timeout_sec` | `30` | Peer liveness timeout |
| `security.noise_nk_protocol.enabled` | `true` | Noise NK sessions on/off |
| `security.noise_nk_protocol.key_store_path` | `"keystore"` | Where Noise keys are persisted (relative to `filesDir`) |
| `security.transport_key` | *(shared secret)* | **Must match across all peers** that talk to each other; control-plane datagrams cannot be decrypted otherwise |
| `discovery.message_prefix` | `"LITEP2P_DISCOVERY"` | LAN discovery marker |
| `nat_traversal.enabled` | `true` | STUN/TURN/hole-punch overall switch |
| `nat_traversal.stun_enabled` | `true` | STUN for external address discovery |
| `nat_traversal.turn_enabled` | `true` | TURN relay fallback (public TURN server) |
| `nat_traversal.turn_config` | *(see config)* | TURN server address/credentials |
| `nat_traversal.hole_punching_enabled` | `true` | UDP hole punching |
| `signaling.enabled` | `true` | Central signaling rendezvous |
| `signaling.url` | `"ws://<host>:8765"` | Signaling server WebSocket URL |
| `overlay.relay_enabled` | `false` | Become an overlay relay (opt-in) |
| `overlay.default_hops` | `0` | Overlay hop count (0–3) |
| `overlay.relay_peers` | `[]` | Persistent bootstrap relay peer ids |
| `overlay.padding_bucket` | `0` | Padding bucket bytes for traffic-analysis resistance (0=off, max 4096) |
| `overlay.obfuscate_transport` | `false` | Per-link payload obfuscation |
| `overlay.cover_interval_ms` | `0` | Cover-traffic interval (0=off) |
| `overlay.pex_interval_ms` | `0` | Peer-exchange advertisement interval |
| `overlay.require_origin_auth` | `false` | Enforce Ed25519 origin signatures |
| `monitoring.telemetry.enabled` | `true` | Telemetry collection |
| `monitoring.telemetry.flush_interval_ms` | `2000` | Telemetry flush cadence |
| `monitoring.telemetry.include_peer_ids` | `true` | Include peer ids in telemetry (false = redact) |
| `reconnect_policy.mode` | `"auto"` | Initial reconnect aggressiveness |
| `battery_optimizer.enabled` | `true` | Battery-aware scheduling |
| `logging.level` | `"debug"` | Engine log verbosity |
| `storage.peer_db.enabled` | `false` | SQLite peer DB for reconnection candidates |

> ⚠️ **`security.transport_key`** is a **shared network secret**. Every peer in
> the same network must run with the same value (desktop reads repo-root
> `config.json`, Android reads its assets copy). Mismatched keys cause
> `CONTROL_CONNECT` datagrams to fail decryption and peers stay `CONNECTING`
> forever. Do not bake real TURN credentials into shipped APKs.

### 9.1 Peer DB (SQLite)

When `storage.peer_db.enabled` is true, the engine maintains
`litep2p_peers.sqlite` under `filesDir` with `peers`, `peer_events`, and `meta`
tables, auto-pruning stale peers after `prune_after_days` (default 15) and
pinning the first peer ever seen. This powers fast reconnection after restarts.

---

## 10. Identity and addressing

- `peer_id` is a **stable UTF-8 string** and the primary key for connections,
  keys, and telemetry attribution. Choose a stable, unique id for your chat
  identity (e.g. a user name, a generated UUID, or a derived key fingerprint).
- If `config.peerId` is null, the engine generates a **persistent device id**
  and reports it via `LiteP2P.peerId` / `litep2p_get_peer_id`.
- The local Noise NK static keypair is persisted under `filesDir/keystore` and
  remains stable across restarts — a user's identity can be tied to it.
- Discovery populates `network_id` (the LAN endpoint, usually `"ip:port"`)
  used for rendezvous between peers on the same local network.
- Out-of-band peer invites can be bootstrapped with `LiteP2P.addPeer(peerId,
  networkId)` (e.g. from a scanned QR code containing the peer's id + endpoint).

## 11. Threading and lifecycle contract

### 11.1 Threading

- `LiteP2P` / `litep2p_*` are **safe to call from any thread**.
- Listener callbacks are dispatched on **internal engine threads**. They are
  NOT posted to the main thread — that is the consumer's responsibility.
- Callback bodies must **not block** (no network I/O, no long DB writes, no
  sleeps). Copy out the data you need (`ByteArray` from `onMessageReceived`)
  and return quickly.
- Recommended pattern: bridge callbacks to the UI thread with
  `Handler(Looper.getMainLooper()).post { ... }`, a `MutableLiveData`, or a
  `Flow`/`Channel` adapter.

### 11.2 Lifecycle

State machine: `STOPPED → STARTING → RUNNING → STOPPING → STOPPED`.

```
init(config)  → stores config (STOPPED only; INVALID_STATE if STARTING/RUNNING)
start()       → accepted only from STOPPED; engine reports onEngineStarted
stop()        → accepted from RUNNING (or no-op if already STOPPED/STOPPING)
shutdown()    → stops if needed, releases all native state; idempotent; re-init allowed after
```

Best practice for a chat app:

1. `addListener` early (Application or MainActivity `onCreate`).
2. `init` once; then `start` on user action / service start.
3. On app stop or logout: `stop()` (keep config), or `shutdown()` (full teardown).
4. After `shutdown()`, a fresh `init()` starts clean.

### 11.3 Single-thread vs multi-thread mode

The engine ships in two flavors: `multiThread` (default) and `singleThread`
(`SINGLE_THREAD_MODE` CMake toggle). `singleThreadMode` in `LiteP2PConfig` is
accepted but currently a compile-time hint only. The `singleThread` flavor
reduces thread count and RAM — useful for very constrained devices; the
multi-threaded flavor gives lower latency under load.

## 12. Reliability and operations guidance

The engine is designed to be "rigid and reliable":

- **Lifecycle rigidity:** start/stop races, double-start, stop-while-starting,
  double-init, and shutdown-while-running are handled without crashes or
  deadlocks (guarded state machine; verified by the C ABI test suite).
- **JNI safety:** no pending-exception leaks across the JNI boundary
  (`ExceptionClear` discipline in `jni_bridge.cpp`).
- **Reconnection:** peer sessions recover across NAT rebinding, Wi-Fi↔cellular
  switches, and interface changes. Feed the engine
  `LiteP2P.setNetworkInfo(...)` on every connectivity change to speed recovery.
- **Bounded resources:** memory and thread counts stay within documented
  budgets per mode, verifiable via the §8 gauges (`rss_bytes`, `thread_count`).
- **Clean shutdown:** `stop` completes within a documented deadline; sockets,
  threads, and file handles are released; `shutdown` is idempotent.

Operational checklist for a production chat app:

- Register listeners **before** starting the engine.
- Handle `onPeersChanged` as a full snapshot (replace, don't merge).
- Copy received `ByteArray` payloads out of the callback.
- Feed connectivity/battery hints (`setNetworkInfo`, `setBatteryLevel`) from
  Android `ConnectivityManager`/`BatteryManager` callbacks.
- Run the engine in a foreground `Service` (as the harness does) so Doze/battery
  saver does not suspend packet delivery.
- Use the LP_APP envelope for delivery status; deduplicate by `msg_id`.

---

## 13. Chat application integration guide

This section is a concrete blueprint for building the application layer of a
chat app on top of LiteP2P. The harness (`:app`) is a working reference for
every pattern below.

### 13.1 Recommended message flow

1. **Identity:** give every user a stable `peerId` (persisted across launches)
   and register it in `LiteP2PConfig.Builder().peerId(id)`.
2. **Bootstrap peers:** LAN discovery finds nearby peers automatically. For
   remote peers, exchange `peerId` (+ optional `networkId`) out-of-band (QR,
   deep link, or a directory server) and call `LiteP2P.addPeer(peerId,
   networkId)`. For NAT traversal across the internet, the engine uses
   STUN/TURN/signaling automatically (`config.json`).
3. **Send chat text:** wrap messages in the LP_APP envelope
   ([§6.2](#62-app-layer-ack-envelope-protocol-lp_app--lp_app_ack)) with a
   unique `msg_id` and `requires_ack: true` to get delivery status. UTF-8
   encode the `body`.
4. **Receive chat text:** handle `onMessageReceived` — the engine already
   stripped the envelope, so `String(data, Charsets.UTF_8)` is your chat line.
   Match `peerId` to a conversation.
5. **Delivery status:** handle `onMessageAcked(messageId, sentTsMs, recvTsMs)`
   to show "delivered" and compute latency. Messages that never ACK can be
   re-sent or flagged by your app.
6. **Presence/peers:** render `onPeersChanged` as the roster; use `PeerInfo.
   connected` for online/offline and `connectionPath` to show
   LAN/relay/indirect.

### 13.2 Censorship-resistant mode (optional)

For blocked-network deployments:

- Set `overlay.relay_enabled: true` on some peers (or call
  `LiteP2P.setOverlayRelayEnabled(true)`) and list them in
  `overlay.relay_peers`.
- Send short messages via `LiteP2P.sendOverlay(peerId, data, wantAck = true)`.
- For offline peers, use `viaMailbox = true` + periodic
  `LiteP2P.pickupMailbox(relayPeerId)`.
- Enable `overlay.require_origin_auth` and register signing keys with
  `LiteP2P.registerPeerSigningKey` for stronger authenticity.
- Keep overlay payloads under 640 bytes.

### 13.3 Android service integration

The harness runs the engine in a **foreground service**
(`app/.../LiteP2PService.kt`) with partial wakelock + Wi-Fi multicast lock so
Doze does not suspend packet delivery. Copy that pattern: engine lifecycle in a
service, UI subscribed to LiveData/Flow bridges, `START_STICKY` return value.

### 13.4 Android connectivity/battery hints

```kotlin
// In a ConnectivityManager.NetworkCallback:
LiteP2P.setNetworkInfo(isWifi, isNetworkAvailable)

// In a BatteryManager / ACTION_BATTERY_CHANGED receiver:
LiteP2P.setBatteryLevel(percent, isCharging)

// On flaky networks, raise reconnect aggressiveness:
LiteP2P.setReconnectMode(ReconnectMode.AGGRESSIVE)
```

---

## 14. Worked examples

### 14.1 Kotlin — minimal 1:1 chat

```kotlin
class ChatEngine(private val context: Context) {

    private val main = Handler(Looper.getMainLooper())
    private val chatLines = MutableLiveData<List<Pair<String, String>>>() // (peerId, text)
    private val pendingAcks = mutableMapOf<String, Long>()

    private val listener = object : LiteP2PListener {
        override fun onEngineStarted() = log("engine started, my peer id = ${LiteP2P.peerId}")
        override fun onPeersChanged(peers: List<PeerInfo>) {
            // peers is a full snapshot: render roster, update online/offline
            roster.postValue(peers)
        }
        override fun onMessageReceived(peerId: String, data: ByteArray) {
            val text = String(data, Charsets.UTF_8)
            main.post { chatLines.value = (chatLines.value ?: emptyList()) + (peerId to text) }
        }
        override fun onMessageAcked(messageId: String, sentTsMs: Long, recvTsMs: Long) {
            val latencyMs = if (recvTsMs > 0 && sentTsMs > 0) recvTsMs - sentTsMs else -1
            main.post { deliverStatus.postValue("$messageId delivered in ${latencyMs}ms") }
        }
    }

    fun start() {
        LiteP2P.addListener(listener)
        val cfg = LiteP2PConfig.Builder()
            .filesDir(context.filesDir.absolutePath)
            .peerId(UserPrefs.loadPeerId(context))   // stable identity
            .commsMode(CommsMode.UDP)
            .build()
        check(LiteP2P.init(cfg) == EngineResult.OK)
        check(LiteP2P.start() == EngineResult.OK)
    }

    fun send(peerId: String, text: String) {
        val msgId = UUID.randomUUID().toString()
        val envelope = JSONObject().apply {
            put("type", "LP_APP")
            put("msg_id", msgId)
            put("requires_ack", true)
            put("sent_ts_ms", System.currentTimeMillis())
            put("body", text)
        }.toString()
        LiteP2P.send(peerId, envelope.toByteArray(Charsets.UTF_8))
        pendingAcks[msgId] = System.currentTimeMillis()   // for UI + re-send
    }

    fun stop() {
        LiteP2P.stop()
        LiteP2P.shutdown()
    }
}
```

### 14.2 C ABI — desktop-style usage

```c
#include "litep2p.h"

static void on_message(void* /*ud*/, const char* peer_id,
                       const uint8_t* data, uint32_t len) {
    printf("[%s] %.*s\n", peer_id, (int)len, (const char*)data);
}

int main(void) {
    litep2p_config_t cfg;
    litep2p_config_init(&cfg);
    cfg.peer_id    = "desktop-alice";
    cfg.comms_mode = "UDP";
    cfg.files_dir  = "/tmp/litep2p-alice";

    litep2p_callbacks_t cb = {0};
    cb.struct_size         = sizeof(cb);
    cb.on_message_received = on_message;
    litep2p_set_callbacks(&cb);

    if (litep2p_init(&cfg) != LITEP2P_OK) return 1;
    if (litep2p_start() != LITEP2P_OK)    return 1;

    const char* bytes = "hello, bob!";
    litep2p_send("bob", (const uint8_t*)bytes, (uint32_t)strlen(bytes));

    /* ... run event loop ... */

    litep2p_stop();
    litep2p_shutdown();
    return 0;
}
```

---

## 15. Error code quick reference

| `EngineResult` / `litep2p_result_t` | Value | Meaning |
|---|---|---|
| `OK` / `LITEP2P_OK` | 0 | Success |
| `INVALID_ARG` / `LITEP2P_ERR_INVALID_ARG` | -1 | Bad argument (blank id, empty payload, bad hex) |
| `INVALID_STATE` / `LITEP2P_ERR_INVALID_STATE` | -2 | Operation not valid in the current engine state (e.g. `send` before `start`) |
| `BUSY` / `LITEP2P_ERR_BUSY` | -3 | Start/stop already in progress |
| `NOT_FOUND` / `LITEP2P_ERR_NOT_FOUND` | -4 | Unknown peer / transfer id |
| `IO` / `LITEP2P_ERR_IO` | -5 | I/O failure |
| `TIMEOUT` / `LITEP2P_ERR_TIMEOUT` | -6 | Operation timed out |
| `UNSUPPORTED` / `LITEP2P_ERR_UNSUPPORTED` | -7 | Feature compiled out or not wired yet |
| `NO_ROUTE` / `LITEP2P_ERR_NO_ROUTE` | -8 | Overlay: no relay path available |
| `INTERNAL` / `LITEP2P_ERR_INTERNAL` | -99 | Internal engine error |

> `EngineResult.fromCode` maps any unrecognized native code to `INTERNAL`.
> `LiteP2P.sendOverlay` returns `null` on failure; the underlying C ABI error is
> `LITEP2P_ERR_NO_ROUTE` when no relay path is available.

---

*End of SDK reference. For engine-internal engineering templates, see
[`docs/IMPLEMENTATION_TEMPLATES.md`](./IMPLEMENTATION_TEMPLATES.md) — that
document is not part of the public SDK surface.*

