# LiteP2P

**Lightweight, efficient peer-to-peer networking SDK for Android** — a C++17
engine with a Kotlin API, distributed as an AAR.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Android%20(minSdk%2024)-brightgreen)](litep2p-core/build.gradle.kts)
[![Version](https://img.shields.io/badge/version-0.4.0-orange)](gradle.properties)

> **Status:** `0.x` pre-release. The public contract is the C ABI
> (`litep2p.h`) + the Kotlin wrapper; expect breaking changes until `1.0`.
> The full integration reference lives in **[docs/api-spec.md](docs/api-spec.md)**.

---

## What it does

LiteP2P handles the entire P2P network layer so application layers (chat,
sync, file sharing, censorship-resistant messaging) can be built on top
without dealing with P2P complexity:

- **Discovery** — LAN broadcast discovery + signaling-server based WAN discovery
- **Connectivity** — LAN direct, WAN hole-punching, TURN relay, signaling relay;
  NAT traversal via STUN/TURN/UPnP
- **Transports** — TCP, UDP, and QUIC (picoquic), selectable per engine
  (`TCP` / `UDP` / `QUIC` / `ALL` / `AUTO`)
- **Security** — Noise NK encrypted sessions (libsodium), per-peer transport
  keys, Ed25519 origin authentication
- **Messaging** — binary-safe fire-and-forget sends **plus v0.4 reliable
  sends**: at-least-once delivery with engine-level receipts
  (`sendReliable` → `onDeliveryStatus`), a persistent outbox that survives
  restarts, receiver-side dedup, and store-and-forward offline mailboxes via
  the signaling server; explicit `QUEUE_FULL` backpressure with live gauges
  (`pendingSendCount()` / `reliablePendingCount()`). (The legacy app-layer
  ACK envelope protocol remains for interop/latency measurement.)
- **File transfer** — offer/accept model, chunking, congestion control,
  pause/resume/cancel, checkpointing
- **Overlay routing (LPX2)** — multi-hop onion-style relay routing with
  offline mailboxes, bounded-reliable delivery, replay protection, and
  secure-by-default censorship resistance (OBF1 transport obfuscation,
  length padding, Ed25519 origin authentication — all opt-out; relay role
  opt-in; see `docs/censorship-resistance.md`)
- **Operations** — first-class telemetry (counters, gauges, latency
  histograms, connection paths), environment hints (battery/network),
  reconnect policies, single-thread mode for reduced resource usage
- **Identity & presence (v0.4)** — opaque alias directory on the signaling
  server (`registerAlias` / `lookupPeer` / `invitePeer`), server-assisted
  presence + last-seen (`subscribePresence` / `onPresence`), cheap RTT pings
  (`ping`), and `PeerInfo.lastSeenMs`
- **Turnkey Android runtime (v0.4)** — `LiteP2PRuntime.start(context)` boots
  the engine in an SDK-owned foreground service: wakelocks, manifest-merged
  permissions, automatic network/battery/Doze hints, sticky restore after
  process death, and a bundled default config + stable peer id. Correct
  background operation in one line.

## Architecture

```
Consumer app
   │  depends on
   ▼
:litep2p-core (AAR)
   ├── Kotlin API — LiteP2P, LiteP2PConfig, LiteP2PListener, flows
   ├── JNI binding layer (jni_bridge.cpp)
   ├── C ABI — litep2p.h  ← THE PUBLIC CONTRACT
   └── C++ engine — SessionManager + modules (transport, crypto/Noise,
       discovery, routing/NAT, session, file transfer, overlay, proxy,
       optimization, telemetry)
```

Design rules: one engine per process (singleton, no handles), stable C ABI
(changes only on a major version bump), zero Android framework types in the
engine, callback-driven events, binary-safe buffers. See
[docs/api-spec.md §1 and §3](docs/api-spec.md).

## Quickstart (Android)

Publish to Maven Local (or depend on the module/AAR directly — all options in
[docs/api-spec.md §2.1](docs/api-spec.md)):

```bash
./gradlew :litep2p-core:publishMultiThreadReleasePublicationToMavenLocal
```

```kotlin
// settings.gradle.kts — repositories { mavenLocal(); google(); mavenCentral() }
// app/build.gradle.kts
dependencies {
    implementation("com.zeengal:litep2p-core:0.4.0")
}
```

```kotlin
import com.zeengal.litep2p.core.*

// ── Zero-config path (v0.4) ─────────────────────────────────────────────
// One line: foreground service, wakelocks, permissions (manifest-merged),
// network/battery/Doze hints, sticky restore, default config + peer id.
LiteP2PRuntime.start(context)
// … later:
LiteP2PRuntime.stop(context)

// ── Manual path (same engine, full control) ─────────────────────────────
// 1. Register listeners BEFORE starting (callbacks arrive on engine threads).
LiteP2P.addListener(object : LiteP2PListener {
    override fun onEngineStarted() { /* engine is up */ }
    override fun onPeersChanged(peers: List<PeerInfo>) { /* render peer list */ }
    override fun onMessageReceived(peerId: String, data: ByteArray) { /* message */ }
})

// 2. Configure + initialize (once per process).
LiteP2P.init(
    LiteP2PConfig.Builder()
        .filesDir(context.filesDir.absolutePath)   // required on Android
        .commsMode(CommsMode.UDP)
        .build()
)

// 3. Start (completion via onEngineStarted / LiteP2P.stateFlow).
LiteP2P.start()

// 4. Send / receive, then stop when done.
LiteP2P.send(peerId, "hello".toByteArray())                 // fire-and-forget
LiteP2P.sendReliable(peerId, msgId, "must arrive".toByteArray()) // with receipts
LiteP2P.stop()
LiteP2P.shutdown()
```

Reactive variants (`stateFlow`, `messagesFlow`, `deliveryStatusFlow`,
`presenceFlow`, `startAndAwait()`) and the full API reference (reliable
messaging, aliases/invites, presence/ping, file transfer, overlay, proxy,
telemetry, environment hints) are in [docs/api-spec.md §5](docs/api-spec.md).

## Building

Prerequisites: JDK 17, Android SDK (compileSdk 36), NDK `26.1.10909125`
(pinned), CMake 3.22.1.

```bash
# Android AAR (both thread-mode flavors)
./gradlew :litep2p-core:assembleMultiThreadRelease
./gradlew :litep2p-core:assembleSingleThreadRelease

# JVM unit tests (pure-Kotlin wire mapping)
./gradlew :litep2p-core:testMultiThreadDebugUnitTest
./gradlew :litep2p-core:testSingleThreadDebugUnitTest
```

The AAR packages `arm64-v8a`, `armeabi-v7a`, and `x86_64` (32-bit `x86` is
excluded: its vendored libsodium is not `-fPIC`). Vendored libsodium static
libs live under `litep2p-core/src/main/cpp/libsodium/<abi>/`; regenerate with
`tools/build_libsodium_android.sh`.

### Desktop (development/test target)

The same engine + `litep2p.h` contract builds for Linux/macOS under
`desktop/` — this is the C ABI conformance target, not a published artifact.

```bash
# macOS: brew install libsodium nlohmann-json   |   Linux: apt install libsodium-dev nlohmann-json3-dev
cmake -S desktop -B desktop/build -DCMAKE_BUILD_TYPE=Release
cmake --build desktop/build -j"$(nproc)"
./desktop/build/bin/c_api_test        # C ABI conformance suite
```

## Testing

| Suite | Where | What it covers |
|---|---|---|
| `LiteP2PCoreTest` (JVM) | `./gradlew :litep2p-core:test…UnitTest` | Kotlin enums/wire mapping vs the C ABI |
| `c_api_test` | `desktop/tests/` | Public C ABI end-to-end (lifecycle, config, disconnect, file-transfer errors, overlay) |
| `crypto_test`, `nat_traversal_test`, `file_transfer_test`, `overlay_test`, `proxy_test` | `desktop/tests/` | Engine module unit/integration tests (hermetic, loopback/in-memory) |
| `quic_test` | `desktop/tests/` | Optional real-QUIC loopback handshake/datagram test; built only with `LITEP2P_ENABLE_REAL_QUIC=ON` and picoquic/picotls available |
| `session_manager_test` | `desktop/tests/` | SessionManager lifecycle/FSM tests; LAN discovery and external subsystems are disabled for hermetic execution |
| `wan_integration_runner`, stress suite | self-hosted CI (`litep2p-sg`/`litep2p-us`) | Real WAN connectivity, packet loss, reconnect churn |
| `tools/harness/` | scripts | e2e messaging, Android connectivity matrices, soak tests |

CI (`.github/workflows/build-and-publish.yml`) builds both Android flavors
for all configured ABIs, runs both flavor JVM unit-test suites, builds and
runs the standard desktop regression set and fuzz smoke tests on every
push/PR. A real-QUIC desktop build runs `quic_test` separately when its
vendored dependencies are enabled. Publishing is tag-gated and requires the
Android, desktop, and fuzz jobs to pass before Maven artifacts are attached to
a GitHub Release on `v*` tags. WAN and stress suites remain scheduled or
manually dispatched because they require dedicated self-hosted infrastructure;
they are operational validation, not enforced tag-release gates.

## Repository layout

```
litep2p-core/          The SDK (Kotlin API + JNI + C++ engine) → AAR
  src/main/cpp/include/litep2p.h   Public C ABI contract
app/                   Development/test harness app (not part of the SDK surface)
desktop/               Linux/macOS build of the same engine; C ABI test suites
docs/api-spec.md       SDK reference (THE integration document)
tools/                 Harness scripts, signaling server, connectivity tests
third_party/           Vendored picoquic/picotls (fetched/built separately)
.github/workflows/     CI: build/test/publish, nightly stress + WAN suites
```

## Configuration

Runtime behavior is driven by `config.json` (discovered in `files_dir`; see
`config.example.json` for the full annotated template and
[docs/api-spec.md §9](docs/api-spec.md) for the reference). Local runtime
config with real endpoints/credentials is git-ignored by design.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
