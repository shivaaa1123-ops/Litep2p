# Network OS Phase 0 — Step 1.1: C++ Module Inventory

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** Every module under `litep2p-core/src/main/cpp/modules/`.
**Purpose:** Baseline for every KEEP/HARDEN/REFACTOR/REPLACE decision in Phases 1–12.

All paths relative to `litep2p-core/src/main/cpp/`.

## 1. Inventory table

| Module | Key classes / files | Responsibility | Interfaces exposed | Test coverage |
|---|---|---|---|---|
| `corep2p/core` | `ConfigManager` (`config_manager.h:12`), `logger`, `device_utils`, `constants.h`, `telemetry.h` | Config loading (`config.json` + `setValueAtPath` dynamic overrides), logging, device identity (`get_persistent_device_id`), compile-time constants, telemetry | `ConfigManager::getInstance()` singleton; `get_persistent_device_id()` | via `c_api_test`, `session_manager_test` |
| `corep2p/crypto` | `noise_nk` (`noise_nk.h:28`), `noise_key_store` (`noise_key_store.h:25`), `crypto_utils`, `noise_protocol`, `aes`, `sha1_md5` | Noise NK handshake + AEAD session crypto, persistent key storage, XChaCha20/AES helpers | `NoiseNKManager`, `NoiseKeyStore` | `crypto_test`, `malformed_input_test` |
| `corep2p/dynamic_config` | `dynamic_configuration_manager` | Runtime config overrides layered over `ConfigManager` | JSON snapshot + path-based get/set | indirect |
| `corep2p/monitoring` | `anomaly_reporter`, `crash_handler` | Structured incident logging (JSON) + async-safe crash handler, anomaly dedup/rate-limit, uploader | incident files under `base_dir/anomalies` | `crash_probe`, `anomalies/` harness |
| `corep2p/reactor` | `epoll_reactor`, `event_thread_pool` | (multi-thread flavor) epoll reactor + worker pool | reactor event loop | indirect |
| `corep2p/security` | `secure_session` (`secure_session.h`) | Wraps Noise NK sessions with replay-drop detection (`receive_message(..., replay_drop)`) | `SecureSession` / `SecureSessionManager` | `crypto_test` |
| `corep2p/transport` | `connection_manager` (TCP, `connection_manager.h:10`), `udp_connection_manager`, `quic_connection_manager`, `real_quic_transport`, `tcp_message`, `udp_message`, `quic_message` | Socket lifecycle, TCP/UDP/QUIC framing, single-thread event-loop variants (`startServerEventLoop`), bound-port fallback (`getBoundPort`) | `ITcpConnectionManager` / `IUdpConnectionManager` | `quic_test` (QUIC); indirect TCP/UDP |
| `plugins/session` | `session_manager` (`session_manager.h:31`, cpp 6373 lines, PIMPL `session_manager_p.h`), `peer_manager`, `peer_state_machine`, `event_manager`, `unified_event_loop`, `wire_codec`, `local_peer_db`, `reliable_send_manager`, `rugged_recovery_manager`, `session_cache`, `tier_manager`, `nat_traversal_manager`, `engine_handler`, `message_handler`, `maintenance_manager`, `peer_lifecycle_manager` | Peer FSM, event loop, wire codec, peer DB (JSON), reliable send + outbox + dedup, session cache, tiers, reconnect, maintenance | `SessionManager` facade; delivery-status/presence/ping/lookup/invite callbacks | `session_manager_test` |
| `plugins/overlay` | `overlay_mailbox` (`overlay_mailbox.h:32`), `overlay_router` (`overlay_router.h:51`), `overlay_frame` | Multi-hop onion routing (LPX2), sealed blobs, bounded mailbox (entry/byte caps, per-origin quota, TTL, LRU), dedup/replay, cover traffic, padding, PEX, Ed25519 origin auth | `OverlayRouter` with `SendFn`/`DeliverFn`/`DeliveryCb` | `overlay_test` |
| `plugins/discovery` | `broadcast_discovery_manager`, `discovery` (`discovery.h:7`), `peer_cache_lru`, `signaling_client` | LAN discovery (obfuscated magic + shared-key AEAD), peer LRU, WebSocket signaling client (alias/invite/presence/mailbox) | `Discovery` interface + `parse_discovery_announcement` (fuzzable) | indirect + `malformed_input_test` |
| `plugins/file_transfer` | `file_transfer_manager`, `transfer_types` (`CHUNK_SIZE=32KB`, `MAX_CHUNKS_IN_FLIGHT=16`), `file_transfer_checkpoint`, `file_transfer_chunks`, `file_transfer_congestion`, `file_transfer_paths` | Chunked transfer engine: OFFER/ACCEPT/DECLINE/CANCEL/PAUSE/RESUME, checkpoint resume, congestion, retransmit backoff, stall timeout | `FileTransferManager` via `wire_file_transfer_manager()` | `file_transfer_test` |
| `plugins/proxy` | `proxy_endpoint` | SOCKS-style proxy: gateway (opt-in) + client, per-stream IO threads | `ProxyEndpoint` (`ENABLE_PROXY_MODULE`) | `proxy_test`, `proxy_peer_test` |
| `plugins/routing` | `nat_traversal` (heartbeat/maintenance/engine threads), `nat_stun`, `turn_client`, `upnp_controller`, `peer_reconnect_policy`, `peer_tier_manager`, `tier_system_failsafe` | NAT hole punching (bounded punch thread pool), STUN/UPnP/TURN, reconnect policy (backoff+jitter+circuit breaker+battery-aware), peer tiers | `NATTraversal::getInstance()` singleton | `nat_traversal_test` |
| `plugins/optimization` | `adaptive_scaler`, `battery_optimizer`, `message_batcher`, `peer_index` | Battery-aware optimization, message batching, peer index | internally wired into `SessionManager` | indirect |
| `plugins/voice_call` | `voice_call_manager`, `voice_call_types` | Real-time voice frames (fire-and-forget), offer/state/frame callbacks | `VoiceCallManager` via `wire_voice_call_manager()` | `voice_call_test` |
| `plugins/jni` | `jni_bridge` (1533 lines), `jni_helpers`, `p2p_api`, `p2p_entry` | Thin JNI: `Java_com_zeengal_litep2p_core_LiteP2PNative_*` maps 1:1 to the C ABI; callback marshalling | `LiteP2PNative` native methods | Kotlin layer |

## 2. Key structural facts

- **C++17 engine**, compiled for desktop (macOS/Linux, `desktop/CMakeLists.txt`) and Android (NDK CMake in `litep2p-core`). Feature modules gated by compile-time macros: `ENABLE_PROXY_MODULE`, `ENABLE_OVERLAY_MODULE`, `HAVE_FILE_TRANSFER`, `HAVE_VOICE_CALL`, `HAVE_NOISE_PROTOCOL`, `HAVE_DISCOVERY`, `HAVE_NETWORK_TRAVERSAL`, `HAVE_OPTIMIZATION`, `HAVE_ROUTING`, `HAVE_JNI`.
- **Single-thread vs multi-thread flavors:** `LITEP2P_SINGLE_THREAD_MODE_COMPILE=1` (Android single-thread AAR) vs env `LITEP2P_SINGLE_THREAD_MODE` (desktop); `EventManager`/`UnifiedEventLoop` switch between unified poll()/kqueue() loop and thread-per-task.
- **The C ABI is the only stable public contract** (`include/litep2p.h`). `jni_bridge.cpp` is a thin 1:1 mapping.
- **Three message paths coexist** (input to locked decision 9): plain `sendMessageToPeer` (`litep2p_send`), reliable `send_reliable` (outbox + dedup + offline mailbox), overlay `send_overlay` (LPX2 onion). See `09-delivery-path-map.md`.
- **QUIC is compiled in on desktop** (`quic_test`, `QuicConnectionManager`, vendored `picoquic`); default Android AAR excludes it (cost recorded in `baseline-*.json`).

## 3. Open observations (input to the KEEP/HARDEN/REFACTOR matrix)

1. `LocalPeerDb` is **JSON-file-based** (`local_peer_db.cpp:1-5`: "Replaces SQLite to avoid dlopen issues on Android"), despite the default path being named `litep2p_peers.sqlite` (`session_manager.cpp:1628`) and METHODOLOGY decision 1 citing it as the SQLite precedent. **The SQLite-wired store assumed by Phase 3 does not exist in production code** (`sqlite3_dyn` is a dynamic loader only; no `sqlite3_open` call sites outside it). Must be reconciled before Phase 3.
2. `reliable_send_manager` persists its outbox as `reliable_outbox.json` (`reliable_send_manager.cpp:14`) under `files_dir` — JSON, not SQLite.
3. ChatP2P-specific logic is interleaved with core session logic in `session_manager.cpp` (6373 lines) — a Phase 1 REFACTOR candidate (extract seams).
4. Overlay mailbox (`overlay_mailbox`) is **in-memory only** on the relay side — no persistence across restarts.

