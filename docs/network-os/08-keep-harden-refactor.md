# Network OS Phase 0 — Step 1.9: KEEP / HARDEN / REFACTOR / REPLACE / MOVE Matrix

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Purpose:** The contract for Phases 1–12 (locked decision 9: reuse, don't rebuild). Verdicts are derived from Steps 1.1–1.7; every later phase must honor this matrix.

Legend: **KEEP** = works, stays as-is · **HARDEN** = correct but needs bounds/crash-consistency work · **REFACTOR** = needs restructuring before reuse · **REPLACE** = replaced by a Network Runtime module · **MOVE** = move to app or core layer.

## 1. Matrix

| Component | File | Verdict | Rationale / work |
|---|---|---|---|
| ConfigManager + dynamic_config | `corep2p/core` | **KEEP** | Works; single mutex. Add `network.port_range`-style keys per phase with docs. |
| Logger / telemetry | `corep2p/core` | **HARDEN** | Telemetry flush interval adds idle wakeups (see `06-retry-map.md`); bound + batch. |
| device_utils (PeerID) | `corep2p/core` | **HARDEN** | Persist random-fallback PeerID (identity invariant §12); IPv6 network_id helpers KEEP. |
| Noise NK + NoiseKeyStore | `corep2p/crypto` | **HARDEN** | Correct crypto; keystore is a plain file → bounds + migration + Phase 12 Keystore hook. |
| aes / sha1_md5 | `corep2p/crypto` | **KEEP** | Legacy; unused by new paths. |
| AnomalyReporter / CrashHandler | `corep2p/monitoring` | **KEEP** | Shipped v0.4; reuse as-is. |
| SecureSession | `corep2p/security` | **KEEP** | Replay-drop handling correct. |
| TCP ConnectionManager | `corep2p/transport` | **HARDEN** | Session bounds/timeouts (Phase 2); idle-socket policy. |
| UDP ConnectionManager | `corep2p/transport` | **HARDEN** | Interface-change restart; bounds. |
| QUIC stack (picoquic) | `corep2p/transport` | **KEEP** | Stays behind `ENABLE_QUIC` (OFF for default AAR); cost recorded in baseline. |
| SessionManager (core) | `plugins/session` | **REFACTOR** | 6373-line monolith; extract seams (identity, transport wiring, message handler) behind Phase 1 interfaces without behavior change. |
| peer_state_machine | `plugins/session` | **KEEP** | Pure FSM, correct transitions. |
| wire_codec | `plugins/session` | **HARDEN** | Add versioned envelope (locked decision 2); fuzz extended (Phase 3/4 frames). |
| reliable_send_manager | `plugins/session` | **HARDEN→REPLACE(P5)** | Fixed-interval retry violates §76 (see `06-retry-map.md`); logic absorbed into object delivery path in Phase 5. |
| local_peer_db | `plugins/session` | **HARDEN** | JSON file is atomic but rewrites whole file; becomes part of Phase 3 store or migrated. |
| session_cache | `plugins/session` | **KEEP** | In-memory, fine. |
| rugged_recovery_manager | `plugins/session` | **KEEP** | Episode-based recovery works. |
| nat_traversal_manager | `plugins/session` | **HARDEN** | Bounds; event-driven hooks for Phase 9 layering. |
| overlay_mailbox | `plugins/overlay` | **HARDEN→REPLACE(P3)** | Proven bounded-carrier logic; generalized into the SQLite object store (Phase 3), sealed-blob semantics retained. |
| overlay_router / overlay_frame | `plugins/overlay` | **KEEP** | LPX2 onion, dedup/replay, cover traffic, Ed25519 origin auth — shipped + tested. |
| discovery + broadcast_discovery_manager | `plugins/discovery` | **HARDEN** | Modular backends in Phase 9; preserve OBF1. |
| signaling_client | `plugins/discovery` | **HARDEN** | Optional-infrastructure mapping (Phase 9); reconnect → backoff+jitter (Phase 7). |
| file_transfer | `plugins/file_transfer` | **KEEP→EXTEND(P10)** | Reuse chunk/checkpoint/congestion verbatim; speak generic objects in Phase 10. |
| proxy_endpoint | `plugins/proxy` | **KEEP** | Opt-in gateway; unchanged. |
| NAT traversal / STUN / UPnP / TURN | `plugins/routing` | **HARDEN** | Bounded worker pool already; layer into Phase 9 reachability. |
| peer_reconnect_policy | `plugins/routing` | **KEEP** | Backoff+jitter+circuit-breaker model for Phase 2/7. |
| peer_tier_manager | `plugins/routing` | **HARDEN** | Trust tiers align with Phase 7 scoring/§81. |
| battery_optimizer / message_batcher / peer_index | `plugins/optimization` | **KEEP** | Internal; works. |
| voice_call | `plugins/voice_call` | **KEEP** | Realtime path unaffected. |
| jni_bridge + p2p_api | `plugins/jni`, `src/jni_bridge.cpp` | **KEEP** | Thin 1:1 mapping; keep thin (Phase 12 rule). |
| litep2p_c_api + litep2p.h | `src`/`include` | **KEEP** | The stable contract; byte-for-byte ABI stability (Phase 1 gate). |
| LiteP2PService / LiteP2PRuntime (Kotlin) | `litep2p-core` | **HARDEN** | Add WorkManager bridge + resource profiles (Phase 8); keep backward-compatible entry points. |
| LiteP2PFlows / NativeEvents | `litep2p-core` | **KEEP** | Event surface. |
| LiteP2PDefaults (peer id prefs) | `litep2p-core` | **KEEP** | Per-device stable id. |

## 2. MOVE decisions

| Component | From → To | Phase |
|---|---|---|
| ChatP2P-specific message semantics (plain send / UI-oriented delivery status) | core → app layer / generic object namespace | 1, 5 |
| Signaling-server mailbox STORE/DELIVER semantics | signaling protocol → optional-object-model mapping | 4, 9 |
| Reliable outbox + dedup | session plugin → object store + object-delivery path | 3–5 |

## 3. REPLACE summary (what actually gets replaced, per locked decision 9)

1. `overlay_mailbox` bounded-carrier logic **generalized** into the SQLite object store (not rewritten) — quota/TTL/LRU semantics carried over.
2. `reliable_send_manager` delivery/status path **absorbed** into the object-delivery path (single dedup + single receipt model, Phase 5).
3. Local peer DB → object store tables (Phase 3) while keeping the JSON file format for backward compatibility or migrating with fixtures (Phase 12).
