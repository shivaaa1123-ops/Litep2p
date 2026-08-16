# LiteP2P — Future Development Roadmap & Plan

**Date:** August 16, 2026
**Based on:** Full code review of the C++ engine (~53K lines), Kotlin layer (~4.4K lines), Android app, desktop CLI, test suite, signaling server, and CI infrastructure.
**Purpose:** Single source of truth for project status, bottlenecks, and the plan to reach production readiness.
**Kept documents:** `docs/api-spec.md` and `documentation/api-spec.md` (identical) are retained — they are the public API contract used by integrators. All other project `.md` notes were consolidated into this file.

---

## 1. Project Assessment

### Overall: 7.5/10 as a P2P engine — 5/10 as a "decentralized platform" (today)

The engine itself is unusually mature for a project of this scale. The transport,
NAT traversal, resilience, and Android integration work is ahead of what most
solo/small-team P2P projects ever achieve. However, for the stated long-term
goal — a library powering decentralized chat, e-commerce, and crypto-wallet
applications — the decentralization layer itself (discovery, multi-hop routing,
pubsub) does not exist yet, and message delivery is not guaranteed end-to-end.

### Codebase snapshot

| Area | Key files | Approx. size |
|---|---|---|
| Public ABI | `litep2p.h`, `litep2p_c_api.cpp` | ~1,100 lines |
| JNI bridge | `jni_bridge.cpp` | 713 lines |
| Transport | `real_quic_transport.cpp` (picoquic), `udp_connection_manager.cpp`, `connection_manager.cpp` (TCP) | ~1,900 lines |
| Crypto | `noise_nk.cpp`, `crypto_utils.cpp`, `noise_key_store.cpp`, `secure_session.cpp` | ~1,800 lines |
| Session core | `session_manager.cpp`, `message_handler.cpp`, `peer_lifecycle_manager.cpp`, `maintenance_manager.cpp`, `rugged_recovery_manager.cpp`, `unified_event_loop.cpp` | ~10,500 lines |
| Routing/NAT | `nat_traversal.cpp`, `nat_stun.cpp`, `peer_tier_manager.cpp`, `peer_reconnect_policy.cpp`, `turn_client.cpp`, `tier_system_failsafe.cpp` | ~6,700 lines |
| Discovery | `signaling_client.cpp`, `broadcast_discovery_manager.cpp`, `discovery.cpp` | ~2,300 lines |
| File transfer | `file_transfer_manager.cpp`, `file_transfer_chunks.cpp` | ~1,800 lines |
| Proxy/relay | `proxy_endpoint.cpp` (LPX1 framing) | ~1,400 lines |
| Kotlin core + app | `LiteP2P.kt`, `LiteP2PService.kt`, `EngineController.kt`, UI, watchdog, trace stores | ~4,400 lines |
| Desktop + tests | CLI, 10 test binaries, WAN runners | ~7,000 lines |
| Infra | Python WebSocket signaling server, GH Actions stress suite (self-hosted SG/US runners) | — |

### Proven strengths (keep and protect these)

1. **Clean layering discipline.** `C ABI (litep2p.h) → JNI bridge → Kotlin singleton → app` is textbook library design. The JNI bridge is the only file that knows both worlds; every JNI call has exception checks; the ABI is a documented, versioned contract.
2. **Real transport engineering.** Genuine QUIC (RFC 9000) over picoquic/picotls with DATAGRAM frames, dual-stack IPv6-preferred sockets, 1 MB socket buffers, non-blocking I/O, graceful stop semantics.
3. **Real NAT traversal.** RFC 5389 STUN with proper retransmission timing (Rm=7), NAT-type classification including symmetric NAT, multi-threaded hole punching with dedup/coalescing/backoff, UPnP, TURN client. This is the hardest part of P2P and it works.
4. **Serious resilience work.** Peer state machine (DISCOVERED→READY→DEGRADED…), battery/network-aware reconnect policy, "rugged recovery" manager, WiFi↔LTE transition handling with session invalidation, LAN-IP rebroadcast, SQLite peer DB with auto-prune and pinning.
5. **Production-grade Android integration.** Foreground service with wake/wifi/multicast locks, WorkManager watchdog, boot receiver, battery-optimization exemption helper.
6. **Test culture.** 10 desktop test binaries, message-size runners, WAN integration runners, soak tests, self-hosted GitHub Actions stress matrix across Singapore and US runners with induced packet loss.
7. Only **1 TODO** in ~53K lines of engine C++.

---

## 2. Bottlenecks (ranked by severity)

### 🔴 CRITICAL — blocks the "decentralized" claim

**B1. Centralized signaling server is the single point of failure.**
`tools/signaling_server/server.py` is a 197-line Python WebSocket server with
**no authentication, no rate limiting, no clustering**. Every peer's rendezvous
depends on it. There is no DHT (Kademlia etc.) and no decentralized peer
discovery beyond LAN broadcast. A chat/e-commerce/crypto app built on this is
only P2P for *data transport* — the *discovery layer* is a client-server system
that must be hosted and scaled by you.

**B2. No multi-hop / overlay routing — ✅ IMPLEMENTED (2026-08-16).**
Solved by the new `overlay` plugin (LPX2): source-routed onion envelopes of
sealed relay instructions, stateless relays, bounded-reliable overlay sends
with path-rotating retries, store-and-forward mailboxes for offline peers,
loop/TTL/replay protection, and opt-in relay roles. See §8 and
`modules/plugins/overlay/`. Remaining hardening noted in §8.
Previously: Node A could talk to B only if directly connected (or via the
TCP-flow-oriented proxy module). If B was behind a symmetric NAT and only C
could reach it, there was no message path A→C→B.

**B3. General messaging is fire-and-forget.**
The ABI explicitly states `litep2p_send() == LITEP2P_OK` means "accepted into
the send path", **not delivered**. The main session path has no end-to-end
ACK + retransmission for arbitrary messages:
- `handleSendMessageWithRetry` (session_manager.cpp:2815) does not actually retry.
- `handleMessageSendComplete` (session_manager.cpp:2839) is a stub that only logs:
  "This is where you would handle ACKs if you had a reliable messaging layer."
- Only file transfer has real chunk-ACK/retransmit logic.
For chat/e-commerce this is a correctness problem. The app-layer ACK tracing in
`MessageTraceStore.kt` is UI instrumentation, not a delivery guarantee.

### 🟠 HIGH — must fix before production

**B4. Hand-rolled Noise NK implementation needs a security audit.**
`noise_nk.cpp` implements the Noise state machine manually on top of libsodium
primitives. Plausibly correct, but unaudited. Specific weak points:
- The **shared-network-key fallback** in `crypto_utils.cpp`
  (`decrypt_message_for_peer` falls back to a config-file hex key, and linearly
  tries *every* registered peer key on auth failure).
- No official Noise test-vector conformance suite wired into CI.
- For a crypto-wallet use case, unaudited custom crypto is not shippable.

**B5. Platforms: Android + macOS/Linux only.**
No iOS, no Windows. For a consumer P2P library, iOS is table stakes — and it is
not just a build target: iOS background execution, cellular NAT, and App Store
review of P2P apps are significant work. The code is POSIX-centric
(epoll/kqueue), so Windows is a porting project.

**B6. QUIC datagram size bottleneck.**
`kMaxDatagram = 1200` in `real_quic_transport.cpp` — the QUIC transport refuses
any application message over one MTU, with only a 64-datagram pending queue per
peer. Meanwhile `config.json` allows `max_message_size: 10 MB`. Large messages
only work over the UDP/TCP paths. This asymmetry will surprise integrators.

### 🟡 MEDIUM — quality / scale concerns

**B7. Thread count and battery cost.**
Full mode spawns: UDP listener, TCP accept + thread-per-client, QUIC loop, punch
worker pool (up to 10), heartbeat, maintenance, engine thread, 3 file-transfer
threads, 2 discovery threads, signaling client… easily 15–25 threads.
Single-thread mode exists but is off by default.

**B8. Three coexisting concurrency models.**
`UnifiedEventLoop` (kqueue/poll), `epoll_reactor`, and raw per-connection
threads all coexist. This complicates reasoning about correctness and
performance. Consolidate over time.

**B9. Scalability evidence gap.**
The tier system advertises 1,000–6,000 peers, but nothing tests beyond small
groups. Concerns at 4-digit peer counts:
- Coarse global mutexes (`m_peers_mutex` guards every peer-map operation).
- O(peers) key-iteration on decrypt aliasing (`crypto_utils.cpp`).
- Full peer-vector marshalled across JNI on every peer-list change.

**B10. Singleton, no-instance-handles ABI.**
One engine per process is a defensible v0.3 decision, but it prevents running
two independent stacks (e.g., wallet identity + social identity) in one app.

**B11. Housekeeping.**
- `app/src_2` backup tree is committed to the repo.
- CMake `project(litep2p VERSION 0.2.0)` disagrees with header `LITEP2P_VERSION 0.3.0`.
- Kotlin API surface is missing file transfer (acknowledged in its own KDoc).
- `// private:` is commented out in `session_manager.h` (leaks internals).
- Overlapping root-level docs (now resolved — consolidated into this file).

---

## 3. Roadmap to Production-Ready

### Phase 1 — Trust & Correctness (the non-negotiables) · ~4–6 weeks

| # | Task | Addresses | Notes |
|---|---|---|---|
| 1.1 | **End-to-end reliability for all messages** | B3 | Add message IDs + receiver ACKs + bounded retransmit at the session layer. The `RuggedRecoveryManager` pending-message scaffolding already exists — wire it into the default send path. Alternative: switch the QUIC path from DATAGRAM to streams and inherit QUIC reliability. |
| 1.2 | **Cryptographic hardening** | B4 | Run official Noise test vectors against `noise_nk.cpp` in CI; add a compile-time flag that *removes* the shared-network-key fallback in production builds; replace key-iteration-decrypt with proper source-address→key binding. |
| 1.3 | **Fix the QUIC >1200-byte path** | B6 | Session-layer fragmentation/reassembly for QUIC datagrams, or move to streams. |
| 1.4 | **Productionize the signaling server** | B1 (interim) | TLS + auth tokens + rate limits + monitoring — or move to hosted infra temporarily while Phase 2 makes it optional. |
| 1.5 | **External security audit (start procurement)** | B4 | For wallet-grade claims this takes weeks of lead time; start early. |

**Exit criteria:** every `litep2p_send()` can be proven delivered or
timed-out; Noise conformance suite green in CI; signaling server hardened.

### Phase 2 — Actually Decentralized · ~2–3 months

| # | Task | Addresses | Notes |
|---|---|---|---|
| 2.1 | **DHT (Kademlia) for peer discovery/rendezvous** | B1 | The single change that makes the "decentralized" claim true. Signaling becomes optional bootstrap-only. **Full design: see `removeCentralizedSignaling.md`** (Stage 1: PEX + DB bootstrap + peer-STUN in 2–3 weeks; Stage 2: Kademlia with signed records, tier-aware routing/client roles). |
| 2.2 | **Relay / multi-hop routing** — ✅ DONE (2026-08-16) | B2 | Implemented as the `overlay` plugin (LPX2 onion envelopes + mailboxes). Remaining hardening: C-ABI/Kotlin surface, cover traffic/padding, DHT-based relay discovery (2.1), WAN soak on the SG/US runners. |
| 2.3 | **Pubsub/gossip layer** | B2 | Needed for chat groups and marketplace data propagation. |

**Exit criteria:** two peers with no shared infrastructure and no direct
network path can find each other and exchange messages through the swarm.

### Phase 3 — Reach & Operations · ~2–3 months (parallelizable with Phase 2)

| # | Task | Addresses | Notes |
|---|---|---|---|
| 3.1 | **iOS port** | B5 | Swift wrapper over the same C ABI. Expect background-mode and cellular-NAT pain. |
| 3.2 | **Distribution** | B11 | Publish AAR to Maven Central, C++ via Conan/vcpkg, semver + ABI policy enforcement, integrator quickstart guide. |
| 3.3 | **Scale & soak certification** | B9 | 100/500/1000-peer churn tests on the existing SG/US runner matrix; throughput benchmarks; Android battery profiling (define a mA/hr budget). |
| 3.4 | **Fuzz every wire parser** | B4 | `wire_codec`, LPX1 framing, file-transfer framing, STUN message parsing. |
| 3.5 | **Kotlin API parity** | B11 | Expose file transfer (`sendFile`, `acceptFileTransfer`, progress callbacks). |
| 3.6 | **Housekeeping** | B7, B8, B11 | Delete `app/src_2`; unify CMake/header versions; restore `private:` in `session_manager.h`; incrementally consolidate the three concurrency models; evaluate making single-thread mode the default for mobile. |

---

## 4. Time to Market

Depends on what "market" means:

| Milestone | Scope | Estimate (1–2 devs) |
|---|---|---|
| **Pilot / friends-beta** — Android chat using current engine + properly-run hosted signaling | Phase 1 items 1.1–1.4 | **6–8 weeks** |
| **Production v1.0 library** — Android+desktop, audited crypto, reliable messaging, hardened signaling | Phases 1 + 3 | **4–6 months** |
| **"Decentralized app platform"** — DHT discovery, multi-hop, pubsub, iOS, wallet-grade security | Everything above | **9–15 months** |

**Recommended strategy: ship the pilot tier first.** The engine's transport /
NAT / recovery work is ahead of typical projects at this stage — but the
decentralization layer (DHT, routing, pubsub) is where most of the remaining
effort lives. Building a simple chat app on the current library immediately
will also expose exactly which message-delivery semantics must be fixed first,
before months are spent on the DHT.

---

## 5. Crypto-Wallet Caveat (read before building wallet features)

For a **crypto wallet** specifically, budget **4–8 weeks and real money
(~$30k–80k)** for an external security audit of the Noise implementation and
key storage (Trail of Bits / NCC class). That is the cost of credibility in
that market; no amount of engineering rigor substitutes for it. Key management
(hardware keystore, Secure Enclave, key derivation) is also currently outside
the engine's scope and must be designed per-application.

---

## 6. Appendix — Key Code-Level Findings (evidence for the bottlenecks)

| Finding | Location | Impact |
|---|---|---|
| Send is fire-and-forget; no delivery guarantee for app messages | `include/litep2p.h` (§3.6 comments), `session_manager.cpp:2839` | Chat/e-commerce cannot prove delivery (B3) |
| `handleSendMessageWithRetry` performs no retry | `session_manager.cpp:2815` | Misleading name; no reliability (B3) |
| QUIC datagram hard cap 1200 bytes, 64 pending/peer | `real_quic_transport.cpp` (`kMaxDatagram`, `kMaxPendingDatagrams`) | Config allows 10 MB messages but QUIC path refuses them (B6) |
| Decrypt fallback tries every registered peer key linearly, then a shared config key | `crypto_utils.cpp` (`decrypt_message_for_peer`) | O(peers) work per packet; weakens the security story (B4) |
| Hand-rolled Noise NK state machine, no test-vector conformance in CI | `noise_nk.cpp` | Unaudited custom crypto (B4) |
| Signaling server: no auth, no rate limit, single process | `tools/signaling_server/server.py` (197 lines) | Centralized SPOF for discovery (B1) |
| `m_peers_mutex` guards all peer map operations globally | `session_manager.cpp` | Contention at high peer counts (B9) |
| Full peer list marshalled across JNI on every change | `jni_bridge.cpp` (`onPeersUpdated`) | JNI overhead grows linearly with peer count (B9) |
| Three concurrency models coexist | `unified_event_loop.cpp`, `epoll_reactor.cpp`, thread-per-TCP-client | Harder to reason about; battery cost (B7/B8) |
| `// private:` commented out | `modules/plugins/session/include/session_manager.h:130` | Implementation details leak into public header (B11) |
| CMake version 0.2.0 vs header version 0.3.0 | `litep2p-core/src/main/cpp/CMakeLists.txt:6`, `litep2p.h:32-34` | Version confusion in packaging (B11) |
| Kotlin API lacks file-transfer surface | `LiteP2P.kt` KDoc acknowledges it | Feature gap for integrators (B11) |
| `app/src_2` committed | `app/src_2/` | Repo hygiene / confusion (B11) |
| Demo self-signed picoquic cert resolved from relative paths | `real_quic_transport.cpp` (`resolve_cert_path`) | Not production certificate management |
| STUN implementation is solid (RFC 5389, Rm=7, IPv6) | `nat_stun.cpp`, `nat_traversal.cpp` | Strength — keep |
| WiFi↔LTE transition handling with session invalidation + LAN-IP rebroadcast | `session_manager.cpp` (`set_network_info`) | Strength — rare mobile hardening |
| Android foreground service + locks + watchdog + boot receiver | `LiteP2PService.kt`, `EngineWatchdogWorker.kt`, `BootReceiver.kt` | Strength — production-grade Android lifecycle |
| Self-hosted SG/US stress CI with induced packet loss | `.github/workflows/stress_suite.yml`, `wan_connectivity.yml` | Strength — real WAN testing infrastructure |

---

## 8. Multi-Hop Overlay (B2) — Implementation Record (2026-08-16)

**Module:** `litep2p-core/src/main/cpp/modules/plugins/overlay/` (new, optional via
`ENABLE_OVERLAY_MODULE`, default ON; auto-disables if Noise/libsodium is off).

### Protocol: LPX2 ("onion-lite" source routing)

```
Origin picks path R1..Rn -> Dest; each hop instruction is a libsodium
sealed box (crypto_box_seal) only that hop can open:

  hop_i_body = seal(pk_i, { kind, next_peer, inner })
  innermost  = seal(pk_dest, { origin, ts, flags, payload })

Outer frame: "LPX2" | ver | flags | ttl | frame_id[16] | body
```

- **Relay privacy:** every relay learns only (prev hop, next hop); the
  destination payload is sealed end-to-end to the destination's static key.
- **Ruggedness:** relays keep ZERO per-circuit state — a relay crash kills one
  attempt only; the origin retries on a rotated path (pick_path_ shuffles
  top-scored candidates). Connect-on-demand with a bounded forwarding queue
  (15 s budget) handles churn.
- **No open-proxy risk:** LPX2 has no INET destinations — a relay can never be
  abused to reach arbitrary internet hosts (unlike the LPX1 proxy module).
- **Loop/routing protection:** random 16-byte frame IDs with a bounded LRU
  dedup cache; per-hop TTL decrement; strict wire parsing (no trailing
  garbage); 15-minute replay window on the sealed timestamp.
- **Reliability:** `send(..., want_ack=true)` → end-to-end overlay ACK back
  through a fresh reverse path (falls back to 0-hop direct when no relays are
  known), bounded retries (default 3) with path rotation, terminal
  Delivered/Failed callbacks.
- **Offline delivery:** `send(..., via_mailbox=true)` → terminal relay holds
  the sealed blob (bounded capacity, LRU eviction, per-origin quota, 24 h TTL);
  the destination calls `pickup_mailbox(relay)` to collect. The relay never
  sees plaintext — mailbox keys are opaque blake2b-128 digests of the
  destination id.
- **Relay discovery:** relay-role advertisements (`kFlagRelayAdvert`) sent
  peer-to-peer; spoofed third-party adverts rejected. Relays opt in
  (`overlay.relay_enabled` in config.json or `set_overlay_relay_enabled`);
  default OFF, matching the proxy-gateway security policy.

### Files

| File | Purpose |
|---|---|
| `modules/plugins/overlay/include/overlay_frame.h` + `src/overlay_frame.cpp` | LPX2 codec: frame header, sealed hop instructions, final payloads, relay adverts |
| `modules/plugins/overlay/include/overlay_mailbox.h` + `src/overlay_mailbox.cpp` | Bounded store-and-forward mailbox (LRU + quotas + TTL) |
| `modules/plugins/overlay/include/overlay_router.h` + `src/overlay_router.cpp` | Origin/relay/destination roles, path selection, retries, ACKs, dedup, tick |
| `desktop/tests/overlay_test.cpp` | 57-assertion end-to-end suite (all passing) |

### Integration points

- `MessageType::OVERLAY_FRAME = 0x32` (new wire type, validated in wire_codec).
- `SessionManager` (constructor/start/stop wiring, message dispatch in
  `message_handler.cpp`); public API: `set_overlay_relay_enabled`,
  `send_overlay(peer, payload, want_ack, via_mailbox)`,
  `overlay_pickup_mailbox(relay)`, `overlay_stats_json()`.
- Sealing keys come from the existing `NoiseKeyStore` static keys —
  `litep2p_register_peer_key()` is how integrators enable overlay to a peer.
- Delivered overlay messages surface through the normal
  `on_message_received` callback tagged with the **origin's** peer id.

### Phase B implementation record (censorship resistance, same day)

Executed against `sensor_registered.md` Phase B:

| Item | Status | What landed |
|---|---|---|
| **B1 Obfuscated transport** | ✅ Done + tested | `OBF1` envelope: XChaCha20-Poly1305 AEAD over an X25519 shared secret derived from the existing Noise static keys (no new key exchange). Sender pk travels in the envelope; `LPX2` magic never appears on the wire. Optional via `overlay.obfuscate_transport`. |
| **B3 Cover traffic / padding** | ✅ Done + tested | Two mechanisms: (a) `pad_wire_frame` — LPX2 frames padded to `overlay.padding_bucket` byte boundaries (fresh random bytes each hop, relays re-pad on forward); (b) idle cover frames (`overlay.cover_interval_ms`) — sealed `HopKind::Cover` frames emitted when the link is silent, consumed silently by receivers. Wire format bumped to LPX2 v2 (pad_len field). |
| **B4 Origin authentication** | ✅ Done + tested | Ed25519 signing keypair generated + persisted in the NoiseKeyStore; every `FinalPayload` (and ACK) is signed; destinations verify against the payload's embedded signer AND against the registered per-peer signing key (identity binding — mismatches are dropped). `overlay.require_origin_auth` enforces signatures. New API: `overlay_register_peer_signing_key()`. |
| **B5 Relay PEX** | ✅ Done + tested | `kFlagRelayPex` frames exchange known relay lists. Adverts now trigger a PEX response; periodic PEX via `overlay.pex_interval_ms`. Relay knowledge spreads peer-to-peer (stage-1 step toward DHT relay discovery). |
| **B2 DoH bootstrap** | 🔶 Hook documented | Designed + config field reserved (`overlay.doh_url`); native implementation requires a TLS client — recommended Android platform `DnsResolver` (Android 13+ DoH) via JNI, or picotls-based DoH for desktop. See `PACKAGING.md`. |
| **B6 Reproducible/F-Droid packaging** | 🔶 Started | `android.enableReproducibleArchives=true` added; app verified to have **zero** Play Services/Firebase dependencies; requirements checklist in `PACKAGING.md`. |

New overlay stats: `pex_tx/rx`, `cover_tx/rx`, `auth_ok/fail`, `obf_ok/fail`.

### Phase C1 implementation record (app-facing API, same day)

Executed against `sensor_registered.md` Phase C1 — the censorship-resistance
layer is now reachable from applications:

| Layer | What landed |
|---|---|
| **C ABI** (`litep2p.h`) | New §3.14: `litep2p_send_overlay`, `litep2p_overlay_pickup_mailbox`, `litep2p_overlay_register_relay`, `litep2p_overlay_register_peer_signing_key`, `litep2p_set_overlay_relay_enabled`, `litep2p_overlay_stats`; new result code `LITEP2P_ERR_NO_ROUTE`; new callback `on_overlay_delivery` (frame_id + delivered). |
| **JNI** (`jni_bridge.cpp`) | Thin wrappers for all six functions; `cabi_on_overlay_delivery` → `NativeEvents.onOverlayDelivery`. |
| **Kotlin** | `LiteP2P.sendOverlay / pickupMailbox / registerRelay / registerPeerSigningKey / setOverlayRelayEnabled / overlayStats`; listener `onOverlayDelivery`; `LiteP2PNative` externals. |
| **Tests** | `c_api_test.cpp` overlay suite: invalid args, NOT_FOUND → NO_ROUTE → OK progression (peer key, then relay+relay-key), want_ack/via_mailbox sends, mailbox pickup, relay toggle, signing-key registration, stats JSON. |

Also fixed during this pass:
- **Latent build bug (desktop)**: `ENABLE_OVERLAY_MODULE` compile definition was
  evaluated BEFORE the `option()` declaration → the module compiled sources but
  the engine's `#if ENABLE_OVERLAY_MODULE` wiring was silently compiled OUT.
  Option moved above the definitions block; verified the overlay is now actually
  created inside `SessionManager` on desktop.
- **Test-isolation bug**: `c_api_test` used the shared persistent keystore
  (`keystore/noise_keystore.json`, 42 real peers), leaking peer keys into tests.
  Hermetic `key_store_path` added to the test config.

Verification: desktop full build 0 errors; `overlay_test` 162/162; `c_api_test`
ALL PASSED (incl. overlay suite); `crypto_test` ALL PASSED; Android NDK
arm64-v8a `liblitep2p.so` links; `:litep2p-core` and `:app` Kotlin compile
(BUILD SUCCESSFUL).

### Test results (2026-08-16)

`overlay_test`: **162/162 PASS** — all prior suites plus: padding buckets
(decode strips pad, uniformity across bucket), obfuscation codec (round-trip,
wrong-key, tamper, magic-hidden, bucketed envelope), router-level obfuscated
3-hop relay delivery (LPX2 never visible, both hops re-wrapped), origin signing
(sign/verify, tamper rejection, key-mismatch rejection, require-enforce drops
unsigned), idle cover frames (emitted + consumed silently), and relay PEX
(advert→PEX response, relay learned through a neighbor). Desktop and Android
NDK (arm64-v8a) builds clean; `crypto_test` passes; the lone
`session_manager_test` failure is the pre-existing "stale public endpoint".

### Second-pass review fixes (same day)

A fresh end-to-end re-read of every overlay file found and fixed:

1. **Mailbox accounting leak** (`overlay_mailbox.cpp::pickup`): byte count was
   read AFTER `std::move(blob)` — moved-from strings are empty, so the total
   never decreased and the mailbox would eventually refuse every store.
   Fixed (size captured before the move) + regression test.
2. **ACK path degrade bug** (`overlay_router.cpp::send_ack_`): if a relay key
   vanished mid-wrap, the loop resized the path AFTER layers were already
   sealed → partially-wrapped envelope redirected to the wrong peer, silently
   lost. Fixed: filter relays to resolvable keys BEFORE wrapping.
3. **Want-ACK lost through mailbox pickup**: pickup re-wraps stored blobs with
   outer flags=0, so `handle_deliver_` (which only read outer flags) never ACKed
   `want_ack + via_mailbox` messages. Fixed: honor the sealed payload's inner
   flag too. Regression test added.
4. **ACK correlation for mailbox delivery**: the ACK referenced the pickup
   frame id, not the origin's original id → origin's pending entry never
   resolved. Fixed: `FinalPayload` now carries `message_frame_id_hex`; the
   destination ACKs the ORIGINAL id. Regression test added.
5. **Data race** on `relay_enabled`: non-atomic bool written at runtime while
   relay paths read it. Fixed: atomic mirror `m_relay_enabled`.
6. **Relay bootstrap gap**: adverts only reached already-known relays and the
   session registered nothing from config → overlay couldn't find relays
   out-of-the-box. Fixed: `overlay.relay_peers` config array seeds persistent
   candidates; new `SessionManager::overlay_register_relay()` API.
7. **Documented limitation**: `origin_peer_id` is unauthenticated (any holder
   of our public key can forge an origin). Added SECURITY NOTE in
   `overlay_frame.h` and hardening item 7 below.

### Remaining hardening (future work)

1. ~~Expose overlay on the C ABI (`litep2p_*`) + Kotlin `LiteP2P` surface.~~ ✅ DONE (2026-08-16, Phase C1 — see §8).
2. Cover traffic / fixed-size frames to resist traffic analysis at the
   network observer level (currently sizes leak payload size buckets).
3. Relay discovery via the DHT (roadmap 2.1) instead of adverts-only.
4. Path failure feedback: relays currently cannot report "next hop
   unreachable" back (drop is silent by design); consider a sealed
   path-error frame after the anonymity story is reviewed.
5. Longer payload support (fragmentation) — current budget ~640 bytes of
   app payload per frame to stay under one datagram.
6. WAN soak: multi-relay churn tests on the SG/US self-hosted runners.
7. **Origin authentication (security)**: `FinalPayload.origin_peer_id` is
   unauthenticated — anyone holding our public key can forge any origin id.
   Add Ed25519 origin signing (generate a signing keypair alongside the Noise
   X25519 key, advertise the Ed25519 public key with relay/peer records, verify
   on delivery). Until then, applications must sign payloads at the app layer.

---

## 9. Changelog of This Document

- **2026-08-16 (Phase C1)** — App-facing API delivered: C ABI §3.14 overlay
  functions + `on_overlay_delivery`, JNI wrappers, Kotlin
  `sendOverlay/pickupMailbox/registerRelay/registerPeerSigningKey/setOverlayRelayEnabled/overlayStats`,
  `c_api_test` overlay suite. Fixed a latent desktop build-flag bug (overlay was
  compiled OUT of SessionManager) and a keystore test-isolation leak. See §8.
- **2026-08-16 (Phase B)** — Censorship-resistance pass: obfuscated transport
  (B1), cover traffic/padding (B3), Ed25519 origin authentication (B4),
  relay PEX (B5) — all implemented + tested (162/162); DoH hook (B2) and
  reproducible packaging (B6) documented. Wire format LPX2 v2. See §8.
- **2026-08-16 (review pass)** — Second-pass review of the overlay module:
  fixed 4 bugs (mailbox accounting, ACK path degrade, want-ACK through
  mailbox, ACK id correlation), 1 data race, 1 bootstrap gap; documented the
  origin-authentication limitation. Suite grew to 72/72.
- **2026-08-16 (later)** — B2 solved: added the `overlay` plugin (LPX2
  multi-hop onion routing, mailboxes, reliable overlay sends). 57/57 new
  tests pass; desktop + Android NDK builds verified. Details in §8.
- **2026-08-16** — Created. Consolidates and replaces:
  `RELIABILITY_AND_PERFORMANCE_IMPROVEMENTS.md`,
  `IMPLEMENTATION_TEMPLATES.md`, `TOP_10_IMPROVEMENTS_SUMMARY.md`,
  `progress_and_marketing.md` (both root and `documentation/` copies).
  API documentation (`docs/api-spec.md`, `documentation/api-spec.md`)
  intentionally retained for integrator use.



