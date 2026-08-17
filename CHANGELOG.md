# Changelog

All notable changes to LiteP2P are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
adheres to [Semantic Versioning](https://semver.org/). The SDK version is
single-sourced from `LITEP2P_VERSION` in `gradle.properties` and mirrored in
`litep2p.h` (`LITEP2P_VERSION_*`) and `LiteP2P.version`.

## [0.4.0] - Unreleased

### Added
- **Reliable messaging with receipts**: `litep2p_send_reliable` /
  `LiteP2P.sendReliable` persist sends into a durable outbox and retry until
  delivered; delivery progress arrives via `onDeliveryStatus`
  (`QUEUED → SENT → DELIVERED`/`FAILED`). Plain `litep2p_send` is
  receipt-eligible when the peer supports it (`onMessageAcked`).
- **Store-and-forward mailboxes**: relay-capable peers hold mail for offline
  peers (bounded, TTL'd); offline peers collect with
  `litep2p_pickup_mailbox` / `LiteP2P.pickupMailbox`.
- **Alias / invite directory**: human-readable aliases registered through the
  signaling server (`litep2p_register_alias`, `litep2p_lookup_alias`,
  `litep2p_invite_peer`); results via `onLookupResult` / `onInviteReceived`.
- **Presence, ping, lastSeen**: `litep2p_ping` / `LiteP2P.ping` (RTT via
  `onPingResult`), presence transitions via `onPresence(peerId, online,
  lastSeenMs)`, and `PeerInfo.lastSeenMs` in peer snapshots.
- **Native send backpressure**: the engine caps queued send events at
  `peer_management.max_pending_sends` (default 1000) and the reliable outbox
  at `offline_queue.max_messages` — beyond the caps, sends fail fast with the
  new `QUEUE_FULL` result (`LITEP2P_ERR_QUEUE_FULL = -10`) instead of growing
  unbounded. New metrics expose live pressure:
  `litep2p_pending_send_count` / `litep2p_reliable_pending_count` and Kotlin
  `LiteP2P.pendingSendCount()` / `LiteP2P.reliablePendingCount()`.
- **Turnkey Android runtime (Feature 4)**: `LiteP2PRuntime.start(context,
  config?)` boots the engine inside the SDK-owned `LiteP2PService` — a
  `START_STICKY` foreground service (`dataSync`) holding the partial
  wakelock + Wi-Fi/multicast locks, auto-restoring the engine after process
  kills (persisted config), wiring network/battery/Doze hints into the engine
  (`EnvironmentHints`), and creating first-run defaults (stable peer id +
  bundled `litep2p_default_config.json` extracted from AAR assets).
  Notification is overridable (icon/title/text/launch-activity/builder hook).
  Permissions and the service declaration ship via manifest merging; the
  library now depends on `androidx.core` (`api`).
- **Signaling server v0.4 protocol**: alias registration/lookup, invites,
  presence + `lastSeenMs`, and mailbox STORE/DELIVER ops — covered by an
  end-to-end smoke test (`tools/signaling_server/smoke_test.py`).

### Changed
- `docs/api-spec.md` §6.3 (backpressure), §13.3 (service integration now
  points at `LiteP2PRuntime` instead of "copy the harness pattern"), §13.4
  (hints auto-wired under the runtime), §15 (QUEUE_FULL).
- `config.example.json` documents `peer_management.max_pending_sends`.

## [0.3.0] - Unreleased

### Added
- **Public C ABI** (`litep2p-core/src/main/cpp/include/litep2p.h`): the stable
  contract between integrators and the engine — process-wide singleton (no
  handles), `struct_size` versioned structs, enumerated result codes, feature
  flags, fire-and-forget `litep2p_send`, callback-accepted file transfers.
- **JNI bridge re-pointed onto the C ABI**: every Kotlin `LiteP2P` method now
  maps 1:1 to a `litep2p_*` function; the engine is owned by the C ABI layer.
- **Multi-hop overlay routing (LPX2)**: source-routed sealed relay hops,
  stateless relays, offline mailboxes, bounded-reliable sends (`want_ack` +
  `on_overlay_delivery`), frame-id dedup, TTL, replay protection.
- **Censorship resistance (Phase B)**: OBF1 obfuscated transport (X25519 +
  XChaCha20-Poly1305, length-bucketed padding), cover traffic, Ed25519 origin
  authentication (payloads + ACKs), relay peer exchange.
- **Overlay API surface**: C ABI `litep2p_send_overlay` / `pickup_mailbox` /
  `register_relay` / `register_peer_signing_key` / `overlay_stats`; Kotlin
  `sendOverlay`, `pickupMailbox`, `registerRelay`, `registerPeerSigningKey`,
  `setOverlayRelayEnabled`, `overlayStats`.
- **Maven publication** (`maven-publish`): `com.zeengal:litep2p-core` (+
  `-singleThread` variant) with POM license/SCM/developer metadata, sources
  jar, and Dokka KDoc javadoc jar; publish to Maven Local today, Maven
  Central-ready.
- **Version single-sourcing**: `LITEP2P_VERSION` in `gradle.properties` feeds
  the POM, `BuildConfig` (`LiteP2P.version`), and the native engine
  (`litep2p_version_string()`).
- **Reproducible archives**: `android.enableReproducibleArchives=true`,
  NDK pinned to `26.1.10909125`.
- **CI**: `.github/workflows/build-and-publish.yml` — Android build (both
  thread-mode flavors, all ABIs) + JVM unit tests + desktop C ABI test suite
  on every push/PR; Maven artifacts attached to GitHub Releases on `v*` tags
  with tag↔version verification.
- **SDK reference**: `docs/api-spec.md` consolidated into a single 15-section
  integration document (quickstart, architecture, C ABI + Kotlin reference,
  messaging/overlay models, telemetry contract, config reference, threading
  and lifecycle contract, worked examples, error codes).

### Changed
- `:app` is now explicitly a development/test harness; it consumes
  `:litep2p-core` and must not leak into the library's public API.
- Desktop build mirrors the Android version macros so tests exercise the same
  version string.
- **Overlay censorship resistance is now secure by default**:
  `obfuscate_transport=true` (OBF1 envelopes on every outgoing frame; the
  receive path auto-detects envelopes by magic, so plain LPX2 frames from
  relaxed/legacy peers still interoperate), `padding_bucket=128` (worst-case
  frame 1216 B stays under the IPv6 minimum MTU of 1280 B),
  `cover_interval_ms=30000` and `pex_interval_ms=60000` (cover traffic is
  emitted by relay-role nodes only, so default clients pay no cost), and
  `require_origin_auth=true` (nodes auto-generate Ed25519 signing keys and
  sign every payload, so enforcement breaks no legitimate traffic). The
  relay role remains opt-in. All knobs stay configurable under the `overlay`
  object in `config.json`; see `docs/censorship-resistance.md`.

### Fixed
- Desktop `ENABLE_OVERLAY_MODULE` option ordering (overlay was silently
  compiled out of SessionManager).
- `c_api_test` keystore isolation; overlay mailbox accounting, ACK
  path/correlation, cover-hop parsing, envelope padding.

## [0.2.0] - 2026-08-16

### Added
- Engine lifecycle overhaul: always-on Android service layer
  (`LiteP2PService` foreground service, `EngineController` state machine,
  `EngineWatchdogWorker`, `BootReceiver`, persisted desired state).
- Homogeneous/heterogeneous communication modes (UDP+TCP listeners, per-peer
  transport tracking).
- Restart recovery: maintenance reconnect for stuck peers, stale Noise
  session / transport-key cleanup on remote restart.
- Public API specification (`docs/api-spec.md`): fire-and-forget send,
  singleton engine, AAR-only distribution decisions finalized.
- Phase 1 C ABI extraction (`litep2p.h` + `litep2p_c_api.cpp`).
- Material 3 dark console UI for the harness app.
- Harness tests: `e2e_messaging_test.py`, `rugged_soak_test.py`.

### Changed
- Proxy gateway disabled by default; secrets no longer tracked in git.

## [0.1.0] - 2026-01-07

### Added
- Initial import: C++ P2P engine (discovery, NAT traversal, Noise NK
  sessions, messaging, file transfer, proxy), Android harness app, desktop
  build, signaling server, stress/WAN self-hosted CI workflows.
- Vendored libsodium build tooling for Android ABIs.
