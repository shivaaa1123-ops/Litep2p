# Network OS Phase 2 — Secure Sessions: Bounds, Capabilities, Multiplexing

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** The authenticated, bounded, reconnect-capable secure session layer (master doc §16–§19, §39, §40, §76).
**Purpose:** Define the contracts Phase 3+ build on (object transfer, receipts, anti-entropy) and the enforcement points for session bounds.

## 1. Session lifecycle ownership

- `NetworkRuntime` owns the session lifecycle (Phase 1 facade). Subsystems request sessions through the runtime; nothing reaches the transport directly.
- `SessionFacade` (`modules/networkos/session/SessionFacade.{h,cpp}`) wraps the existing `SessionManager` and enforces bounds + capability negotiation + telemetry. The underlying peer FSM stays authoritative (Phase 0 matrix: KEEP/HARDEN, no rewrite).

## 2. Capability negotiation (§39, §40)

- A `CapabilityDocument` (`modules/networkos/capability/`) carries: protocol min/max, transports, max frame/object size, feature flags (carrier/chunking/receipts/compression), carrier capacity class, security suites, registered namespaces.
- **Wire**: the document is base64-encoded into the existing `CONTROL_CONNECT`/`CONTROL_CONNECT_ACK` payload as an optional 4th pipe field (`peer_id|pk_hex|boot_id|cap_b64`). Old peers ignore the 4th field; new peers tolerate its absence — byte-for-byte backward compatible.
- **Negotiation**: `negotiated_with()` intersects protocol version ranges and takes the highest common; merged transports/features are the intersection. Non-overlapping ranges are incompatible.
- **Unknown-field tolerance**: optional fields are len-prefixed and skipped by older decoders.
- **Privacy (§50)**: the document contains NO battery level, model, BSSID, or device identifiers (asserted by wire-level test).

## 3. Session bounds (§17)

| Bound | Default | Enforced by |
|---|---|---|
| pending handshakes (CONNECTING/HANDSHAKING) | 16 | `SessionFacade::connect` returns `kBusy` at cap |
| active sessions (READY) | 64 | `SessionFacade` gauge; budget wiring lands with ResourceManager (P8) |
| handshake timeout | 15 s | peer FSM + anomaly stall detection |
| pending sends (engine event queue) | existing `max_pending_sends` | existing engine backpressure |

## 4. Multiplexing contract (§18)

One secure peer session carries multiple **logical streams**. Priority (control first — a bulk transfer must never block chat):

| Priority | Streams |
|---|---|
| 0 (control) | `kStreamControl` (connection/security) |
| 1 (critical) | `kStreamCritical` (delivery, receipts) |
| 2 | `kStreamReceipt` (signed receipts, Phase 5) |
| 3 | `kStreamInventory` (anti-entropy, Phase 6) |
| 4 | `kStreamObject` (object transfer, Phase 3+) |
| 5 | `kStreamApplication` (plain direct stream) |
| 6 (bulk) | `kStreamBulk` (large objects, Phase 10) |

Conformance: the scheduler's priority queue (Phase 1 `IScheduler`) ranks work by the same order; a conformance test asserts `critical > normal > bulk` dispatch. Full per-stream flow control lands with the scheduler (Phase 7/8).

## 5. Reconnect (§76)

- The existing `PeerReconnectPolicy` provides exponential backoff + jitter + circuit breaker + battery-aware retry + event-triggered immediate reconnect (`trigger_immediate_reconnect_all` on network change).
- `SessionFacade::setReconnectMode()` exposes `auto|aggressive|balanced|power_saver`.
- **Session reuse**: `SessionCache` avoids repeated Noise handshakes; a READY session is never torn down for a mere CONTROL_CONNECT retry (only a changed peer public key clears it).

## 6. Security hardening (§19, §70)

- Replay protection: Noise NK per-message sequence + `replay_drop` discrimination; LPX2 `frame_id` dedup + timestamp window.
- Key rotation: identity is versioned (Phase 5+ design hook); never weaken auth to save battery.
- Capability docs are exchanged on the *pre-handshake* control path only — they leak no payload data.

## 7. Telemetry

`SessionFacade::telemetryJson()` exposes: connect_success_total, connect_failed_total, handshake_success_total, handshake_failed_total, reconnect_total, pending_handshakes gauge, active_sessions gauge.

## 8. Verification

`capability_negotiation_test` (143 checks): codec round-trip 10×, unknown-field tolerance, malformed rejection, version intersect, privacy, session bounds, telemetry, stable PeerID across network changes. Live-peer smoke: 2 sessions × 3 runs. Existing suites 5× green.
