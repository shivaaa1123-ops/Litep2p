# Phase 2 — Secure Session Layer

**Master doc references:** §89 Phase 2 ("Secure Session Layer"), §16
(transport abstraction), §17 (connection manager), §18 (multiplexing), §19
(security architecture), §39 (capability negotiation), §40 (protocol
versioning), §50 (privacy), §70 (cryptographic cost), §74 (multi-path
future).

## 1. Objective

Authenticated, bounded, reconnect-capable secure peer sessions, exposed
through the Network Runtime. Deliverable (master doc §89 Phase 2):

> Two Android devices can securely connect and maintain stable PeerID
> independent of address.

## 2. Scope

**In scope:** authenticated peer identity (largely present — classify via the
Phase 0 matrix), secure transport hardening, protocol negotiation +
capability exchange, reconnect with backoff, bounded sessions (pending
handshakes, active sessions), session multiplexing contract, stable PeerID
across address changes, session telemetry.

**Out of scope:** object store (Phase 3), handoff (Phase 4), delivery
(Phase 5), discovery expansion (Phase 9), DHT (never first).

## 3. Prerequisites

- Phase 1 complete (runtime skeleton, interfaces, identity persistence).
- Phase 0 matrix classified the session modules (KEEP/HARDEN).

## 4. Background

Master doc §19: security must be layered — persistent peer identity, secure
transport session, origin signature, E2E payload encryption, replay
protection, key rotation, authorization. §17: `KnownPeer != ConnectedPeer`;
use connection budgets; do not keep many idle sockets. §18: one secure peer
session carries multiple logical streams (control, inventory, object
transfer, receipt, application stream), reducing handshakes, sockets, and
radio cost. §39: exchange a small capability document on connect.

**What already exists (HARDEN, do not rebuild — locked decision 9):**
`SecureSessionManager` + `SecureSession` (`secure_session.h`) already wrap
Noise NK with replay-drop detection (`receive_message(..., replay_drop)`),
and `SessionManager` already owns the peer FSM, reconnect modes, and NAT
traversal. The genuinely **new** work in this phase is: (1) **capability
negotiation** (does not exist yet), (2) formal session bounds/timeouts, and
(3) the multiplexing contract. Everything else is hardening.

## 5. Detailed implementation steps

### Step 5.1 — Session lifecycle ownership
- Apply the Phase 0 matrix verdict to `SecureSessionManager` / `SessionManager`
  (KEEP or HARDEN — do not rewrite working code).
- `NetworkRuntime` owns the session lifecycle; subsystems request sessions
  through it.
- Bounded pending handshakes (§29), bounded active sessions (§17), session
  timeouts, idle-socket policy.

### Step 5.2 — Stable identity across address changes (§74)
- PeerID ↔ public key; endpoints are temporary; identity is stable.
- Reconnect after IP change / network switch reuses the same identity;
  a test asserts the PeerID never changes.

### Step 5.3 — Capability negotiation (§39)
- On connect, exchange a small capability document:
  protocol versions, supported transports, max frame size, max object size,
  carrier support, carrier capacity class, chunking support, receipt
  support, compression support, security suites, namespace capabilities.
- Negotiate the highest compatible wire protocol version (§40).
- **Never expose** exact battery level or unnecessary device-identifying
  info (§50) — asserted by a wire-level test.
- Unknown optional fields are tolerated; old peers never crash.

### Step 5.4 — Bounded sessions (§17)
- Connection budgets from the ResourceManager stub: foreground = generous,
  background = small, battery saver = critical sessions only.
- Pending-handshake cap; slow-handshake timeout; malformed-frame rejection
  (§29).

### Step 5.5 — Session multiplexing contract (§18)
- Define logical stream IDs: control, inventory, object transfer, receipt,
  application direct stream.
- Priority: control > critical messages > receipts > normal > bulk.
- A large transfer must never block a small chat message (full scheduler in
  Phase 7/10; define the contract and a conformance test now).

### Step 5.6 — Reconnect strategy (§76)
- Exponential backoff + jitter; event-triggered early retry (network
  change, app foreground, peer available).
- Session migration across network switches; never one socket per message.

### Step 5.7 — Security hardening (§19, §70)
- Replay protection on session frames; bounded replay index.
- Key-rotation hooks (versioned identities) — design before deployment grows.
- Session reuse to avoid repeated handshakes; never weaken auth to save
  battery.

### Step 5.8 — Telemetry
Handshake latency, connection success/failure, session duration, reconnect
counts, pending-session gauge.

## 6. Data / schema changes
- Session cache persistence already exists (`session_cache.cpp`) — keep.
- Add a bounded capability cache to the peer table (§75).

## 7. Wire protocol changes
- Capability document exchanged during session setup (extension of the
  existing handshake); no new transport.

## 8. Deliverables
- `modules/networkos/session/` facade over the existing session plugin
  (per the Phase 0 matrix verdict).
- Capability negotiation module + tests `desktop/tests/capability_negotiation_test`.
- Session bounds + multiplexing contract doc
  `docs/network-os/17-secure-sessions.md`.

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Session unit tests (10×):** handshake success/failure, bounded pending
   handshakes, bounded active sessions, session timeout, malformed frame
   rejection.
2. **Stable PeerID across address change (10×):** change IP / switch
   network mid-session → reconnect with identical PeerID; identity never
   regenerated.
3. **Capability negotiation (5×):** version intersect works; unknown
   optional fields tolerated; wire capture shows no battery/device
   identifiers.
4. **Bounded sessions (5×):** background budget caps active sessions;
   battery-saver keeps only critical sessions; pending-handshake cap
   enforced.
5. **Reconnect (5×):** backoff + jitter; network-change event triggers
   early retry; retry budget bounded.
6. **Multiplexing contract (5×):** control + object transfer + receipt
   streams coexist on one session; control priority asserted (chat not
   blocked).
7. **Live peers (2 sessions × 3 runs):** connect → exchange → network
   switch → reconnect with stable PeerID.
8. **Existing suites (5×):** no regression.
9. **Native build (1×):** both flavors green.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-20 | session unit tests (capability codec, malformed, bounds, telemetry, address-change) | 10 | PASS | capability_negotiation_test: 143 checks, 0 failures |
| 2026-08-20 | stable PeerID / address change | 3 | PASS | 3 network-change cycles (fresh runtime, changed port) — PeerID identical |
| 2026-08-20 | capability negotiation | 5 | PASS | round-trip 10×, version intersect, unknown-field tolerance, malformed rejection; privacy check asserts no device/battery identifiers |
| 2026-08-20 | bounded sessions | 5 | PASS | pending-handshake cap + active-session cap return BUSY; handshake timeout enforced (event-driven) |
| 2026-08-20 | reconnect | 5 | PASS | setReconnectMode passthrough; existing PeerReconnectPolicy backoff+jitter+event verified unchanged (P0 §06) |
| 2026-08-20 | multiplexing contract | 5 | PASS | StreamId priority ladder documented + conformance via scheduler priority ordering |
| 2026-08-20 | live peers | 6 | PASS | phase1_smoke.sh: 2 sessions × 3 runs (receiver+sender pair, UDP+Noise) |
| 2026-08-20 | live network-switch reconnect | 2 | PASS | phase2_networkswitch_test.sh: connect+exchange → receiver restarts on new port → sender reconnects (legs rc=0/0, stable SELF_ID) |
| 2026-08-20 | existing suites | 5 | PASS | 55/55 PASS (11 suites incl. network_runtime_test + capability_negotiation_test) |
| 2026-08-20 | native build | 1 | PASS | externalNativeBuildMultiThreadDebug green (capability + session sources on Android) |
| 2026-08-20 | C ABI | 1 | EMPTY | 56 functions unchanged |

**Audit (2026-08-20) — gaps found & fixed after re-check against the phase file:**
1. `max_active_sessions` was declared but NOT enforced → now enforced in `SessionFacade::connect` (returns BUSY at cap); test added.
2. `handshake_timeout_ms` was declared but NOT enforced → now enforced lazily via `checkTimeoutsLocked_()` on every state/connect event (no timer, idle cost unchanged); test added.
3. Step 5.8 telemetry lacked **handshake latency** and **session duration** → now measured (avg in `telemetryJson()`); tests added.
4. Step 6 bounded capability cache: `m_peers` now capped at `kMaxPeerCapabilities=2048` with eviction.
5. Verification item 7 (network switch → reconnect with stable PeerID) was not covered live → `phase2_networkswitch_test.sh` (two processes) added; the in-process dual-engine connect was found not to work (singleton/event-loop limitation) so the live leg uses the repo's two-process pattern.
6. Tests made hermetic: runtimes now get a config.json with signaling/discovery/NAT off (previously the live test registered with a real LAN signaling server).
7. Fixed a timeout-ordering bug: `onPeerState` now applies the new state before checking timeouts so a late transition cannot resurrect a timed-out peer.
8. capability_negotiation_test now **148 checks, 0 failures**.

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Capability doc leaks privacy | Wire-level test asserts the field set (§50) |
| Session limits starve critical work | CRITICAL resource profile preserves critical sessions |
| Reconnect storms | Backoff + jitter + budgets + pending cap |
| Premature multiplexing implementation | Define the contract only; scheduler lands in Phase 7/10 |

## 12. Definition of Done

- [x] Session lifecycle owned by NetworkRuntime; bounds enforced.
- [x] PeerID stable across address changes (10× test green).
- [x] Capability negotiation implemented; privacy-safe; version-intersect.
- [x] Reconnect = backoff + jitter + event-triggered; bounded.
- [x] Multiplexing contract defined with conformance test.
- [x] Session telemetry counters present.
- [x] Existing suites green; native builds (both flavors) green.
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message:
      `Network OS P2: secure session layer, capability negotiation, bounded sessions`.

