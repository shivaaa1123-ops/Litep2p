# Reconnection & Recovery Policy (Litep2p)

This document describes a **robust reconnection policy** and **in-connection recovery mechanisms** for Litep2p so that connections and message delivery remain reliable when:

- the local network changes (Wi‑Fi ↔ cellular, LAN ↔ WAN),
- the device IP changes dynamically,
- NAT mappings change,
- peers restart (new Noise keys / new ports),
- discovery/signaling endpoints change while a connect/handshake is in flight.

It is written to match the current architecture:

- `SessionManager` orchestrates peers + FSM + Noise + sending (`app/src/main/cpp/modules/plugins/session/src/session_manager.cpp`).
- `PeerLifecycleManager` processes discovery + connect initiation (`.../peer_lifecycle_manager.cpp`).
- `MessageHandler` processes inbound packets and endpoint “upgrade” (`.../message_handler.cpp`).
- `MaintenanceManager` runs periodic liveness + timeouts (`.../maintenance_manager.cpp`).
- `PeerReconnectPolicy` holds retry/backoff strategy (`app/src/main/cpp/modules/plugins/routing/src/peer_reconnect_policy.cpp`).

---

## 1) Goals and non-goals

### Goals

1. **Never get stuck “connected but not delivering”.** If we claim a peer is usable, messages should flow.
2. **Recover from network/IP changes automatically** without manual user intervention.
3. **Converge quickly to the best endpoint** (LAN path when available, fallback to WAN/relay when needed).
4. **Avoid storms / thundering herd** (bounded concurrency, backoff + jitter).
5. **Make stale events harmless** (late packets from an old attempt cannot break a new attempt).

6. **Support multiple reconnect policy modes** so Litep2p can be tuned for:
   - **Reliability-first** (desktop/server, critical UX) vs
   - **Resource-first** (mobile, battery/data constraints).

### Non-goals (for now)

- Full TCP-like reliability over UDP for all payloads. (We recommend an optional lightweight ACK/dup layer; see §7.)

---

## 2) Terminology and invariants

### Key invariants

- If Noise is enabled, a peer is “usable” **only when** the FSM is `READY` **and** a valid secure session exists.
- Endpoint changes must be treated as **new information** that can immediately justify a new connect attempt.
- A reconnect attempt must be attributable to a specific “generation” so late events can be dropped.

### Terms

- **Advertised endpoint**: stable endpoint learned via discovery/signaling (`peer.network_id` today).
- **Observed endpoint**: source endpoint of an inbound UDP packet (`event.network_id` in `MessageHandler`).
- **Ephemeral mapping**: observed source port differs from advertised; stored in `m_ephemeral_to_advertised_port_map`.
- **Candidate endpoint**: one of potentially multiple endpoints that may work for a peer (LAN, WAN, relay).

---

## 3) Core mechanism: per-peer connection epoch (generation)

### Why

Today, multiple subsystems can trigger retries (discovery updates, NAT traversal, CONNECT timeouts, decrypt failures). When events arrive late (old handshake packets, old CONNECT_ACK, etc.), they can:

- resurrect stale state,
- confuse glare logic,
- flush queues under the wrong session,
- keep the peer stuck in CONNECTING/HANDSHAKING.

### Proposal

Add `uint64_t connect_epoch` to the peer context and propagate it through all connect/handshake flows.

**Where to store:**

- `PeerContext` (in `session_manager_p.h` / `peer_state_machine` context):
  - `uint64_t connect_epoch` (monotonic counter per peer)
  - `std::string connect_target_network_id`

**When to bump epoch:**

- starting a new outbound connect to a different candidate endpoint,
- after `DISCONNECT_DETECTED`,
- after `CONNECT_FAILED` timeout,
- after Noise decrypt failure / session reset,
- after network restore (optional “global epoch bump”, see §6).

**Stamp the epoch onto:**

- outbound connect events (`ConnectToPeerEvent`),
- Noise handshake initiation (store epoch in secure session entry),
- queued messages (store epoch on each queued message).

**Epoch gating rule:**

> Any inbound message/event (handshake packets, CONNECT_ACK, decrypt results, send completions) that does not match the current `connect_epoch` is ignored.

This single change makes late packets and stale retries harmless.

---

## 4) Endpoint management: keep multiple candidates + score them

### Problem

A peer can be reachable via multiple paths, and the “best path” can change during a session:

- signaling gives a WAN endpoint, then LAN discovery appears,
- a peer changes Wi‑Fi and now has a new LAN IP,
- NAT mapping changes and observed ports change,
- a relay becomes necessary after repeated direct failures.

### Proposal: `EndpointSet`

Maintain a per-peer `EndpointSet`:

- `LAN`: private IPv4 candidates learned from discovery and observed packets.
- `WAN`: public candidates learned from STUN/NAT traversal or signaling.
- `Relay`: relay candidate (if supported).

Each candidate carries:

- `ip`, `port`, `kind` (LAN/WAN/Relay),
- timestamps: `last_seen_ms`, `last_success_ms`, `last_failure_ms`,
- counters: `consecutive_failures`, `total_failures`,
- quality: `last_rtt_ms`, `avg_rtt_ms`.

### Candidate scoring

Compute score using a simple rule-of-thumb:

- Prefer **last_success** most recently.
- Prefer **LAN** over WAN when LAN is fresh.
- Penalize recent failures.
- Penalize stale endpoints.

Example (conceptual):

- Base: `+100` for LAN, `+50` for WAN, `+10` for Relay.
- `+min(30, freshness_seconds)` where freshness is “seconds since last seen (smaller is better)”.
- `-20 * consecutive_failures`.

### Integration points in current code

- `PeerLifecycleManager::handlePeerDiscovered(...)` already detects endpoint changes and retries connect when CONNECTING; extend it to **update a LAN candidate** rather than only rewriting `peer.network_id`.
- `MessageHandler::handleDataReceived(...)` already performs an “upgrade” heuristic (public/placeholder → private). Keep that logic, but record it as a **candidate improvement** and (optionally) trigger a connect-epoch bump if the peer is mid-handshake on the wrong path.
- Keep the existing ephemeral mapping map, but treat it as **routing metadata** (observed path) rather than “the peer’s identity”.

---

## 5) Reconnect scheduler: policy-driven, bounded, and reason-aware

### What exists today

- `PeerReconnectPolicy` can compute backoff/jitter and select methods (`get_retry_strategy`).
- `MaintenanceManager` detects inactivity, marks disconnect, and marks CONNECTING timeouts as `CONNECT_FAILED`.
- `SessionManager::Impl::set_network_info(...)` reacts to network restore by refreshing external address and signaling peer list.

### What’s missing

The main reconnect loop should be **policy-driven**, not ad-hoc per subsystem.

---

## 5.1) Reconnect policy modes (required)

Litep2p needs an explicit **mode** so product/UX can choose the right trade-off for the device.

### Mode A: Aggressive (reliability-first)

Use when you care about “get back online ASAP” and can spend extra CPU/radio:

- Fast retry cadence (example): $250\text{ms}, 500\text{ms}, 1\text{s}, 2\text{s}, 4\text{s}, 8\text{s}, \dots$ (with jitter)
- Higher max retries before circuit breaker trips
- Keepalive shorter (more rapid liveness detection)
- Escalate to alternate methods sooner (e.g., Relay earlier if direct repeatedly fails)

### Mode B: Power saver (resource-first / mobile)

Use when running on mobile devices, on battery, or when minimizing data/battery matters:

- Conservative retry cadence (example): $8\text{s}, 16\text{s}, 32\text{s}, 64\text{s}, 5\text{min}, \dots$
- Fewer retries per cycle; longer backoff cap (prevents constant wakeups)
- Keepalive longer
- Avoid expensive methods early (e.g., delay Relay unless strongly indicated)

### Mode C: Balanced

Default for most environments when you want good behavior without extremes.

### Mode D: Auto

Auto chooses between aggressive/balanced/power saver based on:

- network type (Wi‑Fi vs mobile)
- battery level + charging state

### Configuration surface

- `config.json`: `reconnect_policy.mode` = `"auto" | "aggressive" | "balanced" | "power_saver"`
- Runtime override (C++): `SessionManager::set_reconnect_mode("aggressive")` (or the other values)

### Proposed scheduler responsibilities

1. **Track peers**
   - Call `PeerReconnectPolicy::track_peer(peer_id)` when a peer is created/seen.
   - Call `untrack_peer(peer_id)` when a peer is truly removed.

2. **Feed outcomes into policy**
   - On FSM → `READY`: `on_connection_success(peer_id, method, rtt_ms)`.
   - On `CONNECT_FAILED`, `DISCONNECT_DETECTED`, decrypt failure reset, NAT traversal failure: `on_connection_failure(peer_id, attempted_method, packet_loss)`.

3. **Global reconnection loop (Maintenance tick)**

On each `TimerTickEvent` (or at a slower cadence):

- If network is unavailable → do nothing.
- Choose next peer to reconnect using `policy.get_next_peer_to_reconnect()`.
- Only reconnect if `policy.should_reconnect_now(peer_id)` is true.
- Enforce a **global concurrency cap** (e.g., max 2–5 concurrent reconnect attempts).

4. **Reason-aware failure classification (recommended API evolution)**

Extend `on_connection_failure(...)` to include a reason enum:

- `TIMEOUT_CONNECT`
- `TIMEOUT_HANDSHAKE`
- `DECRYPT_FAIL`
- `REMOTE_RESET`
- `NAT_TRAVERSAL_FAIL`
- `NO_ROUTE` / `NETWORK_DOWN`

Then method selection can become smarter:

- repeated UDP timeouts → try TCP earlier,
- decrypt failures → don’t switch transport; restart handshake/keys,
- NAT traversal failure → switch to signaling refresh / relay.

---

## 6) Network change handling (IP changes, interface changes)

### Trigger

On Android, the app should call:

- `SessionManager::Impl::set_network_info(is_wifi, is_available)`
- (optionally) `set_battery_level(...)`

This already triggers:

- `refresh_external_address_async(true)`
- signaling re-bootstrap + peer list request.

### Add a “network restore recovery” sequence

When `is_available` transitions false → true:

1. **Bump a global recovery marker**
   - Option A: bump all peers’ `connect_epoch`.
   - Option B (lighter): mark peers “needs_path_revalidation”.

2. **Clear stale routing metadata**
   - Clear (or age out) `m_ephemeral_to_advertised_port_map` entries older than a short TTL.

3. **Staggered reconnect to previously connected peers**
   - Snapshot peers that were `connected/READY` recently.
   - Enqueue reconnect attempts with small randomized delays (50–500ms) to avoid storms.
   - Let `PeerReconnectPolicy` impose backoff if the network is still unstable.

4. **Signaling refresh is mandatory for cross-network peers**
   - The current code already does “ensure signaling connected” and “LIST_PEERS”; keep it.

### In-connection migration (“peer moved”)

If, while a peer is considered connected, we observe packets from a new endpoint that is plausible:

- record it as a new candidate,
- if it is clearly better (e.g., new private LAN while old endpoint is WAN), either:
  - send a CONTROL_CONNECT handshake on the new path to confirm, or
  - bump epoch and re-handshake using the best candidate.

This is effectively “path migration”.

---

## 7) Recovery while connected (keepalive + session repair)

### Heartbeat is necessary but not sufficient

`MaintenanceManager::handleTimerTick(...)` already sends `CONTROL_PING` periodically and disconnects on silence.

Strengthen it into **path validation + repair**:

1. **Path validation**
   - Track `last_authenticated_rx` separate from discovery.
   - If discovery is fresh but authenticated traffic is stale (already partially implemented via `restart_suspected_ms`), treat it as a **session repair trigger**, not only as disconnect.

2. **Session repair trigger**

On repair trigger:

- bump `connect_epoch`,
- remove Noise session for the peer,
- initiate re-handshake using the best endpoint candidate.

3. **Queue behavior during repair**

- Continue queueing app messages while not READY, but enforce:
  - max queue bytes,
  - max queue length,
  - per-message TTL.

### Optional: lightweight ACK/dup for app messages (recommended)

To make message delivery rugged over UDP and during brief flaps:

- Sender attaches `message_id` (already present in `handleSendMessageWithRetry(...)`).
- Receiver sends ACK control message.
- Sender retries until ACK or TTL.
- Receiver deduplicates by `(peer_id, message_id, connect_epoch)` with bounded memory.

This turns “sometimes lost under churn” into “eventually delivered or expires deterministically”.

---

## 8) Implementation roadmap (practical steps)

### Phase 0 (low risk, high gain): wire policy into reconnection

- Call `track_peer()` when peers are created (e.g., when adding to `m_peers`).
- Call `on_connection_success()` when FSM reaches `READY`.
- Call `on_connection_failure()` for:
  - `CONNECT_FAILED` timeouts,
  - inactivity disconnects,
  - NAT traversal failure events,
  - decrypt failure-triggered resets.
- In `MaintenanceManager`, add a policy-driven reconnect loop (bounded concurrency).

### Phase 1: add `connect_epoch` gating

- Extend `PeerContext` with `connect_epoch`.
- Stamp it on connect events and secure sessions.
- Gate inbound handshake/control transitions by epoch.

### Phase 2: endpoint candidates

- Replace “rewrite `peer.network_id`” with “update candidate set; select best”.
- Keep `peer.network_id` as “current selected route”, not a single source of truth.

### Phase 3: reliability layer

- Add ACK/dup for app messages when using UDP (or when configured).

---

## 9) Operational observability (recommended)

To make issues diagnosable (especially “connected but not delivering”), log and/or expose counters:

- per-peer FSM state, `connect_epoch`, selected endpoint candidate,
- queue size/bytes/oldest age/drops,
- reconnect attempts (count, reason, method, backoff),
- heartbeat stats (PING sent, PONG received, RTT),
- decrypt failures and session resets.

A single JSON endpoint (like `get_reconnect_status_json()` already exists) should include these fields.
