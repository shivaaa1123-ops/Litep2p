# LiteP2P SDK — Change Requests from ChatP2P

**From:** ChatP2P (Android chat app built on `com.zeengal:litep2p-core`)
**Against:** `Litep2p_docs/api-spec.md` v0.3.0
**Date:** 2026-08-17

All five requests are **additive** (new functions, callbacks, and config keys).
Per the spec's own ABI rules (§4.3: additive changes bump MINOR), they can ship
as **v0.4.0 with zero breaking changes**. Each request includes the API sketch,
the concrete pain it solves in ChatP2P, and acceptance criteria.

---

## 1. Reliable-send primitive with engine-level delivery receipts

### The ask

```c
/* C ABI */
litep2p_result_t litep2p_send_reliable(const char* peer_id, const char* msg_id,
                                       const uint8_t* data, uint32_t len,
                                       int max_retries, uint32_t retry_timeout_ms);

/* New callback in litep2p_callbacks_t */
void (*on_delivery_status)(void* user_data, const char* msg_id,
                           int status,    /* QUEUED | SENT | DELIVERED | FAILED */
                           const char* reason); /* OK | NO_ROUTE | PEER_OFFLINE | QUEUE_FULL | TIMEOUT */
```

```kotlin
// Kotlin wrapper
fun LiteP2P.sendReliable(peerId: String, msgId: String, data: ByteArray,
                         maxRetries: Int = 3, retryTimeoutMs: Long = 10_000): EngineResult

// Listener
fun LiteP2PListener.onDeliveryStatus(msgId: String, status: DeliveryStatus, reason: String?) {}

// Reactive
val LiteP2P.deliveryStatusFlow: SharedFlow<LiteP2PDeliveryStatus>
```

Plus receiver-side dedup: `onMessageReceived` fires **at most once per `msg_id`**
within a configurable window, and the outbox **survives engine restarts**
(persisted under `filesDir`).

### Why

Today `send` is fire-and-forget by design, so ChatP2P hand-rolls an entire
reliability stack: an `ACK` envelope type, pending-ACK tracking, retry timers,
and id-based dedup in `P2PMessageSync`. The existing `LP_APP`/`LP_APP_ACK`
envelope doesn't fit either — the engine strips everything except `body`, but
the app's envelope carries routing fields (`fromPeerId`, `toPeerId`,
`messageId`, `replyToMessageId`, `messageType`). So the app cannot use the
engine's ACK path at all.

### Payoff

~60% of `P2PMessageSync` disappears; delivered-ticks become a single callback;
retries survive process death instead of living in volatile in-memory maps.
The single biggest reliability *and* simplicity win.

### Acceptance criteria

- [ ] `sendReliable` returns `OK` when accepted into the persistent outbox.
- [ ] `onDeliveryStatus` fires `DELIVERED` when the receiver ACKs, `FAILED`
      with a machine-readable reason when the retry budget is exhausted.
- [ ] Duplicate `msg_id` on the receiver fires `onMessageReceived` only once.
- [ ] Outbox persists across `stop()`/`start()` and process restart.
- [ ] Plain `send` semantics unchanged (fire-and-forget).

---

## 2. Store-and-forward (offline mailbox) at the base layer

### The ask

When the destination has no session, `send`/`sendReliable` queues the message
into a persisted outbox **and** the existing signaling server holds it for the
destination's `peer_id`, delivering it automatically on the peer's next connect.

```json
// config.json additions
"offline_queue": {
  "enabled": true,
  "max_messages": 500,
  "ttl_ms": 604800000
}
```

### Why

Offline delivery is the defining requirement of a chat app, and right now a
send to an offline peer just fails with `NOT_FOUND`. The overlay *has*
mailboxes, but they're the wrong tool: they require registered relays, Ed25519
keys, and cap payloads at 640 bytes. A base-layer mailbox riding the
already-mandatory signaling server is the natural fit.

### Payoff

Offline delivery works with zero app-side infrastructure. Without this,
ChatP2P would eventually need its own backend just to hold messages — which
defeats the purpose of a P2P SDK.

### Acceptance criteria

- [ ] Send to an offline peer returns `OK` (queued), not `NOT_FOUND`.
- [ ] Message is delivered automatically when the destination connects.
- [ ] TTL expiry drops the message and fires `onDeliveryStatus(FAILED, TTL_EXPIRED)`.
- [ ] Works over the signaling server without any relay/overlay setup.

---

## 3. Identity directory + invite API on the signaling server

### The ask

```kotlin
// Register a stable lookup alias (e.g. SHA-256 of normalized phone number)
fun LiteP2P.registerAlias(aliasHash: String): EngineResult

// Resolve someone's alias to their current peerId (+ last seen)
fun LiteP2P.lookupPeer(aliasHash: String): PeerLookupResult?   // async callback/flow

// Nudge an offline/remote peer to connect (signaling push)
fun LiteP2P.invitePeer(peerId: String): EngineResult
```

```kotlin
data class PeerLookupResult(
    val peerId: String,
    val online: Boolean,
    val lastSeenMs: Long
)
```

### Why

ChatP2P derives `peerId` from a phone-number hash (`PeerIdentity.fromPhone`),
which is clever — but `addPeer` only works if both devices already know each
other's ids and are on the same LAN, or the user exchanges ids out-of-band
(QR/deep link). There is no way to bootstrap a remote peer across the internet
today.

### Payoff

Contact discovery and remote-peer bootstrap work with no app-owned server.
Hash-based lookup keeps it privacy-preserving. This turns the phone-number
identity model from a local convention into a globally usable addressing scheme.

### Acceptance criteria

- [ ] `registerAlias` persists the alias on the signaling server across restarts.
- [ ] `lookupPeer` resolves an alias to a `peerId` even when the peer is offline.
- [ ] `invitePeer` triggers a connect attempt / push to the target peer.
- [ ] Alias values are opaque hashes — the server never sees raw phone numbers.

---

## 4. A turnkey Android runtime component (companion artifact)

### The ask

Publish a small `litep2p-android` artifact (or fold into the AAR) containing:

- **`LiteP2PService`** — a ready foreground service (`START_STICKY`, partial
  wakelock, Wi-Fi multicast lock, overridable notification builder)
- **Manifest-merger contributions:** `FOREGROUND_SERVICE`, `WAKE_LOCK`,
  `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`
  + the service declaration
- **Automatic environment hints:** internal `ConnectivityManager.NetworkCallback`
  → `setNetworkInfo`, battery receiver → `setBatteryLevel`, Doze-aware reconnect mode
- **One-liner API:**

```kotlin
LiteP2PRuntime.start(context, config)   // binds/starts the foreground service + engine
LiteP2PRuntime.stop(context)
```

### Why

Spec §13.3 literally says "copy that pattern" from the harness — meaning every
integrator re-implements ~200 lines of error-prone platform plumbing. ChatP2P
currently has **none of it**: no service, no permissions, no wakelock/multicast
lock, no hint wiring. That's not laziness — it's the integration cost being too
high. Doze will silently suspend packet delivery for any integrator who gets
one detail wrong.

### Payoff

The #1 developer-friendliness win. Correct background operation becomes the
default instead of a checklist, and the whole class of "P2P dies when the
screen is off" bugs vanishes for every consumer, not just this app.

### Acceptance criteria

- [ ] Adding the dependency + one `LiteP2PRuntime.start(...)` call is sufficient
      for correct background operation.
- [ ] Manifest merger supplies all required permissions and the service.
- [ ] Environment hints are fed automatically; no app code needed.
- [ ] Notification channel/id/content are overridable by the host app.
- [ ] Engine survives Doze with screen off on a LAN session.

---

## 5. Presence & reachability primitives

### The ask

```kotlin
// Cheap liveness probe without holding a full session open
fun LiteP2P.ping(peerId: String, timeoutMs: Long = 3000)
// result via callback/flow: RTT ms or UNREACHABLE

// Server-assisted presence via the signaling server
fun LiteP2P.subscribePresence(peerIds: List<String>): EngineResult

// Listener
fun LiteP2PListener.onPresence(peerId: String, online: Boolean, lastSeenMs: Long) {}
```

Plus `PeerInfo.lastSeenMs` added to the existing snapshot.

### Why

ChatP2P needs online/offline/last-seen indicators, but today presence can only
be inferred from `onPeersChanged` — which reflects *established sessions*. The
only way to know a peer is online is to keep a session open, which burns
battery and radio time; and there's no last-seen at all for peers who were
never connected this run.

### Payoff

Presence UI becomes trivial and battery-cheap. Typing indicators stay app-layer
(that's fine — they're chat semantics), but liveness/last-seen is transport
knowledge the engine already has and should expose.

### Acceptance criteria

- [ ] `ping` returns RTT for a reachable peer, `UNREACHABLE` after timeout.
- [ ] `onPresence` fires on online/offline transitions for subscribed peers.
- [ ] `lastSeenMs` is populated for peers known to the signaling server.
- [ ] Presence works without holding an open session to the peer.

---

## Honorable mentions (small asks, same conversation)

- **Kill the `security.transport_key` footgun:** ship a default in the AAR
  assets or auto-negotiate it during handshake. Two devices with mismatched
  keys stay `CONNECTING` forever (§9's own warning) — a brutal first-run
  failure mode.
- **Bundle a default `config.json` in the AAR assets** so integrators don't
  have to author one before the engine works.
- **Richer send-failure reasons** on plain `send` (queue full vs. unknown peer
  vs. not running) instead of a blanket `NOT_FOUND`.

---

## What ChatP2P looks like after all five

`P2PMessageSync` collapses into a thin persistence bridge; `LiteP2PNetworkManager`
gains delivery/presence callbacks instead of polling state; the missing
foreground-service/permissions/hints gap closes by dependency rather than by
hand; and contact discovery stops needing an out-of-band channel. The app layer
would finally be doing only what the spec says consumers should do: chat semantics.

