# Removing Centralized Signaling — Design Plan for Decentralized Discovery

**Date:** August 16, 2026
**Companion to:** `future development roadmap or plan.md` (expands Phase 2, task 2.1)
**Goal:** Replace the centralized Python signaling server (`tools/signaling_server/server.py`) with decentralized peer discovery, eliminating the single point of failure in the discovery layer.

---

## 1. What the signaling server actually does today

Reading `signaling_client.cpp` + `server.py`, it does exactly **three jobs**:

1. **Rendezvous** — "who is out there?" (peer list, PEER_JOINED/PEER_LEFT events)
2. **Endpoint exchange** — shares each peer's `network_id` (ip:port) so peers can connect directly
3. **Presence** — who's online right now

### The key insight

**Once two peers have exchanged endpoints, the engine never touches the signaling server again.** Everything after first contact — hole punching (STUN + the punch pool), Noise NK handshake, messaging, recovery — is already fully P2P. The SQLite peer DB (`local_peer_db.cpp`) even persists peers so restarts reconnect without signaling.

**So the only thing that needs decentralizing is "first contact": how does Alice find Bob's address without asking a central server?** Everything else is already solved.

---

## 2. The four options, honestly compared

| Option | How it works | Effort | Decentralization | Verdict |
|---|---|---|---|---|
| **A. Federation + Peer Exchange (PEX)** | Multiple signaling servers chosen by rendezvous-hash; every direct connection also exchanges peer lists | 2–3 weeks | Partial (no SPOF, but still hosted servers) | Great interim step |
| **B. Gossip/SWIM membership** | Peers periodically swap peer tables with neighbors; membership spreads epidemically | ~1 month | Full, but scales to hundreds, not tens of thousands | Good for small meshes |
| **C. Kademlia DHT** (recommended) | Distributed hash table; peers publish signed records under `H(peer_id)`, others look them up | 2–3 months + hardening | Full — this is what BitTorrent Mainline, IPFS, Tox use | **The real answer** |
| **D. Adopt libp2p (Rust via FFI)** | Battle-tested Kademlia + relay + identify for free | 1–2 months to integrate, but replaces the transport/session stack | Full | Wrong move — discards all the NAT/recovery work |

**Decision: A now, C next.** Do A as a quick win this month, then build C as the Phase 2 centerpiece. Skip D.

---

## 3. Stage 1 — Make signaling *optional* first (2–3 weeks)

Before building a DHT, squeeze the signaling server out of the hot path using
what already exists in the codebase:

### 3.1 Peer Exchange (PEX)
When a peer connection reaches READY state, both sides exchange their
known-peer tables (id, endpoints, last_seen). The existing
`broadcast_discovery_manager.cpp` already has TTL / dedup-cache / rate-limit
logic that can be reused directly.
**Effect:** any one direct connection seeds the whole mesh.

### 3.2 Bootstrap persistence
The SQLite peer DB already survives restarts — promote it: on startup, connect
to cached peers *before* ever touching signaling. The DB becomes the bootstrap
list.

### 3.3 Peer-hosted STUN
The engine already parses STUN (`nat_stun.cpp`). Add a tiny STUN *responder*
mode so any T1/T2 peer can serve as a STUN server for others — the
`NATTraversal` manager just needs the peer's STUN servers added to
`stun_servers_`.
**Effect:** kills the dependency on public STUN servers.

### 3.4 Federate the signaling server (optional)
Run N copies of `server.py`; peers pick their server by
`rendezvous_hash(peer_id) % servers` so two peers looking for each other land
on the same one.

### Stage 1 outcome

The signaling server is only needed for a peer's **very first** contact with
the network — ever.

---

## 4. Stage 2 — Replace first contact with a Kademlia DHT

### 4.1 How it replaces signaling, conceptually

```
Today:   Alice ──"who is bob?"──► Signaling Server ──"bob @ 1.2.3.4:30001"──► Alice

With DHT:
  Bob (online)  ── STORE {id=bob, endpoints, pubkey, ts, sig} ──► k closest peers to H("bob")
  Alice         ── FIND_VALUE H("bob") ──► iteratively asks ever-closer peers
                ◄── gets Bob's signed record ──► connects via the existing NAT stack
```

Signaling, discovery, and presence all collapse into one primitive: **a signed
peer record stored at the k nodes closest to `H(peer_id)`.**
- **Online** = the record is fresh (republished every ~15 min, TTL ~1 hr)
- **Offline** = the record expires

That's presence, for free.

### 4.2 Design specifics for this codebase

**Node identity & records**
- Key: `blake2b_256(peer_id)` — libsodium's `crypto_generichash`, already linked into the build
- Signatures: `crypto_sign_ed25519` — the bundled libsodium already ships
  `crypto_sign_ed25519.h`; it's just not used yet
- Record payload:
  `{peer_id, ed25519_pubkey, endpoints[] (LAN + WAN + IPv6), ports (UDP/QUIC), nat_type, timestamp, ttl, signature}`
  — the engine already classifies NAT type in `detectNATType()`; advertise it so
  dialers know whether to hole-punch first
- Stronger later (Tox-style): derive `peer_id = blake2b(ed25519_pubkey)` so IDs
  are self-certifying and Sybil-resistant

**DHT mechanics (standard Kademlia)**
- 160-bit XOR distance, k-buckets (k = 8–16, 256 buckets), lookup concurrency α = 3
- 4 RPCs: `PING`, `STORE`, `FIND_NODE`, `FIND_VALUE` — implement as a new
  message type on the existing UDP path; each is tiny (~100 bytes, well under
  the 1200-byte QUIC/datagram cap)
- Republish own record every 15 min; bucket refresh hourly; evict nodes after
  failed pings

**The critical mobile insight — reuse the tier system.** Phones behind
symmetric NATs can't receive inbound DHT traffic. Split roles:
- **DHT routing nodes** = peers the `PeerTierManager` already classifies as
  T1/T2 *and* whose `detectNATType()` returns non-symmetric (desktops,
  servers, VPS seed nodes)
- **DHT clients** = everyone else — they do lookups but aren't in routing
  tables. This is exactly how BitTorrent DHT and libp2p handle it, and the
  tier system is a ready-made foundation.

**Bootstrap:** ship 2–3 well-known seed nodes (the existing SG/US VPS CI
runners can double as this), but *any* cached peer from SQLite works after the
first run. Bootstrap nodes carry zero protocol state — they're just the first
k-bucket entries.

### 4.3 The piece DHT alone can't solve: offline peers & symmetric NAT

- **Bob behind symmetric NAT:** Alice finds his record but can't dial him.
  Solution: **relay discovery via the same DHT** — look up "relay nodes" (peers
  advertising `is_relay_node=true`, which the proxy module's `gateway` role
  already implements). Route Alice→relay→Bob using the existing LPX1
  encapsulation. The relay machinery is already built; the DHT just makes it
  discoverable.
- **Bob fully offline:** no discovery system can reach him. If the future chat
  app needs offline delivery, add **mailbox nodes** (relays that
  store-and-forward a bounded number of messages per peer) — Phase 3 material.

---

## 5. Security must-dos (DHTs attract attacks)

1. **Sign every record** with Ed25519 — unsigned records = trivially poisonable routing
2. **Timestamp + TTL inside the signed blob** — prevents replay of stale addresses
3. **Return-routability check** (like BEP-42): a node only enters the routing
   table from an address traffic was actually received from — prevents
   routing-table poisoning
4. **Bucket diversity:** don't let one /24 or one key prefix fill a bucket —
   first defense against eclipsing attacks
5. **Rate-limit FIND_VALUE per source** — the broadcast manager's per-peer rate
   limiter is reusable

---

## 6. Effort summary

| Stage | What | Time |
|---|---|---|
| 1 | PEX + DB bootstrap + peer-STUN (+ optional federation) | **2–3 weeks** |
| 2a | Kademlia core (buckets, 4 RPCs, iterative lookup, signed records) on desktop nodes | **~6 weeks** |
| 2b | Mobile-client role + NAT-type-aware behavior + bootstrap seeds + soak on the SG/US CI | **~4 weeks** |
| 2c | Relay discovery via DHT (proxy module integration) | **~2 weeks** |
| 3 | Mailbox nodes for offline delivery (optional, app-dependent) | later |

Realistic total to "signaling server deleted from the architecture":
**~3–4 months** part-time, with Stage 1 delivering a meaningful SPOF-reduction
within weeks.

---

## 7. Architectural fit

Nothing here discards existing work — the DHT slots in as a new plugin next to
`discovery`/`routing`, feeding endpoints into the *same* connect pipeline
(LAN → direct → hole-punch → relay) that signaling feeds today. The signaling
client stays as one optional "bootstrap provider" among several.

```
                     ┌────────────────────────────────────────────┐
                     │            Discovery providers             │
                     │                                            │
  LAN broadcast ────►│  broadcast_discovery_manager.cpp (exists)  │
  Cached peers ─────►│  local_peer_db / SQLite (exists)           │
  PEX ──────────────►│  NEW: peer exchange on READY (Stage 1)     │
  DHT ──────────────►│  NEW: kademlia plugin (Stage 2)            │
  Signaling ────────►│  signaling_client.cpp (exists, optional)   │
                     └──────────────────┬─────────────────────────┘
                                        ▼
                     same connect pipeline as today:
                     LAN → direct → hole-punch → relay (LPX1)
```


