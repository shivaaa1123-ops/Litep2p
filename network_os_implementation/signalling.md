
```markdown
# SDK Architectural Specification: Mobile-First P2P Routing & Overlay Network

This document defines the technical architecture for the evolved C++ P2P Network SDK. The architecture is engineered specifically for Android OS constraints (Doze Mode, aggressive background process termination, CGNAT drop behaviors, and Google Play Foreground Service policies) while supporting fully decentralized operation with multi-tiered fallback mechanisms.

---

## 1. Network & Routing Architecture

The core runtime uses a **hybrid multi-layer connection and discovery engine**. It maintains a local persistent routing directory containing every known peer's **Peer ID**, **Endpoint (IP:Port)**, **FCM Token ID**, and **Optional Signaling Server Addresses**.

### Discovery & Connectivity Cascade

When an app requests a connection to a target `Peer ID`, the SDK executes the following ordered cascade:


```

+-------------------------------------------------------------------+
| 1. Local Cache Lookup                                             |
| Check SQLite / Key-Value Store for unexpired IP:Port              |
+-------------------------------------------------------------------+
| (Miss / Stale)
v
+-------------------------------------------------------------------+
| 2. Gossip Query (Peer Neighborhood)                               |
| Broadcast lightweight FIND_PEER query to active UDP neighbors     |
+-------------------------------------------------------------------+
| (No Response / Unknown)
v
+-------------------------------------------------------------------+
| 3. Out-of-Band FCM Push Trigger                                   |
| Send FCM payload containing local NAT candidates to Target Token  |
+-------------------------------------------------------------------+
| (Token Stale / Notification Failed)
v
+-------------------------------------------------------------------+
| 4. Community/Global Signaling Fallback (Last Resort)              |
| Query shared signaling server pool retrieved via Gossip           |
+-------------------------------------------------------------------+
| (Network Partitioned)
v
+-------------------------------------------------------------------+
| 5. Offline Out-of-Band Bootstrap                                  |
| Exchange initial handshake / token payload via local QR Code      |
+-------------------------------------------------------------------+

```

---

## 2. Peer Routing Directory & Gossip Protocol

To keep bandwidth overhead low across cellular networks, the gossip protocol uses a differential update strategy with flags to minimize serialization costs.

### Peer Record Structure

```cpp
struct PeerRecord {
    std::string peer_id;            // Cryptographic Public Key Hash
    std::string primary_endpoint;   // Last known reflexive IPv4/IPv6:Port
    std::string fcm_token_id;       // Firebase Cloud Messaging Registration Token
    std::string signaling_addr;     // Shared Signaling Server URL/IP (Optional)
    uint64_t token_version;         // Version counter for FCM Token updates
    uint64_t last_seen_utc;         // Timestamp for stale-entry purge
    uint8_t flags;                  // Bitfield flags (e.g., HAS_NEW_TOKEN, HAS_SIGNALING)
};

```

### Delta Gossip Rules

* **Token Optimization Flag (`0x01`):** FCM registration tokens are long strings. During gossip broadcasts, the `fcm_token_id` field is omitted unless the `HAS_NEW_TOKEN` flag is explicitly set. Peers assume the target peer’s FCM token remains unchanged if the version matches their local routing table.
* **Signaling Address Propagation (`0x02`):** Applications built on this SDK may optionally register public signaling server endpoints. These addresses are attached to gossip payloads under the `HAS_SIGNALING` flag.
* **Community Signaling Fallback Pool:** If an application without a signaling server loses all peer connectivity, it searches its local routing database for any signaling server addresses gossiped by *other* apps on the network. It uses these addresses as a shared fallback pool to locate a single active peer and rebuild its routing table.

---

## 3. Connection Lifecycles & Keep-Alive Strategy

Mobile networks utilize Carrier-Grade NATs (CGNAT), which drop idle TCP/UDP mappings rapidly. To survive these drop rates without draining the battery, the SDK manages socket states across two distinct phases.

```
       [ App Resume / Connection Request ]
                        |
                        v
          +---------------------------+
          | Phase 1: UDP NAT Punching |
          | Fast candidate discovery  |
          +---------------------------+
                        |
                        v
          +---------------------------+
          | Phase 2: Dual-Stack State |
          +---------------------------+
            /                       \
           /                         \
          v                           v
+-----------------------+   +-----------------------+
|  TCP Idle Connection  |   |  UDP Active Data Channel|
|  Adaptive Heartbeat   |   |  Low Latency Transfer |
|  (State Preservation) |   |  (P2P Payload Mesh)   |
+-----------------------+   +-----------------------+

```

### Phase 1: UDP Punching & Channel Establishment

1. **Candidate Exchange:** Ephemeral local and STUN-derived public reflexive endpoints are exchanged out-of-band via FCM Push payload or Gossip.
2. **Hole Punching:** Sockets send simultaneous UDP hole-punching bursts to establish bidirectional connectivity through CGNAT boundaries.

### Phase 2: Dual-Stack Execution & Idle Heartbeats

* **TCP Idle Control Channel:** Once punch-through succeeds, a low-overhead TCP control socket is established for long-term connection state maintenance.
* **Adaptive Heartbeat Timers:** Rather than using static timers that trigger radio tail-time battery drain, the SDK utilizes adaptive keep-alive intervals:
* **Initial Probe Interval:** Starts at 45 seconds.
* **Adaptive Ramping:** Gradually ramps to 90s, 120s, and up to 180s based on detected network stability.
* **Radio Synchronization:** Heartbeats are synchronized bidirectionally (Peer A ping $\rightarrow$ Peer B pong) to ensure mobile radios wake up only once per cycle.


* **UDP Active Data Bursting:** When active data transfer is requested, the SDK spins up parallel UDP streams (or QUIC frames) for high-throughput, low-latency transmission. Once idle, data channels close, reverting the connection to the low-power TCP control state.

---

## 4. Android Integration & Platform Limits

Android OS imposes stringent power and process constraints that govern background execution.

### WorkManager & Background Resumption

* **No Infinite Foreground Services:** The SDK avoids relying on permanent background Foreground Services (`FGS`), which violate modern Android 14/15 Google Play policies.
* **FCM High-Priority Wake-Up:** FCM push payloads wake the app from deep sleep (Doze Mode). On receipt, native C++ state machines are initialized to handle direct incoming connection attempts.
* **Periodic WorkManager Tasks:** When the process is active in the background, `WorkManager` runs lightweight routing table cleanups, purging stale endpoints, and updating active tokens.

---

## 5. C++ Native SDK Engine Architecture

The architecture separates network logic from platform abstraction via clean JNI bindings.

```
+-----------------------------------------------------------------+
|                       Android Layer (Kotlin)                    |
|  - Firebase Messaging Service (Push Payload Handlers)           |
|  - WorkManager (Periodic Routing Table Purge)                   |
|  - Platform Power & Connectivity Observers                      |
+-----------------------------------------------------------------+
                                | JNI Interface
                                v
+-----------------------------------------------------------------+
|                       C++ Core Engine                           |
|  +-----------------------+          +------------------------+  |
|  | Network Object Storage|          | Peer Discovery Engine  |  |
|  | - SQLite Routing Table|          | - Push Signaling Module|  |
|  | - Lease & Quotas      |          | - Gossip Module        |  |
|  +-----------------------+          +------------------------+  |
|  +-----------------------------------------------------------+  |
|  | Event-Driven Socket Reactor (libuv / custom epoll loop)   |  |
|  | - Adaptive Keep-Alive Timer Engine                        |  |
|  | - UDP Hole Punching / TCP Fallback Controllers            |  |
|  +-----------------------------------------------------------+  |
+-----------------------------------------------------------------+

```

### Key Engine Components

1. **JNI Dispatcher:** Translates inbound FCM notifications into native events and exposes direct C++ bindings to the Kotlin/Java host app.
2. **Event-Driven Socket Reactor:** Uses a cross-platform non-blocking event loop (`epoll` on Linux/Android) to handle hundreds of concurrent peer connections with minimal memory overhead.
3. **Storage Engine:** Houses local key-value state, routing caches, and pending lease/message queues using an embedded SQLite database.

---

## 6. Implementation Checklist & Phase Roadmap

### Phase 1: Core Engine & Dual-Stack Sockets

* [ ] Implement non-blocking UDP hole-punching and STUN candidate resolution in C++.
* [ ] Build adaptive TCP keep-alive socket manager (45s–180s dynamic intervals).
* [ ] Implement embedded SQLite storage for local peer records and routing tables.

### Phase 2: Gossip Protocol & Delta Updates

* [ ] Implement `PeerRecord` binary serialization format.
* [ ] Build delta-gossip engine with `HAS_NEW_TOKEN` (`0x01`) and `HAS_SIGNALING` (`0x02`) flag checks.
* [ ] Build community signaling pool discovery logic (storing and querying gossiped signaling server endpoints).

### Phase 3: Out-of-Band Discovery & Push Integration

* [ ] Build FCM payload generator containing NAT candidate lists and connection nonces.
* [ ] Construct JNI bindings for Kotlin FCM Receiver $\rightarrow$ Native C++ Engine dispatch.
* [ ] Implement the 4-tier fallback state machine (`Local Cache` $\rightarrow$ `Gossip` $\rightarrow$ `FCM Push` $\rightarrow$ `Community Signaling`).

### Phase 4: Android Hardening & OS Compatibility

* [ ] Implement `WorkManager` background maintenance tasks for directory pruning.
* [ ] Optimize socket wakeups for Android Doze Mode alignment.
* [ ] Add offline QR-code exchange serialization for non-network bootstraps.

```

```