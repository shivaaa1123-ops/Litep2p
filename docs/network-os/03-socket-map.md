# Network OS Phase 0 — Step 1.3: Socket Ownership Map

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** Which module opens/closes sockets, endpoint resolution, reconnect paths, idle-socket policy.
**Purpose:** Input to Phase 1 `ITransport` (thin facade), Phase 2 bounded-session work, and Gate C (dynamic ports).

## 1. Socket owners

| Socket | Owner | Created by | Closed by | Reconnect path |
|---|---|---|---|---|
| UDP listener (data) | `UdpConnectionManager` (`udp_connection_manager.h:23`) | `startServer`/`startServerEventLoop` | `stop()` | `restartSocket()` after interface change; dynamic port range from `network.port_range` (`config_manager.h:55`) with `getBoundPort()` fallback |
| TCP listener (data) | `ConnectionManager` (`connection_manager.h:10`) | `startServer` | `stop()` | — (peer reconnects outbound) |
| TCP client sockets | `ConnectionManager::connectToPeer` | outbound connect (engine thread or event loop) | `disconnectPeer`/`stop` | FSM `CONNECTING→…→DISCONNECTED→CONNECTING` loop |
| UDP NAT-traversal sockets | `NATTraversal` (`nat_traversal.h`) | punch workers (bounded, `MAX_ON_DEMAND_PUNCH_THREADS=10`) | on punch completion/timeout | re-punch via `enqueue` (coalesced) |
| STUN probe sockets | `nat_stun` / `NATTraversal` | STUN server probes | per-probe | heartbeat tick |
| UPnP control sockets | `upnp_controller` | when UPnP enabled (`isUPnPEnabled`) | cleanup | — |
| TURN client sockets | `turn_client` | on TURN relay use | teardown | — |
| LAN discovery socket | `broadcast_discovery_manager` (`discovery.h:7`) | `start`/`startEventLoop` on `network.discovery_port` (default 30000) | `stop` | periodic broadcast (`DISCOVERY_BROADCAST_INTERVAL_SEC=5`) |
| Signaling WebSocket | `signaling_client` | on `ensure_signaling_connected_async` | server drop / `stop` | `getSignalingReconnectIntervalMs()` backoff + `m_last_signaling_reconnect_kick` throttle (`maintenance_manager.h:20`) |
| Overlay relay sockets | none (reuses session path) | — | — | LPX2 frames ride the session send path (`overlay_router.h:259 send_or_queue_`) |
| Proxy upstream/downstream | `ProxyEndpoint` per-stream `io_thread` (`proxy_endpoint.h:168`) | on stream open | on stream close | — |

## 2. Endpoint resolution

- `network_id` strings are `host:port` (IPv4/IPv6-aware; `format_network_id`/`parse_network_id` in `device_utils.cpp:268-326`).
- Peer DB reconnect candidates are resolved from `LocalPeerDb::get_reconnect_candidates` (JSON store, `local_peer_db.h:55`) and passed to `connectToPeer`.
- Discovery announcements advertise `peer_id:port`; obfuscated form is `<magic> || nonce || AEAD_ct` (`parse_discovery_announcement`, `discovery.h:49`).
- `setConnectionPort` (discovery) propagates the real bound port when the configured port was contended (`discovery.h:38`).

## 3. Idle-socket policy

- Idle heartbeat: `PING_INTERVAL_SEC=10`, `PEER_TIMEOUT_SEC=30`, `TIMER_TICK_INTERVAL_SEC=10` (`constants.h:13-14,17`).
- Keepalive interval is battery-aware via `PeerReconnectPolicy::get_keepalive_interval_seconds()`.
- Sessions are cached (`SessionCache`, `cache_lifetime_sec` from config, default 3600) to avoid re-handshake, and cleaned by `cleanup_expired()`.
- **Idle socket count is config/topology dependent**: the engine keeps the data listeners (UDP+TCP) and the discovery socket open at idle, plus NAT/STUN heartbeat sockets when enabled. Measured counts are recorded in `baseline-*.json`.

## 4. Dynamic port (censorship resistance)

- `network.port_range = [lo, hi]`: the engine binds a random free port at startup (`getDataPortRange`, `config_manager.h:55`); peers learn the real endpoint via discovery (`setConnectionPort`) and the peer DB.
- Discovery port and magic/shared-key are config-driven (`getDiscoveryPort`, `getDiscoveryMagic`, `getDiscoverySharedKey`).
