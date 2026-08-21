# 15 — Modular Discovery & Optional Infrastructure

**Phase 9.** Master doc: §14 (discovery architecture), §15 (optional
infrastructure), §73 (NAT/internet reachability layering), §79 (HA peers),
§52 (carrier willingness), §50 (privacy), §72 (no premature DHT), §89 P9.

## Goal

Discovery is **modular** with explicit graceful degradation: LAN + known-peer
reconnect + peer exchange + optional bootstrap/rendezvous all work together,
and the network keeps operating in connected components if every optional
infrastructure service disappears.

## Components

- **`modules/networkos/discovery/DiscoveryManager`** — the coordinator.
  - Backend registration behind a common `IDiscoveryBackend` interface:
    LAN, known-peer reconnect, peer exchange, optional bootstrap
    (signaling server), optional relay. Future BLE / Wi-Fi Direct / DHT plug
    in without touching the core (§14).
  - **Intensity scaling** from the resource profile (Phase 8): ECO/low-battery/
    metered => on-demand; active => fuller scans. Discovery never adds
    periodic battery churn.
  - **Graceful degradation** (§15, invariant 19): the runtime never refuses to
    start or operate when optional infrastructure is absent.
  - **NAT/internet reachability layering** (§73):
    `direct → NAT traversal → relay → store-and-forward`.
  - **Carrier willingness + HA capabilities** (§52/§79): policy flags honored;
    a low-battery peer advertises `storage_carrier=false`.
  - **Bounded peer exchange** (§50): never floods; dedup by id; bounded per
    exchange; fresher info wins.
  - **Serverless presence + alias fallback** (decision 11): presence and alias
    resolution still work with the signaling server down (peer exchange +
    known-peer table).
- **Runtime wiring** — owns `discovery()`, feeds discovery intensity from the
  `ResourceManager` budget on every platform signal.

## Graceful degradation matrix (§15)

| Component | Present | Absent |
|---|---|---|
| signaling server | better discovery + reachability (aliases, invites, mailbox) | known peers + LAN + peer exchange + connected components continue |
| relay nodes | reachability for NAT'd peers | store-and-forward through reachable peers |
| NAT traversal | direct/hole-punched paths | relay or store-and-forward |

## Gate A — decentralization

No single point of failure: killing the server, relays, or an HA peer (one at a
time and in combination) never removes the last functional path. Operation only
degrades when every non-optional backend is gone.

## Rules

- No global DHT in v1 (§72 — measure before building).
- No global reputation; capabilities carry no battery/identifying data (§50).
- OBF1 obfuscated discovery + dynamic ports + padding are preserved (capture
  regression in this phase).
- Discovery intensity is data-driven by the resource manager, never a fixed
  aggressive loop.