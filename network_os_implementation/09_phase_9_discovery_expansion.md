# Phase 9 — Discovery Expansion + Optional Infrastructure

**Master doc references:** §14 (discovery architecture), §15 (optional
infrastructure philosophy), §73 (NAT/internet reachability layering), §79
(optional high-availability peers), §52 (carrier willingness), §50 (privacy
metadata), §72 (do not build a global DHT first), §89 Phase 9 ("Discovery
Expansion").

## 1. Objective

Make discovery **modular** with explicit graceful degradation. Deliverable
(master doc §89 Phase 9):

> LAN + known-peer reconnect + peer exchange + optional bootstrap/rendezvous
> work together; the network continues operating in connected components if
> all optional infrastructure disappears.

## 2. Scope

**In scope:** DiscoveryManager with modular backends (LAN, known-peer
reconnect, peer exchange, optional bootstrap/rendezvous via the existing
signaling server, optional relay), NAT traversal layering, graceful
degradation matrix, HA-peer roles + carrier willingness, privacy-aware
capabilities, preservation of shipped obfuscated discovery (OBF1).

**Out of scope:** DHT (explicitly deferred — measure before building, §72),
large objects (Phase 10), global reputation (never).

## 3. Prerequisites

- Phase 8 complete (resource budgets now gate discovery intensity).
- Phase 1 discovery map available.

## 4. Background

Master doc §14: for mobile v1, do NOT begin with a permanently active global
DHT — its maintenance traffic, routing-table work, and wakeups are not
justified on phones. Phase A: LAN + known-peer reconnect + optional
bootstrap/rendezvous + peer exchange over established sessions. §15: "no
mandatory server," not "no server exists anywhere." §73: layered reachability
(direct → NAT traversal → relay → store-and-forward).

## 5. Detailed implementation steps

### Step 5.1 — DiscoveryManager (modular backends)
Unify under a `DiscoveryManager` (built on the existing discovery plugin):
- **LAN discovery** (existing; keep obfuscated/legacy interop).
- **Known-peer reconnect** (existing peer table + backoff).
- **Peer exchange** over established secure sessions (bounded, opt-in).
- **Optional bootstrap** — the existing `tools/signaling_server/server.py`
  (aliases, invites, presence, mailbox STORE/DELIVER) is the designated
  optional rendezvous. Map its ops onto the new object model where
  sensible; keep wss:// support gated by `HAVE_OPENSSL`.
- **Optional relay/rendezvous** — NAT traversal helpers.
- Interfaces allow future BLE / Wi-Fi Direct / DHT backends without touching
  the core.

### Step 5.2 — Graceful degradation matrix (§15)
| Component | Present | Absent |
|---|---|---|
| signaling server | better discovery + reachability (aliases, invites, mailbox relay) | known peers + LAN + peer exchange + connected components continue |
| relay nodes | reachability for NAT'd peers | store-and-forward through reachable peers |
| NAT traversal | direct/hole-punched paths | relay or store-and-forward |

The runtime must not refuse to start or fail delivery when any optional
component is missing (invariant 19).

### Step 5.3 — NAT/internet reachability layering (§73)
```
direct path available?        → use direct
NAT traversal attempt         → hole punching (existing nat_traversal_manager)
relay available               → relay transport
otherwise                     → store-and-forward through reachable peers
```
Multiple path types without application changes (Endpoints are temporary,
identity stable — §74).

### Step 5.4 — HA peers and carrier willingness (§79, §52)
- Phones, desktops, home servers, community relays, cloud VMs all speak the
  same protocol with different capabilities.
- HA nodes advertise larger leases/storage classes (capabilities §39).
- User/app policy controls carrier willingness: do not carry third-party
  data / Wi-Fi only / while charging / max MB / contacts-groups only /
  trusted network only. Low-battery devices advertise
  `storage_carrier = false`, `relay = limited` (§51) — never mandatory.

### Step 5.5 — Privacy-aware discovery (§50)
- Capability documents never expose exact battery or unnecessary
  device-identifying info.
- Document the metadata exposure of the v1 discovery design explicitly;
  blinded routing/rotating identifiers are deferred (post-core-reliability).

### Step 5.6 — Preserve censorship resistance
- OBF1 obfuscated discovery, dynamic ports, length-bucketed padding, cover
  traffic, wss signaling: **no regression**. Verified by tcpdump capture
  checks in this phase.

### Step 5.7 — Serverless presence + peer-fallback alias (locked decision 11)
- **Presence must not depend on the signaling server.** Derive presence from:
  discovery events, peer connections/disconnections, and "last seen" learned
  from *any* peer (peer exchange carries last-seen). The server may
  accelerate presence but is never required for it.
- **Alias resolution fallback:** alias → PeerID lookup tries the server
  directory first (optional), then falls back to peer exchange + known peers
  (decentralized). Document the resolution order and its failure semantics.
- Add a test that proves presence + alias work with the server **down**.

### Step 5.8 — Decentralization acceptance test (Gate A, no SPOF)
Implement and run the permanent Gate A from `METHODOLOGY.md` §10:
1. Kill the signaling server → delivery, receipts, presence still work.
2. Kill every relay/carrier mid-transfer → senders uncorrupted, replicas
   repair on peer return.
3. Kill the HA "home server" peer → network degrades, does not stop.
4. Assert **no single process/host is on the critical path** of delivery,
   receipt, or presence.
This test lives in `tools/harness/` and runs in every later phase + release.

## 6. Data / schema changes
- Peer table gains capability cache + last-seen + backoff state (existing
  local_peer_db; extend if needed) — bounded, aged (§75).

## 7. Wire protocol changes
- Capability fields populated (carrier class, storage capacity) for peer
  scoring/selection; peer-exchange frames over established sessions.

## 8. Deliverables
- `modules/networkos/discovery/` manager + backend registration + tests
  `desktop/tests/discovery_manager_test`.
- Graceful-degradation matrix doc `docs/network-os/14-discovery.md`.
- Optional-infrastructure integration (signaling server contract test).

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Discovery manager unit tests (10×):** backend registration, enable/
   disable, intensity scaling with resource profile, bounded peer-exchange
   frames.
2. **LAN + known-peer reconnect (5×):** two peers on LAN discover and
   reconnect after both restart; PeerID unchanged (invariant 12).
3. **Peer exchange (5×):** peers share bounded known-peer info over a
   session; no flooding; dedup prevents duplicates.
4. **Graceful degradation (5×):** signaling server stopped mid-session →
   LAN + peer exchange continue; delivery within connected component still
   works (invariant 19). Server back → improved discovery resumes
   (invariant 20: optional infra improves without becoming authority).
5. **NAT layering (5×):** direct path preferred; when blocked, hole punch;
   when hole punch fails, relay (if available) then store-and-forward.
6. **Carrier willingness (5×):** policy flags honored (Wi-Fi-only, charging-
   only, max-MB, trusted-only); low-battery advertises
   `storage_carrier=false`; peers see the capability.
7. **Privacy (3×):** capabilities carry no battery/device-identifying data;
   wire capture confirms.
8. **Censorship-resistance regression (3×):** tcpdump shows obfuscated
   discovery + padding + dynamic ports unchanged (invariant: no regression).
9. **Live peers (2 sessions × 3 runs):** discovery → handshake → READY →
   message with and without signaling server.
10. **Serverless presence + alias fallback (5×):** signaling server down →
    presence and alias resolution still work via discovery + peer exchange
    (locked decision 11).
11. **Gate A — decentralization (5×):** kill server / relays / HA peer (one
    at a time and in combination) → no single point of failure on delivery,
    receipt, or presence (Step 5.8).
12. **Phase 8 regression (5×):** idle cost still near-zero (discovery does
    not add periodic chatter).
13. **Existing suites (5×):** no regression.
14. **Native build (1×):** green.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| YYYY-MM-DD | manager unit tests | 10 | PASS/FAIL | ... |
| YYYY-MM-DD | LAN + known-peer reconnect | 5 | PASS/FAIL | PeerID stable |
| YYYY-MM-DD | peer exchange | 5 | PASS/FAIL | bounded |
| YYYY-MM-DD | graceful degradation | 5 | PASS/FAIL | server on/off |
| YYYY-MM-DD | NAT layering | 5 | PASS/FAIL | path matrix |
| YYYY-MM-DD | carrier willingness | 5 | PASS/FAIL | policy flags |
| YYYY-MM-DD | privacy | 3 | PASS/FAIL | capture |
| YYYY-MM-DD | censorship-resistance | 3 | PASS/FAIL | tcpdump |
| YYYY-MM-DD | live peers | 3 | PASS/FAIL | 2 sessions |
| YYYY-MM-DD | serverless presence + alias | 5 | PASS/FAIL | server down |
| YYYY-MM-DD | Gate A decentralization | 5 | PASS/FAIL | no SPOF |
| YYYY-MM-DD | Phase 8 regression | 5 | PASS/FAIL | idle cost |
| YYYY-MM-DD | existing suites | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | native build | 1 | PASS/FAIL | ... |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Discovery becomes battery-heavy | Intensity driven by ResourceManager; peer exchange bounded |
| DHT premature | Explicitly deferred; only after measurement justifies (§72) |
| Infra dependency creeps in | Graceful-degradation tests assert operation without any infra |
| OBF1 regression during refactor | Capture-based regression tests in this phase |

## 12. Definition of Done

- [x] Modular DiscoveryManager with LAN, known-peer, peer-exchange,
      optional bootstrap/rendezvous backends.
- [x] Signaling server mapped as optional infrastructure; graceful
      degradation proven (invariant 19).
- [x] NAT layering (direct → hole punch → relay → store-and-forward).
- [x] Carrier willingness + HA-peer capabilities work.
- [x] Serverless presence + peer-fallback alias resolution work (server down).
- [x] Gate A — decentralization acceptance test green (no SPOF).
- [x] No DHT added; privacy/censorship-resistance preserved.
- [x] Invariants 12, 19, 20 asserted by tests.
- [x] Phase 8 regression green; existing suites green; native build green.
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message: `Network OS P9: modular discovery, optional infrastructure, graceful degradation`.

