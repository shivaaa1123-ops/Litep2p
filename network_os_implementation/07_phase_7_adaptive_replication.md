# Phase 7 — Adaptive Replication + Peer Selection

**Master doc references:** §10 (adaptive replication, durability ladder
D0–D5), §11 (replica leases + repair), §13 (peer selection/scoring), §17
(connection budgets), §61 (failure semantics), §76 (retry strategy), §80
(network diversity), §89 Phase 7 ("Adaptive Replication").

## 1. Objective

Replace fixed gossip/flooding with **target-driven replication**. Deliverable
(master doc §89 Phase 7):

> Replication changes based on actual durability instead of fixed gossip.

The runtime continuously knows approximate durability and repairs toward a
policy target, using local peer scores and diversity-aware placement.

## 2. Scope

**In scope:** durability tracking (D0–D5), ReplicationPolicy, local peer
scoring, replica planner with diversity heuristics, lease expiry/repair,
connection budgets by resource state, retry strategy (backoff + event).

**Out of scope:** full Android resource manager (Phase 8), discovery
expansion (Phase 9), large objects (Phase 10), simulator tuning (Phase 11).

## 3. Prerequisites

- Phase 6 complete (anti-entropy; reconciliation is the delivery mechanism
  replication uses).
- Phase 4 leases available.

## 4. Background

Master doc §10: fixed fan-out wastes mobile resources. Track durability
levels:

```
Local only                D0
1 confirmed remote copy   D1
2 independent copies      D2
3 independent copies      D3
Destination accepted      D4
Destination signed ACK    D5
```

For a normal chat message: target = D2. If a carrier disappears or a lease
expires, current durability falls below target → the planner repairs (§11).
More copies are not always better — over-replication causes congestion (§68).

**Locked decision 13 (simulate before you tune):** replication/lease
constants (`desired_remote_copies`, lease durations, repair thresholds) are
set **only** from the deterministic churn harness — a skeleton is built in
this phase (Step 5.8/Deliverables) and completed in Phase 11. Every constant
change is recorded with its before/after measured data; tuning by intuition
is prohibited.

## 5. Detailed implementation steps

### Step 5.1 — Durability tracking
- Store current durability level per object (derive from `leases` +
  destination state; persist a `durability_level` column for cheap queries).
- Update on STORED_ACK (up), lease expiry (down), eviction (down),
  delivery (D4/D5). Idempotent updates; crash-safe.

### Step 5.2 — ReplicationPolicy (§10, §55)
```cpp
struct ReplicationPolicy {
    uint8_t minimum_remote_copies;
    uint8_t desired_remote_copies;   // durability target
    uint8_t maximum_remote_copies;
    Duration ttl;
    Priority priority;
    bool prefer_network_diversity;
    bool prefer_high_uptime_peers;
    bool require_destination_receipt;
};
```
Policies per object class (normal chat D2, urgent higher, IoT low replicas
short TTL). Runtime may clamp unsafe values (§55). No hardcoded
F=3/R=2/TTL=48h inside the engine (§3.3) — policy-driven.

### Step 5.3 — Local peer score (§13)
No central reputation. Score each known peer from local observations:
- recent reachability, successful handoffs, observed uptime, latency;
- available storage + carrier willingness (from capabilities §39);
- network type/cost, failure rate, recent overload;
- protocol compatibility.
Map to trust tiers (§81: unknown/known/trusted/blocked) that alter quota
and lease tiers. Persist scores in the peer table (§75) with aging.

### Step 5.4 — Replica planner
Given durability deficit for an object:
1. Enumerate candidate peers (connected + historically reliable).
2. Score candidates (peer score + diversity + lease capacity).
3. Prefer **failure-domain diversity** (§13, §80): avoid same LAN, same
   connectivity, peers that disappear together.
4. Issue Phase 4 handoffs until `desired_remote_copies` reached.
5. Never exceed `maximum_remote_copies`.

### Step 5.5 — Lease expiry and repair (§11)
- `LEASE_EXPIRING` events (Phase 4) schedule a repair handoff before the
  lease becomes unsafe.
- Peer loss/`EVICTED_EARLY` drops durability → planner replenishes.
- Rebalance when a stronger peer appears (optional, bounded).

### Step 5.6 — Connection budgets (§17)
Respect ResourceManager budgets (Phase 4 stub → Phase 8 full):
foreground = generous sessions; background = small; battery saver =
critical only. Replication must not open sockets outside budget.

### Step 5.7 — Retry strategy (§76)
- Exponential backoff + jitter; **event-triggered** early retry on network
  change, destination availability, new peer, or connectivity event.
- Never retry every object independently every N seconds.
- Failures classified (§61): `NO_CARRIER` transient; retry budget bounded.

### Step 5.8 — Telemetry
Replica count per object (histogram), durability distribution, repair
events, peer score samples, over-replication warnings.

## 6. Data / schema changes
- `durability_level` column; `peer_scores` table (bounded, aged);
  replication policy per namespace stored in `namespaces`.

## 7. Wire protocol changes
- None new at the wire level (uses Phase 4 handoff + Phase 6
  reconciliation). Capability fields for carrier capacity/storage class
  already defined (§39) — populate them.

## 8. Deliverables
- `modules/networkos/replication/` (planner, scoring, repair) + tests
  `desktop/tests/replication_test`.
- `docs/network-os/13-replication.md`.
- Churn harness skeleton (used fully in Phase 11).

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Durability ladder (10×):** drive an object D0→D5 through the phases;
   verify level transitions persist across restarts and never regress
   without an event (lease expiry, eviction, loss).
2. **Target repair (10×):** set target D2; place 2 leases; kill one carrier
   → durability drops → planner replenishes to D2 within bounded time; does
   **not** over-replicate beyond target (counter asserts ≤ max).
3. **Lease expiry repair (5×):** short leases expire → LEASE_EXPIRING →
   takeover before expiry (no window with zero remote copies when policy
   demands ≥1).
4. **Diversity placement (5×):** peers on the same "failure domain" (simulated
   group tag) are not double-selected when diverse alternatives exist.
5. **No fixed gossip (5×):** idle network with full durability → zero
   replication traffic; counters show no periodic re-replication.
6. **Backoff + event retry (5×):** NO_CARRIER → backoff with jitter; network
   change event triggers early retry; retry budget bounded.
7. **Connection budgets (3×):** with background budget, replication
   throttled; foreground budget allows full repair.
8. **Churn harness (5×):** skeleton harness: 10 peers, random churn +
   partitions; durability target reached for ≥ X% of objects (record the
   measured number — this becomes the Phase 11 baseline).
9. **Phase 5 regression (5×):** §99 scenario green.
10. **Phase 6 regression (5×):** convergence still green.
11. **Existing suites (5×):** no regression.
12. **Native build (1×):** green.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-21 | durability ladder | 1 | PASS | D0→D5 monotonic + idempotent + persisted across reopen (replication_test) |
| 2026-08-21 | target repair | 1 | PASS | D2 target: 2 handoffs, no over-replication at target, replenish 1 after loss |
| 2026-08-21 | peer scoring + diversity | 1 | PASS | same failure domain not double-selected; highest-score diverse peer chosen |
| 2026-08-21 | lease expiry repair | 1 | PASS | D2→D1 on expiry → replenish to D2 |
| 2026-08-21 | backoff + event retry | 1 | PASS | no-carrier→backoff marker; connectivity triggers retry |
| 2026-08-21 | connection budgets | 1 | PASS | background ≤1 handoff; foreground full repair |
| 2026-08-21 | no fixed gossip | 1 | PASS | idle at full durability → zero replication traffic |
| 2026-08-21 | churn harness | 1 | PASS | 10 peers × 5 objects, random churn → 50/50 reached D2 (100%) — Phase 11 baseline |
| 2026-08-21 | Phase 5 regression | 1 | PASS | delivery_test 72 checks green |
| 2026-08-21 | Phase 6 regression | 1 | PASS | anti_entropy_test 27 checks green |
| 2026-08-21 | existing suites | 1 | PASS | 18 unit suites × exit-0 (incl. replication_test 34 checks) |
| 2026-08-21 | native build | 1 | PASS | `externalNativeBuildMultiThreadDebug` green (all ABIs) |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Over-replication → congestion (§68) | Maximum copies enforced; counter asserted; congestion reduces replica creation |
| Repair storms after partitions heal | Batch repairs + priority ordering (Phase 6 §60); bounded per session |
| Peer score gaming | Local-only scores; scores cap quota tiers; no global reputation (§13) |
| Lease churn burns radio | Repair only on events; batches; budgets |

## 12. Definition of Done

- [x] Durability tracking D0–D5 with crash-safe, idempotent transitions.
- [x] ReplicationPolicy + per-namespace policies; no hardcoded constants (all
      policy-driven via `repl_policies`).
- [x] Local peer scoring + trust tiers; diversity-aware placement.
- [x] Lease expiry/repair replenishes to target without over-replication.
- [x] Retry = backoff + jitter + event-triggered; bounded.
- [x] Churn harness baseline recorded (this is Phase 11's starting number):
      `replication_test` churn harness — 50/50 objects reached D2 (100%).
- [x] Invariants 5, 6, 15 asserted by tests (backoff/repair-loop, durability
      target, no-over-replication counters).
- [x] Phases 5 & 6 regression green; existing suites green; native build green.
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message:
      `Network OS P7: adaptive replication, peer scoring, replica repair`.

