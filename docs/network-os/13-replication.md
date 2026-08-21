# 13 — Adaptive Replication & Peer Scoring

**Phase 7.** Master doc: §10 (durability ladder D0–D5), §11 (replica leases +
repair), §13 (local peer scoring), §17 (connection budgets), §55 (replication
policy), §61 (failure semantics), §76 (retry), §80 (network diversity).

## Goal

Replace fixed gossip/flooding with **target-driven replication**: the runtime
continuously knows *approximate durability* per object and repairs toward a
policy target using local peer scores + failure-domain diversity — never
over-replicating past the policy maximum.

## Durability ladder (§10)

```
Local only                  D0
1 confirmed remote copy     D1
2 independent copies        D2   <- normal chat target
3 independent copies        D3
Destination accepted        D4
Destination signed ACK      D5
```

Durability is persisted per object (`objects.durability_level`). It rises
monotonically on protocol proof (STORED_ACK, delivery ack) and falls only on an
explicit loss event (lease expiry, carrier loss, eviction) that triggers
repair.

## Components

- **`ObjectStore`** — five new features:
  - `durability_level` column + idempotent `raise/lower/set/getDurability`.
  - `repl_policies` table: per-namespace min/desired/max copies, TTL, priority,
    diversity/high-uptime/receipt preferences (§55).
  - `peer_scores` table: local-only peer evidence, bounded + aged (§13/§75).
  - `replica_backoff` table: per-object repair backoff marker (invariant 5).
  - `forEachObjectBelowDurability` — deficit scan for the planner.
- **`replication/ReplicaPlanner`** — the planner:
  - `plan()` — scan deficits, repair toward policy target, bounded by budget.
  - `chooseCandidates()` — score + failure-domain diversity placement (§13/§80).
  - `repairObject()` — never exceed `maximum_remote_copies` (§68).
  - `noteStoredAck / noteDeliveryAcked / noteLeaseExpired / noteEvictedEarly`
    — durability accounting from protocol events (§10/§11).
  - Retry: exponential backoff + jitter, **event-triggered** early retry
    (peer_ready / connectivity), bounded (§76).
  - Connection budgets: foreground vs background handoff caps (§17/§5.6).
  - Telemetry counters (§5.8).
- **Runtime wiring** — owns a `ReplicaPlanner`, routes STORED_ACK→D1,
  RECEIVED_ACK→D5, LEASE_EXPIRING→repair, peer_ready/connectivity→retry.

## Schema v4

| Table | Purpose |
|---|---|
| `objects.durability_level` | current D-level (0..5) |
| `repl_policies` | per-namespace replication policy |
| `peer_scores` | local peer evidence, bounded + aged |
| `replica_backoff` | per-object repair backoff markers |

## No over-replication

`repairObject` computes `issue = min(deficit, max - current)`; the planner
never emits more handoffs than the policy allows. Idle networks at full
durability emit **zero** replication traffic (no periodic gossip timers).

## Rules

- Constants (copy counts, lease durations, repair thresholds) are tuned only
  from the deterministic churn harness (Locked decision 13) — the skeleton is
  in `desktop/tests/replication_test.cpp` (`test_churn_harness`); every change
  is recorded with its measured before/after.
- Peer scores are **local-only**; no global reputation; scores cap quota/lease
  tiers (§13).
- Repair is event-triggered + bounded; backoff markers prevent tight loops.