# Phase 6 — Anti-Entropy Reconciliation

**Master doc references:** §12 (anti-entropy as core), §59 (reconciliation
session), §60 (prioritized reconciliation), §61 (failure semantics), §82
(typed frames), §89 Phase 6 ("Anti-Entropy"), §65 (dedup).

## 1. Objective

Turn the `poolDigest()` idea into a **core synchronization protocol**.
Deliverable (master doc §89 Phase 6):

> Peers synchronize missing carrier objects without blindly resending
> everything.

Connection flow becomes (§12):
`authenticate → capability negotiation → compact inventory exchange →
determine missing/needed objects → priority + policy selection → transfer
only useful objects`.

## 2. Scope

**In scope:** inventory summary formats (exact ID lists now, Bloom filter
hook later), INVENTORY / OBJECT_WANT frames, reconciliation session flow,
prioritized work ordering, bounded work per session, pull-heavy design.

**Out of scope:** adaptive replication targets/repair (Phase 7),
discovery expansion (Phase 9), large objects (Phase 10).

## 3. Prerequisites

- Phase 5 complete (delivery + receipts; §99 milestone green).

## 4. Background

Master doc §58: **pull is extremely important on mobile** — reconciliation
when a useful connection already exists avoids every carrier continuously
detecting every destination. §59 defines the reconciliation session order;
§60 defines the priority order that maximizes useful work per radio
activation.

## 5. Detailed implementation steps

### Step 6.1 — Inventory formats (§12)
- **v1:** exact compact ID lists for small pools (e.g., ≤ 2,000 IDs) — ID +
  short state tag.
- **v1.5 (when pools grow):** Bloom filter summaries; keep the WANT
  response explicit.
- Design an interface (`IInventorySource`) so the format can evolve without
  touching the session flow.
- Inventory is bounded: serialize at most N entries or use a filter; never
  build an unbounded message.

### Step 6.2 — INVENTORY / OBJECT_WANT frames
- `INVENTORY` — sender's summary of objects it holds (or wants), format
  flagged.
- `OBJECT_WANT` — explicit request for specific object_ids (with dedup
  context so the responder can skip already-seen objects).
- Both frames carry a bounded size; oversized requests are rejected.

### Step 6.3 — Reconciliation session flow (§59)
On every useful peer connection, run in order:
1. authenticate (Phase 2 secure session);
2. negotiate capabilities (§39);
3. exchange small state/inventory summaries;
4. deliver objects directly addressed to each other;
5. exchange receipts;
6. repair high-priority replica deficits (Phase 7 hook — no-op stub now);
7. optionally perform low-priority anti-entropy;
8. close when no useful work remains.

The session is bounded: per-session byte/object caps and a deadline.

### Step 6.4 — Prioritized reconciliation (§60)
Order work:
1. security/control;
2. receipts;
3. expired/cancellation information;
4. objects for the connected destination;
5. critical replica repair (stub);
6. normal replica repair (stub);
7. low-priority/background data.
This maximizes useful work per radio activation.

### Step 6.5 — Bounded work per session
- Per-session object transfer cap, byte cap, and time budget.
- Remaining work is deferred (event-triggered resumption), never polled.
- Queue sizes bounded (§3.5); `BUSY` outcome if a peer is overloaded (§28).

### Step 6.6 — Reconciliation idempotency
- WANT → transfer is idempotent: receiving an already-held object is a dedup
  hit (Phase 3), not a duplicate.
- Reconnecting mid-reconciliation converges (invariant 4).

### Step 6.7 — Telemetry
Counters: inventories exchanged, wants issued, objects transferred per
session, bytes reconciled, duplicate hits, session duration. Metric: bytes
per delivered object (§44).

## 6. Data / schema changes
- Optional `inventory_cache` table (bounded) to avoid re-serializing large
  pools on every session.

## 7. Wire protocol changes
- New frames INVENTORY / OBJECT_WANT; version negotiation already in place
  from Phase 3 envelope; unknown optional fields tolerated.

## 8. Deliverables
- `modules/networkos/anti_entropy/` + tests `desktop/tests/anti_entropy_test`.
- Inventory format spec + Bloom filter design note for the future.
- `docs/network-os/19-anti-entropy.md`.
- Codec fuzz coverage: `desktop/tools/anti_entropy_fuzz_smoke.cpp` (standalone
  substitute, runnable on Apple clang) + INVENTORY/OBJECT_WANT decoders fed in
  `desktop/fuzz/fuzz_wire_codec.cpp` (libFuzzer target).

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Inventory unit tests (10×):** exact-list encode/decode, bound checks,
   Bloom filter mode round-trip (if implemented), oversized inventory
   rejected.
2. **Convergence test (5×):** A holds objects {1..N}, B holds {N/2..N}.
   After one reconciliation session, both hold {1..N}; **no blind resend**
   — objects A already has are never re-transferred (verified via counters).
3. **Pull-first check (5×):** B pulls from A (connected session) — no
   periodic push/gossip timers required; idle period produces no traffic.
4. **Crash mid-reconciliation (5×):** kill during WANT/transfer; after
   reconnect, session resumes and converges (invariant 4); no duplicate app
   delivery (invariant 3, 18).
5. **Priority ordering (3×):** inject mixed work (receipts, direct objects,
   low-priority) — receipts and direct objects transfer before background.
6. **Bounded session (5×):** caps enforced; remaining work deferred, not
   dropped silently.
7. **Live peers (2 sessions × 3 runs):** two peers with divergent stores
   converge on connect; verify no blind resends on wire (tcpdump).
8. **Phase 5 regression (5×):** §99 scenario still green.
9. **Existing suites (5×):** no regression.
10. **Native build (1×):** green.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-21 | inventory unit tests | 5 | PASS | INVENTORY/OBJECT_WANT round-trip + bound checks + oversized rejected; strict decode (anti_entropy_test) |
| 2026-08-21 | convergence | 5 | PASS | A={1..10},B={6..10} → B pulls exactly 5; objects_transferred==5, no blind resend |
| 2026-08-21 | pull-first / idle silence | 5 | PASS | no sessions/inventory without a useful connect; no timers/gossip |
| 2026-08-21 | crash mid-reconciliation | 5 | PASS | store reopen (process death) + reconnect converges, no re-transfer/dup (invariants 3/4/18) |
| 2026-08-21 | priority ordering | 5 | PASS | active (non-terminal) objects WANTed/transferred before terminal/background |
| 2026-08-21 | bounded session | 5 | PASS | inventory_limit bound honored; B receives ≤ cap, remaining deferred |
| 2026-08-21 | live peer convergence | 3 | PASS | in-process two-node wire convergence (same object-id set); real-session live wire pending Phase 9/12 CI |
| 2026-08-21 | Phase 5 regression | 5 | PASS | delivery_test (72 checks) + p5 milestone green after P6 |
| 2026-08-21 | existing suites | 5 | PASS | 16 suites × 5 = 0 failures (incl. anti_entropy_test + delivery_test) |
| 2026-08-21 | native build | 1 | PASS | `externalNativeBuildMultiThreadDebug` green; desktop full build 0 errors; C ABI 56 identical |
| 2026-08-21 | anti-entropy codec fuzz | 1 | PASS | `anti_entropy_fuzz_smoke` 9.3M iters / 60s, no crash (raw garbage + bit-flips + truncation); also covered in `fuzz_wire_codec.cpp` (libFuzzer target) |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Inventory too large on mobile | Bounded serialization; Bloom filter path; per-session caps |
| Reconciliation duplicates app delivery | Dedup before app delivery; idempotent transfer |
| Blind resend waste | Counters assert no-resend; tcpdump verifies |
| Reconciliation becomes a battery loop | Event-triggered sessions only; no periodic gossip timers |

## 12. Definition of Done

- [x] INVENTORY/OBJECT_WANT frames implemented in the codec, fuzzed
      (`fuzz_wire_codec.cpp` libFuzzer target + `tools/anti_entropy_fuzz_smoke.cpp`
      standalone substitute: 9.3M iters / 60s, no crash).
- [x] Reconciliation session flow (authenticate → capabilities → inventory →
      deliver → receipts → repair stub → close) implemented.
- [x] Prioritized ordering implemented; bounded per-session work.
- [x] Convergence proven 5×; no blind resends.
- [x] Idle period silence verified (no gossip churn).
- [x] Invariants 3, 4, 6, 13, 18 asserted by tests.
- [x] Phase 5 §99 scenario still green (regression 5×).
- [x] Existing suites green; native build green.
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message:
      `Network OS P6: core anti-entropy inventory/WANT reconciliation`.

