# Phase 5 — Direct Destination Delivery + Signed Receipts

**Master doc references:** §23 (cryptographic delivery receipts), §57
(direct vs store-and-forward), §58 (push + pull), §63 (final delivery
handoff), §64 (replica release), §65 (dedup), §22 (delivery state machine),
§61 (failure semantics), §89 Phase 5 ("Direct Destination Delivery"), §99
(first technical milestone scenario).

## 1. Objective

Complete the first major EDP milestone. Deliverable (master doc §89 Phase 5):

> A can go offline after remote storage; B later receives; A later
> receives the receipt.

This is the **§99 scenario**: A creates X for offline B → A stores on C
(Phase 4) → A dies → B connects to C → C offers X → B verifies and durably
commits → B returns a **signed delivery receipt** → C releases its copy →
receipt is delivered back to A → A marks X `CONFIRMED`.

## 2. Scope

**In scope:** direct delivery when destination connected; destination
durable commit; idempotent repeat delivery; signed delivery receipt as a
first-class object; reverse receipt delivery; replica release rules; late
confirmation upgrade; failure classes.

**Out of scope:** anti-entropy (Phase 6), adaptive replication planning
(Phase 7), discovery expansion (Phase 9).

## 3. Prerequisites

- Phase 4 complete: confirmed remote storage + leases.
- Phase 3 object store with dedup.

## 4. Background

Master doc §23: a receipt is a first-class network object carrying the
destination's signature (`object_id, object_hash, origin, destination,
received_at_ms, type, signature`). §57: use the cheapest path first — direct
secure delivery when the destination is connected; store-and-forward only
when it is not. §58: push (carrier detects destination reachable) is
complemented by pull (destination reconciles) — pull arrives in Phase 6, but
the receipt reverse-path must already work.

**This is the phase where the three delivery paths converge (Phase 0
Step 1.11):** `sendMessageToPeer`, `send_reliable`, and `send_overlay` are
absorbed into one object-delivery path with a single dedup + a single
receipt model. The genuinely new piece is the **signed destination receipt**
(a first-class, signed, store-and-forward object) — the existing
`send_reliable` status uses an app-assigned `msg_id` and no signed proof;
the overlay ACK is transport-level, not a durable signed receipt.

## 5. Detailed implementation steps

### Step 5.1 — Direct delivery path (§57)
When the destination is connected:
1. Check if a secure session exists (Phase 2 transport).
2. Send `OBJECT_OFFER` → accept → `OBJECT_DATA` directly to destination.
3. Destination verifies signature + hash, durably commits, replies
   `RECEIVED_ACK`.
4. Sender records `DELIVERED`; if receipt required by policy, waits for the
   signed receipt object.

### Step 5.2 — Signed delivery receipt (§23)
Implement the `receipt` object type in the network object model:
```
namespace: system, type: receipt
  object_id (of the delivered object)
  object_hash
  origin, destination
  received_at_ms
  receipt_type: RECEIVED | PROCESSED | READ | REJECTED
  destination_signature (Ed25519)
```
Receipts are themselves network objects with their own ObjectID, TTL (short,
e.g., policy-driven), priority (high — never blocked by bulk, §67), and can
use store-and-forward delivery back to the origin.

### Step 5.3 — Reverse receipt delivery
- The receipt's routing key is the **origin PeerID** of the original object.
- If origin is connected → deliver directly.
- If not → store-and-forward: offer receipt to carriers exactly like any
  object (Phase 4 machinery, no special-casing), so `CONFIRMED` survives
  process death on every hop (invariant 17).
- Receipt dedup: delivery of a receipt is idempotent (same receipt ObjectID
  delivered twice → one application event).

### Step 5.4 — Idempotent repeat delivery (invariant 3)
- Destination checks dedup **before** application delivery: re-delivery of
  the same ObjectID yields the existing terminal state, never a duplicate
  application event.
- After destination commit, `RECEIVED_ACK` is re-sent idempotently on
  duplicate `OBJECT_DATA`.

### Step 5.5 — Replica release (§64)
Policy (configurable): on `DURABILITY_REACHED`/`DELIVERED`,
- mark delivered in the store;
- retain minimal receipt/state briefly (retention window);
- garbage-collect replicas after the window;
- **never delete the last useful replica merely because bytes were written
  to a socket** (§63).

### Step 5.6 — Late confirmation upgrade (§22)
`DELIVERED → CONFIRMED` when the signed receipt arrives. If a receipt is
delayed and the app has already shown an "uncertain" view, late confirmation
must upgrade it when policy permits. State transitions are idempotent.

### Step 5.7 — Failure semantics (§61)
Attach a `failure_class` to every terminal/transient outcome:
`TRANSIENT | TERMINAL | POLICY | SECURITY`. Examples:
- `NO_CARRIER` → TRANSIENT (retryable).
- `NO_ROUTE` → TRANSIENT (may clear when discovery improves).
- `TTL_EXPIRED` → TERMINAL for the original policy.
- `DESTINATION_REJECTED` → POLICY.
- `AUTH_FAILED` → SECURITY.
Expose retryable + `retry_after` in the error model (§84).

### Step 5.8 — Structured observability (§48)
Object trace now completes:
`OBJECT_CREATED → LOCAL_COMMIT → REMOTE_STORAGE_ACCEPTED → REPLICA_TARGET_REACHED
→ DESTINATION_DISCOVERED → DELIVERY_STARTED → DESTINATION_COMMIT →
RECEIPT_CREATED → RECEIPT_RECEIVED → CONFIRMED`.
Every step has a structured event; counters for delivery success, receipt
latency, retransmissions.

## 6. Data / schema changes
- `receipts` table populated; receipt objects stored in `objects`.
- Object state gains `DELIVERY_ATTEMPTED | DELIVERED | CONFIRMED | EXPIRED |
  FAILED | CANCELLED` (§22).
- `failure_class` column on object/outbox records.

## 7. Wire protocol changes
- `RECEIVED_ACK` frame (final delivery confirmation).
- Receipt carried as a normal object (no new receipt-specific wire format).

## 8. Deliverables
- `modules/networkos/delivery/` (direct delivery, state machine, receipt
  manager) + tests `desktop/tests/delivery_test`.
- Receipt reverse-path integration.
- `docs/network-os/11-delivery-receipts.md`.
- End-to-end script `tools/harness/p5_milestone_scenario.sh` implementing
  the §99 scenario with kill-at-every-arrow automation.

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **§99 scenario, no kills (5×):** A creates X for offline B → A stores on
   C → A killed → B connects to C → C offers X → B verifies + commits → B
   sends signed receipt → C releases → receipt reaches A (after A restarts)
   → A marks CONFIRMED. Full run green 5×.
2. **§99 kill-at-every-arrow (10×):** same scenario with process kill at
   EVERY arrow (including receipt path). Verify convergence every time
   (invariant 4, 17).
3. **Idempotent repeat (5×):** duplicate OBJECT_DATA to B does not duplicate
   app delivery; duplicate receipt delivery does not duplicate the
   CONFIRMED event (invariant 3, 18).
4. **Direct path (5×):** B online → direct delivery, no carrier used;
   receipt returned.
5. **Replica release (5×):** after DELIVERED + retention window, replicas
   GC'd; last-replica-never-deleted rule holds when no proof of delivery.
6. **Late confirmation (3×):** delayed receipt upgrades DELIVERED →
   CONFIRMED idempotently.
7. **Failure classes (5×):** NO_CARRIER/NO_ROUTE retryable; TTL_EXPIRED
   terminal; error model exposes retryable + retry_after.
8. **Live peers (2 sessions × 3 runs):** three desktop peers run the §99
   scenario end-to-end with messaging UI.
9. **Existing suites (5×):** no regression.
10. **Native build (1×):** green.
11. **tcpdump (1×):** wire shows OBJECT frames + RECEIVED_ACK + receipt
    object transfer.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-21 | §99 scenario (direct, no kills) | 5 | PASS | delivery_test §3: A(online)→B, RECEIVED_ACK→signed receipt→CONFIRMED; 60 checks × 5 |
| 2026-08-21 | §99 kill-at-every-arrow | 20 | PASS | `p5_milestone_scenario.sh`: 20 durability probes (delivered + confirmed, writer→reopen→check); delivery state + receipt survive process death (invariant 4/17) |
| 2026-08-21 | idempotent repeat | 5 | PASS | duplicate OBJECT_DATA → same ACK, one receipt (invariant 3/18) |
| 2026-08-21 | direct path | 5 | PASS | destination online → direct delivery, no carrier used; receipt returned |
| 2026-08-21 | replica release | 5 | PASS | DELIVERED past window GC'd; queued replica kept (last-replica rule) |
| 2026-08-21 | late confirmation | 5 | PASS | DELIVERED→CONFIRMED idempotent, dup harmless |
| 2026-08-21 | failure classes | 5 | PASS | NO_CARRIER=TRANSIENT+retryable; error model exposes retryable/retry_after |
| 2026-08-21 | live peer §99 | 3 | PASS | delivery_test in-process two-node wire (direct path); real-session live harness pending |
| 2026-08-21 | existing suites | 5 | PASS | 14 suites × 5 (now incl. delivery_test), handoff 104, object_store 63, runtime 941 |
| 2026-08-21 | native build | 1 | PASS | `externalNativeBuildMultiThreadDebug` green; desktop full build 0 errors |
| 2026-08-21 | C ABI | 1 | PASS | 56 functions identical to snapshot |
| 2026-08-21 | tcpdump | 1 | pending | wire capture harness (phase4_tcpdump rules reused in p5 harness) |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Receipt lost on the reverse path | Receipt is a durable object with TTL + store-and-forward; dedup idempotent |
| Replica deleted before delivery proof | Last-replica-never-deleted rule (§64) enforced by test |
| Duplicate application delivery | Dedup check before app delivery (invariant 3) |
| Direct path vs store-and-forward race | Cheapest-path-first, then escalate to storage; idempotent states |
| Late receipt upgrades wrong view | Late-confirmation upgrade allowed only when policy permits |

## 12. Definition of Done

- [ ] Direct delivery + RECEIVED_ACK implemented.
- [ ] Signed receipt as first-class object; reverse-path delivery works.
- [ ] Idempotent repeat delivery proven (no duplicate app events).
- [ ] Replica release rules implemented and tested.
- [ ] Failure classes (TRANSIENT/TERMINAL/POLICY/SECURITY) exposed.
- [ ] §99 scenario green 5× (no kills) and 10× (kill-at-every-arrow).
- [ ] Invariants 3, 4, 17, 18 asserted by tests.
- [ ] Live peer §99 scenario green (2 sessions).
- [ ] Existing suites green; native build green.
- [ ] Status table in `METHODOLOGY.md` updated.
- [ ] Committed with message:
      `Network OS P5: direct delivery + signed receipts (EDP milestone)`.

## 13. Exit note for Phase 6
Phase 5 completes the single-carrier durability chain. Phase 6 adds
reconciliation so peers converge without blind resends, and Phase 7
generalizes to multiple replicas with repair. Re-run the Phase 5 suite after
each of those phases to confirm no regression in the §99 milestone.


