# Phase 4 — Confirmed Remote Storage + Replica Leases

**Master doc references:** §11 (replica leases), §19.3 (origin signature), §24
(never ACK before durable commit), §28 (backpressure outcomes), §63
(two-phase durable handoff), §65 (dedup), §82 (typed frames), §89 Phase 4
("Confirmed Remote Storage"), §61 (failure semantics).

## 1. Objective

Implement the **two-phase durable handoff** — the generalized R1/R2 primitive:

```
Sender/Carrier → OBJECT_OFFER
Receiver/Carrier → verify → durable commit → STORED_ACK
Sender/Carrier → records remote durability
```

Deliverable (master doc §89 Phase 4):

> Device A can obtain proof that Device C durably holds an object for B.

Plus **carrier storage leases** (§11): C accepts object X with a signed
lease (`accepted_until`, `storage_class`) instead of an indefinite promise.

## 2. Scope

**In scope:** OBJECT_OFFER / OBJECT_DATA / STORED_ACK frames in the existing
codec; carrier admission policy; lease model + signed lease; two-phase handoff
state machine; idempotency; never-ACK-before-commit enforcement; lease expiry
handling; handoff telemetry; minimal ResourceManager stub (connection/storage
budgets) pulled forward.

**Out of scope:** destination delivery + signed receipts (Phase 5),
replication planning (Phase 7), anti-entropy (Phase 6).

## 3. Prerequisites

- Phase 3 complete: object store + envelope + dedup + crash recovery.
- Phase 2 platform adapter available.

## 4. Background

Master doc §63: a carrier must **durably commit** before sending STORED_ACK;
never delete the last useful replica merely because bytes were written to a
socket. §11: storage should be a *lease* — phones must not make indefinite
promises; low-storage devices offer short leases, charging/always-on peers
offer longer ones. This phase also introduces honest rejection: a
low-storage device can say `REJECTED_QUOTA`/`BUSY` (§93 invariant 7).

**Reuse, don't rebuild (locked decision 9):** the relay role already exists
in `overlay_router.h` (opt-in `relay_enabled`, `OverlayMailbox`, sealed
blobs, path rotation). Build the handoff on top of it. The genuinely **new**
primitives this phase adds are: (1) the signed `STORED_ACK` **lease**
(`accepted_until`, `storage_class`, carrier signature) — today's mailbox
pickup returns no signed storage proof to the origin; (2) the explicit
OBJECT_OFFER/ACCEPT/REJECT/DATA frame sequence; and (3) the two-phase,
crash-safe, never-ACK-before-commit handoff state machine.

## 5. Detailed implementation steps

### Step 4.1 — Handoff frames (extend existing wire codec)
Add typed frames per §82 to `wire_codec.cpp` (+ fuzz target input):

- `OBJECT_OFFER` — object_id, namespace, size, payload_hash, lease offer
  (requested storage_class, requested lease duration), origin/destination.
- `OBJECT_ACCEPT` / `OBJECT_REJECT` — accept with offered lease terms, or
  reject with a reason code (`REJECTED_AUTH | REJECTED_POLICY |
  REJECTED_QUOTA | BUSY | RETRY_AFTER`).
- `OBJECT_DATA` — payload transfer (chunked if payload large; streaming
  buffers, bounded memory).
- `STORED_ACK` — signed/validated storage acknowledgement containing
  `object_id`, `accepted_until`, `storage_class`, `recipient_id`, signature
  (this is the lease).

All lengths validated before allocation (§29); unknown optional fields
ignored safely; replay detection via dedup index before expensive work.

### Step 4.2 — Carrier admission policy
Before accepting an object, a carrier evaluates (§26, §52, §81):
- namespace authorization + quota headroom;
- origin trust class (unknown/known/trusted/blocked) → quota and lease
  length tiers;
- current storage pressure → shorter lease or `BUSY`/`RETRY_AFTER`;
- configured carrier willingness (app/user policy: Wi-Fi only, charging
  only, max bytes, contacts/groups only, trusted network only).
Admission is explicit: never silently drop after pretending to accept (§28).

### Step 4.3 — Lease model (§11)
- On `OBJECT_ACCEPT`, the carrier stores the object and returns a signed
  `STORED_ACK` lease: `object_id, accepted_until, storage_class, carrier_id`.
- `accepted_until = now + lease_duration` (carrier chooses duration within
  policy, e.g., 6h default; shorter under pressure; never beyond object TTL).
- The sender records the lease and its `lease_expires_at_ms` in the object
  store (Phase 3 schema already reserves this column).
- Before a lease becomes unsafe, the replication planner (Phase 7) can take
  over / renew; in this phase, lease expiry is logged + flagged via event
  so Phase 7 can act.
- Eviction must respect leases: an accepted lease copy is not evicted before
  `accepted_until` unless `EVICTED_EARLY` is recorded (§27) so repair can
  run.

### Step 4.4 — Two-phase handoff state machine
Add delivery states (§22 subset) with **idempotent transitions**:
`QUEUED_LOCAL → REMOTE_ACCEPTED → DURABILITY_REACHED` (target = ≥1 lease in
this phase; Phase 7 generalizes). Transitions persist in the store's state
column; replay after crash converges (§93 invariant 4).

Flow on sender:
1. Persist object locally (`QUEUED_LOCAL`).
2. Offer to eligible connected peer(s) (peer selection minimal: any
   READY/relay-capable peer in this phase).
3. On `OBJECT_ACCEPT` → send `OBJECT_DATA`.
4. On `STORED_ACK` → validate signature + lease terms → persist lease →
   `REMOTE_ACCEPTED`.
5. `NO_CARRIER` failure (structured, retryable) if no eligible peer accepted
   during this attempt (§61: transient, not terminal).

Flow on carrier:
1. `OBJECT_OFFER` → admission check → `OBJECT_ACCEPT`/`OBJECT_REJECT`.
2. `OBJECT_DATA` → verify hash + origin signature → **durable commit
   (object + dedup + lease in one transaction)** → send `STORED_ACK`.
3. Never send `STORED_ACK` before commit succeeds (§24; invariant 2).

### Step 4.5 — Idempotency
- Re-offer of an already-held object returns a fresh lease for the same
  object (dedup hit) — no duplicate storage.
- Re-send of `OBJECT_DATA` after a crash that happened post-commit is
  answered with `STORED_ACK` again (idempotent) — never a second copy.

### Step 4.6 — Lease expiry + renewal hooks
- Periodic (event-triggered, not timer-polled) sweep flags
  `lease_expires_at_ms` objects whose lease is near expiry.
- Emit `LEASE_EXPIRING` event for Phase 7.
- `EVICTED_EARLY` records for carrier-copy eviction.

### Step 4.7 — Minimal ResourceManager stub (pulled forward)
Implement a minimal `ResourceManager` that consumes PlatformAdapter signals
(battery, charging, metered, storage pressure) and outputs:
- `accept_new_handoffs` (storage admission),
- `max_concurrent_handoffs`,
- `storage_lease_duration_hint`.
Phase 8 extends it fully. Wire it into the admission check (Step 4.2).

### Step 4.8 — Telemetry
Structured events for every handoff step (master doc §48 trace):
`REMOTE_STORAGE_REQUEST → REMOTE_STORAGE_ACCEPTED/REJECTED →
STORED_ACK_RECEIVED → LEASE_EXPIRING`. Counters: handoff success/rate,
carrier acceptance rate, lease length distribution, reject reasons.

## 6. Data / schema changes
- `leases` table populated (object_id, carrier_id, accepted_until,
  storage_class, lease_signature).
- Object state column gains `REMOTE_ACCEPTED` / `DURABILITY_REACHED`.
- Migration of any existing mailbox handoff state into the new model.

## 7. Wire protocol changes
- New frames OBJECT_OFFER / OBJECT_ACCEPT / OBJECT_REJECT / OBJECT_DATA /
  STORED_ACK in `wire_codec.cpp`; versioned envelope bump; fuzz inputs
  updated; malformed-frame tests extended (desktop/tests/malformed_input_test.cpp).

## 8. Deliverables
- Handoff module (`modules/networkos/handoff/` or equivalent) + tests
  `desktop/tests/handoff_test`.
- Minimal ResourceManager stub + PlatformAdapter wiring.
- Telemetry events + counters.
- `docs/network-os/10-handoff-protocol.md` (protocol + lease spec).

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Frame unit tests (10×):** encode/decode OBJECT_OFFER/DATA/STORED_ACK,
   malformed inputs rejected, unknown fields tolerated, oversized lengths
   rejected before allocation.
2. **Kill-at-every-arrow (10×):** three-peer topology (sender S, carrier C,
   destination D). Kill S or C at every arrow of
   offer → accept → data → commit → STORED_ACK. After restart, the sender
   must always converge to the correct state; **never** an
   acknowledged-but-not-stored object (invariant 2).
3. **Lease correctness (5×):** STORED_ACK signature validates; accepted_until
   ≤ object TTL; carrier does not evict before accepted_until; `EVICTED_EARLY`
   recorded when forced.
4. **Idempotent replay (5×):** replay OBJECT_DATA after post-commit crash →
   STORED_ACK again, single stored copy (invariant 3/4).
5. **Honest rejection (5×):** carrier at quota returns `REJECTED_QUOTA`;
   busy carrier returns `BUSY`/`RETRY_AFTER`; sender marks failure
   `TRANSIENT` and retries later (not permanent).
6. **Live peer handoff (2 sessions × 3 runs):** S → C → (D offline) durable
   handoff proven; S can be killed after STORED_ACK and restart with proof.
7. **ResourceManager stub (3×):** storage-pressure signal shortens lease
   duration; charging raises it.
8. **Existing suites (5×):** no regression.
9. **Native build (1×):** green.
10. **tcpdump capture (1×):** verify handoff frames on the wire match the
    protocol spec.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| YYYY-MM-DD | frame unit tests | 10 | PASS/FAIL | ... |
| YYYY-MM-DD | kill-at-every-arrow | 10 | PASS/FAIL | kill points listed |
| YYYY-MM-DD | lease correctness | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | idempotent replay | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | honest rejection | 5 | PASS/FAIL | reason codes |
| YYYY-MM-DD | live peer handoff | 3 | PASS/FAIL | ... |
| YYYY-MM-DD | ResourceManager stub | 3 | PASS/FAIL | ... |
| YYYY-MM-DD | existing suites | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | native build | 1 | PASS/FAIL | ... |
| YYYY-MM-DD | tcpdump capture | 1 | PASS/FAIL | frames match spec |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| STORED_ACK sent before durable commit | Transactional commit gate in Step 4.4; enforced by kill tests |
| Lease terms abused (carrier promises more than it can hold) | Signed lease, storage_class tiers, pressure-based duration |
| Sender treats transient NO_CARRIER as terminal | Failure classes (§61) with retryable flag; backoff |
| Frame parsing DoS via declared lengths | Validate lengths before allocation; fuzz + malformed tests |
| Storage admission races with quota | Admission check inside the same transaction as insert |

## 12. Definition of Done

- [ ] Handoff protocol (offer/accept/reject/data/STORED_ACK) implemented in
      the existing codec, fuzz inputs updated.
- [ ] Signed leases implemented; lease expiry hooks emit events.
- [ ] Never-ACK-before-commit enforced and proven by kill-at-every-arrow 10×.
- [ ] Honest rejection with structured reasons works.
- [ ] Minimal ResourceManager stub wired into admission.
- [ ] Handoff telemetry events + counters present.
- [ ] Invariants 2, 3, 4, 5, 7 asserted by tests.
- [ ] Live peer handoff proven (S → C, D offline), repeated 2 sessions.
- [ ] Existing suites green; native build green.
- [ ] Status table in `METHODOLOGY.md` updated.
- [ ] Committed with message:
      `Network OS P4: confirmed remote storage + signed replica leases`.



