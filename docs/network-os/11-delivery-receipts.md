# Network OS — Direct Delivery + Signed Receipts (Phase 5)

> Master doc §22/§23, §57, §58, §61, §63, §64; phase file
> `network_os_implementation/05_phase_5_direct_delivery_and_receipts.md`.

## 1. Objective

The first EDP milestone (**§99**):

> A can go offline after remote storage; B later receives; A later receives
> the receipt.

```
A creates X for offline B → A stores on C (Phase 4) → A dies
→ B connects to C → C offers X → B verifies + durably commits
→ B returns a signed delivery receipt → C releases its copy
→ the receipt is delivered back to A → A marks X CONFIRMED
```

## 2. Delivery paths (one object-delivery path)

The three legacy send paths converge here into a single object-delivery layer
with one dedup and one receipt model:

1. **Direct delivery (Step 5.1)** — when the destination is connected, offer
   `OBJECT_OFFER` → `OBJECT_ACCEPT` → `OBJECT_DATA` straight to it (cheapest
   path first, §57). The destination verifies the origin signature + hash,
   **durably commits**, and replies `RECEIVED_ACK` (0x39) instead of a storage
   lease. The origin marks the object `DELIVERED`.
2. **Store-and-forward (Phase 4 carrier)** — when the destination is offline,
   the object rides the confirmed remote-storage path to a carrier; the carrier
   *pushes* it to the destination when it connects (`forwardPending`).
3. **Pull (Phase 6)** — reconciliation arrives in Phase 6; the receipt
   reverse-path must already work.

The genuinely new primitive is the **signed destination receipt** — a
first-class, signed, store-and-forward object.

## 3. Roles (a peer can hold several at once)

| Role | Responsibility |
|------|----------------|
| **ORIGIN** (`storeAndDeliver`) | persist durable local copy; pick direct vs store-and-forward; on `RECEIVED_ACK` mark `DELIVERED`; on the returned signed receipt mark `CONFIRMED` (late upgrade idempotent). |
| **CARRIER** | storage peer holding a Phase 4 copy; when destination connects, `forwardPending` pushes it; on `RECEIVED_ACK` releases its replica after the retention window (§64). |
| **DESTINATION** | the peer named in `destination`; on `OBJECT_DATA` "for me" verifies + durably commits (**dedup before application delivery**) + replies `RECEIVED_ACK`; signs + routes a receipt back to the origin (§23). |

## 4. Signed receipt (§23)

```text
namespace: system, type: receipt
  object_id (of the delivered object)
  object_hash
  origin, destination
  received_at_ms
  receipt_type: RECEIVED | PROCESSED | READ | REJECTED
  destination_signature (Ed25519 over canonical_receipt_bytes)
```

- Receipts are themselves NetworkObjects (own ObjectID, short TTL, **high
  priority** — never blocked by bulk, §67).
- They use store-and-forward for the reverse hop (no special-casing), so
  `CONFIRMED` survives process death on every hop (invariant 17).
- Routing key is the **origin PeerID** of the delivered object (Step 5.3).

## 5. Idempotency & replica release

- **Invariant 3/18:** duplicates are harmless. The destination checks dedup
  *before* application delivery; a duplicate `OBJECT_DATA` re-returns the same
  `RECEIVED_ACK` and never a second receipt or a second `CONFIRMED` event.
- **Replica release (§64):** after `DELIVERED` + retention window the carrier
  garbage-collects its replica. The **last-useful-replica rule** holds: only
  `DELIVERED` (delivery proof) replicas are ever removed — never a
  still-queued/undelivered copy merely because bytes reached a socket.

## 6. Failure semantics (§61)

Every outcome carries a `failure_class` + retry hint:
`TRANSIENT` (NO_CARRIER, NO_ROUTE, BUSY) · `TERMINAL` (TTL_EXPIRED) ·
`POLICY` (DESTINATION_REJECTED) · `SECURITY` (AUTH_FAILED). The error model
exposes `retryable()` + `retry_after_ms()`.

## 7. Storage / wire

- Store **schema v3**: `receipts` table + `delivered_at_ms / confirmed_at_ms /
  `failure_class` columns on `objects`; forward migration from v2.
- **One new frame**: `RECEIVED_ACK = 0x39`. Receipts travel as ordinary
  objects (no receipt-specific wire format).

## 8. Module map

- `modules/networkos/delivery/` — `delivery_frames.{h,cpp}` (RECEIVED_ACK +
  receipt codec, strict decoders) and `DeliveryManager.{h,cpp}` (the state
  machine; roles above).
- `modules/networkos/objectstore/` — schema v3 + Phase 5 store methods.
- `modules/networkos/runtime/` — owns a `DeliveryManager`; routes typed frames
  to handoff (storage) vs delivery (destination==me); pushes on `peer_ready`.
- Tests `desktop/tests/delivery_test.cpp`; end-to-end
  `tools/harness/p5_milestone_scenario.sh`.