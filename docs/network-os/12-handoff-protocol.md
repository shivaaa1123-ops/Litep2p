# Network OS Phase 4 — Durable Network Object Store Protocol (confirmed remote storage + replica leases)

## 1. Purpose

The **two-phase durable handoff** (master doc §63 R1/R2): Device A can obtain
**proof** that Device C durably holds an object for B. A carrier accepts an
object only with a **signed lease** (`accepted_until`, `storage_class`,
carrier Ed25519 signature) instead of an indefinite promise (§11).

## 2. Frames (wire codec, MessageType 0x34–0x38)

All frames ride the **existing encrypted session channel** (Noise NK when
enabled), are never batched, and use bounded length-prefixed binary encoding
(all lengths validated **before** allocation, §29). Decoders are **strict**:
unknown/trailing fields are rejected — the frames are point-to-point within
one protocol version, so strictness is chosen over forward-tolerance. Frame
payload codecs live in `modules/networkos/handoff/`
(`handoff_frames.h/.cpp`).

| Frame | Type | Direction | Payload |
|---|---|---|---|
| `OBJECT_OFFER` | 0x34 | S→C | object_id_hex, namespace, origin, destination, size_bytes, payload_hash_hex, expires_at_ms, requested storage_class, requested lease_ms |
| `OBJECT_ACCEPT` | 0x35 | C→S | object_id_hex, accepted_until_ms, storage_class, carrier_id |
| `OBJECT_REJECT` | 0x36 | C→S | object_id_hex, reason (1=auth, 2=policy, 3=quota, 4=busy, 5=retry_after), retry_after_ms |
| `OBJECT_DATA` | 0x37 | S→C | object_id_hex, serialized signed `obj::NetworkObject` envelope |
| `STORED_ACK` | 0x38 | C→S | object_id_hex, carrier_id, accepted_until_ms, storage_class, signature, carrier_pk_hex |

**Backward compatibility:** the 5 types are new enum values; older peers
reject unknown types with the existing unknown-type path (no ABI change). The
C ABI (56 functions) is unchanged.

## 3. Lease model (§11)

- The carrier chooses `accepted_until = now + duration` where duration =
  requested (capped) else default 6h; **storage pressure shortens to 1h**,
  **charging lengthens to 24h** (ResourceManager stub, Step 4.7).
- `accepted_until` is capped at the object TTL expiry — **a lease never
  outlives the object**.
- The carrier signs `canonical_lease_bytes(object_id, carrier_id,
  accepted_until_ms, storage_class)` with its Ed25519 origin-signing key.
- The sender verifies with the carrier's **registered** signing public key
  (out-of-band trust anchor; `overlay_register_peer_signing_key`).
- Sender persists the validated lease in the `leases` table and the object's
  `lease_expires_at_ms`; state → `DURABILITY_REACHED`.

## 4. Two-phase state machine

```
Sender:  QUEUED_LOCAL --offer--> (offer in flight) --OBJECT_ACCEPT-->
         REMOTE_ACCEPTED --OBJECT_DATA--> --STORED_ACK validated+persisted-->
         DURABILITY_REACHED   (target = >=1 signed lease; Phase 7 generalizes)

Carrier: OBJECT_OFFER -> admission (authz / quota headroom / capacity /
         resource hints) -> ACCEPT | REJECT(reason)
         OBJECT_DATA -> verify envelope + origin signature -> durable commit
         (object + dedup + usage + lease in ONE transaction) -> STORED_ACK
```

- **Never ACK before commit** (invariant 2): `STORED_ACK` is emitted only
  after `putWithLease` returns `kOk` (the commit gate). Proven by the SIGKILL
  harness (`handoff_kill_test.sh`, 10 cycles).
- **Idempotency** (invariants 3/4): a post-commit `OBJECT_DATA` replay hits
  the dedup record → a fresh lease row, **never a second copy**.
- **Honest rejection** (invariant 7): `REJECTED_AUTH | REJECTED_POLICY |
  REJECTED_QUOTA | BUSY | RETRY_AFTER`. Sender marks `NO_CARRIER` **transient**
  and keeps the object queued for `retryPending()` on peer_ready.

## 5. Store changes (schema v2)

- `leases(object_id, carrier_id, accepted_until_ms, storage_class,
  lease_signature, carrier_pk_hex)`.
- `evicted_early(object_id, carrier_id, evicted_at_ms, lease_was_until_ms)` —
  recorded when a carrier evicts a copy whose lease is still live (§27; Phase 7
  repair reads it).
- `objects.envelope_blob` — the full serialized signed envelope persisted so
  the sender can re-transfer `OBJECT_DATA` after a crash and the carrier can
  forward on delivery (Phase 5).
- New object states `REMOTE_ACCEPTED`, `DURABILITY_REACHED`.
- `putWithLease()` — the carrier atomic accept (one transaction).
- Migration v1→v2: idempotent `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE
  objects ADD COLUMN envelope_blob` (checked via `PRAGMA table_info`).

## 6. Runtime wiring

`Runtime::handoff()` returns the `HandoffManager` (valid while running, only
with an object store). The runtime wires:
- sends via `SessionManager::send_handoff_frame` (typed, non-batched);
- receives via `SessionManager::set_handoff_frame_handler` (engine-thread
  dispatch, no handler = dropped — carrier role off by default);
- peer list via `SessionManager::getConnectedPeerIds` (READY peers);
- lease signing via the engine's origin-signing keypair
  (`get_local_signing_keys`), verification via `get_peer_signing_key`;
- `retryPending()` on every `peer_ready` event (transient NO_CARRIER retry);
- platform signals → `ResourceManager::onSignal` (storage pressure shortens
  leases, charging/battery shape concurrency) and an event-triggered
  `sweepLeases()` that emits `LEASE_EXPIRING` on connectivity/foreground
  events (Phase 7 planner hooks this).

## 7. Verification record (Phase 4 doc §9–§10)

| Suite | Runs | Result |
|---|---|---|
| handoff_test (frames/state machine/lease/rejection/resource) | 10× | PASS (104 checks) |
| handoff_kill_test.sh (SIGKILL at every arrow) | 10 cycles | PASS |
| lease correctness (sig/TTL-cap/EVICTED_EARLY) | in handoff_test | PASS |
| idempotent replay | in handoff_test | PASS |
| honest rejection (QUOTA/AUTH) | in handoff_test | PASS |
| live peer handoff (S→C, D offline) + restart proof | 6 runs | PASS |
| ResourceManager stub | in handoff_test | PASS |
| existing suites (14) × 5 passes | 5 | PASS (see log) |
| native Android build | 1 | PASS |
| tcpdump capture | 1 | PASS (two-phase flow on wire) |
| C ABI gate | 1 | PASS (56 identical) |
| fuzz smoke | 60s | PASS (12.7M iters, no crash) |
