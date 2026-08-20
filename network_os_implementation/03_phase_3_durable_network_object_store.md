# Phase 3 — Generic Network Object + Durable Object Store

**Master doc references:** §4 (Network Object), §5 (Object Identity), §20
(immutable vs mutable headers), §21 (TTL/clock), §24 (storage architecture),
§25 (DB choice), §26 (quotas), §27 (eviction), §28 (backpressure), §29
(anti-abuse), §65 (dedup), §89 Phase 3 ("Durable Network Object Store").

## 1. Objective

Replace the messaging-specific internal model with a **generic, durable
Network Object** and a **transactional, crash-safe object store**. Deliverable
(master doc §89 Phase 3):

> An object survives process death/reboot and restores correctly.

This is the foundation everything else (storage handoff, delivery, receipts,
replication) is built on. Chat messages become one namespace/type of object.

## 2. Scope

**In scope:** ObjectID, network object envelope (immutable signed origin
header + mutable forwarding header), SQLite-backed object store with
transactions, TTL expiry, quotas, dedup, eviction, backpressure outcomes,
crash recovery, namespace isolation, E2E payload encryption key model.

**Out of scope:** remote storage handoff (Phase 4), delivery/receipts
(Phase 5), anti-entropy (Phase 6), replication (Phase 7), wire protocol
changes beyond the envelope type.

## 3. Prerequisites

- Phase 1 complete (runtime skeleton, stable interfaces, identity
  persistence).
- Phase 2 complete (secure sessions, capability negotiation).
- Phase 0 baselines available to compare against.

## 4. Background

Master doc §4: *"a network object can survive the disappearance of its
creator and can be securely stored, replicated, routed, delivered,
acknowledged, and expired by the network according to policy."* §3.2 defines
precise status meanings — this phase implements the local half:
`QUEUED_LOCAL` = durably persisted locally.

**Reuse, don't rebuild (locked decision 9):** `overlay_mailbox.h` already
implements correct bounded carrier storage — total entry/byte caps
(`max_entries`, `max_total_bytes`), per-origin quota (`per_origin_quota`),
TTL expiry, LRU eviction, and sealed (opaque) blobs. The object store must
**generalize this proven logic** into a generic, SQLite-backed store; do NOT
write a second, parallel quota/eviction system. The genuinely new work is:
(1) the signed immutable/mutable envelope, (2) transactions + crash recovery
with the never-ACK-before-commit rule, (3) the generic `ObjectID`/dedup, and
(4) the E2E payload key model.

## 5. Detailed implementation steps

### Step 3.1 — ObjectID
`ObjectID = NetworkID + OriginPeerID + random 128-bit nonce` (§5). Rules:
globally unique, cheap offline, unpredictable, transport-independent, stable
across replication, safe as dedup key, bound into the signed object.
Implement `modules/networkos/object/src/object_id.cpp` with binary + hex
encoding and a DB column type.

### Step 3.2 — Network object envelope
Define the on-disk/wire structure per §20:

```
SIGNED ORIGIN HEADER (immutable, origin-authenticated)
    protocol_version, network_id, namespace_id, object_id,
    origin, optional destination, object_type,
    created_at_ms, ttl_ms, priority, delivery_class,
    max_hops, hop_count(0), payload_size, payload_hash, security_flags
FORWARDING HEADER (mutable, carrier-updatable)
    hop_count, previous_peer, local routing hints, lease info
PAYLOAD (opaque to the runtime; E2E encrypted)
ORIGIN SIGNATURE (Ed25519 over signed origin header + payload hash)
```

Separate immutable from mutable — carriers must never rewrite
origin-authenticated fields without invalidating the signature (§20).
Payload is opaque to the network runtime (§4).

### Step 3.3 — Origin signature
Ed25519 over: protocol_version | network_id | namespace_id | object_id |
origin | destination | object_type | created_at_ms | ttl_ms | priority |
delivery_class | max_hops | payload_size | payload_hash | security_flags.
Reuse existing engine signing. Verify the signature before any expensive work
(§29: signature verification before expensive work).

### Step 3.4 — E2E payload encryption key model (locked decision #4)
- Each object gets a random 256-bit content key.
- Payload encrypted with XChaCha20-Poly1305 using engine primitives.
- Content key wrapped for each recipient/origin using their public keys;
  wrappers stored in the envelope's recipient-wrapped section.
- Storage/relay peers see ciphertext + envelope metadata only.
- Document the scheme in `docs/network-os/11-e2e-key-model.md` (P0 mapped
  `09-` to `delivery-path-map.md`).

### Step 3.5 — SQLite object store
New module `modules/networkos/objectstore/` implementing `IObjectStore` from
Phase 2. Schema (SQLite WAL):

```
objects(object_id PK, namespace_id, origin, destination, object_type,
        created_at_ms, ttl_ms, expires_at_ms, priority, payload_size,
        payload_hash, payload_blob, origin_header_blob, origin_signature,
        forwarding_header_blob, state, lease_expires_at_ms, replica_hint)
dedup(object_id PK, terminal_state, created_at_ms)     -- bounded (§65)
receipts(...)                                          -- Phase 5 uses
leases(...)                                            -- Phase 4 uses
namespaces(namespace_id PK, quota_bytes, ...)          -- quotas
```

Requirements from §25: crash-safe transactions; small binary metadata;
indexed expiry (`expires_at_ms`); indexed destination; indexed namespace;
efficient batch deletion; predictable disk usage; corruption detection/
recovery (integrity check on open + journal). Write amplification: batch
metadata updates; never rewrite payload blob to update hop state; store
payload separately from frequently-updated metadata if benchmarks show
benefit.

### Step 3.6 — Namespace isolation + quotas (§26, §53)
Hierarchical quotas: global SDK cap → namespace cap → origin cap → object
class cap. Enforce on insert. Reserve a system/control quota that cannot be
consumed by peers. One hostile peer/application must not exhaust the pool
(§93 invariant 10).

### Step 3.7 — TTL and clock handling (§21)
- Store `origin_created_at` + `ttl_duration`; expiry = created + ttl.
- Gossip/forwarding never refreshes object life.
- Monotonic clock for local retry scheduling; wall clock for durable
  protocol records; never persist monotonic time across reboots as protocol
  time.
- Configurable clock-skew tolerance; reject unreasonable remote timestamps.

### Step 3.8 — Dedup (§65)
- Persist `ObjectID → terminal/local state` for at least
  `TTL + receipt window + configured safety margin`, bounded by quota.
- Compact terminal records survive longer than payloads.
- Check dedup BEFORE expensive work on the receive path.

### Step 3.9 — Eviction (§27)
Score-based (expired?, priority, remaining TTL, replica count, object size,
lease, application class, delivery urgency, last access, origin quota
pressure). Never evict critical system metadata just for being old. When a
promised carrier copy is evicted early, record it so the protocol can repair
(Phase 7 hook).

### Step 3.10 — Backpressure outcomes (§28)
Every receiving path returns an explicit outcome:
`ACCEPTED | REJECTED_AUTH | REJECTED_POLICY | REJECTED_QUOTA | BUSY |
RETRY_AFTER | UNSUPPORTED`. Never silently drop after pretending to accept.

### Step 3.11 — Crash recovery (§24, §62, §63)
- Every mutation is transactional; the store never ACKs before durable
  commit (§93 invariant 2).
- Atomic receive path: verify → persist object + dedup → commit → send
  storage ACK.
- Journal + snapshot design; replay after restart converges.
- Test kill points: before DB write, during DB write, after commit before
  ACK, after ACK send, before callback, after callback.

### Step 3.12 — Memory budget (§34)
Bounded caches; no full-carrier-inventory duplication between C++ and Kotlin;
JNI exchanges compact events/handles, not whole states. Blobs streamed, never
whole-object RAM buffering.

## 6. Data / schema changes
- New `networkos` SQLite schema (or new tables in the existing DB file).
- Schema version + forward migration; Phase 2 skeleton must open both old
  and new schemas.
- Migration fixtures from old outbox/mailbox data if applicable.

## 7. Wire protocol changes
- New envelope/object framing type wrapped in the existing codec
  (`wire_codec.cpp` + `fuzz_wire_codec.cpp` updated).
- No new session-level frames yet (Phase 4 adds them).

## 8. Deliverables
- `modules/networkos/object/` and `modules/networkos/objectstore/` modules.
- `desktop/tests/object_store_test` + `desktop/tests/object_envelope_test` +
  `desktop/tools/object_store_kill_probe` (crash probe) +
  `desktop/tools/object_store_kill_test.sh` (kill harness) +
  `desktop/tools/envelope_fuzz_smoke` (libFuzzer substitute, see §10).
- `docs/network-os/11-e2e-key-model.md` (E2E key model).
- Schema version + migration fixtures.

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Envelope unit tests (10×):** encode/decode round-trip, signature
   verify, tamper-detection (any byte flip in signed header or payload
   must fail verification), forwarding-header updates preserve signature,
   unknown-field tolerance.
2. **Store crash tests (10×):** insert/get/delete with SIGKILL at every
   arrow of the atomic receive path; after each kill, reopen and verify
   consistency (no acknowledged-but-not-stored object — invariant 2).
3. **Restart survival (5×):** create object → kill → restart → object
   present with correct state; TTL not extended by restart.
4. **Quota enforcement (5×):** namespace/origin quotas reject over-quota
   inserts with `REJECTED_QUOTA`; system reserve untouched.
5. **TTL expiry (5×):** objects with short TTL expire exactly at
   created+ttl; never refreshed by "gossip" (re-insert attempt fails).
6. **Dedup (5×):** re-inserting the same ObjectID returns existing state,
   does not duplicate; dedup table bounded.
7. **Memory bounds (3×):** high-water mark during 1,000-object batch stays
   within configured cap (no whole-batch buffering).
8. **Existing suites (5×):** `c_api_test`, `session_manager_test` still
   green (envelope is additive).
9. **Native build (1×):** `:litep2p-core:externalNativeBuildMultiThreadDebug`
   green.
10. **Fuzz (brief):** extend `fuzz_wire_codec.cpp` with envelope input;
     run 60s, no crashes.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-20 | envelope unit tests | 10 | PASS | `object_envelope_test` 131 checks × 10, 0 failures; round-trip, tamper (payload byte flip fails), forwarding-header mutation preserves signature, unknown-field tolerance, malformed rejection |
| 2026-08-20 | store crash tests | 10 | PASS | `object_store_kill_test.sh` 10 cycles × (burst kill at random arrow + post-commit kill); reopen always clean; killed-after-N-inserts ⇒ exactly N present; committed object always survives SIGKILL |
| 2026-08-20 | restart survival | 10 | PASS | `object_store_test` reopen sections (also 100× restart from Phase 1 covers identity); TTL unchanged by reopen |
| 2026-08-20 | quota enforcement | 10 | PASS | namespace/origin/global caps; over-quota insert → `REJECTED_QUOTA`; system reserve untouched |
| 2026-08-20 | TTL expiry | 10 | PASS | expires at created+ttl; re-insert with new TTL does NOT extend (dedup-idempotent); dedup record survives expiry |
| 2026-08-20 | dedup | 10 | PASS | same ObjectID re-insert returns existing state; dedup table bounded |
| 2026-08-20 | memory bounds | 10 | PASS | 1000-object batch: per-object inserts (no whole-batch buffering); byte accounting exact; spot-check read |
| 2026-08-20 | existing suites | 5 | PASS | `run_all_tests.sh 5` = 13 suites × 5 = 0 failures (added object_envelope_test, object_store_test) |
| 2026-08-20 | native build | 1 | PASS | `:litep2p-core:externalNativeBuildMultiThreadDebug` SUCCESSFUL (1m44s); C ABI check 56 functions identical |
| 2026-08-20 | fuzz | 1 | PASS | libFuzzer runtime absent on Apple clang 12 (documented); TU compiles clean; `envelope_fuzz_smoke --seconds 60`: 9,833,167 iterations (≈2.0M parsed), no crash; fuzz_wire_codec extended with envelope input |
| 2026-08-20 | RE-VALIDATION audit | 1 | PASS | Full code audit of every Step 3.1–3.12 vs implementation; live two-node smoke 6/6 rc=0; performance measured. Found + fixed: (1) `open()` self-deadlock on failure paths (called `close()` while holding the non-recursive mutex — triggered by corrupt/future-schema DBs); (2) O(N²) quota + dedup scans on every insert (global `SUM(payload_size)` over `objects` + `COUNT(*) FROM dedup`) — replaced with an incremental `usage` table + amortized dedup prune. Added tests: corruption-open rejection, forward-migration rejection, usage-accounting consistency (store suite 43 → 63 checks) |
| 2026-08-20 | store perf (store_bench) | 2 | PASS | before: 10k/512B put 248 obj/s (O(N²)); after: 10k/512B put 3,734 obj/s, get 42,017 obj/s, cold open 28 ms, size 194%; 100k/64B put 4,263 obj/s, get 38,565 obj/s, cold open 176 ms, size 792% (tiny-payload row overhead) |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Envelope schema changes later → storage migration pain | Freeze schema in this phase; E2E key model decided (Step 3.4) |
| SQLite write amplification on Android | WAL + batched commits; measure in Step 3.12 |
| Signature verify cost on receive path | Verify before decode; batch verify only where semantics safe |
| Quota bypass via dedup/eviction races | Quota checks inside the same transaction as insert |

## 12. Definition of Done

- [x] ObjectID + envelope + origin signature implemented and unit-tested 10×
      (`object_envelope_test`, 131 checks × 10 green).
- [x] E2E key model documented and implemented (`e2e.h/cpp` — XChaCha20-Poly1305
      payload AEAD + `crypto_box_seal` content-key wrapping; see
      `docs/network-os/11-e2e-key-model.md`).
- [x] SQLite object store with transactions, quotas, TTL, dedup, eviction
      (`ObjectStore` on `sqlite3_dyn`, WAL, `synchronous=NORMAL`, crash-safe
      open, forward-migration guard).
- [x] All §9 verification items green at required repetitions (§10 log).
- [x] Re-validation passed: full code audit of Steps 3.1–3.12; two defects found
      in audit and fixed with regression tests (open()-self-deadlock on corrupt/
      future-schema DBs; O(N²) quota/dedup scans — now O(1)-ish via incremental
      `usage` table + amortized prune). Store suite 63 checks; live two-node
      smoke 6/6; performance: 10k put 3,734 obj/s / get 42k obj/s / open 28 ms.
- [x] Invariants 2, 6, 8, 9, 10, 16 asserted by tests (never ACK before
      commit — SIGKILL harness; dedup-before-work; quota-in-transaction;
      bounded memory; namespace isolation; signed-origin + tamper detect).
- [x] Native build green; existing suites green (13 suites × 5 passes, 0
      failures; C ABI 56 functions identical).
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message:
      `Network OS P3: generic network object + durable SQLite object store`.


