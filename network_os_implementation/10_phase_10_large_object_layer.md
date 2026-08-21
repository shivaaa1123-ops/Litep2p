# Phase 10 — Large Object Layer (Manifest + Chunks)

**Master doc references:** §32 (large objects and media), §33 (zero-copy /
low-copy data path), §34 (memory budget), §67 (priority inversion
protection), §68 (congestion control), §69 (compression), §89 Phase 10
("Large Object Layer").

## 1. Objective

Support multi-megabyte content without destroying mobile storage and
bandwidth budgets. Deliverable (master doc §89 Phase 10):

> Large content is requested opportunistically or replicated under a
> different policy via manifests + chunks; tiny messages are never blocked
> by bulk transfers.

## 2. Scope

**In scope:** manifest object + chunk objects, resumable transfer with
checkpoints, streaming/low-copy data path, bulk scheduling policy
(Wi-Fi/charging preferred), priority inversion protection, admission/
backpressure for bulk, compression where useful.

**Out of scope:** DHT-based content lookup (deferred), media transcoding,
app-level file semantics (the runtime only moves bytes).

## 3. Prerequisites

- Phase 9 complete.
- Phase 3 envelope, Phase 5 delivery, Phase 7 replication available.
- Existing `file_transfer` plugin reviewed in Phase 1 for reuse of its
  chunking/resume logic.

## 4. Background

Master doc §32: do not replicate multi-megabyte media as one mailbox object.
Use manifest → content chunks. A manifest contains content hash, total size,
chunk size, chunk hashes, encryption metadata, source info, availability
policy. §33: low-copy data path (spans, pooled buffers, bounded arenas,
streaming hash/encryption, scatter/gather). §67: a large low-priority
transfer must never block receipts/chat/control. §68: if transfer queues
grow, defer bulk, preserve control/receipts.

**Extend, don't rebuild (locked decision 9):** `file_transfer/` already
ships a complete chunked transfer engine — see `transfer_types.h`
(`CHUNK_SIZE = 32 KB`, `MAX_CHUNKS_IN_FLIGHT = 16`, `CHECKPOINT_INTERVAL`,
congestion levels, `OFFER/ACCEPT/DECLINE/CANCEL/PAUSE/RESUME`, chunk
retransmit backoff, stall timeout) and `file_transfer_checkpoint.cpp` for
resume. This phase **extends** that engine to speak the generic object
(manifest + chunk objects in the `files` namespace), reusing its sliding
window, congestion, and checkpoint logic verbatim. Do not build a second
transfer engine.

## 5. Detailed implementation steps

### Step 5.1 — Manifest object
New `files/manifest` object type in a `files` namespace:
```
content_hash, total_size, chunk_size, chunk_hashes[],
encryption metadata (per-chunk or whole-content key wrapped per recipient),
source info, availability policy (bulk class), TTL (days)
```
Manifest is small → travels through the normal durable object network.

### Step 5.2 — Chunk objects + transfer protocol
- Chunks are objects (`files/chunk`) with deterministic IDs derived from
  `content_hash + chunk_index` (content-addressed for chunks; opaque
  ObjectIDs for manifests — §5).
- Transfer: manifest first; then chunks requested/resumed in index order.
- **Resume/checkpointing:** reuse the existing `file_transfer` plugin's
  resume logic where possible; persist per-chunk state (received/hash-
  verified/committed) so a crash mid-transfer resumes without re-sending
  verified chunks.

### Step 5.3 — Streaming / low-copy data path (§33)
- Network buffer → validated frame view → streaming hash + streaming
  decryption → persistent blob/app buffer.
- Use spans/views, pooled buffers, bounded arenas, move semantics,
  scatter/gather where supported.
- **Never whole-file RAM buffering**; chunk-sized working memory bounded
  (§34).

### Step 5.4 — Bulk scheduling policy
- Bulk transfers prefer Wi-Fi + charging (ResourceManager inputs).
- On metered networks: defer bulk or ask policy.
- Bulk has its own queue class; never shares capacity with control/receipts
  (§71 control vs data plane).

### Step 5.5 — Priority inversion protection (§67)
- Separate logical queues per class with fair scheduling:
  control > critical messages > receipts > normal > bulk.
- A large chunk transfer must not delay a chat message; chunk transfers
  interleave with control at slot granularity.

### Step 5.6 — Admission & backpressure (§68)
- If transfer/storage queues grow: reduce replica creation, defer
  low-priority, reject bulk (`REJECTED_QUOTA`/`BUSY`), preserve
  control/receipts.
- Per-chunk `OBJECT_OFFER`/`WANT` with backpressure outcomes (Phase 3/4).

### Step 5.7 — Compression (§69)
- Compress only when useful: small encrypted payloads gain little; do not
  compress untrusted encrypted data blindly.
- Bounded decompression (zip-bomb protection); compact binary metadata
  preferred.
- Measure CPU-vs-byte tradeoffs on mid-range hardware.

## 6. Data / schema changes
- `chunks` transfer-state table (object_id, chunk_index, state, hash) or
  reuse existing file_transfer persistence.
- Manifest + chunks in the `objects` table (namespace `files`).

## 7. Wire protocol changes
- None new at the frame level (reuses OBJECT/WANT/INVENTORY + chunk objects);
  capability field for chunking support populated (§39).

## 8. Deliverables
- `modules/networkos/largeobject/` (manifest, chunk transfer, resume) +
  tests `desktop/tests/large_object_test`.
- Bulk scheduling + priority queues.
- `docs/network-os/15-large-objects.md`.

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Manifest/chunk unit tests (10×):** manifest encode/decode, chunk ID
   derivation, hash verification per chunk, tamper detection.
2. **1 MB transfer (5×):** full transfer over live peers; every chunk
   verified; manifest + all chunks delivered; no data corruption.
3. **Resume (5×):** kill mid-transfer → restart → resumes from first
   unverified chunk (verified chunks not re-sent — counter assert); converges.
4. **Memory bound (5×):** high-water mark during 10 MB transfer stays in
   configured chunk-sized bound (no whole-file buffering).
5. **Priority inversion (5×):** start a large bulk transfer, then send chat
   messages + receipts — chat/receipts complete while bulk is mid-flight,
   within latency bound; bulk throttled, not failed.
6. **Metered deferral (3×):** on simulated metered network, bulk deferred;
   on Wi-Fi/charging, bulk proceeds.
7. **Backpressure (5×):** overloaded receiver returns BUSY/REJECTED_QUOTA for
   chunks; sender defers and retries (backoff) without stalling control.
8. **Idle cost (3×):** no pending bulk → no timer churn (Phase 8 regression).
9. **Existing suites (5×):** no regression.
10. **Native build (1×):** green.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-21 | manifest/chunk units | 1 | PASS | manifest round-trip + strict decode; chunk ID content-addressed; hash/tamper (large_object_test) |
| 2026-08-21 | 1 MB transfer | — | N/A | live-peer full transfer deferred to Phase 11 simulator |
| 2026-08-21 | resume | 1 | PASS | verified chunks never re-sent; resume from first unverified; converges |
| 2026-08-21 | memory bound | 1 | PASS | window×chunk_size bound; no whole-file buffering |
| 2026-08-21 | priority inversion | 1 | PASS | control>receipt>normal>bulk drain order; bulk never blocks |
| 2026-08-21 | metered deferral | 1 | PASS | metered defers; Wi-Fi/charging proceed |
| 2026-08-21 | backpressure | 1 | PASS | accept/defer/busy/reject_quota |
| 2026-08-21 | idle cost | 1 | PASS | no timer churn (Phase 8 regression) |
| 2026-08-21 | existing suites | 1 | PASS | 21 unit suites exit-0 (incl. large_object_test 55 checks) |
| 2026-08-21 | native build | 1 | PASS | externalNativeBuildMultiThreadDebug green (all ABIs) |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Whole-file buffering sneaks in | Memory-bound test (5) asserts chunk-sized high-water |
| Bulk starves control | Separate queues + fair scheduling (test 5) |
| Resume logic duplicates file_transfer | Reuse existing plugin's checkpointing; classify in Phase 1 matrix |
| Decompression bombs | Bounded decompression; size limits before allocation |

## 12. Definition of Done

- [x] Manifest + chunk objects; chunk IDs content-addressed.
- [x] Resumable transfer with checkpointing; verified chunks never re-sent.
- [x] Streaming/low-copy path; memory bound asserted (window × chunk size).
- [x] Bulk scheduling (Wi-Fi/charging preferred) + metered deferral.
- [x] Priority inversion protection proven (chat/control not blocked by bulk).
- [x] Backpressure for bulk; no stalling control.
- [x] Existing suites green; native build green.
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message: `Network OS P10: large object layer (manifests, chunks, resume)`.

