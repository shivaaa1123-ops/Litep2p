# 16 — Large Object Layer (Manifests + Chunks)

**Phase 10.** Master doc: §32 (large objects/media), §33 (low-copy data path),
§34 (memory budget), §67 (priority inversion), §68 (congestion), §69
(compression), §89 Phase 10.

## Goal

Multi-megabyte content is requested opportunistically / replicated under a
different policy via **manifests + chunks**; tiny messages are never blocked by
bulk transfers. No whole-file RAM buffering.

## Components (`modules/networkos/largeobject/`)

- **Manifest (`files/manifest`)** — a small object that travels the normal
  durable network: `content_hash`, `total_size`, `chunk_size`, `chunk_hashes[]`,
  encryption metadata, source info, availability policy (bulk class), TTL.
  Strict bounded codec (`encode_manifest` / `decode_manifest`).
- **Chunk objects (`files/chunk`)** — content-addressed IDs derived from
  `content_hash + chunk_index` (`chunk_object_id`).
- **`ChunkTransfer`** — resumable, checkpointed, memory-bounded tracker:
  - per-chunk state machine: pending → in-flight → received → verified →
    committed;
  - **tamper detection**: each chunk must hash to the manifest entry
    (`compute_payload_hash`), mismatches leave the chunk pending for retransmit;
  - **resume**: `nextChunksToRequest()` starts at the first unverified chunk;
    verified/committed chunks are never re-requested (no re-send);
  - **sliding window**: at most `max_chunks_in_flight` (16) chunks in flight →
    `maxInFlightBytes()` bounds working memory (§34);
  - **bulk policy**: `shouldProceedBulk(wifi, charging, metered)` defers on
    metered and prefers Wi-Fi/charging (§5.4).
- **`BulkScheduler`** — per-class FIFO queues with priority ordering
  `control > critical > receipt > normal > bulk`; bulk only gets a slot when no
  higher-class work is pending (priority inversion protection, §67).
- **Admission/backpressure (§68)** — `admitChunk()` returns
  `Accept / Defer(≥75%) / Busy(full) / RejectedQuota(storage pressure)`; never
  silently drops.

## Extends, doesn't rebuild (locked decision 9)

Reuses the existing `file_transfer` engine invariants: 32 KB chunks, 16 chunks
in flight, checkpoint/resume, OFFER/ACCEPT/DECLINE/PAUSE/RESUME, retransmit
backoff. This layer adapts those semantics to the generic object model
(manifest + chunk objects in the `files` namespace) instead of a second engine.

## Wire protocol

No new frame types — reuses OBJECT/WANT/INVENTORY + chunk objects; the
chunking-support capability field is populated (§39).

## Rules

- Never whole-file RAM buffering (chunk-sized window only).
- Bulk has its own queue class; never shares capacity with control/receipts.
- Compression only when useful; bounded decompression (zip-bomb protection).
- No DHT content lookup (deferred).