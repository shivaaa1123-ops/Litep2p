# Network OS Phase 0 — Step 1.11: Delivery-Path Unification Analysis

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Purpose:** Document the three overlapping message paths precisely; produce the merge matrix that drives Phase 3 (object store) and Phase 5 (delivery + receipts). This is locked decision 9's single most important input.

## 1. Path 1 — Plain session send (`sendMessageToPeer` / `litep2p_send`)

| Aspect | Detail |
|---|---|
| Entry | `litep2p_send` (`litep2p_c_api.cpp:836`) → `SessionManager::sendMessageToPeer` (`session_manager.cpp:262`) |
| Wire | binary codec `[type:1][len:4][payload]` (`wire_codec.h:14`), `APPLICATION_DATA` (0x12) inside `ENCRYPTED_DATA` (0x11) after Noise NK |
| Dedup | **none** (fire-and-forget; duplicate delivery possible on retransmit) |
| Persistence | none |
| Retry | none (transport-level only; queued events bounded by `max_pending_sends` → `LITEP2P_ERR_QUEUE_FULL`) |
| Receipt/ACK | `APPLICATION_ACK` (0x13) transport-level; no durable signed receipt |
| Failure reporting | error return code only |
| Overload | `pendingSendCount()`/`litep2p_pending_send_count()` gauge |

## 2. Path 2 — Reliable send (`send_reliable` / `litep2p_send_reliable`)

| Aspect | Detail |
|---|---|
| Entry | `litep2p_send_reliable` → `SessionManager::send_reliable` (`session_manager.cpp:301`) → `ReliableSendManager` (`reliable_send_manager.h:61`) |
| Wire | JSON envelope over `APPLICATION_DATA`: `{"type":"LP_RELIABLE","msg_id":"...","body_b64":"..."}`; ACK `{"type":"LP_RELIABLE_ACK","msg_id":"..."}` (`reliable_send_manager.h:34-36`) |
| Dedup | app-assigned `msg_id`; receiver-side `is_duplicate()` in-memory window (`m_dedup_window_ms=1h`, `reliable_send_manager.h:132`) |
| Persistence | durable outbox `reliable_outbox.json` under `files_dir` (`reliable_send_manager.cpp:14`); survives stop/start/restart |
| Retry | fixed-interval re-send every `retry_timeout_ms` (default 10s) × `max_retries` (default 3) — **§76 non-compliant** (no backoff/jitter) |
| Offline | when no live session and offline queue enabled → signaling server `STORE` (store-and-forward mailbox), delivery on peer connect |
| Receipt | status callback `QUEUED→SENT→DELIVERED|FAILED(reason)`; **no signed proof** (app `msg_id`, no destination signature) |
| Bounds | `m_max_messages=500`, `m_ttl_ms=7d`, `reliable_outbox_full()` |

## 3. Path 3 — Overlay send (`send_overlay` / `litep2p_send_overlay`)

| Aspect | Detail |
|---|---|
| Entry | `litep2p_send_overlay` (`litep2p.h:425`) → `SessionManager::send_overlay` (`session_manager.cpp:182`) → `OverlayRouter::send` |
| Wire | LPX2 onion envelope `OVERLAY_FRAME` (0x32): sealed per-hop `crypto_box_seal` instructions (`overlay_frame.h:34-42`), `frame_id` 16B dedup + TTL + replay window |
| Dedup | `frame_id` LRU (`dedup_cache_size=4096`) + timestamp replay window (15 min, `overlay_router.h:66-67`) |
| Persistence | in-memory: pending-send table (origin), mailbox sealed blobs (relay), dedup LRU |
| Retry | `ack_timeout_ms=4000`, `max_send_attempts=3`, **rotated relay path** per retry (`overlay_router.h:60-61`) |
| Offline | `via_mailbox` → relay `OverlayMailbox` (bounded: 1000 entries/16MB, per-origin quota 64, TTL 24h) |
| Receipt/ACK | optional `want_ack` → overlay ACK back along a fresh reverse path; Ed25519 origin-signed payload + ACK (`overlay_frame.h` FinalPayload) |
| Failure reporting | `DeliveryCb` per send (Delivered/Failed), `litep2p_overlay_stats` JSON counters |
| Bounds | `max_pending_sends=512`, `max_forward_queue=256`, `relay_table_max=256`, `mailbox_pickup_batch=16` |

## 4. Merge matrix (what each later phase absorbs)

| Capability | Path 1 (plain) | Path 2 (reliable) | Path 3 (overlay) | Absorbed by |
|---|---|---|---|---|
| durable storage | ✗ | outbox JSON | mailbox (relay) | **P3 object store** |
| dedup key | none | app `msg_id` | `frame_id` | **P3 ObjectID** (P5 single dedup) |
| retry policy | none | fixed (bad) | backoff+rotate (good) | **P5/P7 retry strategy** |
| signed receipt | ✗ | ✗ | origin-signed payload+ACK (not destination-signed) | **P5 signed destination receipt** |
| offline store-and-forward | ✗ | signaling STORE | overlay mailbox | **P4 confirmed remote storage** |
| transport-level ACK | APPLICATION_ACK | LP_RELIABLE_ACK | overlay ACK | **P5 RECEIVED_ACK** |

**Target (P5):** one object-delivery path with a single dedup (ObjectID) + a single receipt model (signed destination receipt as a first-class object). Plain/reliable/overlay semantics become policies on the same object (`delivery_class`, `priority`, `require_receipt`).

## 5. Open questions for Phase 3/5

1. ObjectID derivation must cover all three dedup keys today (none / msg_id / frame_id) — migration strategy needed for in-flight `msg_id`-based dedup state.
2. The signaling-server mailbox (`STORE`/`DELIVER`) is server-side (Python) — its mapping onto the new object model must preserve serverless-first behavior (locked decision 11).
3. Overlay ACK is transport-level; P5's signed receipt is the durable proof — both must coexist (receipt supersedes ACK, not replaces).
