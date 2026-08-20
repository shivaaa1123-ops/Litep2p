# Network OS Phase 0 — Step 1.4: Persistence Map

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** Where durable state lives, transactional vs not, write-amplification points.
**Purpose:** Input to Phase 3 object store (SQLite WAL decision), Phase 5 receipts, Phase 8 dormant persistence.

## 1. Durable stores

| Store | Format | File(s) | Owner | Transactional? | Survives process death? |
|---|---|---|---|---|---|
| Peer DB | JSON (`local_peer_db.cpp:1-5`: "JSON file-based … replaces SQLite") | `files_dir/litep2p_peers.sqlite` (name only; content is JSON) | `LocalPeerDb` | Atomic write via `save_atomic()` (tmp + rename, `local_peer_db.cpp`) | **YES** (load on open) |
| Noise keystore | JSON lines (local keypair, peer keys, Ed25519 signing keys) | `files_dir/keystore` | `NoiseKeyStore` | Atomic tmp+rename (`noise_key_store.cpp:219`); dirty-flag re-save | **YES** |
| Reliable outbox | JSON | `files_dir/reliable_outbox.json` (`reliable_send_manager.cpp:14`) | `ReliableSendManager` | `save_outbox_locked()` whole-file rewrite on each mutation (see §3) | **YES** (`load_outbox()` on `configure`) |
| Anomaly incidents | JSON files | `base_dir/anomalies/*.json` | `AnomalyReporter` | per-incident write + rotation cap | **YES** |
| Telemetry | JSON periodic flush | `getTelemetryFilePath()` | telemetry | append/rewrite per flush interval | **YES** (bounded) |
| Crash reports | JSON | `base_dir/anomalies` (crash context) | `CrashHandler` | async-safe write | **YES** |
| Config | JSON | `config.json` (or `files_dir/config.json`) | `ConfigManager` | `loadConfig`/`saveConfig` | **YES** |

## 2. In-memory-only (lost on restart)

| Store | Owner | Notes |
|---|---|---|
| Session cache | `SessionCache` (`session_cache.h`) | optimized handshake resumption only; no persistence |
| Overlay mailbox (relay side) | `OverlayMailbox` (`overlay_mailbox.h`) | bounded, in-memory; sealed blobs lost on relay restart (Phase 4/5 concern) |
| Overlay pending sends / dedup LRU | `OverlayRouter` | in-memory; dedup window lost on restart |
| Reliable dedup window | `ReliableSendManager::m_seen` | `m_dedup_window_ms=1h`; in-memory |
| Peer FSM state | `SessionManager::Impl` | reconstructed from peer DB + discovery on start |

## 3. Transactionality & write amplification

- **Peer DB:** every `upsert_peer`/`set_peer_connected` mutates the in-memory map then `save()` rewrites the whole JSON file (atomic). Frequent discovery updates → **full-file rewrites** (write amplification).
- **Reliable outbox:** `send_reliable`, `on_ack`, `cancel`, `tick` all call `save_outbox_locked()` which rewrites the whole outbox JSON. High churn → whole-file rewrites per message state change.
- **Keystore:** save-once-at-init + dirty re-save; low amplification.
- **No SQLite/WAL anywhere in production code today** (`sqlite3_dyn` is an unused loader; see `01-module-inventory.md` §3). METHODOLOGY decision 1 (SQLite WAL for Phase 3) is therefore a **new implementation**, not a reuse.

## 4. Crash-safety gaps (Phase 3/4 hardening candidates)

1. Whole-file JSON rewrites are atomic (tmp+rename) but not crash-consistent across *multiple* related objects — a single object store transaction primitive does not exist yet.
2. `never-ACK-before-commit` (master doc §24) has no durable-commit gate today: `STORED_ACK` equivalents are in-memory or server-side (signaling mailbox `STORE`/`DELIVER`).
3. Outbox + dedup state are in different files; a crash between them can duplicate app delivery (mitigated only by the in-memory dedup window).
4. Overlay mailbox is not durable — Phase 4 must decide whether carrier leases require persistence.
