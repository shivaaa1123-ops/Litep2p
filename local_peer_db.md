# Local Peer DB (SQLite) — Behavior, Priority, Insertion & Deletion

This document describes the **current implemented behavior** of LiteP2P’s local peer database (SQLite):

- when the DB is used (and its priority vs discovery/signaling)
- how rows are inserted/updated
- how rows are deleted (auto-prune)
- what timestamps/columns mean

It also complements the schema comment block embedded in `config.json`.

## What it is

- Backend: SQLite database file `litep2p_peers.sqlite`
- SQLite is loaded dynamically via `dlopen`/`dlsym` (no vendored SQLite source).
- If SQLite cannot be loaded/opened, the engine continues without persistence.

## Priority: who wins and when it’s used

LiteP2P’s peer knowledge comes from multiple sources. The intent is:

1. **Live connectivity and runtime observations** (active session state) are authoritative.
2. **Discovery (LAN broadcast / local observations)** is preferred for LAN endpoints.
3. **Local DB** is used as a cached hint to bootstrap/reconnect.
4. **Signaling** is used *on-demand* only to bootstrap when the DB cannot provide a reachable peer.

### When the DB is used

The DB is used in two main places:

- **Startup / bootstrapping:** load known peers into memory so UI can show them and the engine can try reconnects.
- **Reconnect cycle:** attempt peers from the DB in a paced “DB-first” queue.

### When signaling is used

Signaling is contacted only when:

- the DB is empty, **or**
- the engine has tried (paced) DB reconnect candidates and **exhausted** them without reaching a peer.

After the engine falls back to signaling due to DB empty/exhausted, it keeps a **best-effort persistent signaling connection** so it can:

- receive fresh peer updates from the server
- avoid repeatedly reconnecting/handshaking with the signaling server

This persistent signaling mode does **not** imply tight polling: `LIST_PEERS` is still throttled and only requested when bootstrapping.

## Configuration

The effective config keys are:

```json
{
  "storage": {
    "peer_db": {
      "enabled": true,
      "path": "",
      "reconnect_candidate_limit": 2000,
      "prune_after_days": 15
    }
  }
}
```

- `storage.peer_db.enabled` (bool, default: **true**)
- `storage.peer_db.path` (string, default: empty → auto-resolve)
- `storage.peer_db.reconnect_candidate_limit` (int, default: **2000**)
- `storage.peer_db.prune_after_days` (int, default: **15**)

### Path resolution (high level)

If `storage.peer_db.path` is non-empty, it is used as-is.
Otherwise the DB path is derived from the config/executable directory (platform-dependent) with a fallback to CWD.

On Android, the DB path is injected using the app’s private storage directory (e.g., `context.getFilesDir()`).

## Schema (current)

### Versioning

- `meta(schema_version)` is used for schema migration.
- Current schema is effectively **v2** (adds `never_delete`).

### Tables

`peers` (one row per peer):

- `peer_id TEXT PRIMARY KEY`
- `network_id TEXT`
- `ip TEXT`
- `port INTEGER`
- `connectable INTEGER`
- `connected INTEGER`
- `never_delete INTEGER DEFAULT 0`  
  Exemption flag: `1` means this peer is **never auto-deleted**.
- `first_seen_ms INTEGER`  
  “First entered”: when this `peer_id` was first created in the DB.
- `last_seen_ms INTEGER`
- `last_discovery_ms INTEGER`
- `last_connected_ms INTEGER`  
  “Last successful connect”: last time a successful connection was observed.
- `last_disconnected_ms INTEGER`
- `updated_ms INTEGER`

`peer_events` (audit trail):

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `peer_id TEXT`
- `event_type TEXT`
- `detail TEXT`
- `ts_ms INTEGER`

Indexes include recency/connectability lookups, plus an index on `last_connected_ms` for pruning.

## Insertion & update logic (what gets written)

### The core rule: UPSERT by `peer_id`

All writes are **UPSERT** (insert-or-update) keyed by `peer_id`.

### What is intentionally NOT persisted (LAN/private endpoints)

The peer DB is intended as a longer-lived reconnect hint for **public/WAN** endpoints.
To avoid polluting it with machine-local addresses that are only valid on the current LAN, the DB
**does not persist private/local IPv4 endpoints**, including:

- RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- loopback: `127.0.0.0/8`
- link-local: `169.254.0.0/16`
- CGNAT: `100.64.0.0/10`
- `0.0.0.0/8`

These peers are still usable at runtime via discovery/observations; they’re simply not written to the SQLite DB.

For older DB files that may already contain `192.168.x.x` entries from previous runs, the DB applies a best-effort
cleanup on open to remove those legacy rows.

Writes happen when the engine learns/upgrades a peer’s endpoint or state, including from:

- discovery updates (LAN)
- signaling peer lists/updates (WAN bootstrap)
- connection state transitions (connected/disconnected)

### “Pinning” (never_delete)

To ensure the DB never becomes completely empty due to pruning, the DB applies a pinning rule:

- **The first peer ever inserted** into the DB is stored with `never_delete = 1`.

This is a conservative “seed” behavior; additional pin/unpin controls can be added later.

### Timestamps

- `first_seen_ms` is set only once (on first insert).
- `last_seen_ms` and `updated_ms` are updated on each UPSERT.
- `last_discovery_ms` is updated on discovery events.
- `last_connected_ms` is updated when a peer transitions to **connected**.
- `last_disconnected_ms` is updated when a peer transitions to **disconnected**.

### Connection success tracking

“Successful connect” is defined by the runtime FSM marking a peer as connected.
When that happens, the DB is updated so pruning and future reconnect ordering have strong signals.

## Deletion logic (auto-prune)

The DB includes an auto-prune operation that runs periodically from the session maintenance loop.

### Prune window

- Controlled by `storage.peer_db.prune_after_days` (default: **15**).

### Which peers are deleted

Peers are deleted only if `never_delete = 0` and they are stale beyond the cutoff:

1. **Peers that have connected before:**
   - delete if `last_connected_ms > 0` and `last_connected_ms < now - prune_after_days`
2. **Peers that never connected:**
   - delete if `last_connected_ms == 0` and `first_seen_ms < now - prune_after_days`

Associated `peer_events` rows are also removed for deleted peers.

### Which peers are never deleted

- Any peer with `never_delete = 1`.

## DB-first reconnect + on-demand signaling: end-to-end flow

At a high level:

1. **Load reconnect candidates from DB** (up to `reconnect_candidate_limit`) into an in-memory queue.
2. **Pace reconnect attempts** to avoid storms.
3. If the DB is empty or the queue is exhausted without success:
  - enter **signaling fallback mode**
  - connect/register to signaling and **request a peer list** (throttled)
4. When signaling returns peers:
   - choose a connectable endpoint
   - attempt connection
   - **UPSERT** it into the DB
5. Once connected to any peer:
  - signaling remains connected (best-effort) for ongoing peer updates

## Threading & safety

- DB operations are best-effort and protected by a DB-internal mutex.
- DB operations avoid holding core peer locks while executing SQLite calls.

## Where this logic is implemented (code pointers)

- DB implementation:
  - `app/src/main/cpp/modules/plugins/session/include/local_peer_db.h`
  - `app/src/main/cpp/modules/plugins/session/src/local_peer_db.cpp`
    - `LocalPeerDb::upsert_peer(...)` (insertion/update)
    - `LocalPeerDb::set_peer_connected(...)` (connected/disconnected timestamps)
    - `LocalPeerDb::prune_stale_peers(int prune_after_days)` (auto-deletion)

- DB-first reconnect + on-demand signaling orchestration:
  - `app/src/main/cpp/modules/plugins/session/src/session_manager.cpp`
    - `SessionManager::Impl::db_first_connect_and_prune_tick_()` (priority logic)
    - signaling peer-list handling (updates DB after signaling results)
  - `app/src/main/cpp/modules/plugins/session/src/maintenance_manager.cpp`
    - calls the DB-first tick from the maintenance loop

## Failure modes

- If SQLite cannot be loaded/opened: DB feature is disabled for that run; networking continues.
- If DB operations fail: errors are logged; engine behavior continues.
- If signaling server is not reachable / connect fails:
  - the engine logs the failure
  - continues running (no crash)
  - retries are throttled/backed-off
