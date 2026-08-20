# Network OS Phase 0 — Step 1.2: Threading Model Map

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** Threads, event loops, locking, and blocking calls in the engine.
**Purpose:** Idle-thread baseline (Gate B), Phase 1 `IScheduler` input, lock-order reference for later phases.

## 1. Event flow

```
app/UI ──▶ C ABI (litep2p_c_api.cpp) ──▶ SessionManager (PIMPL)
                                             │
        ┌────────────────────────────────────┼───────────────────────────┐
        ▼                                    ▼                           ▼
  TCP ConnectionManager            UDP ConnectionManager          NATTraversal (singleton)
        │                                    │                           │
        └──────────────┬─────────────────────┘                           │
                       ▼                                                   ▼
              EventManager ──▶ UnifiedEventLoop (poll()/kqueue()/timerfd)  STUN/UPnP/punch threads
                       │
                       ▼
        MessageHandler → PeerStateMachine (pure FSM) → PeerLifecycleManager → app callbacks
                       ▼
        MaintenanceManager (timer tick) / ReliableSendManager (tick) / overlay router tick
```

- The **single-thread flavor** funnels all I/O + timers + events through `UnifiedEventLoop` (`unified_event_loop.h:35`, `runLoop()`, `m_timer_interval_ms{500}`).
- The **multi-thread flavor** uses `EventManager`'s legacy thread-per-task: `m_processingThread` + `m_timerThread` + connection-manager listener threads (`event_manager.h:52-79`).

## 2. Threads at idle vs active

| Thread | Owner | Idle | Active | Notes |
|---|---|---|---|---|
| `unified_event_loop` thread | `EventManager::m_loop_thread` | **YES** (blocked in poll/kqueue) | YES | single-thread flavor only |
| `event processing` thread | `EventManager::m_processingThread` | **YES** (blocked on CV) | YES | multi-thread flavor only |
| `timer` thread | `EventManager::m_timerThread` | **YES** (blocked on CV) | YES | multi-thread flavor only |
| TCP listener thread | `ConnectionManager` | **YES** | YES | `startServer` |
| UDP listener thread | `UdpConnectionManager` | **YES** | YES | `startServer` (multi-thread); event-loop variant registers fd instead |
| NAT heartbeat | `NATTraversal::heartbeat_thread_` (`nat_traversal.h:422`) | **YES** | YES | bounded interval; on-demand punch workers only while punching (`MAX_ON_DEMAND_PUNCH_THREADS=10`) |
| NAT maintenance | `NATTraversal::maintenance_thread_` | **YES** | YES | cleanup tick |
| NAT engine | `NATTraversal::engine_thread_` | **YES** | YES | |
| overlay tick | `OverlayRouter::m_tick_thread` (`overlay_router.h:280`, `tick_interval_ms{2500}`) | **YES** | YES | only when overlay enabled |
| peer tier cleanup | `PeerTierManager::m_cleanup_thread` | **YES** | YES | |
| peer tier promotion | `PeerTierManager::m_promotion_thread` | **YES** | YES | |
| proxy stream IO | `ProxyEndpoint` per-stream `io_thread` (`proxy_endpoint.h:168`) | **NO** | YES (per stream) | created on demand |
| signaling WebSocket | `SignalingClient` | **NO** | YES (when connected) | client-managed |
| engine thread (Kotlin) | `LiteP2PService.engineExecutor` single thread | n/a (Android) | YES | serializes native init/start/stop |

**Idle thread count:** multi-thread flavor holds the 4 NAT/tier/overlay threads + event/timer + TCP/UDP listeners. Single-thread flavor replaces event+timer with one loop thread but still owns the NAT/tier/overlay threads. See `baseline-*.json` for measured counts.

## 3. Locking

- `ConfigManager` — single `m_mutex` around the whole JSON doc (`config_manager.h:218`).
- `SessionManager::Impl` — `m_peers_mutex` (peer map), `m_peer_contexts` guards, event-queue mutex in `UnifiedEventLoop` (`m_fds_mutex`, `m_event_mutex`, `m_scheduled_mutex`).
- `NoiseNKManager` — `m_sessions_mutex` + `m_keys_mutex`; `NoiseKeyStore` — `m_mutex`.
- `OverlayRouter` — single `m_mu` + atomics for cover/last-tx; `OverlayMailbox` — `m_mu`.
- `NATTraversal` — per-subsystem mutexes (heartbeat/punch/peer maps).
- `litep2p_c_api.cpp` — `g_api_mutex` serializes init/start/stop/shutdown; `g_cb_mutex` guards callback structs; callback invocation is copy-under-lock then call outside the lock (comment at `litep2p_c_api.cpp:183`).
- `PeerReconnectPolicy` — `peers_mutex_`; state refreshed via `set_battery_level` / `set_network_info`.
- **No detected global lock-order inversion** today; Phase 1 must document the canonical order (ConfigManager → SessionManager impl → per-module).

## 4. Blocking calls inside the event loop

- `local_peer_db` JSON load/save (`save_atomic` writes tmp file then rename) runs on engine threads during upsert — small but synchronous file I/O on the event path.
- `reliable_send_manager::save_outbox_locked()` writes `reliable_outbox.json` synchronously on the send path (`reliable_send_manager.cpp`).
- `NoiseKeyStore::save()` does file I/O (tmp+rename, `noise_key_store.cpp:219`) on the init path.
- SQLite is **not** on any hot path (no production SQLite usage — see `01-module-inventory.md` §3).
- DNS/`getaddrinfo` occurs in transport connect paths (TCP connect, signaling WS).
- **Implication for Phase 1 `IScheduler`/`IPlatformAdapter`:** all persistent writes are candidates to move off the event thread or batch in the NetworkOS skeleton.
