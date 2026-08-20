# Network OS Phase 0 — Step 1.6: Retry Logic Map

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** All retry/timer/backoff paths; flag any §76 violations ("retry every N seconds" without backoff+jitter+event trigger).
**Purpose:** Input to Phase 1 `IScheduler` event-driven retries, Phase 2 reconnect, Phase 7 retry strategy.

## 1. Retry owners

| Owner | Retry mechanism | Backoff | Event-triggered? | Bounded? |
|---|---|---|---|---|
| `ReliableSendManager` (`reliable_send_manager.h:61`) | fixed-interval re-send every `retry_timeout_ms` (default 10s) up to `max_retries` (default 3) | **None** (fixed interval; no jitter) | no (timer tick) | yes (`m_max_messages=500`, retry count) |
| `PeerStateMachine` (`peer_state_machine.h:18-19`) | `MAX_HANDSHAKE_RETRIES=5`, `MAX_CONNECT_RETRIES=5` | FSM counters; handshake cooldown (`last_handshake_completed`) | partial (events: DISCOVERED/CONNECT_REQUESTED/network hints) | yes |
| `PeerReconnectPolicy` (`peer_reconnect_policy.h`) | adaptive exponential backoff + jitter, circuit breaker (`circuit_breaker_until_ms`), battery-aware retry config, `trigger_immediate_reconnect_all` on network transitions | **YES** (`calculate_backoff_with_jitter`, `backoff_level` 1,2,4,8…) | **YES** (`set_network_info`/`set_battery_level` → immediate reconnect; reset on network change) | yes (`max_backoff_ms`, `max_retries`, circuit breaker) |
| `MaintenanceManager` (`maintenance_manager.h`) | periodic ticks: heartbeat, discovery broadcast, signaling reconnect kick, peer retry scan, LAN re-discovery, endpoint fallback | signaling reconnect has throttle (`m_last_signaling_reconnect_kick`) | partial | yes (throttles) |
| signaling client reconnect | `getSignalingReconnectIntervalMs()` fixed interval | **None** | partial | yes (interval config) |
| NAT traversal | STUN heartbeat + punch retry (bounded worker pool, coalesced enqueue) | yes (heartbeat interval, punch budget) | yes | yes |
| OverlayRouter (`overlay_router.h`) | `ack_timeout_ms{4000}`, `max_send_attempts{3}`, path rotation (retry via *different* relay path) | timeout-based; no fixed periodic loop | yes (ACK/timeout) | yes (`max_pending_sends{512}`) |
| `rugged_recovery_manager` | episode-based recovery: `RECOVERY_REQUESTED` event resets retry counters, aggressive reconnect | — | yes | yes |

## 2. §76 compliance flags

- **§76 non-compliant:** `ReliableSendManager` uses a **fixed-interval** re-send (`retry_timeout_ms`) with no backoff/jitter — this is exactly the "retry every N seconds" loop §76 prohibits. Phase 7 (`retry strategy`) must convert to exponential backoff + jitter + event triggers.
- **§76 compliant:** `PeerReconnectPolicy` (backoff + jitter + circuit breaker + event-triggered), overlay (timeout + path rotation + bounded attempts).
- **Mixed:** signaling reconnect is fixed-interval but rate-limited by MaintenanceManager; acceptable short-term, migrate to `IScheduler` in Phase 8.
- All retry loops are **bounded** (counters/queues caps) — invariant 15 already holds structurally.

## 3. Timer inventory (feed for Phase 8 "no independent timers")

| Timer | Period | Owner | Idle cost |
|---|---|---|---|
| unified event loop tick | 500 ms | `UnifiedEventLoop` | poll timeout only |
| peer heartbeat/ping | 10 s | `MaintenanceManager`/session | packet per connected peer |
| discovery broadcast | 5 s | discovery (`DISCOVERY_BROADCAST_INTERVAL_SEC=5`) | packets even with zero peers |
| overlay tick | 2.5 s | `OverlayRouter::m_tick_thread` | wakeup per tick |
| NAT heartbeat | config (`NATHeartbeatIntervalSec`) | `NATTraversal` | packets |
| telemetry flush | `TelemetryFlushIntervalMs` (default 30 s) | telemetry | JSON write |
| NAT cleanup | `NATCleanupIntervalSec` | `NATTraversal` | wakeup |

These are measured (not assumed) in `baseline-*.json` (idle network bytes + wakeups).
