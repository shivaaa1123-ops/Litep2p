# Network OS Phase 1 — Runtime Skeleton & Stable Interfaces

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** The `modules/networkos/` skeleton every later phase plugs into.
**Purpose:** Stable seams (Runtime, ITransport, IIdentityStore, IObjectStore, IScheduler, IPlatformAdapter) + persisted identity + zero behavior regression.

## 1. Module layout

```
litep2p-core/src/main/cpp/modules/networkos/
├── include/networkos/                 ← stable C++ interface headers
│   ├── Runtime.h                      ← Result, RuntimeState, RuntimeConfig, RuntimeEvent, Runtime, createRuntime()
│   ├── ITransport.h                   ← Endpoint, TransportCapability, ITransport (P2 hardens)
│   ├── IIdentityStore.h               ← Identity, IIdentityStore, createFileIdentityStore()
│   ├── IObjectStore.h                 ← ObjectId, ObjectMeta, QuotaInfo, IObjectStore (declared; P3 implements)
│   ├── IScheduler.h                   ← Task, TaskPriority, SchedulerEvents, IScheduler, createScheduler()
│   └── IPlatformAdapter.h             ← PlatformSignal, PlatformInfo, IPlatformAdapter
├── runtime/src/NetworkRuntime.cpp     ← facade: start/stop/restore + event sink (§35)
├── identity/src/FileIdentityStore.cpp ← create-once persisted PeerID (atomic tmp+rename)
├── scheduler/src/Scheduler.cpp        ← thread-free priority queue, event-driven dispatch
└── platform/
    ├── desktop/NullPlatformAdapter.cpp    (desktop build)
    └── android/AndroidPlatformAdapter.cpp (Android build; JNI wiring in P8)
```

## 2. Runtime lifecycle

`start()` order (per master doc §7): load config → open identity → open transports (existing `SessionManager` behind the facade) → restore durable state → notify scheduler → event loop (owned by `SessionManager`). `stop()` is the reverse. `restore()` reconstructs identity from `files_dir/identity.json` after process death.

No logic moved in Phase 1 (locked decision 9) — `SessionManager`, discovery, and overlay keep their current behavior; the facade only establishes the lifecycle skeleton. **C ABI byte-for-byte unchanged** (verified by `desktop/tools/check_c_abi.sh`).

## 3. Identity persistence (Step 2.3)

`FileIdentityStore` persists `peer_id` to `files_dir/identity.json` with an atomic tmp+rename write. The rule is create-once: `loadOrCreate()` never replaces an existing id, so PeerID is identical across restarts, IP changes, and SIGKILL at any point (the write is all-or-nothing). This closes the Phase 0 gap where the random-fallback device id was regenerated per process run. Noise key material stays in `NoiseKeyStore`; Android Keystore integration is a Phase 12 hook (via the adapter, not core).

## 4. Scheduler skeleton (Step 2.4)

`Scheduler` is a thread-safe priority queue (max-heap by priority then due time) with task metadata (earliest_run/deadline/network/unmetered/charging/batch/bytes/CPU) and event hooks. **It owns no thread** — `Runtime::onPlatformSignal` and the event hooks call `process(now)` at event boundaries, so idle cost is unchanged (Gate B: no new threads, no new timers). Phase 8 routes the same interface to WorkManager.

## 5. Platform adapter (Step 2.5)

`IPlatformAdapter` abstracts connectivity/metered/battery/charging/storage/foreground signals and a `requestWakeup` scheduling bridge. Desktop uses `NullPlatformAdapter`; Android compiles `AndroidPlatformAdapter` (signal recording stub; real Android sources wired via JNI in Phase 8). The core never calls Android APIs directly.

## 6. Verification summary (see phase file §10 for the log)

| Suite / metric | Result |
|---|---|
| Existing suites (9) × 5 | green (run_all_tests.sh) |
| network_runtime_test | 922 checks, 0 failures (100× restart loop + identity + scheduler + adapter) |
| SIGKILL restore | 20/20 runs, PeerID stable |
| C ABI diff | empty (56 functions, snapshot committed) |
| Live peer smoke | 2 sessions × 3 runs green (latency runner) |
| Native Android build | green (both networkos adapters compile) |
| Idle threads | 31 (unchanged vs P0 baseline) |

## 7. Committed

`Network OS P1: core runtime skeleton, stable interfaces, platform adapter`
