# Phase 1 — Core Architecture Refactor: Runtime Skeleton & Stable Interfaces

**Master doc references:** §89 Phase 1 ("Core Architecture Refactor"), §16
(transport abstraction), §7 (runtime lifecycle), §8 (scheduler), §37
(threading), §38 (locking), §36 (stable C ABI), §42 (platform signals),
§94 (suggested C++ public model), §96 (decision hierarchy).

## 1. Objective

Create the stable skeleton the whole Network OS will be built on:
- A `NetworkRuntime` facade with a clean `start()` / `stop()` / restore
  lifecycle.
- Stable interface headers: `ITransport`, `IObjectStore`, `IScheduler`,
  `IPlatformAdapter`, `IIdentityStore`.
- Persisted cryptographic identity (PeerID stable across restarts and IP
  changes — master doc §12 invariant "network changes do not change peer
  identity").
- A `PlatformAdapter` seam so the C++ core never depends on Android APIs.
- **Zero behavior regression**: the existing engine keeps working behind the
  facade exactly as before.

## 2. Scope

**In scope:** new `modules/networkos/` skeleton, interface headers, identity
persistence, scheduler skeleton, platform adapter interface + Android/JNI
adapter stub, lifecycle wiring, C ABI kept byte-for-byte compatible.

**Out of scope:** object store (Phase 3), new protocol frames, replication,
discovery expansion, resource budgets. Existing modules are *wrapped*, not
rewritten.

## 3. Prerequisites

- Phase 0 complete: architecture map + baselines committed.
- Desktop and native Android builds green.

## 4. Background

Master doc §89 Phase 1 deliverable: *"SDK starts, persists identity, opens
transports, restores state, and shuts down cleanly."* Everything later —
object store, handoff, replication, resource manager — plugs into this
skeleton. The key discipline is §3.1/§97: the runtime must tolerate process
death, connectivity change, and IP change; identity must be stable while
endpoints are temporary (§74).

## 5. Detailed implementation steps

### Step 2.1 — Define stable interface headers
Create `modules/networkos/include/networkos/` with pure-virtual interfaces:

- `Runtime.h` — `Result start(const RuntimeConfig&)`, `Result stop()`,
  `Result restore()` (reconstruct state from persistence), event sink hook.
- `ITransport.h` — `capabilities()`, `connect(Endpoint)`, `listen()`,
  `close()`, per master doc §16. Do not expose socket details upward.
- `IIdentityStore.h` — load/create/export stable PeerID + key material.
- `IObjectStore.h` — declared now, implemented in Phase 3: put/get/delete,
  transaction handles, quota queries, expiry iterator.
- `IScheduler.h` — `schedule(Task)` with task metadata (earliest run,
  deadline, priority, requires network, requires unmetered, can batch,
  estimated bytes/CPU), plus event hooks (`onConnectivityChanged`,
  `onAppForeground`, `onMaintenanceWindow`, `onPeerAvailable`).
- `IPlatformAdapter.h` — abstract signals: connectivity, metered flag,
  battery/charging, storage pressure, foreground/background, wakeup
  opportunities; and scheduling bridge (maps `IScheduler` tasks to
  WorkManager/alarm on Android).

Rules: the C ABI stays a **process-wide singleton with no handles** in v1
(locked decision 10); C++ ABI stability is NOT required across releases
(only the C ABI is stable — §36).

### Step 2.2 — Runtime skeleton
Implement `modules/networkos/runtime/src/NetworkRuntime.cpp`:
- `start()` order: load config → open identity → open transports →
  restore durable state → notify scheduler → begin event loop.
- `stop()` order (reverse, clean shutdown, no blocked threads left).
- `restore()` after process death: bring the runtime back to the same
  logical state from persistence. Log every restore path.
- Event bus: single native event queue feeding a single JNI dispatch
  boundary (§35). No arbitrary Java callbacks from many native threads.

### Step 2.3 — Identity persistence
- Reuse existing PeerID generation; persist key material via
  `IIdentityStore`. On Android, integrate Android Keystore where the crypto
  design allows (§19.1) — via the adapter, not from core.
- Test: PeerID identical across 100 restarts and across IP changes.

### Step 2.4 — Scheduler skeleton
- Implement `IScheduler` core with task metadata + event-driven triggers.
- **No independent timers in subsystems yet**; subsystems ask the scheduler.
- Default: nothing runs unless an event (network, foreground, peer,
  maintenance, charging) or a queued task fires.

### Step 2.5 — PlatformAdapter + Android adapter stub
- `PlatformAdapter` interface in core; `modules/networkos/platform/android/`
  adapter wired through JNI to `LiteP2PRuntime` (connectivity callback,
  lifecycle callbacks, WorkManager job wiring).
- Android build compiles the adapter; desktop build uses a
  `NullPlatformAdapter`/desktop adapter.

### Step 2.6 — Wrap existing engine behind the facade
- `NetworkRuntime` delegates today to `SessionManager` + discovery + overlay
  exactly as the current entry points do (`LiteP2P`/C ABI). This is a
  *facade*; no logic moves yet. Keep C ABI behavior identical.

### Step 2.7 — Threading & locking hygiene
- Enforce from Phase 1's thread map: ownership + message passing over shared
  mutable state (§38), no new global mutexes, defined lock ordering,
  bounded worker pools, no thread-per-subsystem (§37).
- Keep single-thread flavor behavior intact.

### Step 2.8 — C ABI compatibility check
- Build a script that diffs `litep2p.h` symbol set + signatures before/after
  this phase. It must be empty. Update `docs/api-spec.md` only if the diff is
  non-empty (should not happen in this phase).

### Step 2.9 — Lightweight transport wiring (locked decisions 8, 9)
- Default compile = **TCP + UDP (NAT traversal) only**; QUIC stays behind an
  `ENABLE_QUIC` flag that is **OFF** for the default Android AAR.
- Interface headers are **thin facades** over the existing
  `SessionManager` / `SecureSessionManager` / discovery / overlay — no logic
  is moved or rewritten in this phase (reuse, don't rebuild).
- Record AAR size + idle RAM after wiring and compare to the Phase 0
  baseline (feeds Gate B).

## 6. Data / schema changes
- New identity/keystore table if none exists (migrate existing PeerID).
- Nothing else.

## 7. Wire protocol changes
None.

## 8. Deliverables
- `modules/networkos/` skeleton with interface headers
  (Runtime, ITransport, IObjectStore, IScheduler, IPlatformAdapter,
  IIdentityStore).
- `NetworkRuntime` lifecycle (start/stop/restore) + identity persistence.
- PlatformAdapter interface + Android/JNI adapter stub.
- C ABI compatibility script (permanent CI gate).

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Existing-suite stability (5×):** `c_api_test`, `session_manager_test`,
   `overlay_test` — the refactor must not change behavior. All 5 runs green.
2. **Restart loop (100×):** start → identity read → stop, 100 consecutive
   cycles. PeerID must be identical every time. Repeat with a killed process
   (SIGKILL at random points during start) 20× and verify clean restore.
3. **C ABI diff (1×):** `litep2p.h` symbol set + signatures identical before
   vs after (scripted diff). Must be empty.
4. **Live peer smoke (2 sessions × 3 runs):** two peers discover, handshake,
   reach READY, exchange a message — behavior unchanged vs Phase 0 baseline.
5. **Native Android build (1×):** `:litep2p-core:externalNativeBuildMultiThreadDebug`
   green, including the new platform adapter on the Android side.
6. **Idle-thread check:** native thread count at idle must not increase vs
   Phase 0 baseline (goal: same or fewer).

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-20 | existing suites (c_api, session, overlay, proxy, file_transfer, crypto, nat, malformed, voice) | 5 | PASS | run_all_tests.sh --loop 5; 50/50 PASS |
| 2026-08-20 | network_runtime_test (restart loop + identity + scheduler + adapter) | 1 | PASS | 922 checks, 0 failures |
| 2026-08-20 | restart loop (PeerID stable) | 100 | PASS | PeerID identical across 100 start/stop cycles + 100 identity re-creations |
| 2026-08-20 | SIGKILL restore | 20 | PASS | sigkill_restore_test.sh: PeerID stable across 20 kills at random points |
| 2026-08-20 | C ABI diff | 1 | EMPTY | 56 functions; snapshot at tools/abi/litep2p_abi_snapshot.txt |
| 2026-08-20 | live peer smoke | 6 | PASS | phase1_smoke.sh: 2 sessions × 3 runs (see log) |
| 2026-08-20 | native build | 1 | PASS | externalNativeBuildMultiThreadDebug green (networkos module + Android adapter compile) |
| 2026-08-20 | idle threads | 1 | PASS | 31 threads at idle — unchanged vs Phase 0 baseline (no new threads added by the facade) |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Facade delegation regresses behavior | 5× existing suites + live peer smoke before/after |
| Identity migration breaks existing PeerIDs | Migrate, don't regenerate; verify same PeerID after upgrade |
| Two event loops fighting | Keep the existing loop as the single event source in this phase |
| C ABI drift | Scripted `litep2p.h` diff gate in CI (add to `.github/workflows/`) |

## 12. Definition of Done

- [x] `modules/networkos/` skeleton with interfaces (Runtime, ITransport,
      IObjectStore, IScheduler, IPlatformAdapter, IIdentityStore).
- [x] `NetworkRuntime` start/stop/restore works; 100× restart loop green.
- [x] PeerID stable across restarts and IP changes (test exists).
- [x] C ABI diff empty; `docs/api-spec.md` unchanged.
- [x] Existing suites green 5×; live peer smoke green.
- [x] Native Android build green (both flavors compile).
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message:
      `Network OS P1: core runtime skeleton, stable interfaces, platform adapter`.

