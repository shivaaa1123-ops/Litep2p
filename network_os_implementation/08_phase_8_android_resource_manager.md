# Phase 8 — Android Resource Manager + Scheduling

**Master doc references:** §7 (runtime lifecycle on Android), §8 (Android
scheduling strategy), §9 (radio and battery strategy), §42 (ResourceManager),
§43 (resource profiles), §77 (wakeup budget), §88 (initial resource targets),
§78 (background reliability reality), §95 (Android API shape).

## 1. Objective

Make the runtime **resource-aware on Android**. Deliverable (master doc
§89 Phase 8):

> The same protocol behaves aggressively when appropriate and nearly sleeps
> when idle.

## 2. Scope

**In scope:** full ResourceManager (signals in → budgets out), resource
profiles (ECO/BALANCED/RELIABLE/CRITICAL), central scheduler + task
metadata, PlatformAdapter→WorkManager bridge, wakeup budget as a first-class
metric, lifecycle bridge (foreground/background/dormant), single-thread and
multi-thread flavor consistency.

**Out of scope:** discovery expansion (Phase 9), large objects (Phase 10),
public API finalization (Phase 12).

## 3. Prerequisites

- Phase 7 complete (replication now consumes budgets).
- Phase 4 ResourceManager stub exists.

## 4. Background

Master doc §8: avoid independent timers in every subsystem — one central
scheduler with task metadata. §9: the biggest battery mistake would be
frequent periodic gossip. §43 defines profiles. §78: Android may prevent the
app from running for long periods; the SDK cannot honestly guarantee a
sleeping phone acts as a carrier — reliability comes from multiple peers,
optional always-on nodes, opportunistic handoffs, and replica repair when
execution becomes available.

## 5. Detailed implementation steps

### Step 5.1 — ResourceManager (full) (§42)
Inputs (from PlatformAdapter): battery state, charging state, metered
network flag, connection type, data saver, storage pressure, thermal state
(if available), foreground/background, OS scheduling opportunity.
Outputs: connection budget, replication budget, bandwidth budget, CPU
budget, discovery intensity, storage acceptance, maintenance allowance,
lease duration hint.
The C++ engine consumes abstract signals; the Android adapter obtains them
from Android (ConnectivityManager, BatteryManager, DeviceStorageManager,
ActivityManager lifecycle, WorkManager).

### Step 5.2 — Resource profiles (§43)
- **ECO** — minimal background work, minimal replicas, no opportunistic
  bulk, discovery on demand.
- **BALANCED** — default; adaptive replication; background reconciliation
  when convenient.
- **RELIABLE** — more redundancy, faster repair, higher carrier preference.
- **CRITICAL** — per-object (not global): immediate replication, high
  priority, stronger durability target.
Profiles switch via policy/config; never violate hard safety limits (§85).

### Step 5.3 — Central scheduler (§8)
- All work goes through `IScheduler` with task metadata (earliest run,
  deadline, priority, requires network, requires unmetered, requires
  charging, can batch, estimated bytes, estimated CPU).
- Prefer triggers over timers (master doc §9 list): app foreground, network
  available, existing peer connection, LAN peer discovered, high-priority
  object arrives, maintenance opportunity, charging, existing traffic.
- **No independent timers per subsystem** — migrate any remaining ones from
  Phase 1's retry map.

### Step 5.4 — PlatformAdapter → Android bridge
- Map scheduler tasks to WorkManager (with network/unmetered/charging
  constraints) and alarms for critical deadlines.
- Foreground service remains only for active-mode communication; dormant
  mode requires zero service guarantees (§78 — never base correctness on
  `START_STICKY`).

### Step 5.5 — Wakeup budget metric (§77)
- Track wakeups as a first-class metric: count, source subsystem, duration.
- Test targets:
  - idle network: near-zero periodic wakeups;
  - no pending work: no gossip timer churn;
  - pending normal work: batched with existing opportunities;
  - critical work: allowed to spend more energy.

### Step 5.6 — Lifecycle bridge (Active/Opportunistic/Dormant) (§7)
- **Active:** app foreground/user communicating — live connections,
  aggressive direct delivery, low-latency policy.
- **Opportunistic:** legitimate background — process pending durable work,
  sync inventories, deliver high-priority, expire old data, compact DBs.
- **Dormant:** process dead/device asleep — everything required to resume is
  persisted (outbound objects, carrier objects, delivery states, receipts,
  peer knowledge, retry metadata, migration state, identity).
- Reconstruct runtime state from persistence on resume.

### Step 5.7 — Single-thread vs multi-thread flavors
- Verify both AAR flavors behave identically at the API level; the scheduler
  and ResourceManager must not change observable semantics between flavors.
- Idle thread count target: minimal active native threads at idle (§88).

### Step 5.8 — Doze / battery saver behavior
- Under Doze: no network, no timers; persist everything; resume on
  maintenance windows.
- Under battery saver: drop to ECO-like behavior; critical-only sessions.

## 6. Data / schema changes
- `resource_state` persisted (profile, budgets) so restore() can rebuild
  without re-deriving; bounded size.

## 7. Wire protocol changes
None (budgets are local policy; capability fields already exist).

## 8. Deliverables
- `modules/networkos/resources/` (ResourceManager, profiles, scheduler
  integration) + tests `desktop/tests/resource_manager_test`.
- Android adapter implementation in the Kotlin/JNI layer
  (`LiteP2PRuntime` + `PlatformAdapter` Android impl).
- Wakeup accounting hooked into telemetry.

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Idle-cost test (5×):** runtime idle, no pending work, 60s window —
   CPU ≈ 0%, no periodic network chatter, wakeups ≈ 0 (compare to Phase 1
   baseline; must be equal or better).
2. **Profile behavior (5×):** ECO vs BALANCED vs RELIABLE — replication
   fan-out, reconciliation frequency, and discovery intensity differ as
   specified; switching profiles takes effect without restart.
3. **Budget enforcement (5×):** set background budget → replication
   throttled, handoffs capped; foreground → full budgets restored.
4. **Event-driven check (5×):** no pending work → zero timers fire; network
   change triggers scheduled work early (counters prove event-triggering).
5. **Doze simulation (3×):** desktop harness simulates Doze (no network,
   no timers) for 10 min → state intact, no wakeups; resume restores state
   (invariant 11).
6. **Wakeup accounting (5×):** every wakeup attributed to a subsystem;
   histogram recorded; no unattributed wakeups.
7. **Dormant persistence (5×):** kill process mid-work; on restart the
   runtime reconstructs state from persistence and resumes (invariant 17).
8. **Flavor parity (5×):** single-thread and multi-thread builds pass the
   same resource tests with equivalent observable behavior.
9. **Device test (when available, 2 sessions):** real Android: Doze, battery
   saver, background restriction — behavior per profile; capture logcat +
   Battery Historian.
10. **Phase 7 regression (5×):** replication still repairs to target under
     budgets.
11. **Existing suites (5×):** no regression.
12. **Native build (1×):** both flavors green.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| YYYY-MM-DD | idle cost | 5 | PASS/FAIL | vs P1 baseline |
| YYYY-MM-DD | profile behavior | 5 | PASS/FAIL | ECO/BAL/RELIABLE |
| YYYY-MM-DD | budget enforcement | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | event-driven check | 5 | PASS/FAIL | no timers idle |
| YYYY-MM-DD | Doze simulation | 3 | PASS/FAIL | ... |
| YYYY-MM-DD | wakeup accounting | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | dormant persistence | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | flavor parity | 5 | PASS/FAIL | single/multi |
| YYYY-MM-DD | device test | 2 | PASS/FAIL | sessions |
| YYYY-MM-DD | Phase 7 regression | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | existing suites | 5 | PASS/FAIL | ... |
| YYYY-MM-DD | native build | 1 | PASS/FAIL | both flavors |

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Scheduler becomes a new timer farm | All tasks via IScheduler; counters prove event-driven (test 4) |
| Budgets starve critical delivery | CRITICAL profile per-object; hard safety limits never lowered |
| Flavor divergence | Same resource test suite run on both flavors (test 8) |
| Wakeup metric gamed by tests | Attribute wakeups to subsystems; assert no unattributed |

## 12. Definition of Done

- [ ] Full ResourceManager with profiles and budget outputs.
- [ ] Central scheduler: event-driven, task metadata, no subsystem timers.
- [ ] PlatformAdapter→WorkManager bridge; lifecycle bridge
      (active/opportunistic/dormant).
- [ ] Wakeup budget metric tracked; idle cost meets §88 targets
      (near-zero idle).
- [ ] Both AAR flavors pass parity tests.
- [ ] Invariants 7, 11, 17 asserted by tests.
- [ ] Phase 7 regression green; existing suites green; native build green.
- [ ] Status table in `METHODOLOGY.md` updated.
- [ ] Committed with message:
      `Network OS P8: Android resource manager, scheduler, wakeup budget`.

