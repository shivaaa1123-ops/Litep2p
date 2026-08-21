# 14 — Android Resource Manager & Scheduling

**Phase 8.** Master doc: §8 (central scheduling), §9 (radio/battery), §42
(ResourceManager), §43 (profiles), §77 (wakeup budget), §78 (background
reality), §88 (targets), §89 Phase 8.

## Goal

The same protocol behaves **aggressively when appropriate and nearly sleeps
when idle**. The runtime is resource-aware on Android; the C++ core consumes
abstract signals from `IPlatformAdapter`.

## Components

- **`modules/networkos/resources/ResourceManager`** — the single source of
  truth that turns platform signals into concrete budgets (§42):
  - Inputs: connectivity, metered, battery, charging, storage pressure,
    foreground, wakeup window (maintenance opportunity).
  - Outputs (`ResourceBudget`): connection budget, replication budget,
    bandwidth, CPU quota, discovery intensity, storage acceptance, lease
    duration hint, maintenance allowance.
- **Profiles (§43)** — ECO / BALANCED / RELIABLE / CRITICAL. Each maps to a
  budget shape; CRITICAL is per-object (never a global floor cut). Switching
  profiles takes effect immediately (no restart). Hard safety limits are never
  violated (§85).
- **Wakeup budget (§77)** — every wakeup attributed to a subsystem
  (`noteWakeup(source, ms)`); `unattributedWakeups()` should stay ~0. Idle
  produces no periodic wakeups (no gossip timers, §9).
- **Lifecycle bridge (§7)** — Active / Opportunistic / Dormant. `snapshot()`
  persists profile + budgets; `restore()` rebuilds them on resume without
  re-deriving (invariant 11/17).

## Runtime wiring (`NetworkRuntime`)

- Owns `m_resources` (built in the constructor, restored in `start()` from
  `files_dir/resource_state.json`).
- On each `onPlatformSignal`: pushes to the adapter, feeds the ResourceManager,
  and propagates the result to consumers (e.g. `replication->setBudgetBackground`
  when background/dormant/ECO). This keeps the energy policy in ONE place.
- On `stop()`: persists `resource_state.json`.

## Budget behavior

| Profile | replication | connections | discovery | storage |
|---|---|---|---|---|
| ECO | 0 | 0 | 0 | no |
| BALANCED | 8 | 8 | 60 | yes |
| RELIABLE | 16 | 16 | 100 | yes |
| CRITICAL | 32 | 32 | 100 | yes |

Additional clamps: offline/Doze => zero radio work; low-battery => ECO-like;
metered => small budgets; storage-pressure => no inbound storage.

## Rules

- No independent timers per subsystem — all deferred work goes through
  `IScheduler` (event-driven). The scheduler owns no thread (idle budget).
- Idle cost target (§88): near-zero periodic wakeups; no gossip churn.
- Single-thread vs multi-thread flavors must exhibit identical observable
  behavior at the API level.