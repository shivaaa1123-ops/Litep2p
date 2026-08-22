# Phase 11 — Simulator, Chaos Lab, and Reliability Gates

**Master doc references:** §44 (reliability model), §45 (simulation before
large deployment), §46 (chaos testing on real Android devices), §47 (fuzz
testing), §87 (performance benchmarks), §93 (rugged invariants — the 20-item
manifest), §89 Phase 11 ("Simulator and Chaos Lab").

## 1. Objective

Turn "reliability" from a claim into **measured, reproducible data**. This
phase is a **release gate**: nothing ships until the invariant manifest,
chaos runs, and reliability metrics pass.

## 2. Scope

**In scope:** reliability metrics definitions, deterministic simulator or
desktop churn harness (scales from Phase 7's skeleton), Android device chaos
harness, fuzz expansion to all parsers, the §93 invariant test manifest,
tuning constants with data.

**Out of scope:** new product features; global consensus/reputation
(explicitly never, §92).

## 3. Prerequisites

- Phases 0–10 complete.
- Phase 7 churn harness skeleton exists.

## 4. Background

Master doc §44: do not claim "effectively certain" without data. Measure
P(delivery before TTL), P(receipt returned), median/P95 delivery, replica
survival, bytes per delivered object, wakeups/day, CPU ms/object. §45: do not
tune replication constants by intuition — inject churn, loss, partitions,
clock skew, storage exhaustion, malicious peers. §46: chaos on real Android
devices (kill, force-stop, toggle Wi-Fi, reboot, fill storage, change time).
§47: fuzz frame parser, capability parser, object header, receipt, inventory,
decompression, state transitions.

## 5. Detailed implementation steps

### Step 5.1 — Reliability model + metrics (§44)
Define and instrument:
- P(delivery before TTL), P(receipt returned), median/P95 delivery time,
  replica survival over TTL, bytes per delivered object, wakeups per day,
  CPU ms per object, energy estimate per delivered object.
- Expose via existing telemetry (monitoring module); add fields as needed.

### Step 5.2 — Simulator / churn harness (from Phase 7 skeleton)
Deterministic harness (or closely-related routing/replication policy code)
scaling 10 → 100 → 1,000 → 10,000 peers. Inject:
- peer churn, packet loss, partitions, high latency, clock skew;
- storage exhaustion, carrier refusal, corrupted frames, malicious peers;
- duplicate delivery, delayed receipts, device reboot, process kill,
  changing IP, intermittent destination availability.
Output: reliability + cost numbers per scenario; tune replication constants
from data (never intuition).

### Step 5.3 — Android device chaos harness (§46)
Automate on real devices:
- kill app process; force-stop (where conditions permit); toggle Wi-Fi;
  toggle mobile data; switch networks; reboot; fill storage; change time;
  disconnect peers; sleep/wake device; upgrade/downgrade build; corrupt
  selected local state in test environment.
Target: **after interruption, the runtime always returns to a known,
internally consistent state.**

### Step 5.4 — Fuzz expansion (§47)
Extend existing fuzz targets (`desktop/fuzz/`) to cover:
frame parser, capability parser, object header, receipt parser, inventory
parser, lease parser, malformed length fields, decompression inputs, state
transitions, protocol negotiation. Use ASan/UBSan builds (already wired for
desktop sanitizer builds). Run each target with a time budget; zero crashes.

### Step 5.5 — §93 invariant test manifest
Convert the 20 rugged invariants into a named, runnable test suite
(`desktop/tests/invariants_test` + harness scripts). Each invariant maps to
≥1 concrete test; the suite runs as a single gate:
1. malformed peer → no unbounded allocation;
2. crash → no acknowledged-but-not-stored object;
3. replay → no duplicate app delivery;
4. restart during handoff → converges;
5. losing carrier → sender state intact;
6. expired objects don't live forever;
7. low-storage device rejects honestly;
8. malicious peer cannot forge origin;
9. carrier cannot modify encrypted payload undetected;
10. one app cannot exhaust resources;
11. idle runtime creates almost no work;
12. network changes don't change identity;
13. old/new protocol versions negotiate safely;
14. every queue bounded;
15. every retry bounded/backed off;
16. every external length validated;
17. delivery status survives process death;
18. late duplicate delivery harmless;
19. network operates without mandatory infrastructure;
20. optional infra improves without becoming trusted authority.

### Step 5.6 — Tuning with data
- Re-run Phase 7 churn baseline; adjust replication constants/lease
  durations from measured results.
- Document every constant change with its before/after measurement.

## 6. Data / schema changes
- Test-harness databases only (simulator state, chaos checkpoints); nothing
  in the production schema.

## 7. Wire protocol changes
None (harness exercises existing protocol).

## 8. Deliverables
- Simulator/churn harness under `tools/simulator/` (or extended
  `tools/harness/`).
- Device chaos scripts `tools/harness/chaos/`.
- Expanded fuzz targets.
- Invariant manifest suite `desktop/tests/invariants_test`.
- Reliability report `docs/network-os/20-reliability-report.md` + metrics
  baseline.

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Invariant manifest suite (10×):** full §93 suite green on every run.
2. **Fuzz runs (5× per target):** frame/header/receipt/inventory/lease
   parsers under ASan/UBSan — zero crashes/hangs, bounded time.
3. **Churn scenarios (5× each at 10/100/1,000 peers):** record P(delivery
   before TTL), median/P95 delivery, replica survival, bytes/object,
   wakeups/day estimates. Each scenario deterministic (fixed seed).
4. **Partition/heal (5×):** partition then heal → anti-entropy converges;
   no duplicate app delivery post-heal.
5. **Malicious peer scenarios (5×):** forged signature, replay, oversized
   lengths, storage exhaustion attempts — invariants 1, 8, 9, 16 hold.
6. **Android chaos (2 sessions × 3 runs per scenario):** kill/force-stop/
   Wi-Fi toggle/reboot/storage-fill/time-change; runtime returns to a known,
   consistent state every time.
7. **Reliability report (1×):** numbers recorded, compared to Phase 7
   baseline; constant changes documented with before/after data.
8. **Regression sweep (5×):** all prior phase suites (P1–P10) green.
9. **Native build (1×):** green (both flavors).

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-22 | invariant manifest | 10 | PASS | all 20 invariants, 56 checks, 0 failures ×10 |
| 2026-08-22 | fuzz targets | 5×target | PASS | parser_fuzz_smoke 30s×5 seeds + AE/envelope smokes; 0 crashes, 0 roundtrip fails |
| 2026-08-22 | churn 10/100/1k | 5 | PASS | P(del)=1.000 all tiers; med 30/60/90 s; gates 0 |
| 2026-08-22 | partition/heal | 5 | PASS | converge post-heal; dup=0; P(del)=1.000 |
| 2026-08-22 | malicious peers | 5 | PASS | forgeries rejected every run (inv 1/8/9/16 hold) |
| 2026-08-22 | Android chaos | 0 | SKIP | no device attached; harness ready (`tools/harness/chaos/`), release-gated on device |
| 2026-08-22 | reliability report | 1 | PASS | `docs/network-os/20-reliability-report.md` committed |
| 2026-08-22 | regression sweep | 5 | PASS | all suites ×5 rounds = 0 failures (P2–P10) |
| 2026-08-22 | native build | 1 | PASS | `externalNativeBuildMultiThreadDebug` BUILD SUCCESSFUL |
| 2026-08-22 | determinism | 2 | PASS | same seed ⇒ identical behavior (CPU-timing fields excluded) |
| 2026-08-22 | 10k scaled | 1 | PASS | hostile mix; gates hold; P(del)=0.594 in short window |

### Findings recorded during the phase (all fixed or documented)
1. Simulator last-mile fidelity: delivery at scale requires the runtime's
   actual mechanisms — push-on-destination-connect (`forwardPending`) AND
   bounded inventory propagation with destination WANT-pulls + fetch-to-carry.
   Modeled faithfully; 1,000-peer P(delivery) went 0.03 → 1.000.
2. Planner retry jitter used a non-seedable RNG — added
   `ReplicaPlanner::Config::jitter_seed` (default 0 = production behavior
   unchanged) so chaos runs are reproducible (§45 "fixed seeds").
3. `invariants_test` initially deadlocked in the TTL-sweep check by removing
   objects inside the `forEachExpired` callback — reentrancy hazard documented;
   test now collects then removes.

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Simulator diverges from real code | Run the same routing/replication policy code (master doc §45) |
| Chaos tests flaky | Fixed scenarios + seeds; flakiness is a bug |
| Constant tuning by intuition | Every change gated on measured before/after (§45) |
| Fuzz budget too small | CI gate with time budget; zero-crash policy |

## 12. Definition of Done

- [x] Reliability metrics instrumented and reported
      (`modules/networkos/metrics/ReliabilityMetrics` + simulator JSON;
      `docs/network-os/20-reliability-report.md`).
- [x] Simulator/churn harness scales to 1,000 peers (exact mode) and
      10,000 peers (scaled hot-200 carrier model); deterministic runs proven
      (same seed => byte-identical JSON).
- [x] Android chaos harness automated (`tools/harness/chaos/`, 10 scenarios +
      orchestrator); consistent-recovery proven on device when available —
      SKIP-honest without a device (see §10 log).
- [x] All parsers fuzzed; zero crashes in budgeted runs
      (`parser_fuzz_smoke` covers capability/envelope/handoff/receipt/
      inventory/want/manifest; plus libFuzzer targets and the P6 smoke).
- [x] §93 invariant manifest suite green 10×
      (`desktop/tests/invariants_test`, all 20 invariants, 56 checks).
- [x] Constants tuned with data; report committed (no constant change
      warranted by first data — see report §5).
- [x] Regression sweep green; native builds green.
- [x] Status table in `METHODOLOGY.md` updated.
- [x] Committed with message:
      `Network OS P11: simulator, chaos lab, reliability gates + invariant manifest`.

### Notes / deviations
- The reliability report lives at `docs/network-os/20-reliability-report.md`
  (`16-` is taken by Phase 10's large-object doc).
- Replica-survival sampling needs runs whose window reaches TTL/2; use
  `churn_simulator --ttl-ms` to shorten virtual TTL in short windows.
- Android chaos scenarios are adb-driven and SKIP honestly (exit 2) when no
  device is attached; they are release-gated on a device when available.

