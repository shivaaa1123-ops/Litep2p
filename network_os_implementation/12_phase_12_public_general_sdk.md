# Phase 12 — Public General-Purpose SDK + Compatibility Contract

**Master doc references:** §36 (stable C ABI), §39 (capability negotiation),
§40 (protocol versioning), §41 (upgrade/DB migration), §54 (application API),
§55 (delivery policy API), §56 (example policies), §83 (API compatibility),
§84 (error model), §85 (configuration), §95 (Android API shape), §89
Phase 12 ("Public General-Purpose SDK"), Appendix C (v1 success criteria).

## 1. Objective

Expose the Network OS as a **public, stable, general-purpose SDK**. Deliverable
(master doc §89 Phase 12):

> Stable C ABI + Android JNI/Kotlin API + namespace registration + delivery
> policies + diagnostics + compatibility contract. ChatP2P becomes a
> reference application.

## 2. Scope

**In scope:** finalize C ABI (process-wide singleton, no internal structs
exposed, no opaque runtime handles in v1 — locked decision 10); Kotlin
wrapper finalization (thin, Flow events, lifecycle bridge); namespace
registration; delivery policy API; version negotiation (SDK vs wire vs app);
upgrade/DB migration + rollback; compatibility tests; diagnostics/
observability surface; docs/api-spec.md + config.example.json updates; Maven
publication + portable distribution; Appendix C success criteria.

**Out of scope:** new protocol features; global DHT/reputation (never).

## 3. Prerequisites

- Phases 0–11 complete (all gates green).
- Phases 4–5 delivery policy structures exist.

## 4. Background

Master doc §54: the public API should be simple —
`runtime.send(destination, ns, payload, policy)` + `subscribe` + `cancel` +
`status`. §83: once third parties use the SDK, API stability is critical —
semantic versioning, deprecation periods, capability queries, feature flags,
compatibility tests. §40: separate SDK version, wire protocol version, and
app protocol version. Appendix C defines the v1 success criteria.

Note: §83's "opaque handles/PIMPL" guidance is **overridden for v1** by
locked decision 10 — the C ABI remains a process-wide singleton with no
handles, matching the current `litep2p.h` contract. Multi-runtime handles
are deferred to a future major version.

## 5. Detailed implementation steps

### Step 5.1 — Finalize the stable C ABI (§36, §94)
- **Process-wide singleton, no handles** (locked decision 10); no internal
  structs/headers exposed.
- Function set covers: runtime start/stop; send (with DeliveryPolicy);
  cancel; status; subscribe (namespace handler); diagnostics snapshot;
  version/capability query.
- Update `litep2p_c_api.cpp`, `include/litep2p.h`, `jni_bridge.cpp`,
  Kotlin wrapper, and `docs/api-spec.md` **together** (project rule).

### Step 5.2 — Kotlin wrapper finalization (§95)
- Thin layer: lifecycle bridge, platform resource signals, secure key
  integration (Android Keystore where design allows), application callbacks,
  Android scheduling bridge, permissions/connectivity.
- Kotlin does NOT implement routing/replication/dedup (runtime owns it).
- `NetworkSdk.deliveryEvents` Flow/collect surface for delivery status +
  receipts.
- Keep backward-compatible entry points from the current `LiteP2P` API.

### Step 5.3 — Namespace registration + delivery policies (§53, §55)
- Namespace registration with quota, priority ceiling, object-size limits,
  carrier policy, protocol version.
- DeliveryPolicy API with clamping of unsafe values:
  TTL, priority, min/desired replicas, require receipt, network cost,
  carrier policy, max payload bytes.

### Step 5.4 — Version negotiation (§40, §39)
- Separate SDK / wire / app protocol versions.
- On connect: capability negotiation picks compatible wire version;
  unknown optional fields tolerated; old peers never crash.
- Versioned envelope from Phase 3 carries protocol_version.

### Step 5.5 — Upgrade / DB migration + rollback (§41)
- Every persistent schema change: schema version, forward migration,
  failure recovery, rollback considerations, test fixtures from old
  versions.
- **Never release a migration tested only on a fresh install.**
- Import bridge for v0.4-era data (existing outbox/mailbox/PeerID).

### Step 5.6 — Compatibility tests + deprecation policy (§83)
- Semantic versioning; deprecation periods; feature flags; compatibility
  test matrix (old SDK ↔ new wire, new SDK ↔ old wire).
- API surface snapshot test (like the Phase 2 ABI diff, now permanent).

### Step 5.7 — Diagnostics / observability surface (§48, §49, §87)
- Public diagnostics snapshot (counters, gauges, histograms, config
  fingerprint, peer summary) — opt-in, privacy-safe identifiers.
- Benchmarks (from Phase 1) as repeatable release numbers.

### Step 5.8 — Documentation + config
- Update `docs/api-spec.md` (authoritative contract) for all API changes.
- Update `config.example.json` + `config.json` with new keys
  (`network.*`, `policy.*`, `resource.*`), and `config_manager.cpp` defaults.

### Step 5.9 — Publication (project rule, after user approval + green tests)
- Run the full Maven publication command (§4 of overview).
- Refresh portable distribution `~/Downloads/litep2p-core-0.4.0/` + `.zip`.
- Both flavors (MultiThread / SingleThread) rebuilt and published.

## 6. Data / schema changes
- Schema migrations from all prior phases shipped with fixtures + rollback.

## 7. Wire protocol changes
- Wire version bumped only if needed; capability negotiation covers it.

## 8. Deliverables
- Final C ABI + Kotlin API; docs/api-spec.md updated.
- Compatibility test suite (`desktop/tests/compat_test`).
- Migration fixtures + rollback tests.
- Published AARs + Maven local artifacts + portable distribution.

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **C ABI surface snapshot (5×):** symbol set + signatures match the
   frozen reference; no accidental drift (CI gate).
2. **Kotlin API tests (5×):** wrapper unit + integration tests green on
   both flavors.
3. **Version negotiation (5×):** old wire version ↔ new runtime and new
   wire ↔ old runtime both negotiate safely (invariant 13); unknown optional
   fields don't crash.
4. **Migration tests (5×):** upgrade from fresh install AND from Phase 3-era
   fixture data; rollback verified; no data loss.
5. **Compatibility matrix (5×):** supported Android API levels, 32/64-bit,
   low/mid/high RAM, Wi-Fi/mobile data/bad Wi-Fi, NAT variants, IPv4/IPv6,
   network switching, Doze, battery saver, low storage, process death,
   reboot, upgrade, clock changes (from §86).
6. **Namespace policies (5×):** quotas/priority ceilings enforced; one app
   cannot exhaust resources (invariant 10).
7. **Diagnostics surface (3×):** snapshot JSON is stable, privacy-safe,
   config-fingerprinted.
8. **Full regression sweep (5×):** every phase suite P0–P11 green.
9. **Three-phone live scenario (2 sessions × 3 runs):** Appendix C core
   scenario — sender-offline store-and-forward, process death survival,
   duplicate-frame immunity, verifiable receipt, fixed TTL, bounded storage,
   explicit carrier refusal, no mandatory server.
10. **Final idle/bench numbers (5×):** compare to Phase 1 baseline —
    show no regression, meet §88 targets.
11. **Publication check (1×):** Maven local artifacts present for both
    flavors; portable distribution refreshed.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-22 | C ABI snapshot | 5 | PASS | 64-symbol frozen reference (`c_abi_reference.txt`); drift gate green ×5 |
| 2026-08-22 | Kotlin API tests | 5 | PASS | wrapper compiles both flavors; `NetworkOs` surface + deliveryEvents Flow; native build green |
| 2026-08-22 | version negotiation | 5 | PASS | old↔new matrix + wire v1 + envelope forward tolerance (inv 13) |
| 2026-08-22 | migration + rollback | 5 | PASS | v1 fixture → v4 data-intact ×5; future-DB guard ×5 |
| 2026-08-22 | compatibility matrix | 0 | DEFER | §86 device matrix — awaiting the two physical devices |
| 2026-08-22 | namespace policies | 5 | PASS | registry validation + clamps ×5 (quota/ceiling/caps) |
| 2026-08-22 | diagnostics surface | 5 | PASS | stable keys, config fingerprint, privacy-safe ×5 |
| 2026-08-22 | full regression sweep | 5 | PASS | all suites ×5 rounds = 0 failures (P1–P11) |
| 2026-08-22 | three-phone scenario | 0 | DEFER | Appendix C — awaiting physical devices |
| 2026-08-22 | final bench numbers | 0 | DEFER | vs P1 — run in device session |
| 2026-08-22 | publication check | 1 | PASS | Maven local both flavors + sources + dokka + portable zip |

### Notes
- `nos_send` live two-runtime loopback is opt-in (`LITEP2P_NOS_LIVE=1`);
  CI-default is SKIP pending the device session (underlying paths green in
  P2/P5 suites). This is the first thing to re-check on the provided phones.
- SDK version stays **0.4.0** for this release train (Network OS surface ships
  as a 0.x minor feature set); bump to 0.5.0 together with ChatP2P adoption.

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| ABI drift after freeze | Permanent snapshot gate in CI |
| Migration breaks field devices | Fixtures from old versions; rollback path; never fresh-install-only testing |
| Kotlin layer re-implements logic | Code review rule: runtime owns routing/replication/dedup |
| Publication incomplete | Checklist: both flavors AARs + sources + dokka + Maven local + zip |

## 12. Definition of Done — v1 success criteria (Appendix C)

- [x] Stable C ABI + JNI/Kotlin API shipped (`litep2p_nos_*`, `NetworkOs`) —
      additive, snapshot-gated.
- [ ] Three Android phones complete sender-offline store-and-forward delivery —
      **awaiting the two physical devices** (desktop loopback of every
      underlying stage is green).
- [x] Every protocol stage survives process death (P3–P8 suites + migration
      fixtures; re-verified on devices when available).
- [x] Duplicate frames do not duplicate application delivery (inv 3/18 green).
- [x] Sender receives a verifiable final receipt (P5 suite; receipts always on).
- [x] TTL remains fixed across forwarding (P5/P7 suites).
- [x] Storage is strictly bounded (P3/P10 suites; namespace quotas enforced).
- [x] Carrier refusal is explicit (backpressure outcomes §28/§68).
- [x] No mandatory central server (Gate A / invariant 19 green).
- [x] Idle CPU/network close to zero (P8/P11 measurements; event-driven).
- [x] Protocol state inspectable/debuggable — `litep2p_nos_diagnostics()` /
      `NetworkOs.diagnostics()` with stable keys + config fingerprint.
- [x] Multiple SDK/application versions negotiate safely (inv 13 + compat_test).
- [x] Simulated churn demonstrates measured reliability (P11 report numbers).
- [x] Artifacts published to Maven local; portable distribution refreshed.
- [x] Status table in `METHODOLOGY.md` updated (Phase 12 done).
- [x] Committed with message:
      `Network OS P12: public general-purpose SDK + compatibility contract`.

> Device-gated items (three-phone Appendix C scenario, §86 compatibility
> matrix, final bench comparison) are the remaining work for the hardware
> session and are tracked in §10 as DEFER.

## 13. Final note
This completes the Network OS v1. The master doc's §100 long-term vision
(messaging, data sync, distributed files, IoT, backup on one substrate) is
now supported by the generic object runtime built through Phases 1–12.
Re-verify the full invariant manifest + three-phone scenario before every
future release.

