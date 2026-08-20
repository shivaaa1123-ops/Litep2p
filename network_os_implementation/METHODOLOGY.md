# Network OS Implementation — Methodology & Invariants

## 1. Purpose

This folder contains **one implementation plan per phase** for evolving the
LiteP2P C++ engine into a **reliable, mobile-first, decentralized Network OS
runtime** ("Network Runtime"), as described by the authoritative master doc:

- **Master reference:** `docs/network_os_mobile_first_detailed.md`
  ("the master doc", 101 sections + appendices).
- **API contract:** `docs/api-spec.md` must stay in sync with every API change.
- **Project rules:** `.clinerules/01-project-rules.md` governs builds, Maven
  publication, and repo conventions. Follow it without exception.

## 2. How to use this folder

1. Complete phases **strictly in order** (`00` → `12`). This file is the
   methodology; `README.md` is the index; each phase file has a
   `## 9. Verification Plan` and a `## 11/12. Definition of Done`.
2. **A phase is NOT complete** until its Verification Plan has passed the
   required **repeated-verification cycles** (the user demands "verified again
   and again") AND its Definition of Done is met.
3. Never start phase N+1 until phase N's exit criteria are recorded in this
   folder's status table and the code is committed.
4. Every phase must keep shipped behavior working: no regressions in existing
   `c_api_test`, `session_manager_test`, live peer messaging,
   censorship-resistance (dynamic ports, OBF1, padding, wss signaling).
5. When native code changes, the project rule requires a green
   `:litep2p-core:externalNativeBuildMultiThreadDebug` before release AARs.
   After the user approves a complete change set and all tests pass, run the
   Maven publication command (see §4 below).

## 3. Locked technical decisions (decided up front; all phases must comply)

These resolve the open questions in the master doc. Revisit only with explicit
user approval:

1. **Database — SQLite (WAL).** Already used in the repo
   (`modules/plugins/session/src/local_peer_db.cpp`, `sqlite3_dyn.cpp`).
   The Network Object Store (Phase 3) uses SQLite with WAL, crash-safe
   transactions, and batched commits. Re-benchmark before any other engine.
2. **Wire format — wrap the existing binary codec.** The repo already has a
   fuzzed binary codec (`modules/plugins/session/src/wire_codec.cpp`, fuzzed
   by `desktop/fuzz/fuzz_wire_codec.cpp`). Add a **versioned envelope** around
   it. Do not introduce a new serialization dependency (no Protobuf/
   FlatBuffers in v1).
3. **Crypto — engine primitives only.** XChaCha20-Poly1305 (bundled cipher),
   Noise NK handshake, Ed25519 origin signatures, libsodium. Never add
   ad-hoc crypto. Gate OpenSSL with `HAVE_OPENSSL` (desktop-only; Android
   compiles wss out).
4. **E2E payload encryption key model.** Per-object symmetric key, wrapped for
   each recipient with engine primitives. Storage/relay peers never see
   plaintext. Design this in Phase 3 so the envelope schema is final before
   Phase 4.
5. **Optional infrastructure = the existing signaling server.**
   `tools/signaling_server/server.py` (aliases, invites, presence, mailbox
   STORE/DELIVER, `wss://` on TLS builds) is the optional
   bootstrap/rendezvous/relay helper. The protocol must degrade gracefully
   when it is absent (Phase 9).
6. **The C ABI is the contract.** `litep2p-core/src/main/cpp/src/litep2p_c_api.cpp`
   + `include/litep2p.h` + thin `jni_bridge.cpp` + thin Kotlin wrapper.
   Changing the ABI requires updating all four plus `docs/api-spec.md`
   together.
7. **Never regress censorship resistance.** Dynamic ports, OBF1 obfuscated
   transport, length-bucketed padding, cover traffic, obfuscated discovery,
   and `wss://` signaling are shipped features; every refactor must preserve
   them (verified by capture-based tcpdump checks where relevant).
8. **TCP-first; QUIC is opt-in.** The default lightweight Android build
   compiles **TCP + UDP (NAT traversal) only**. QUIC (vendored `picoquic`,
   `QuicConnectionManager`, `real_quic_transport`) stays behind a build flag
   (e.g. `ENABLE_QUIC`), **OFF** for the default AAR. Enable only after
   Phase 0/8 measurements show network-switch handoff justifies the
   AAR-size/memory cost. Phase 0 records AAR size and idle RAM **with and
   without** QUIC.
9. **Reuse, don't rebuild.** The engine already ships and tests: overlay
   store-and-forward (`overlay_mailbox.h` — bounded entries/bytes, per-origin
   quota, TTL, LRU eviction, sealed blobs), LPX2 relay routing
   (`overlay_router.h` — stateless relays, path rotation, dedup/replay),
   Ed25519 origin auth, file transfer (`file_transfer/` — 32KB chunks,
   checkpoint resume, congestion, retransmit), Noise NK sessions, OBF1/
   padding/cover traffic, telemetry, backpressure, and reconnect modes.
   Phases must **HARDEN or EXTEND** these, never greenfield-rewrite. The
   Phase 0 KEEP/HARDEN/REFACTOR/REPLACE/MOVE matrix is the enforcement tool.
10. **Keep the process-wide singleton C ABI for v1.** `include/litep2p.h` is
    a no-handle, process-wide singleton. Do **not** introduce opaque runtime
    handles in v1 (lighter, zero API break). Defer a multi-runtime
    handle-based ABI to a future major version. This overrides any
    "opaque handles" wording elsewhere in the plan.
11. **Serverless-first.** Reliable delivery, signed receipts, and presence
    must **never require** the signaling server. Presence is derived from
    discovery + peer events + last-seen from any peer. Alias resolution has
    a peer-exchange / known-peers fallback. The signaling server
    (`tools/signaling_server/`) is an **optional accelerator**, never a
    dependency (gate: "decentralization acceptance test", §10).
12. **Configurable censorship-resistance intensity.** OBF1, padding, and
    cover traffic stay **default-ON**, but their intensity is a
    per-resource-profile dial (ECO = lighter padding / less cover; RELIABLE
    = full). The machinery is never removed — lightweight and resistance
    must coexist, and the tradeoff must be measurable (Phase 0).
13. **Simulate before you tune.** Replication/lease constants are set **only**
    from the deterministic churn simulator. The churn harness (Phase 11) is
    pulled forward into Phase 7 so tuning is never intuition-driven. Every
    constant change is recorded with its before/after measurement.

## 4. Global build & test commands

```bash
# Desktop build (primary verification environment)
cmake -S desktop -B desktop/build_fixcheck
cmake --build desktop/build_fixcheck

# Desktop test suites
desktop/build_fixcheck/bin/c_api_test
desktop/build_fixcheck/bin/session_manager_test

# Manual live peer (two nodes for discovery → handshake → READY → message)
desktop/build_fixcheck/bin/litep2p_peer_mac --no-tui --daemon --log-level info \
  --id <id> --config config.json

# Fast native-only Android compile check (required after native changes)
./gradlew :litep2p-core:externalNativeBuildMultiThreadDebug

# Release AARs + Maven local publication (only after user approval + green tests)
./gradlew :litep2p-core:assembleMultiThreadRelease :litep2p-core:assembleSingleThreadRelease \
  :litep2p-core:multiThreadReleaseSourcesJar :litep2p-core:singleThreadReleaseSourcesJar \
  :litep2p-core:dokkaJar \
  :litep2p-core:publishMultiThreadReleasePublicationToMavenLocal \
  :litep2p-core:publishSingleThreadReleasePublicationToMavenLocal

# Optional signaling server (for integration/discovery tests)
python3 tools/signaling_server/server.py
```

## 5. Global verification methodology (applies to EVERY phase)

Every phase must run these cycles and record results in its Verification Log.

### 5.1 Repeat-until-stable rule
The README floor is **at least 3 consecutive runs**; this plan's stability-
critical suites require **5 consecutive runs** (more for crash/race-prone
paths) with **all green on every run**. Flaky tests are bugs: fix them,
never "skip and move on."

### 5.2 Unit tests (desktop)
- `desktop/build_fixcheck/bin/c_api_test`
- `desktop/build_fixcheck/bin/session_manager_test`
- New phase-specific test binaries under `desktop/tests/`.

### 5.3 Live peer integration (required for every feature change)
Two (and when the phase requires it, three) desktop peers:
discovery → handshake → READY → message → receipt. Run the full scenario
**at least 3 times** per session, in at least 2 sessions on different days.

### 5.4 Crash / restart tests ("kill at every arrow")
For every protocol step (offer, data, commit, ack, callback), kill the
process at that exact point and verify recovery converges to the correct
state. Derived from master doc §99.

### 5.5 Native Android build check
`./gradlew :litep2p-core:externalNativeBuildMultiThreadDebug` must be green
after any native change before proceeding.

### 5.6 Capture-based network checks (where relevant)
Use tcpdump to verify wire-level behavior (obfuscation, dynamic ports,
padding). Unit tests cannot see the wire.

### 5.7 Bounds & resource checks
Every phase must re-check the bounded-everything principle (master doc §3.5):
queues, caches, tables, retries, timers, allocations all have explicit bounds.

### 5.8 Verification Log
Each phase file contains a `## 10. Progress Log` section. Fill the table
with run date, suite, result, and notes. Commit the log with the phase code.

## 6. Cross-phase rugged invariants (master doc §93)

These invariants must hold at every phase boundary. Phases that first assert
each invariant are noted in brackets.

1. A malformed peer cannot cause unbounded allocation. [P3, P6, P11]
2. A process crash cannot create an acknowledged-but-not-stored object. [P3, P4]
3. Replaying a frame cannot duplicate application delivery. [P3, P5, P6]
4. Restarting during handoff converges to the correct state. [P3, P4, P5]
5. Losing a carrier does not corrupt the sender's state. [P4, P7]
6. Expired objects do not live forever because of gossip. [P3, P6, P7]
7. A low-storage device can reject storage honestly. [P4, P8]
8. A malicious peer cannot forge the origin. [P3, P4]
9. A carrier cannot modify encrypted application payload undetected. [P3, P4]
10. One application cannot exhaust all SDK resources. [P3, P8]
11. Idle runtime creates almost no work. [P1, P2, P8]
12. Network changes do not change peer identity. [P1, P2, P9]
13. Old and new protocol versions negotiate safely. [P2, P6, P12]
14. Every queue is bounded. [P1–P10]
15. Every retry is bounded/backed off. [P7]
16. Every externally supplied length is validated. [P3, P11]
17. Delivery status survives process death. [P4, P5]
18. Late duplicate delivery is harmless. [P5, P6]
19. The network can operate without mandatory infrastructure. [P9]
20. Optional infrastructure can improve reliability without becoming a
    trusted central authority. [P9]

## 7. Phase dependency graph

```
P0 Freeze & Measure ──▶ P1 Core Refactor ──▶ P2 Secure Session Layer
      └────────────────────────────────────────────┴──▶ P3 Object Store
                                                            └──▶ P4 Remote Storage
                                                                  └──▶ P5 Delivery+Receipts
                                                                         ├──▶ P6 Anti-Entropy
                                                                         └──▶ P7 Replication
                                                                               ├──▶ P8 Resource Mgr
                                                                               └──▶ P9 Discovery
                                                                                     ├──▶ P10 Large Objects
                                                                                     └──▶ P11 Simulator/Chaos
                                                                                           └──▶ P12 Public SDK
```

P8 (Android resource manager) overlaps P7 in practice; a minimal
`ResourceManager` stub is pulled forward into P4/P5 per the review.

## 8. Status tracking

Update after each phase is approved and committed:

- [x] Phase 0 — Freeze & Measure (`00_phase_0_freeze_and_measure.md`) — **COMPLETE** (commit `be2b084`; maps `docs/network-os/01..09` + `baseline-2026-08-20.json`; 5× suites green; live-peer + idle baselines recorded in §10)
- [x] Phase 1 — Core Runtime Refactor (`01_phase_1_core_architecture_refactor.md`) — **COMPLETE** (commit `55d6adc`; `modules/networkos/` skeleton + `NetworkRuntime` lifecycle + `FileIdentityStore` + scheduler + platform adapters; 100× restart + 20× SIGKILL + C ABI diff empty + 5× suites green + native build green)
- [x] Phase 2 — Secure Session Layer (`02_phase_2_secure_session_layer.md`) — **COMPLETE** (commits `9ef55fa` + audit fixes `2438a4e`; capability negotiation on CONTROL_CONNECT, SessionFacade bounds/timeouts/telemetry, multiplexing contract, stable-PeerID tests; 148-check suite + 5× suites green + live peers + network-switch test + native build)
- [ ] Phase 3 — Durable Network Object Store (`03_phase_3_durable_network_object_store.md`)
- [x] Phase 3 — Durable Network Object Store (`03_phase_3_durable_network_object_store.md`) — **COMPLETE** (commit `019c40b`; `object/` ObjectID + signed immutable/mutable envelope + E2E key model, `objectstore/` SQLite/WAL store (transactions, hierarchical quotas, TTL, dedup-before-work, score eviction, crash-safe open, forward-migration guard), runtime owns store at `files_dir/networkos.sqlite`; envelope 131 checks × 10, store 43 checks × 10, SIGKILL harness 10/10, 13 suites × 5 = 0 failures, native build green, C ABI 56 functions identical, fuzz 60s no crash)
- [ ] Phase 4 — Confirmed Remote Storage (`04_phase_4_confirmed_remote_storage.md`)
- [ ] Phase 5 — Direct Delivery + Receipts (`05_phase_5_direct_delivery_and_receipts.md`)
- [ ] Phase 6 — Anti-Entropy (`06_phase_6_anti_entropy.md`)
- [ ] Phase 7 — Adaptive Replication (`07_phase_7_adaptive_replication.md`)
- [ ] Phase 8 — Android Resource Manager (`08_phase_8_android_resource_manager.md`)
- [ ] Phase 9 — Discovery Expansion (`09_phase_9_discovery_expansion.md`)
- [ ] Phase 10 — Large Object Layer (`10_phase_10_large_object_layer.md`)
- [ ] Phase 11 — Simulator & Chaos Gates (`11_phase_11_simulator_and_chaos_lab.md`)
- [ ] Phase 12 — Public SDK & Compatibility (`12_phase_12_public_general_sdk.md`)

## 9. Definition of a completed phase (summary)

A phase is done when ALL of the following are true:
1. All steps in the phase file are implemented and committed.
2. The Verification Plan ran its required repetition cycles, all green.
3. The Progress Log (## 10 in each file) is filled in and committed.
4. No regression in existing suites or live-peer scenarios.
5. `:litep2p-core:externalNativeBuildMultiThreadDebug` green (native changes).
6. Status table above updated; next phase may begin only after user approval.
7. All applicable acceptance gates (§10) pass.

## 10. Cross-cutting acceptance gates (permanent, measured every release)

These are the "constitution" gates that every phase — and every future
release — must keep green. Each gate has a **measurable** criterion; no
"effectively certain" without data.

### Gate A — Decentralization acceptance test (no single point of failure)
Run the full three-node §99 scenario (Phase 5) and assert the system
continues to work with each optional component killed, **one at a time and
in combination**:
1. Kill the signaling server → delivery, receipts, and presence still work
   within the connected component (LAN + known peers + peer exchange).
2. Kill every relay/carrier mid-transfer → senders are not corrupted and
   replicas repair once peers return (Phase 7).
3. Kill the "home server" HA peer → the network degrades but does not stop;
   phones still exchange directly.
4. Assert: **no single process or host is on the critical path** of
   delivery, receipt, or presence. This is the definition of "no SPOF."
**Criterion:** all sub-scenarios green 5× (Phases 5, 7, 9, 11).

### Gate B — Lightweight acceptance test (mobile-first)
Targets (validate in Phase 0, enforce from Phase 1 onward; final numbers
locked by Phase 11 with measured data):
- Idle native RSS: **< 15 MB** (single-thread flavor) / **< 25 MB**
  (multi-thread), no pending work.
- Idle CPU: **< 0.5%** averaged over a 60 s window.
- Idle network: **0 bytes** periodic chatter (no timers, no gossip, no
  polling).
- Periodic wakeups while idle: **0**.
- AAR size: **< 2.5 MB per ABI** for the default TCP-only build; QUIC is
  NOT in the default build.
- Active native threads at idle: minimal (bounded, enumerated in Phase 0).
**Criterion:** measured in Phase 0 (baseline) and Phase 8/11 (assert
non-regression + meet target). Any feature that violates a target must be
rejected or reworked — there is no "temporary" budget breach.

### Gate C — Censorship-resistance acceptance test
- OBF1 obfuscated transport, dynamic ports, length-bucketed padding, cover
  traffic, and `wss://` signaling remain default-ON in the stock config.
- tcpdump capture proves: (1) no plaintext PeerID/alias on the wire, (2)
  frame sizes fall into a small bucket set (padding active), (3) ports are
  dynamic.
- ECO profile may reduce padding/cover intensity but never disables the
  machinery.
**Criterion:** capture-based checks green after every transport/discovery
change (Phases 2, 9, 12).

### Gate D — Reliability acceptance test (the "world's most reliable" bar)
- The 20 rugged invariants (§6) hold — enforced by the §93 manifest suite
  (Phase 11), green 10×.
- §99 kill-process-at-every-arrow scenario green 10× (Phase 5) and re-run
  after every later phase.
- Measured reliability numbers (Phase 11): `P(delivery before TTL)`,
  `P(receipt returned)`, median/P95 delivery time, replica survival,
  bytes/object, wakeups/day, CPU ms/object — all recorded, trended, and
  used to tune constants (never intuition).
**Criterion:** manifest suite + chaos runs green; constants documented with
before/after data.

### Gate E — Security acceptance test
- Origin forgery impossible (Ed25519), payload tamper detected
  (XChaCha20-Poly1305 AEAD), replay rejected, storage peers cannot read
  plaintext (E2E key model), authorization separate from authentication.
- Fuzz: every parser (frame, envelope, header, receipt, inventory, lease,
  capability, decompression) zero crashes under ASan/UBSan in budgeted runs.
**Criterion:** security tests + fuzz gates green every release.


