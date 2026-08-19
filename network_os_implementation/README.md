# Mobile-First Decentralized Network OS SDK — Phase-by-Phase Implementation

This folder turns the architecture in
[`docs/network_os_mobile_first_detailed.md`](../docs/network_os_mobile_first_detailed.md)
into a **sequenced, executable, verifiable** build plan. Each phase is its own
file. You work through them **in order, one at a time**:

> **Choose one file → execute it → verify it again and again → mark it complete
> → move to the next.**

## The phases

| # | File | Goal (one sentence) | Gate |
|---|------|---------------------|------|
| 0 | [`00_phase_0_freeze_and_measure.md`](00_phase_0_freeze_and_measure.md) | Map + benchmark the current SDK before touching it. | `ARCHITECTURE_MAP.md` + baseline benchmarks reviewed |
| 1 | [`01_phase_1_core_architecture_refactor.md`](01_phase_1_core_architecture_refactor.md) | Stable core interfaces (Runtime, Transport, Identity, ObjectStore, Scheduler, PlatformAdapter). | SDK starts / persists identity / restores state / shuts down cleanly |
| 2 | [`02_phase_2_secure_session_layer.md`](02_phase_2_secure_session_layer.md) | Authenticated, bounded, reconnect-capable secure peer sessions. | Two peers hold stable PeerID across address changes |
| 3 | [`03_phase_3_durable_network_object_store.md`](03_phase_3_durable_network_object_store.md) | Generic durable NetworkObject store (transactions, TTL, quotas, dedup, crash recovery). | Object survives process death and reboot |
| 4 | [`04_phase_4_confirmed_remote_storage.md`](04_phase_4_confirmed_remote_storage.md) | Confirmed durable remote storage (OFFER/DATA/STORED_ACK) + carrier leases. | A obtains signed proof C holds X for B |
| 5 | [`05_phase_5_direct_delivery_and_receipts.md`](05_phase_5_direct_delivery_and_receipts.md) | Direct delivery + signed destination receipts + reverse receipt object. | **Milestone**: kill-process-at-every-arrow test passes |
| 6 | [`06_phase_6_anti_entropy.md`](06_phase_6_anti_entropy.md) | Inventory / WANT / batch reconciliation between connected peers. | Peers converge without blind resend |
| 7 | [`07_phase_7_adaptive_replication.md`](07_phase_7_adaptive_replication.md) | Durability targets, peer scoring, replica planner, lease repair. | Replication matches actual durability, not fixed gossip |
| 8 | [`08_phase_8_android_resource_manager.md`](08_phase_8_android_resource_manager.md) | Resource-aware scheduler on Android (foreground/charging/battery/metered). | Same protocol: aggressive when appropriate, near-sleep when idle |
| 9 | [`09_phase_9_discovery_expansion.md`](09_phase_9_discovery_expansion.md) | Modular discovery: LAN, known peers, peer exchange, optional bootstrap/rendezvous. | Discovery works with and without optional infrastructure |
| 10 | [`10_phase_10_large_object_layer.md`](10_phase_10_large_object_layer.md) | Manifests + chunks + resumable streaming for large objects. | 10 MB file transfers reliably on Wi-Fi, pauses resume |
| 11 | [`11_phase_11_simulator_and_chaos_lab.md`](11_phase_11_simulator_and_chaos_lab.md) | Deterministic simulator + chaos/fuzz/reliability lab as a release gate. | Measured P(delivery), wakeups, crash-recovery matrix green |
| 12 | [`12_phase_12_public_general_sdk.md`](12_phase_12_public_general_sdk.md) | Public general-purpose SDK: stable C ABI, JNI/Kotlin, namespaces, diagnostics, compatibility. | AARs published, api-spec updated, ChatP2P is a reference app |


## Rules of engagement

1. **One phase at a time, in order.** Phase N starts only when Phase N−1 is
   marked **COMPLETE** (its Definition of Done all checked).
2. **Every phase is verified again and again.** Run its verification suite at
   least three times; record every run in the file's *Progress Log*. A phase
   is only "done" when the verification is repeatable, not when it passed once.
3. **Reliability is measured, never assumed.** Each phase records numbers:
   test exit codes, live-peer delivery traces, memory high-water marks, wakeup
   counts, crash-recovery runs. No "effectively certain" claims without data.
4. **Process liveness is an optimization. Durable state is the source of
   truth.** (Appendix B of the plan doc.) Every subsystem must survive:
   process kill, reboot, IP change, Doze, network switch.
5. **Idle cost approaches zero.** A phase that adds periodic timers, polling,
   or background chatter must justify it and prove it with wakeup metrics.
6. **Never weaken security to save battery.** All crypto uses the engine's own
   primitives (XChaCha20-Poly1305, Noise NK). No ad-hoc crypto, ever.
7. **Bounded everything.** Every queue, table, retry, cache, and buffer gets an
   explicit bound in this phase, and a test that provokes the bound.
8. **Keep the public contract stable.** The JNI C ABI (`include/litep2p.h`)
   is the contract. Any change updates `litep2p_c_api.cpp`, `jni_bridge.cpp`,
   the Kotlin wrapper, and `docs/api-spec.md` together.

## The constitution

Before writing code, read **two files** that override everything else:

- [`METHODOLOGY.md`](METHODOLOGY.md) — **§3 Locked technical decisions**
  (13 decisions, including: TCP-first/QUIC opt-in, reuse-don't-rebuild, keep
  the singleton C ABI, serverless-first, configurable censorship-resistance,
  simulate-before-you-tune) and **§10 Cross-cutting acceptance gates**
  (A: decentralization/no-SPOF, B: lightweight, C: censorship-resistance,
  D: reliability, E: security). A phase is not done unless its applicable
  gates pass.
- The phase files themselves — each has a **Definition of Done** and a
  **Progress Log** that must be filled in and committed.

The phases were reviewed against the current C++ engine on 2026-08-20. The
review found the engine is already ~70% of the target: overlay store-and-
forward (`overlay_mailbox.h`), relay routing (`overlay_router.h`), file
transfer (`file_transfer/`), Noise NK sessions, obfuscation, telemetry, and
backpressure are all shipped. The plan therefore **reuses and hardens these
rather than rebuilding them**, and its genuinely new work is: the generic
signed NetworkObject, signed storage leases, signed receipts, anti-entropy,
adaptive replication, and capability negotiation.
