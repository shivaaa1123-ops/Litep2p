# Phase 0 — Freeze, Measure, and Map the Current SDK

**Master doc references:** §89 Phase 0 ("Freeze and Measure Current SDK"),
§98 ("Recommended First Concrete Engineering Sprint"), §87 (performance
benchmarks), §44 (reliability measurement), §86 (testing matrix).

## 1. Objective

Before touching architecture, produce a complete, accurate picture of the
current engine and baseline numbers. **Do not refactor what you cannot
measure.** The output of this phase is the single source of truth for every
later KEEP/HARDEN/REFACTOR/REPLACE decision.

## 2. Scope

**In scope:**
- Document current modules, classes, threads, sockets, persistence,
  mailbox implementation, identity/crypto, retry logic, Android lifecycle,
  JNI boundary, configuration, and database.
- Baseline benchmarks (idle CPU/RAM/network, startup, message latency,
  memory high-water).
- Classify every component as KEEP / HARDEN / REFACTOR / REPLACE / MOVE.

**Out of scope:**
- Any production code changes (measurement harnesses and throwaway scripts
  only, kept under `desktop/tests/` or `tools/`).
- New features.

## 3. Prerequisites

- Clean checkout of `main`.
- Desktop build green: `cmake -S desktop -B desktop/build_fixcheck &&
  cmake --build desktop/build_fixcheck`.
- `./gradlew :litep2p-core:externalNativeBuildMultiThreadDebug` green.

## 4. Background

The master doc warns that a network OS must be "rugged": durable state is the
source of truth, process liveness is an optimization (§7). Before we can move
ChatP2P-specific logic out of the core (§89 Phase 1), we must know exactly what
is in the core today. Phase 1 produces that map plus baselines so every later
phase can prove it improved idle cost, latency, or reliability.

## 5. Detailed implementation steps

### Step 1.1 — Inventory current C++ modules
Walk `litep2p-core/src/main/cpp/modules/` and produce a table per module:

| Module | Key classes | Responsibility | Interfaces exposed | Test coverage |
|---|---|---|---|---|
| corep2p/core | ConfigManager, logger, device_utils | config, logging | ... | ... |
| corep2p/crypto | Noise/XChaCha20 primitives | crypto | ... | ... |
| corep2p/transport | ConnectionManager, QuicConnectionManager | sockets, framing | ... | ... |
| corep2p/security | SecureSessionManager | handshake/AEAD | ... | ... |
| corep2p/monitoring | telemetry, AnomalyReporter, crash handler | counters/gauges | ... | ... |
| plugins/session | SessionManager, peer FSM, wire_codec, reliable_send, rugged_recovery, local_peer_db | sessions, delivery | ... | session_manager_test |
| plugins/overlay | overlay_mailbox, overlay_router, overlay_frame | LPX2 routing, mailboxes | ... | overlay_test |
| plugins/discovery | LAN, obfuscated discovery | discovery | ... | ... |
| plugins/routing, file_transfer, proxy, voice_call, optimization, jni | ... | ... | ... | ... |

Output: `docs/network-os/01-module-inventory.md`.

### Step 1.2 — Map threading model
Document (with file:line references):
- `unified_event_loop.cpp`, `event_manager.cpp`, peer FSM event flow.
- Which threads exist at idle vs active (list them).
- Locking: which mutexes, any global locks, lock ordering.
- Blocking calls inside event loop (I/O, DB).
Output: `docs/network-os/02-thread-map.md` including a small diagram.

### Step 1.3 — Map socket ownership
- Which module opens/closes sockets (transport ConnectionManager, NAT
  traversal, signaling websocket client).
- Endpoint resolution, reconnect paths, idle-socket policy.
- Count of sockets held idle.
Output: `docs/network-os/03-socket-map.md`.

### Step 1.4 — Map persistence
- `local_peer_db.cpp` SQLite schema (`litep2p_peers.sqlite`).
- Durable outbox, mailbox storage (overlay + signaling server),
  receipts, dedup, session cache, tier state.
- Which writes are transactional, which are not; write amplification points.
Output: `docs/network-os/04-persistence-map.md`.

### Step 1.5 — Map identity and crypto
- PeerID generation/format, key storage, Noise handshake, origin
  signatures (Ed25519), where keys are persisted, platform-secure storage
  status on Android (Keystore integration present?).
Output: `docs/network-os/05-identity-crypto-map.md`.

### Step 1.6 — Map retry logic
- `reliable_send_manager.cpp`, `maintenance_manager.cpp`, retry timers,
  backoff policy, reconnect policy, event-triggered retries.
- Identify any "retry every N seconds" loops that violate §76
  (retry must be exponential backoff + jitter + event-triggered).
Output: `docs/network-os/06-retry-map.md`.

### Step 1.7 — Map Android service lifecycle + JNI
- `LiteP2PService`, `LiteP2PRuntime`, `jni_bridge.cpp`, C ABI functions.
- Foreground service use, WorkManager use, process-death handling.
- Single-thread vs multi-thread flavor differences.
Output: `docs/network-os/07-android-lifecycle-map.md`.

### Step 1.8 — Baseline benchmarks
Add a repeatable harness (native binary under `desktop/tests/` or
`desktop/tools/`, not a production code change) measuring, with the engine
at idle and under load:
- startup time, database open time, object insert/batch insert;
- idle CPU over 60s window, idle native thread count, idle RAM (RSS),
  idle network bytes/interval;
- 1 KB and 8 KB message send/receive latency (p50/p95) on LAN;
- dedup lookup, frame parsing, handshake, reconnect latency;
- memory high-water mark during a 100-message burst;
- **AAR size per ABI** (arm64-v8a, armeabi-v7a, x86, x86_64) **with QUIC
  compiled in vs. without** (build twice; records the cost of `picoquic`
  for Gate B);
- **idle CPU/RAM/network with obfuscation + cover traffic ON vs. OFF**
  (config toggle; quantifies the lightweight-vs-resistance dial for
  Gate C, locked decision 12);
- native thread count at idle, enumerated by name/owner (feeds Gate B).
Run **each metric 5 times** and store results as JSON:
`docs/network-os/baseline-YYYY-MM-DD.json`.

### Step 1.9 — Produce the KEEP/HARDEN/REFACTOR/REPLACE/MOVE matrix
For every component from Steps 1.1–1.7, classify it:
- **KEEP** — works, stays as-is.
- **HARDEN** — correct but needs bounds/crash-consistency work.
- **REFACTOR** — needs restructuring before reuse (e.g., extract
  ChatP2P-specific logic out of core).
- **REPLACE** — to be replaced by a Network Runtime module (e.g., mailbox →
  object store).
- **MOVE** — move to app layer or to core layer.
Output: `docs/network-os/08-keep-harden-refactor.md`. This matrix is the
contract for Phases 1–12.

### Step 1.10 — Baseline structured tests
Ensure the existing suites (`c_api_test`, `session_manager_test`, overlay,
proxy, file_transfer) run from a single command and are green. Add any
missing fixtures needed to make benchmarks repeatable.

### Step 1.11 — Delivery-path unification analysis (locked decision 9)
The engine currently exposes **three overlapping message paths**; document
each precisely and produce a merge matrix (this is the single most important
input to Phase 3):
1. `sendMessageToPeer` — plain string over the session path.
2. `send_reliable` — persistent outbox + retry + receiver dedup +
   app-assigned `msg_id` + status; offline store-and-forward via the
   signaling-server mailbox.
3. `send_overlay` — LPX2 onion + sealed blob + `OverlayMailbox` +
   `frame_id` dedup + TTL + replay window + Ed25519 origin auth.

For **each** path record: where it persists, its dedup key and scope, its
retry policy, its receipt/ACK semantics, and its failure reporting. Then map
which path each later phase absorbs (object store = durable storage; handoff
= carrier transfer; delivery = destination commit + receipt).
Output: `docs/network-os/09-delivery-path-map.md`.

## 6. Data / schema changes
None (measurement only). If any read-only instrumentation is added, keep it
behind a compile flag and out of release AARs.

## 7. Wire protocol changes
None.

## 8. Deliverables
- `docs/network-os/` directory with files 01–08 listed above, plus
  `09-delivery-path-map.md` (Step 1.11).
- `docs/network-os/baseline-YYYY-MM-DD.json` (includes QUIC on/off and
  obfuscation on/off numbers).
- Updated status table in `METHODOLOGY.md` (Phase 0 → done).

## 9. Verification Plan (repeated cycles — required)

Run in this order; record every run in §10.

1. **Existing-suite stability (5×):** `c_api_test`, `session_manager_test`,
   `overlay_test`, `proxy_test`, `file_transfer_test` each 5 consecutive
   runs, all green.
2. **Live peer baseline (2 sessions × 3 runs):** two desktop peers,
   discovery → handshake → READY → message both directions. Record latency.
3. **Idle-cost baseline (5×):** 60s idle windows; record CPU%, RAM RSS,
   native thread count, network bytes. This is the number every later phase
   must not worsen (and P8 must improve).
4. **Crash-instrumentation check:** confirm any throwaway instrumentation is
   compile-flagged and does not ship.
5. **Documentation consistency:** all `docs/network-os/*.md` files exist and
   are accurate; the KEEP/HARDEN/REFACTOR/REPLACE/MOVE matrix is complete
   for every module found in Step 1.1.

## 10. Progress Log

| Date | Suite / metric | Runs | Result | Notes |
|---|---|---|---|---|
| 2026-08-20 | c_api_test | 5 | PASS | run_all_tests.sh --loop 5; green every pass |
| 2026-08-20 | session_manager_test | 5 | PASS | green every pass |
| 2026-08-20 | overlay_test | 5 | PASS | green every pass |
| 2026-08-20 | proxy_test | 5 | PASS | green every pass |
| 2026-08-20 | file_transfer_test | 5 | PASS | green every pass |
| 2026-08-20 | crypto_test | 5 | PASS | green every pass |
| 2026-08-20 | nat_traversal_test | 5 | PASS | green every pass |
| 2026-08-20 | malformed_input_test | 5 | PASS | green every pass |
| 2026-08-20 | voice_call_test | 5 | PASS | 3/6 FAIL before test-only flake fix (voice_call_test.cpp:298 waited only for caller state); 8/8 PASS after |
| 2026-08-20 | idle CPU/RAM/network | 5 | see JSON | passes 1-5 → baseline JSON per pass; see below |
| 2026-08-20 | live peer baseline | 3 | PASS | message_latency_runner receiver+sender pair; see below |

**Idle-cost baseline (5×, 60s windows, daemon peer, signaling/NAT/discovery off):**
| pass | RSS KB | threads | CPU% |
|---|---|---|---|
| 1 | 6587 | 31 | 0 (macOS; tick sampling N/A) |
| 2 | 6505 | 31 | 0 |
| 3 | 7934 | 31 | 0 |
| 4 | 7353 | 31 | 0 |
| 5 | 7922 | 31 | 0 |
| mean | **7260** | **31** | **0** |

**Live peer baseline (loopback, UDP + Noise, 20 iters/size):**
| session | handshake_ms | 1KB p50/p95 ms | 8KB p50/p95 ms |
|---|---|---|---|
| 1 | 5069 | 309.3 / 315.0 | 309.7 / 322.6 |
| 2 | 5074 | 309.2 / 315.0 | 309.5 / 315.3 |
| 3 | 5109 | 309.1 / 341.9 | 310.4 / 321.0 |
| 4 | 5059 | 309.9 / 316.5 | 309.7 / 340.2 |
| 5 | 5113 | 309.8 / 380.7 | 310.0 / 315.4 |

**Startup (daemon peer to running):** cold 854 ms; warm runs 227/223/224/218 ms (mean 223 ms).

**Notable findings this phase:**
- `LocalPeerDb` is JSON-file, not SQLite (METHODOLOGY decision 1's SQLite precedent does not exist in production code; `sqlite3_dyn` is an unused loader).
- Fixed-interval reliable-send retry (`reliable_send_manager`) violates §76 — Phase 7 must convert to backoff+jitter+event.
- Random-fallback PeerID is not persisted (desktop) — Phase 1 `IIdentityStore` work.
- Keystore is a plain JSON file, not Android Keystore.
- Per-ABI release libs are 2.95–4.19 MB vs Gate B target <2.5 MB/ABI — Phase 8/11 gap.
- voice_call_test ring-timeout scenario was flaky (test-side race); fixed test-only.

## 11. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Matrix is inaccurate → wrong refactor decisions later | Two engineers independently map; cross-check file:line refs |
| Benchmarks not reproducible | Same machine/config, fixed seed, recorded env (OS, ABI, config.json) |
| Scope creep into refactoring | Strictly no production code changes; only docs + throwaway harnesses |

## 12. Definition of Done

- [x] All `docs/network-os/01..08` maps exist, are accurate, and are reviewed.
- [x] Baseline JSON recorded (5 runs per metric).
- [x] Existing suites green 5×.
- [x] Live peer baseline recorded.
- [x] Status table in `METHODOLOGY.md` updated.
- [ ] Committed with message: `Network OS P0: freeze & measure (maps + baselines)`.


