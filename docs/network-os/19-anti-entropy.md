# Network OS — Anti-Entropy Reconciliation (Phase 6)

> Master doc §12/§59/§60/§65/§82; phase file
> `network_os_implementation/06_phase_6_anti_entropy.md`.

## 1. Objective

Turn `poolDigest()` into a **core synchronization protocol**:

> Peers synchronize missing carrier objects without blindly resending
> everything.

Connection flow (§12):
`authenticate → capability negotiation → compact inventory exchange →
determine missing/needed objects → priority + policy selection → transfer only
useful objects`.

## 2. Inventory formats (§12)

- **v0 (implemented):** compact exact ID list (id + short state tag) for small
  pools. Bounded to `kMaxInventoryEntries` (2 000) — an oversized inventory is
  **rejected before allocation**.
- **v1.5 (designed, not built):** Bloom-filter summaries, keeping the WANT
  response explicit. The **`IInventorySource`** interface separates the format
  from the session flow so v1.5 can land without touching reconciliation.

## 3. Frames (§82)

- `INVENTORY` (0x3A) — sender's held-object summary, format-flagged.
- `OBJECT_WANT` (0x3B) — explicit request for specific object_ids, carrying the
  requester's dedup context (`already_held`) so the responder never re-sends
  what the requester already has.
- Both are bounded; oversized requests are rejected.

## 4. Reconciliation session (§59)

On every useful peer connection (pull-first, event-triggered on `peer_ready`,
**never from a timer**), in order:

1. authenticate (Phase 2) — established
2. negotiate capabilities (Phase 2) — established
3. **exchange inventory summaries** (this module)
4. deliver objects directly addressed to the peer (Phase 5)
5. exchange receipts (Phase 5)
6. repair high-priority replica deficits — `runRepairHook` (Phase 7 stub)
7. low-priority anti-entropy (this module)
8. close when no useful work remains

The session is **bounded** (§6.5): per-session inventory/object/byte/time caps
(`inventory_limit`, `max_objects_per_session`, `max_bytes_per_session`,
`session_deadline_ms`). Remaining work is deferred (re-WANTed on a later
session), never silently dropped.

## 5. Prioritization (§60)

The pull side WANTs non-terminal, active objects (oldest first) and treats
terminal (CONFIRMED/FAILED) ids as dedup — they are never worth pulling or
re-sending. Responder ordering follows: control → receipts → direct →
repair (stub) → background.

## 6. Idempotency & invariants

`WANT → transfer` is idempotent: receiving an already-held object is a dedup hit
(Phase 3 store), not a duplicate (invariants 3, 18). Reconnecting
mid-reconciliation converges (invariant 4); the recipient's durable store makes
this crash-safe.

## 7. Module map

- `modules/networkos/anti_entropy/` — `anti_entropy_frames.{h,cpp}` (INVENTORY /
  OBJECT_WANT codec, strict + bounded) and `AntiEntropyManager.{h,cpp}` (session
  flow, `IInventorySource`, pull computation, prioritized/bounded transfer,
  telemetry, repair stub).
- `modules/networkos/objectstore/` — `enumerateInventory` (bounded inventory
  enumeration).
- `modules/networkos/runtime/` — owns the manager (`runtime.antiEntropy()`),
  kicks sessions on `peer_ready`, routes INVENTORY/OBJECT_WANT frames.
- Tests `desktop/tests/anti_entropy_test`; inventory format spec + Bloom-filter
  design note live in the phase file (§Step 6.1).