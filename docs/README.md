# LiteP2P Documentation Index

Start here. This page tells you which document to read for which job, and
which documents are **for SDK consumers** versus **internal engineering
records**.

## I want to build an app on the SDK

| Read | What it covers |
|---|---|
| [**api-spec.md**](api-spec.md) | **THE integration reference.** Quickstart (Gradle setup, first messages), full C ABI + Kotlin API reference, messaging/reliability model, telemetry schema, `config.json` reference, threading & lifecycle contracts, worked examples, error codes, and the Network OS object runtime (§16). |
| [censorship-resistance.md](censorship-resistance.md) | The overlay (LPX2) layer: OBF1 obfuscation, padding, cover traffic, PEX, origin authentication — defaults, opt-outs, and interop guarantees. |
| [desktop-peer.md](desktop-peer.md) | Building and running the desktop CLI peer (`litep2p_peer`) to test your Android app against a real second node. |

Recommended reading order for a new integrator:
`api-spec.md §1–§2` → build & run the harness →
`api-spec.md §5–§6` (Kotlin API + messaging model) →
`§9` (`config.json`) → `§11` (threading/lifecycle) → `§13–§14` (recipes).

## Internal engineering records (not part of the SDK contract)

These are historical design/implementation maps of the Network OS work
(Phases 0–12). They explain *why the engine is built the way it is*; they do
**not** describe the public API and may drift from it. The numbers are record
identifiers assigned as the work progressed, so they reflect implementation
order only loosely — use the table below, not the file number, to find a
topic.

| File | Topic |
|---|---|
| `network-os/01-module-inventory.md` | Baseline inventory of every C++ module |
| `network-os/02-thread-map.md` | Engine thread inventory |
| `network-os/03-socket-map.md` | Socket/port inventory |
| `network-os/04-persistence-map.md` | On-disk artifacts map |
| `network-os/05-identity-crypto-map.md` | Identity + crypto material map |
| `network-os/06-retry-map.md` | Retry/backoff paths |
| `network-os/07-android-lifecycle-map.md` | Android lifecycle integration points |
| `network-os/08-keep-harden-refactor.md` | Phase 1 KEEP/HARDEN/REFACTOR decisions |
| `network-os/09-delivery-path-map.md` | End-to-end delivery path baseline |
| `network-os/10-runtime-skeleton.md` | Network OS runtime skeleton |
| `network-os/11-e2e-key-model.md` | End-to-end key model |
| `network-os/18-delivery-receipts.md` | Direct delivery + signed receipts (Phase 5) |
| `network-os/12-handoff-protocol.md` | Two-phase durable carrier handoff (Phase 4) |
| `network-os/19-anti-entropy.md` | Inventory/WANT reconciliation (Phase 6) |
| `network-os/13-replication.md` | Adaptive replication planner (Phase 7) |
| `network-os/14-resource-manager.md` | Resource/energy budget manager (Phase 8) |
| `network-os/15-discovery.md` | NOS discovery manager (Phase 9) |
| `network-os/16-large-objects.md` | Chunked large-object layer (Phase 10) |
| `network-os/17-secure-sessions.md` | Session bounds & security contracts |
| `network-os/20-reliability-report.md` | Simulator/chaos-lab reliability report (Phase 11) |
| `network_os_mobile_first_detailed.md` | The master architecture doc (§-numbered; referenced by code comments as "master doc §NN") |
| `IMPLEMENTATION_TEMPLATES.md` | Engineering templates used during implementation |

Per-phase implementation records live in [`network_os_implementation/`](../network_os_implementation/)
(`METHODOLOGY.md` is the index). The frozen ABI symbol set is snapshotted at
[`desktop/tests/c_abi_reference.txt`](../desktop/tests/c_abi_reference.txt).

## Operational notes

- The **signaling server** (`tools/signaling_server/server.py`) is required
  for WAN discovery, alias/presence, and offline mailboxes. Its runtime knobs
  are documented in its source header; deployment hardening (TLS/wss://) is
  planned as a dedicated operations document.
