# Sensor Registered — Market Strategy & Implementation Plan

> Note: file name as requested by the project owner. This document is the
> working plan for positioning this engine in a distinct market segment.

**Date:** August 16, 2026
**Purpose:** Single actionable plan the project owner works through phase by
phase to claim a distinct market segment for this engine.
**Companion docs:** `future development roadmap or plan.md` (technical
roadmap), `removeCentralizedSignaling.md` (discovery decentralization),
`docs/api-spec.md` (public API contract for integrators), `PACKAGING.md`
(F-Droid / reproducible distribution).

---

## 1. The Name Collision — Fix First, This Is Mandatory

The engine is currently named **LiteP2P**. An established, production-funded
project already owns that name:

- **`paritytech/litep2p`** — Rust crate (MIT, ~161★, 1,233 commits), maintained
  by **Parity Technologies** (the Polkadot core team).
- libp2p-compatible networking library: transports **TCP, QUIC, WebRTC,
  WebSocket**; protocols **Kademlia DHT, Identify, Ping, Bitswap, mDNS,
  request-response**; built on `tokio` async Rust.
- Runs in production inside **Polkadot/Substrate** nodes.

Anyone searching "LiteP2P" finds Parity's crate, not this engine. A distinct
name is **step zero** of claiming a distinct segment.

### Suggested names (choose one)

| Name | Fit |
|---|---|
| **SableNet** | Neutral, suggests resilience |
| **OverMesh** | Highlights the overlay/mesh capability |
| **MeshForge** | Build-y, developer-friendly |
| **RelayFree** | Communicates censorship resistance |
| **CommsMesh** | Direct about the use case |
| **Pyre** | Short, activist-friendly, memorable |
| **Backbone** | Infrastructure feel |

### Rename checklist (do while codebase is small)

- [ ] Pick final name (check trademark + crates.io/npm/Maven for collisions)
- [ ] Rename repo directory + GitHub org/repo name
- [ ] Update `litep2p.h` (header guard, function prefixes `litep2p_*`)
- [ ] Update Kotlin package `com.zeengal.litep2p` and `LiteP2P` singleton
- [ ] Update CMake project names (`project(litep2p ...)`, targets
  `litep2p_engine`, `litep2p_corep2p`, module targets)
- [ ] Update ABI version string (`LITEP2P_VERSION_*`)
- [ ] Update Android applicationId / service class names
- [ ] Update docs (`docs/api-spec.md`, `documentation/api-spec.md`,
  `future development roadmap or plan.md`, `removeCentralizedSignaling.md`)
- [ ] Update `config.json` references, scripts (`run.sh`, test scripts),
  CI workflow names

---

## 2. Honest Capability Map (Where This Engine Stands)

| Capability | **This engine** (C++/Android) | **paritytech/litep2p** (Rust) | **rust-libp2p** | **Tor + pluggable transports** | **Session / Briar** |
|---|---|---|---|---|---|
| Target platform | **Mobile-first** (Android NDK) + macOS/Linux | Server/desktop | Server/desktop | Desktop/mobile apps (Tor) | End-user apps |
| Embeddable SDK | ✅ Kotlin/JNI now, iOS planned | Rust (tokio) only | Rust + FFI bindings | No (it's a network, not an SDK) | No (closed apps) |
| Transports | UDP, TCP, **real QUIC** (picoquic), **OBF1 obfuscated** (Phase B) | TCP, QUIC, WebRTC, WS | TCP, QUIC, WS, WebRTC | TCP, obfs4, etc. | UDP (Session), Tor (Briar) |
| NAT traversal | **STUN + multi-thread hole punch + UPnP + TURN + signaling** | Kademlia/DCUtR-ish | DCUtR, relay v2, AutoNAT | Built-in | Weak / Tor |
| **Mobile battery/lifecycle** | ✅ Foreground service, locks, watchdog, battery-aware reconnect | ❌ not designed for it | ❌ | ❌ | Partial |
| Censorship resistance | ✅ **Onion-lite overlay + OBF1 + cover traffic + mailboxes + origin auth (Phase B)** | ❌ not a goal | ❌ not a goal | ✅ the gold standard | ✅ but app-level |
| Offline delivery (mailboxes) | ✅ Store-and-forward sealed mailboxes | ❌ | ❌ | ❌ | Partial |
| Anonymity | 🔶 Layer-encrypted multi-hop + cover traffic; **full onion/obfs4 pending** | ❌ | ❌ | ✅ Full onion | Partial |
| Ecosystem lock-in | None (self-contained) | Polkadot/libp2p | libp2p/IPFS | Tor | Own networks |
| Maturity | v0.3, **no external audit yet** | Production in Polkadot | Battle-tested | Decades | Years |

**Bottom line:** this engine is NOT competing with Parity's litep2p or libp2p.
They build server-side infrastructure for the Web3 ecosystem. Nobody has built
what this engine is: an embeddable, mobile-first, censorship-resilient P2P
messaging substrate.

---

## 3. Market Map — Who Owns What

| Segment | Owned by | This engine's chance |
|---|---|---|
| Web3 node networking (Polkadot/IPFS/Filecoin) | paritytech/litep2p, rust-libp2p | ❌ Don't fight this |
| General developer infrastructure | libp2p | ❌ Same reason |
| **Censorship-resistant mobile messaging SDK** | **Nobody. This is the gap.** | ✅ **Claim this.** |
| End-user censorship apps | Session, Briar, Tox, Ricochet, Signal (centralized) | ⚠️ Don't compete at app level — **become their substrate** |

The gap is structurally defensible: Tor solves censorship but is not an SDK;
Session solves censorship but is a closed app with its own Rust network; Briar
is Tor-over-Bluetooth niche; libp2p ignores censorship entirely. This engine
already has mobile hardening (NAT, battery, lifecycle) and the onion-lite
overlay + mailboxes. The moat is ours to claim.

---

## 4. The Segment to Claim

> **"The embeddable, mobile-first, censorship-resilient P2P communications
> engine"** — an SDK that lets any app developer build chat, media,
> marketplace, or wallet apps that (a) work on phones behind aggressive NATs,
> (b) survive censorship — including DPI, port blocking, and network
> shutdowns — and (c) deliver messages even when peers are offline.

### Two revenue tracks that don't conflict

| Track | Audience | How it works |
|---|---|---|
| **Public / freedom track** | Protesters, free media, journalists, activists | Free, open-source engine; adoption + community + trust |
| **Private / enterprise track** | NGOs, journalist networks, humanitarian field teams, regulated industries that cannot use public chains (defense, banking consortia, sovereign entities) | Commercial license + SLA + hosted bootstrap relay/STUN infrastructure + white-label; these customers pay for support and compliance |

---

## 5. Improvement Phases — Work Through One By One

### Phase A — Claim the identity (2–4 weeks)

| # | Task | Notes |
|---|---|---|
| A1 | **Rename the engine** (see §1) | Mandatory — cannot be "LiteP2P" |
| A2 | Publish the C ABI spec + roadmap publicly | `docs/api-spec.md` is the contract |
| A3 | Rename the repository | Do while the codebase is small |
| A4 | Check trademarks + package registry collisions (Maven, crates.io, npm, SwiftPM) | Before committing to a name |

### Phase B — Close the censorship-resistance gaps (the moat, 2–3 months)

These are the features the target user (protesters, free media) cannot live
without, and no competing SDK has them:

| # | Task | Status in technical roadmap |
|---|---|---|
| B1 | **Pluggable transports** (obfs4-style / Shadowsocks-style / WebSocket-over-CDN domain fronting) — defeats DPI and port blocking. **#1 missing capability.** Tor has it; no mobile P2P SDK does. | ✅ **DONE 2026-08-16** — OBF1 obfuscated transport (XChaCha20-Poly1305 over X25519, length-bucketed). DPI hides the LPX2 magic + uniform sizes. Tested 162/162. Next: obfs4-style KDF + WebSocket-over-CDN variants. |
| B2 | **Encrypted-DNS bootstrap** (DoH/DoT) so discovery survives DNS censorship | 🔶 **Hook designed** — `overlay.doh_url` reserved; native impl needs a TLS client (Android `DnsResolver` DoH via JNI, or picotls). See `PACKAGING.md`. |
| B3 | **Cover traffic / traffic padding** — metadata resistance for the onion-lite overlay | ✅ **DONE 2026-08-16** — `padding_bucket` (LPX2 v2 pad field) + idle `Cover` frames (`cover_interval_ms`). |
| B4 | **Origin authentication** — Ed25519 signing | ✅ **DONE 2026-08-16** — signing keypair persisted in NoiseKeyStore; payloads + ACKs signed; registered-key identity binding; `overlay_register_peer_signing_key()`. |
| B5 | **DHT relay discovery** — removes the signaling SPOF entirely | 🔶 **Stage 1 DONE 2026-08-16** — Relay PEX (advert→PEX response + periodic). Full DHT still roadmap 2.1 + `removeCentralizedSignaling.md`. |
| B6 | **Sideload-friendly packaging**: reproducible APK builds, F-Droid distribution, no Play-Store dependency | 🔶 **Started 2026-08-16** — reproducible archives on; zero Play Services deps verified; checklist in `PACKAGING.md`. |

### Phase C — Developer experience (the adoption engine, 2–3 months)

| # | Task | Notes |
|---|---|---|
| C1 | **Kotlin API parity** — expose `sendOverlay`, `pickupMailbox`, `overlayRegisterRelay`, `overlayRegisterPeerSigningKey` through JNI | ✅ **DONE 2026-08-16** — full C ABI (§3.14) + JNI + Kotlin surface landed; `on_overlay_delivery` listener; `c_api_test` overlay suite; verified Kotlin compiles. |
| C2 | **iOS port** (roadmap 3.1) — Swift package over the same C ABI | Losing iOS = losing half the activist market |
| C3 | **Publish artifacts**: AAR → Maven Central; SwiftPM; Conan/vcpkg for C++ | roadmap 3.2 |
| C4 | **Reference chat app** (open source, on top of the existing Android app) + docs site + protocol spec | This is what makes developers adopt instead of rolling their own |
| C5 | **Showcase media/file transfer flows** | File transfer already exists — surface it |

### Phase D — Trust (what actually wins this market)

| # | Task | Notes |
|---|---|---|
| D1 | **External security audit** before marketing to protesters | "Audited" is a purchase criterion in this segment |
| D2 | **Open source under a protective license** — AGPL-3.0 (or MIT + separate patent grant) | Protesters will not adopt a black box |
| D3 | Android 13+ FGS compliance (`dataSync` type, permissions) + battery profiling with a published mA/hr budget | Already partially done in `LiteP2PService.kt` |
| D4 | **Public "censorship-resistance test report"** from the SG/US soak runners | Turn the CI stress infrastructure into marketing evidence |

---

## 6. Rough Timeline to Market-Ready

| Milestone | Scope | Time (1–2 devs) |
|---|---|---|
| Rename + public repo + Kotlin API parity | Phase A + C1 | 3–4 weeks |
| Pluggable transports + DoH + cover traffic | Phase B (B1/B3 done; obfs4 variants + B2) | 6–8 weeks |
| iOS SDK + Maven/SwiftPM artifacts + reference app | Phase C | 6–10 weeks |
| Audit + pilot with 1–2 real orgs (NGO/media) | Phase D | ongoing; 4–8 weeks for audit |

**First sales target: 1–2 humanitarian/activist tech NGOs** — they fund and
field-test exactly this technology. Their pilot feedback plus an audit gives
the credibility needed to sell the private/enterprise track.

---

## 7. Honest Risks & Caveats

1. **Trust and distribution are the real risks**, not technology. A P2P
   engine alone is not a product — developers need the app scaffold, docs, and
   proof it survives real network shutdowns.
2. **The SG/US soak runners are a genuine differentiator** — use them to
   produce a public, repeatable "censorship-resistance test report".
3. Do not position against paritytech/litep2p or libp2p — they are funded,
   battle-tested, and own the Web3-infrastructure segment. Stay in the
   mobile-censorship-resistance lane.
4. Re-verify the brand name (trademark + registries) before deep investment —
   renaming late is painful.
5. **B1 note:** OBF1 provides DPI resistance, not full obfs4-grade anonymity —
   the next increment is an obfs4-style KDF and WebSocket-over-CDN
   domain-fronting transports. Until then the strongest defense in depth is
   OBF1 + cover traffic + onion-lite multi-hop together.
