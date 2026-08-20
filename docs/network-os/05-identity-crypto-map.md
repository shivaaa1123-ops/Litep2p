# Network OS Phase 0 — Step 1.5: Identity & Crypto Map

**Date:** 2026-08-20
**Branch:** `network-os-dev`
**Scope:** PeerID generation/format, key storage, Noise handshake, origin signatures, platform-secure storage status.
**Purpose:** Input to Phase 1 `IIdentityStore` + stable-PeerID invariant (§12), Phase 3 envelope signing, Gate E.

## 1. Peer identity

| Aspect | Current implementation |
|---|---|
| Generation | `get_persistent_device_id()` (`device_utils.cpp:44`): MAC-derived `litep2p-device-<mac_hex>` (prefers en0/wlan0/eth0) or `litep2p-random-<12-hex>` fallback (`device_utils.cpp:28`) |
| Stability | Stable per device unless MAC unavailable (then random, regenerated per process run — **Gap**: random fallback does not persist the ID) |
| Override | `litep2p_init(config.peer_id)` → `g_resolved_peer_id` (`litep2p_c_api.cpp:573-577`); Kotlin `LiteP2PDefaults.getOrCreatePeerId` persists a per-device peer id in SharedPreferences (`LiteP2PDefaults.kt`) |
| Wire exposure | PeerID appears in discovery announcements (obfuscated when `discovery_shared_key` set) and LPX2 headers; never plaintext on the wire when OBF1/padding active |

## 2. Crypto primitives

| Primitive | Use | Implementation |
|---|---|---|
| Noise NK | Session handshake + AEAD (`noise_nk.h:28`); pattern `e → e,ee,es → se`; initiator knows peer static key | `NoiseNKSession`; replay-window seq tracking; `decrypt(..., replay_drop)` distinguishes replay from auth failure (`noise_nk.h:85`) |
| XChaCha20-Poly1305 | Transport AEAD + discovery announcement encryption | bundled cipher (`crypto_utils`) |
| crypto_box_seal | LPX2 per-hop sealing (`overlay_frame.h:109 seal_hop`) | libsodium |
| Ed25519 | Overlay origin authentication: local signing keypair signs FinalPayloads; peer signing keys are trust anchors (`noise_key_store.h:114-127`, `litep2p_overlay_register_peer_signing_key`) | libsodium |
| AES / SHA1/MD5 | legacy helpers (`aes.h`, `sha1_md5.h`) | bundled |
| OpenSSL | wss:// signaling only; gated `HAVE_OPENSSL` (desktop-only; Android compiles out) | desktop |

## 3. Key storage

| Store | Contents | Persistence | Platform-secure? |
|---|---|---|---|
| `NoiseKeyStore` (`noise_key_store.h:25`) | local Noise static keypair, peer static keys, local Ed25519 signing keypair, peer signing keys | JSON file at `security.noise_nk_protocol.key_store_path` (default `files_dir/keystore` via `apply_files_dir_config`, `litep2p_c_api.cpp:352-359`), atomic tmp+rename | **Not hardware-backed.** Header comment (`noise_key_store.h:17-22`) says Android Keystore is the *intended* backer via JNI; the current C++ store writes a plain file. **Gap for Phase 1 `IIdentityStore` / Phase 12 Kotlin Keystore integration.** |
| `LiteP2PDefaults` (Kotlin) | per-device peer id | SharedPreferences | standard (non-encrypted) prefs |
| peer DB | peer endpoints + timestamps (no keys) | JSON file | no secrets |

## 4. Censorship-resistance crypto (Gate C)

- Discovery announcements: `<magic> || nonce(12) || AEAD_ct` when `network.discovery_shared_key` configured; magic configurable per deployment (`config_manager.h:68-75`).
- OBF1 obfuscated transport + length-bucketed padding + cover traffic are default-ON (overlay `Config` `padding_bucket`, `cover_interval_ms`; `overlay_router.h:69-78`).
- Replay protection: LPX2 `frame_id` dedup LRU + timestamp replay window (`overlay_router.h:66-67`); Noise seq replay window.

## 5. Gaps to flag

1. **Random-fallback PeerID is not persisted** at the C++ level (desktop). Phase 1 `IIdentityStore` must persist/create-once so PeerID is stable across restarts (invariant §12).
2. **Keystore is a plain JSON file**, not Android Keystore/EncryptedSharedPreferences. The Phase 0 matrix verdict is **HARDEN** (bounds + migration) with a Phase 12 hook for Keystore-backed storage.
3. Noise NK requires pre-registered peer static keys (out-of-band). Capability negotiation (Phase 2) must not regress this trust model.
