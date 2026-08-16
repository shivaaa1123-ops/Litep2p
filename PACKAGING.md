# Packaging & Distribution — Phase B (B6)

**Goal:** the engine + reference app must be distributable without Google Play,
with byte-reproducible builds that activists, journalists, and NGOs can verify
themselves. Trust in the binary is a purchase criterion in this market.

## Current state (verified 2026-08-16)

- **No Play Services / Firebase dependency.** The reference app uses only
  AndroidX (core, appcompat, material, lifecycle, navigation, viewpager,
  WorkManager). It builds and runs entirely without Google.
- `android.enableReproducibleArchives=true` added to `gradle.properties`
  (AGP ≥ 8.1) — removes build timestamps from APK/AAB.
- The engine is a native library (`liblitep2p.so` per ABI) inside `:litep2p-core` —
  nothing ties it to Play.

## Requirements to ship F-Droid-ready

- [ ] **Reproducible end-to-end:** confirm two CI builds of the same commit
      produce identical APKs (sha256) — this is the F-Droid verifiability bar.
- [ ] **Deterministic NDK objects:** keep `-ffile-prefix-map` /
      `-fdebug-prefix-map` in CMake so .so paths don't embed absolute build dirs
      (breaks reproducibility between builders). Add to root cpp CMakeLists:
      `target_compile_options(... -ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=.)`
- [ ] **F-Droid metadata repo entry:** `fdroidmetadata.yml` with the build recipe
      (gradle assembleMultiThreadRelease, ndkVersion pinned, keystore: none —
      F-Droid signs).
- [ ] **Signing policy:** publish only release builds signed with a pinned
      keystore; publish sha256 + `minisign`/OpenPGP signatures on the release
      page. Never rely on Play App Signing.
- [ ] **Sideload path in the reference app:** a "Verify this APK" screen showing
      the APK sha256 + engine version string (`LiteP2P.version`) so users can
      cross-check against the published hash.
- [ ] **No network calls to Google:** check runtime (WorkManager is fine — it
      has no GMS dependency when `play-services` is absent).

## Distribution targets (priority order for the freedom track)

1. **F-Droid** (for the reference app) — the de-facto store for human-rights apps.
2. **GitHub Releases** with pinned hashes + signatures (direct download link for
   sideloading).
3. **Direct APK** on the project site with a curl-able checksum file.
4. Maven Central for the **library** (developers) — separate from app distribution.

## DoH bootstrap note (B2 status)

Encrypted-DNS bootstrap is *designed but not yet implemented*: the native engine
has no TLS/HTTPS client yet. Recommended integration order:

1. **Android (fast path):** expose `overlay.doh_url` from config and resolve
   signaling/bootstrap hostnames through the platform `DnsResolver`
   (`DnsResolver.getNetworkResolver().rawQuery` with `DoH`)
   — Android 13+ does DoH natively; add a JNI bridge call.
2. **Desktop/native:** implement a minimal DoH client over the already-vendored
   picotls TLS stack (or link a small TLS library) — GET
   `https://<doh>/dns-query?dns=...` (RFC 8484). Until then, hostnames fall back
   to the system resolver (`getaddrinfo`).
