# LiteP2P Project Rules

## What this project is
LiteP2P is a native peer-to-peer messaging engine (C++ core) with a Kotlin
Android wrapper (`LiteP2P`/`LiteP2PRuntime`/`LiteP2PService`), a desktop CLI
peer (`desktop/`), and a Python signaling server (`tools/signaling_server/`).
v0.4 adds censorship resistance: dynamic ports, obfuscated discovery,
`wss://` signaling.

## Repo layout
- `litep2p-core/src/main/cpp/` — the C++ engine (all native logic lives here):
  - `modules/corep2p/` — core: config, crypto (noise), security, transport
  - `modules/plugins/` — discovery, session, overlay
  - `src/jni_bridge.cpp` + `src/litep2p_c_api.cpp` — public C ABI (`include/litep2p.h`)
- `litep2p-core/src/main/java/com/zeengal/litep2p/core/` — Kotlin wrapper
- `desktop/` — desktop CLI peer + tests (`desktop/tests/`)
- `tools/signaling_server/` — Python WebSocket signaling server
- `docs/api-spec.md` — the authoritative API contract; update it when the API changes
- `config.json` — the desktop reference the desktop peer actually reads; keep it in
  sync with the new keys (e.g. `network.port_range`)
- `config.example.json` — documented config template (source of truth for docs)

## Build & test
- **Desktop**: `cmake -S desktop -B desktop/build_fixcheck && cmake --build desktop/build_fixcheck`
  - Run tests: `desktop/build_fixcheck/bin/c_api_test`, `.../session_manager_test`
  - Manual live peer: `desktop/build_fixcheck/bin/litep2p_peer_mac --no-tui --daemon --log-level info --id <id> --config <config.json>`
- **Android**: `./gradlew :litep2p-core:assembleMultiThreadRelease` (and
  `SingleThread`); `:litep2p-core:externalNativeBuildMultiThreadDebug` for a
  fast native-only compile check. Two ABI/threading flavors are published to
  Maven local — always rebuild both.
- After native changes: rebuild the release AARs and refresh
  `~/Downloads/litep2p-core-0.4.0/` + the `.zip` (the portable distribution).
  For the Gradle-consumable copy, see "AAR publication (Maven local)" below —
  it is the required step after **every** approved change.

## AAR publication (Maven local) — required after every approved change

- Whenever a change set is complete, **the user is satisfied with it**, and
  **all tests pass**, rebuild and regenerate the AAR files and publish them to
  Maven Local **before declaring the task done**:
  `./gradlew :litep2p-core:assembleMultiThreadRelease :litep2p-core:assembleSingleThreadRelease :litep2p-core:multiThreadReleaseSourcesJar :litep2p-core:singleThreadReleaseSourcesJar :litep2p-core:dokkaJar :litep2p-core:publishMultiThreadReleasePublicationToMavenLocal :litep2p-core:publishSingleThreadReleasePublicationToMavenLocal`
- This writes the new AARs and artifacts to `~/.m2/repository/com/zeengal/…`
  (artifacts `litep2p-core` and `litep2p-core-singleThread`).
- **Maven Local is machine-local and only usable by Gradle on this machine** —
  it is NOT a remote/public repository, and no one else can consume it. The
  Android app project consumes these artifacts via `mavenLocal()`.
- If native (C++) code changed, additionally refresh the portable
  distribution: `~/Downloads/litep2p-core-0.4.0/` + the `.zip`.
- Publish only after: desktop tests green (`desktop/build_fixcheck/bin/c_api_test`,
  `.../session_manager_test`) and, for native changes, a successful
  `:litep2p-core:externalNativeBuildMultiThreadDebug`.

## Conventions
- C++ is compiled for both desktop and Android: keep code portable (no
  platform headers except under guards). OpenSSL is desktop-only — gate with
  `HAVE_OPENSSL` (`#ifdef`); Android builds compile the wss path out.
- Config keys are read via `ConfigManager` from `config.json` (`network.*`,
  `signaling.*`, `security.*`, ...). Defaults live in `config_manager.cpp`;
  document every new key in `config.example.json` and `docs/api-spec.md`.
- All crypto uses the engine's own primitives (XChaCha20-Poly1305 via the
  bundled cipher, Noise NK handshake). Never add ad-hoc crypto.
- Log lines go through the existing logging (prefix `[SM]` for session manager,
  `Signaling:` for signaling, etc.).
- Kotlin wrapper must stay thin and backward-compatible; the JNI C ABI is the
  contract — changing it requires updating `jni_bridge.cpp`, `LiteP2P.kt`, and
  the API spec together.

## Testing etiquette
- Every feature change must be validated with the desktop live peers (two
  nodes: discovery → handshake → READY → message) before declaring done.
- Native C++ changes need a green `externalNativeBuildMultiThreadDebug` before
  rebuilding release AARs.
- Capture-based checks (tcpdump) are the way to verify network-level behavior
  (obfuscation, ports) — the unit tests can't see the wire.

## Git workflow
- Commit style: one-line imperative summary, e.g.
  "Censorship resistance (Phase A): dynamic ports, obfuscated discovery, wss signaling".
- Push to `origin/main` (repo: `git@github.com:shivaaa1123-ops/Litep2p.git`).
- Don't commit build artifacts (`desktop/build*`, AARs are distributed via
  `~/Downloads` + Maven local, not the repo).
