## Code-first review of `Litep2p`

### What’s working well (and is worth preserving)
- **Clear module split**: `app/src/main/cpp/modules/corep2p/*` (transport/crypto/security/reactor) vs `app/src/main/cpp/modules/plugins/*` (session/routing/discovery/proxy/…).
- **Desktop harness reuses the real engine**: `desktop/CMakeLists.txt` compiles the same engine sources as Android, which is great for fast iteration and regression hunting.
- **Single-thread support is real, not “ifdef theater”**: the `UnifiedEventLoop` (`modules/plugins/session/src/unified_event_loop.cpp`) provides a coherent model (kqueue on macOS, poll elsewhere).

---

## Top priority issues (high impact / high leverage)

### 1) JNI layer duplication + lifecycle leaks
- You effectively have *two* JNI bridge implementations:
  - `app/src/main/cpp/src/jni_bridge.cpp` (the one actually built by `app/src/main/cpp/CMakeLists.txt`)
  - `app/src/main/cpp/modules/plugins/jni/src/jni_bridge.cpp` (built by `modules/plugins/jni/CMakeLists.txt`, but **not** wired into the Android build)
- In the “real” JNI bridge (`app/src/main/cpp/src/jni_bridge.cpp`), `jniBridgeInit()` creates **new global refs every start**, but there’s no corresponding cleanup path invoked on stop; `jniBridgeCleanup()` exists but isn’t called. If you stop/start repeatedly, this will leak references (and can get weird if classes are reloaded).

**Recommendation**
- Make JNI caching **init-once** (e.g., on `JNI_OnLoad`) and clean on `JNI_OnUnload`, or call `jniBridgeCleanup()` on stop/restart boundaries.
- Either remove `modules/plugins/jni/*` or wire it properly and delete the duplicate implementation—right now it’s a maintenance trap.

### 2) Signaling client robustness/security limitations
`modules/plugins/discovery/src/signaling_client.cpp`:
- Only supports plaintext `ws://` (no TLS).
- Handshake check is weak (looks for “101” and “Switching Protocols”, does **not** validate `Sec-WebSocket-Accept`).
- JSON messages are built via string concatenation without escaping (peer IDs / network IDs containing quotes can break the protocol).
- Long-term: websocket framing tends to grow edge cases (fragmentation, ping/pong, close handling, partial reads).

**Recommendation**
- If this is production-facing: use a hardened WebSocket implementation or at least validate `Sec-WebSocket-Accept`, implement ping/pong, and escape JSON fields.

### 3) Desktop build structure is correct but inefficient/duplicated
`desktop/CMakeLists.txt` compiles `${ENGINE_SOURCES}` into *every* binary (peer + each test), which:
- slows builds significantly,
- increases the chance of accidental ODR/flag mismatches over time.

Also, the file list has minor duplication/overwrites (e.g., `DISCOVERY_SOURCES` is defined twice).

**Recommendation**
- Build the engine once as a `STATIC` (or `OBJECT`) library target and link it into `litep2p_peer_*` + tests.
- Deduplicate the source lists so desktop and Android aren’t silently diverging.

### 4) UDP single-thread path allocates per packet and has heuristic drops
`modules/corep2p/transport/src/udp_connection_manager.cpp`:
- `processOnePacket()` allocates a fresh `std::vector<char>` every call.
- It drops packets if the first 32 bytes contain `"DISCOVER"` (could theoretically collide with real payload bytes).

**Recommendation**
- Reuse a buffer (stack or member) in ST mode.
- Narrow the discovery detection to a stricter header/magic format.

---

## Medium-term maintainability improvements

### Make “mode” types explicit
You pass protocol/mode as strings in several places (e.g., `P2PNode::start(..., comms_mode)` in `desktop/src/p2p_node.cpp`). This is brittle.

**Recommendation**
- Replace stringly-typed modes with enums (and parse at the boundary).

### Reduce singleton/global coupling where it blocks testing
Patterns like `ConfigManager::getInstance()` and `NATTraversal::getInstance()` make multi-node-in-one-process testing harder (and force “reset” APIs like `shutdown()` to exist).

**Recommendation**
- Consider dependency injection at least for tests: make SessionManager accept interfaces for config, clock, transport, NAT traversal.

### Logging consistency and sinks
There’s a mix of `nativeLog(...)`, `LOG_INFO(...)`, and UI interception (e.g., `TerminalCLI` redirects stdout/stderr in `desktop/src/terminal_cli.cpp`).

**Recommendation**
- Define a single logging API with pluggable sinks (Android logcat sink, desktop TUI sink, file sink), and avoid stdout redirection as a routing mechanism.

---

## Testing/tooling notes
- Desktop “tests” are standalone executables with custom macros (e.g., `desktop/tests/session_manager_test.cpp`, `desktop/tests/nat_traversal_test.cpp`). They’re useful, but they’re not integrated with `ctest` (no `enable_testing()` / `add_test()`).
- `pytest.ini` exists but points to a non-existent `setupTests/` directory—likely stale.

**Recommendation**
- Add CTest registration so CI can run `ctest` uniformly.
- Either remove or fix `pytest.ini` to avoid confusion.

---

## Current todo list ✅
1. Map repo architecture — completed  
2. Review networking stack — completed  
3. Review platform glue — completed  
4. Review build & tests — completed  
5. Write prioritized code review — completed
