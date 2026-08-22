# Desktop Peer — build, run, and interop-testing guide

The desktop peer (`litep2p_peer_<platform>`) is the same C++ engine that ships
in the Android AAR, compiled for Linux/macOS from the same `litep2p.h`
contract. Use it to develop and test your application against a real second
node while your app runs on a phone or emulator.

## 1. Build

```bash
# macOS: brew install libsodium nlohmann-json | Linux: apt install libsodium-dev nlohmann-json3-dev
cmake -S desktop -B desktop/build -DCMAKE_BUILD_TYPE=Release
cmake --build desktop/build -j
# binary: desktop/build/bin/litep2p_peer_mac  (macOS) / litep2p_peer_linux (Linux)
```

The `<PLATFORM>` suffix is set by CMake (`litep2p_peer_mac`, `litep2p_peer_linux`).
Conformance/unit-test binaries (`c_api_test`, `session_manager_test`, …) are
built into the same `bin/` directory.

## 2. Command-line options

```
Usage: litep2p_peer_<platform> [OPTIONS]

  --id ID         Explicit peer id (useful for testing)
  --port PORT     Listen port (default: 30001)
  --config FILE   Path to configuration file (default: ./config.json)
  --log-level LVL debug|info|warning|error|none (default: none)
  --proxy ROLE    Local proxy role: off|gateway|exit|client|both (default: off)
  --mode MODE     homogeneous | heterogeneous
                    homogeneous:    accept connections ONLY via --protocol /
                                    communication.default_protocol
                    heterogeneous:  accept UDP and TCP (and QUIC) simultaneously
  --protocol P    Transport for homogeneous mode: UDP|TCP|QUIC
  --tui-telemetry-ms MS  Telemetry pane refresh (default 1000, min 100)
  --no-tui        Plain log output instead of the interactive UI
  --daemon        Run as daemon (no stdin; for background/test automation)
  --help          Show help
```

Notes:

- The config file is JSON with comments (JSONC). The repo-root `config.json`
  is the reference; [`config.example.json`](../config.example.json) is the
  fully annotated template, and
  [api-spec.md §9](api-spec.md#9-configjson-reference) documents every key.
- `--id`, `--port`, `--mode`, `--protocol` override the corresponding config
  values for this run only.
- With `--daemon`, the peer keeps running until killed (`SIGTERM`/`SIGINT`).

## 3. Two-peer LAN smoke test

Run two peers on one machine with distinct ids and ports (the LAN discovery
broadcast port `network.discovery_port` — default 30000 — is shared, which is
fine):

```bash
# terminal 1
desktop/build/bin/litep2p_peer_mac --no-tui --daemon --log-level info \
    --id alice --port 30001 --config config.json

# terminal 2
desktop/build/bin/litep2p_peer_mac --no-tui --daemon --log-level info \
    --id bob --port 31001 --config config.json
```

Within a few seconds each peer discovers the other via LAN broadcast and the
Noise NK handshake runs automatically (`security.transport_key` must match —
it does when both read the same `config.json`). Watch progress with:

```bash
tail -f litep2p.log          # or run without --no-tui for the TUI
```

Then, from your Android app (or the `:app` harness) connected to the same
LAN, `LiteP2P.send(aliceId, ...)` should appear in alice's log. For WAN tests,
point both peers at the same signaling server (`signaling.url`) — see
[api-spec.md §13](api-spec.md#13-chat-application-integration-guide).

## 4. Interactive commands (TUI mode)

Run without `--no-tui`/`--daemon` and type `help` at the prompt. Useful
commands:

| Command | Effect |
|---|---|
| `connect <peer_id>` | connect to a known peer |
| `peers` / `status` | roster and engine state |
| `send <peer_id> <text>` | send a plain message |
| `proxy <off\|gateway\|exit\|client\|both\|status>` | change this peer's proxy role live |
| `admin_proxy <peer_id> <role>` | send an `LP_ADMIN` command to change a **remote** peer's role |

`admin_proxy` only works if the target peer allows you in its `config.json`:

```json
"remote_control": { "enabled": true, "allowed_senders": ["<your_peer_id>"] }
```

## 5. Running the test suites

```bash
./desktop/build/bin/c_api_test            # public C ABI conformance, end-to-end
./desktop/build/bin/session_manager_test  # engine lifecycle/FSM
# plus crypto_test, overlay_test, delivery_test, handoff_test, compat_test, …
```

`c_api_test` is the gate the project treats as "the contract still holds" —
run it after any change to `litep2p.h` or the engine.
