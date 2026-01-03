# Desktop peer testing (macOS + Linux)

This guide assumes you already built the binaries:
- macOS: `desktop/build_mac/bin/litep2p_peer_mac`
- Linux: `desktop/build_linux_docker/bin/litep2p_peer_linux` (for running on a real Linux machine, copy this binary there; Docker-on-mac networking isn’t great for UDP broadcast discovery)

## 1) Quick smoke test (each binary)

- Run and verify it starts without crashing:
  - `./desktop/build_mac/bin/litep2p_peer_mac --help`
  - `./desktop/build_linux_docker/bin/litep2p_peer_linux --help`

## 2) Best real-world test: two machines on the same LAN

### Network requirements

- Both machines on the same LAN/VLAN.
- Allow UDP ports:
  - **30000/udp** (plaintext LAN discovery)
  - **30001/udp** (encrypted data channel; `--port`)

### Start peers

On macOS (Machine A):
- `./desktop/build_mac/bin/litep2p_peer_mac --port 30001 --id macA --log-level info`

On Linux (Machine B):
- `./litep2p_peer_linux --port 30001 --id linuxB --log-level info`

(You can use different `--port` values too; keep them consistent with your test expectations.)

### Connect and send messages (from the TUI)

In either peer’s TUI:
- The **PEERS** panel should update automatically as peers are discovered/connected.
- The **MESSAGES** panel should show inbound and outbound messages.
- `peers`  
  Prints the full peer IDs to the OUTPUT panel.
- `connect <id-prefix>`  
  You can paste the full ID or just a unique prefix (the PEERS panel shows a short-id).
- `send <id-prefix> hello from mac/linux`
- `broadcast hello everyone`

If the PEERS panel looks stale, run `peers` (or `refresh`) to force a redraw.

Helpful:
- `status` shows current state.
- `logfilter info` (or `debug`) to adjust what lands in the LOGS panel.

## 3) If discovery doesn’t show peers

- Confirm both sides are on the same broadcast domain (some Wi‑Fi networks block broadcast/multicast).
- Confirm firewalls allow **UDP 30000** and **UDP 30001**.
- Try running both peers with `--log-level debug` temporarily to see discovery traffic.

## 4) Cross-network testing (different NATs)

LAN discovery won’t cross NATs. For cross-network tests you’ll need:
- a reachable signaling server (WebSocket) configured in `config.json`
- (optionally) a TURN server in `config.json`

Start both peers with the same `config.json`, then use `peers` / `connect` / `send` as above.

## Docker / multiple instances

See `desktop/DOCKER_TESTING.md` for Docker bridge/host/macvlan notes and multi-container recipes (including macOS Docker Desktop limitations).
