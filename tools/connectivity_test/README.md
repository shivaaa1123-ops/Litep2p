# Network Connectivity Test

This tool verifies that your Signaling Server and TURN Server are correctly deployed and reachable from different networks.

## Prerequisites

On both VPS instances (or devices) you want to test:
1. Python 3.7+
2. `websockets` library

```bash
pip install websockets
```

## How to Run

You need two separate terminals (on different machines/VPSs).

**On Machine A (Responder):**
```bash
python3 verify_network.py --role responder
```

**On Machine B (Initiator):**
```bash
python3 verify_network.py --role initiator
```

## What it Tests

1. **Signaling:** Both peers connect to `ws://167.172.94.33:8765`.
2. **Discovery:** Initiator sends a signal to Responder via the server.
3. **TURN:** Both peers send a STUN Binding Request to `167.172.94.33:3478` to verify the UDP port is open and the server is responding.

If both scripts exit with `SUCCESS`, your infrastructure is ready for the C++ engine.
