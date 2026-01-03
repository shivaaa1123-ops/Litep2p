# LiteP2P Desktop Testing Suite

A native C++ P2P application for fast testing and debugging on your development machine (Mac/Linux).

## Why Desktop Version?

Instead of:
1. Compile → 
2. Install APK on devices → 
3. Start devices → 
4. Run logcat → 
5. Filter logs → 
6. Copy/paste logs → 
7. Send for analysis

You can now:
1. Compile → Run in terminal (1 minute total)
2. See all logs in terminal immediately
3. Test both Mac and Linux machines simultaneously

## Quick Start

### macOS

```bash
cd desktop
chmod +x build_mac.sh
./build_mac.sh

# Run first peer on port 30001
./build_mac/bin/litep2p_peer_mac --port 30001

# In another terminal, run second peer on port 30002
./build_mac/bin/litep2p_peer_mac --port 30002
```

### Linux / Ubuntu VM

```bash
# Install dependencies (first time only)
sudo apt-get install cmake build-essential uuid-dev

cd desktop
chmod +x build_linux.sh
./build_linux.sh

# Run first peer on port 30001
./build_linux/bin/litep2p_peer_linux --port 30001

# In another terminal, run second peer on port 30002
./build_linux/bin/litep2p_peer_linux --port 30002
```

### Testing with Shared Folder (Mac Host + Ubuntu VM)

**On macOS:**
```bash
./build_mac/bin/litep2p_peer_mac --port 30001
```

**On Ubuntu VM (via shared folder):**
```bash
# In shared folder
cd /mnt/shared/desktop  # or your mount point
./build_linux/bin/litep2p_peer_linux --port 30001
```

Since the VM is in bridge mode, it will get a different IP from the network and can connect to your Mac.

## CLI Commands

```
peers                - List discovered peers
send <peer_id> <msg> - Send message to peer
status <peer_id>     - Get peer status  
help                 - Show available commands
quit                 - Exit program
```

## Example Session

### Terminal 1 (macOS, Port 30001):
```
> peers
[INFO] Discovered peers:
  [1] 11c7aff6-0648-4aa0-a153-93ca856f5ee9
  
> send 11c7aff6-0648-4aa0-a153-93ca856f5ee9 Hello from Mac!
[→] Sending to 11c7aff6... OK
```

### Terminal 2 (Ubuntu VM, Port 30001):
```
╔════════════════════════════════════════════════════╗
║              ✓ MESSAGE RECEIVED                    ║
╚════════════════════════════════════════════════════╝
[FROM] adb5623c-1234-5678-abcd-ef0123456789
[MSG]  Hello from Mac!
```

## Architecture

```
desktop/
├── CMakeLists.txt           # Build configuration
├── build_mac.sh            # macOS build script
├── build_linux.sh          # Linux build script
├── include/
│   ├── p2p_node.h         # Main P2P interface
│   └── peer_cli.h         # CLI wrapper
└── src/
    ├── main.cpp           # Entry point
    ├── peer_cli.cpp       # CLI implementation
    └── p2p_node.cpp       # P2P core wrapper
```

This is a **self-contained implementation** - no dependencies on Android modules. Designed for:
- Fast iteration (compile in seconds)
- Direct terminal output (no logcat filtering)
- Cross-machine testing (Mac + Ubuntu VM on same network)
- Simplified debugging of core P2P logic

## Logging

All logs appear directly in the terminal with timestamps:

```
[HH:MM:SS] [INFO] Initializing P2P node...
[HH:MM:SS] [INFO] Peer ID: adb5623c-1234-5678-abcd-ef0123456789
[HH:MM:SS] [INFO] Listen Port: 30001
[HH:MM:SS] [✓] P2P node started successfully

[HH:MM:SS] [→] Sending message to 11c7aff6... message_len=20
[HH:MM:SS] [✓] Message sent successfully
```

## Requirements

### macOS
- CMake 3.16+: `brew install cmake`
- Xcode Command Line Tools (usually pre-installed)

### Ubuntu/Linux
- CMake 3.16+: `sudo apt-get install cmake`
- Build tools: `sudo apt-get install build-essential`
- UUID library: `sudo apt-get install uuid-dev`

## Troubleshooting

### Build fails on macOS
```bash
# Update Xcode command line tools
xcode-select --install

# Or install cmake
brew install cmake
```

### Build fails on Linux
```bash
# Ensure all dependencies are installed
sudo apt-get update
sudo apt-get install -y cmake build-essential uuid-dev

# Rebuild
cd desktop
./build_linux.sh
```

### Cannot connect between Mac and Ubuntu VM
1. Ensure VM is in **bridge mode** (not NAT)
2. Check both machines can ping each other
3. Verify firewall allows ports 30000-30010
4. Check network interfaces with `ifconfig` (Mac) or `ip addr` (Linux)

## Performance Comparison

| Task | Android Method | Desktop Method |
|------|---|---|
| Compile | 45s | 3-5s |
| Install | 30s | 0s |
| Start app | 5s | <1s |
| View logs | Manual filtering | Instant |
| Send message | Copy/paste logs | Direct terminal |
| **Total time** | **2-3 minutes** | **10-15 seconds** |

## Development Roadmap

**Phase 1 (Current):** ✅ Complete
- CLI interface
- Build system for macOS and Linux
- Self-contained P2P node wrapper

**Phase 2 (Next):** In Progress
- Real network transport (TCP/UDP)
- Peer discovery implementation
- Message serialization/deserialization

**Phase 3 (Future):**
- Full SessionManager integration
- Event queue implementation
- Heartbeat mechanism
- Cross-validation with Android version
