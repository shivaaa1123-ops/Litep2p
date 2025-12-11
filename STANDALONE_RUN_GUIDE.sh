#!/bin/bash

################################################################################
#
# LiteP2P STANDALONE EXECUTABLE - BUILD AND RUN GUIDE
#
# Run the compiled LiteP2P executable directly on your terminal
# and see discovery, networking, and data packet logs
#
################################################################################

cat << 'GUIDE'

╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║       RUN LITEP2P EXECUTABLE DIRECTLY IN YOUR TERMINAL                    ║
║                                                                            ║
║  Compile and run the P2P peer as a standalone executable with real-time   ║
║  logs showing discovery, networking, and data packets                      ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════════════════════════
STEP 1: BUILD THE EXECUTABLE
════════════════════════════════════════════════════════════════════════════════

Navigate to project root:
  $ cd /Users/Shiva/StudioProjects/Litep2p

Create build directory:
  $ mkdir -p build && cd build

Build with CMake:
  $ cmake -DCMAKE_BUILD_TYPE=Debug ..
  $ make -j$(nproc)

This will compile everything with DEBUG mode enabled to show logs.


════════════════════════════════════════════════════════════════════════════════
STEP 2: FIND THE COMPILED EXECUTABLE
════════════════════════════════════════════════════════════════════════════════

After compilation, find the executable:
  $ find build -type f -executable -name "litep2p*"

Look for binary files like:
  build/litep2p_peer
  build/bin/litep2p_peer
  build/litep2p_main
  build/src/litep2p


════════════════════════════════════════════════════════════════════════════════
STEP 3: RUN THE EXECUTABLE DIRECTLY
════════════════════════════════════════════════════════════════════════════════

3A. Simple Run (View all logs)
──────────────────────────────

Run the binary directly:
  $ ./build/litep2p_peer

Or if in build directory:
  $ cd build && ./litep2p_peer

You should see logs like:
  [INFO] Initializing LiteP2P peer
  [DEBUG] Loading configuration
  [INFO] Starting network services
  [DISCOVERY] Listening for discovery packets
  [TRANSPORT] Binding to port 9000
  [INFO] Peer is now online


3B. Run with Debug Output (Most Detailed)
──────────────────────────────────────────

Run with environment variable for debug mode:
  $ LOG_LEVEL=DEBUG ./build/litep2p_peer

Or with verbose flag:
  $ ./build/litep2p_peer --verbose

Or with debug flag:
  $ ./build/litep2p_peer --debug


3C. Run with Specific Port
──────────────────────────

Run on specific port:
  $ ./build/litep2p_peer --port 9000

Run on custom port 8000:
  $ ./build/litep2p_peer --port 8000

Run with custom configuration:
  $ ./build/litep2p_peer --config custom_config.conf


3D. Run and Save Output
───────────────────────

Run and save all output to file:
  $ ./build/litep2p_peer > litep2p.log 2>&1

Run and save, also display in terminal (tee):
  $ ./build/litep2p_peer 2>&1 | tee litep2p_output.log

Run in background and save:
  $ ./build/litep2p_peer > litep2p.log 2>&1 &


════════════════════════════════════════════════════════════════════════════════
STEP 4: WHAT YOU'LL SEE IN OUTPUT
════════════════════════════════════════════════════════════════════════════════

STARTUP PHASE (First few lines):
──────────────────────────────────
[INFO] LiteP2P Peer Initialization Started
[DEBUG] Reading configuration file
[DEBUG] Loading crypto keys
[INFO] Initializing event loop
[TRANSPORT] Binding to port 9000
[DISCOVERY] Starting discovery service
[INFO] Peer initialization complete


DISCOVERY PHASE (If enabled):
──────────────────────────────
[DISCOVERY] Broadcasting discovery announcement
[DISCOVERY] Listening for peer announcements
[DEBUG] Discovery packet sent: type=HELLO size=256 bytes
[DEBUG] Discovery service waiting for responses...


NETWORKING PHASE (Continuous):
───────────────────────────────
[TRANSPORT] Listening on 127.0.0.1:9000
[TRANSPORT] Socket ready
[DEBUG] Network thread started


DATA PACKET SIMULATION (If enabled):
─────────────────────────────────────
[TRANSFER] Simulating data packet
[TRANSFER] Packet: size=1024 bytes, payload=test_data
[TRANSPORT] Sending packet from peer-self to peer-1
[DEBUG] Packet sent successfully
[TRANSPORT] Packet transmitted: 1024 bytes


════════════════════════════════════════════════════════════════════════════════
STEP 5: EXAMPLE COMMANDS TO RUN
════════════════════════════════════════════════════════════════════════════════

5A. Basic Run (Shows everything)
──────────────────────────────────

  $ cd /Users/Shiva/StudioProjects/Litep2p/build
  $ ./litep2p_peer

Press Ctrl+C to stop.


5B. Run with Output Filtering
──────────────────────────────

Run and show only discovery messages:
  $ ./litep2p_peer 2>&1 | grep -i "discovery"

Run and show only transport/data messages:
  $ ./litep2p_peer 2>&1 | grep -i "transfer\|transport\|send\|recv"

Run and show only startup:
  $ ./litep2p_peer 2>&1 | grep -i "init\|start\|ready"

Run and highlight errors:
  $ ./litep2p_peer 2>&1 | grep --color -i "error\|failed\|warn"


5C. Run with Real-Time Filtering
─────────────────────────────────

Show logs as they appear with timestamps:
  $ ./litep2p_peer 2>&1 | while IFS= read -r line; do echo "[$(date '+%H:%M:%S')] $line"; done

Show logs with line numbers:
  $ ./litep2p_peer 2>&1 | nl

Show logs with colors (if supported):
  $ ./litep2p_peer 2>&1 | sed \
    -e 's/ERROR/\x1b[31mERROR\x1b[0m/g' \
    -e 's/DISCOVERY/\x1b[32mDISCOVERY\x1b[0m/g' \
    -e 's/TRANSFER/\x1b[33mTRANSFER\x1b[0m/g'


5D. Run Multiple Instances
───────────────────────────

Run peer-1 (Terminal 1):
  $ ./build/litep2p_peer --port 9001

Run peer-2 (Terminal 2):
  $ ./build/litep2p_peer --port 9002

Run peer-3 (Terminal 3):
  $ ./build/litep2p_peer --port 9003


════════════════════════════════════════════════════════════════════════════════
STEP 6: WHAT EACH LOG TYPE MEANS
════════════════════════════════════════════════════════════════════════════════

[INFO] Information
  → General operational status
  → Examples: "Peer started", "Service enabled", "Ready for connections"

[DEBUG] Detailed debugging info
  → Low-level operation details
  → Examples: "Allocated memory", "Buffer created", "Processing packet"

[DISCOVERY] Discovery protocol events
  → Peer discovery messages
  → Examples: "Sending broadcast", "Received announcement", "Connected to peer"

[TRANSPORT] Network transport events
  → Socket operations, connections
  → Examples: "Bound to port", "Sent packet", "Received data"

[TRANSFER] Data transfer events
  → File/data transmission
  → Examples: "Sending 1MB", "Received chunk", "Transfer complete"

[CRYPTO] Cryptography events
  → Encryption/decryption operations
  → Examples: "Generating keys", "Encrypted packet", "Verified signature"

[ERROR] Error messages
  → Something went wrong
  → Examples: "Connection refused", "Invalid packet", "Out of memory"

[WARN] Warning messages
  → Potential issues but continuing
  → Examples: "High latency", "Packet loss detected", "Slow connection"


════════════════════════════════════════════════════════════════════════════════
STEP 7: RUN WITH SIMULATION (Generate Packet Activity)
════════════════════════════════════════════════════════════════════════════════

If your executable has simulation modes:

Run with packet simulation:
  $ ./build/litep2p_peer --simulate-packets

Run with network simulation:
  $ ./build/litep2p_peer --simulate-network

Run with data generation:
  $ ./build/litep2p_peer --generate-data 1024 --count 10

Run with continuous data transfer:
  $ ./build/litep2p_peer --continuous-transfer 100


════════════════════════════════════════════════════════════════════════════════
STEP 8: CAPTURE OUTPUT TO FILE
════════════════════════════════════════════════════════════════════════════════

8A. Save full output
────────────────────

Run and save all output:
  $ ./build/litep2p_peer > peer_output.log 2>&1

View the saved log:
  $ cat peer_output.log

Follow the log as it's being written (in another terminal):
  $ tail -f peer_output.log

Count lines in the log:
  $ wc -l peer_output.log


8B. Save filtered output
────────────────────────

Save only discovery messages:
  $ ./build/litep2p_peer 2>&1 | grep "DISCOVERY" > discovery.log

Save only data transfer:
  $ ./build/litep2p_peer 2>&1 | grep "TRANSFER" > transfer.log

Save errors only:
  $ ./build/litep2p_peer 2>&1 | grep "ERROR" > errors.log


════════════════════════════════════════════════════════════════════════════════
STEP 9: REAL-TIME TERMINAL EXAMPLES
════════════════════════════════════════════════════════════════════════════════

EXAMPLE 1: Basic Run
────────────────────

Terminal output will look like:

$ ./build/litep2p_peer
[2024-12-09 14:23:45] [INFO] LiteP2P Peer starting...
[2024-12-09 14:23:45] [CORE] Initializing configuration
[2024-12-09 14:23:46] [DEBUG] Loading config from: /etc/litep2p.conf
[2024-12-09 14:23:46] [CRYPTO] Generating encryption keys
[2024-12-09 14:23:47] [CRYPTO] Key generation complete
[2024-12-09 14:23:47] [TRANSPORT] Binding to port 9000
[2024-12-09 14:23:48] [TRANSPORT] Listen socket created successfully
[2024-12-09 14:23:48] [REACTOR] Starting event loop
[2024-12-09 14:23:49] [DISCOVERY] Starting discovery service
[2024-12-09 14:23:50] [DISCOVERY] Broadcasting discovery packet
[2024-12-09 14:23:50] [DEBUG] Broadcast packet size: 256 bytes
[2024-12-09 14:23:51] [TRANSFER] Preparing test data: 1024 bytes
[2024-12-09 14:23:52] [TRANSFER] Sending data packet
[2024-12-09 14:23:52] [TRANSPORT] Packet sent: 1024 bytes
[2024-12-09 14:23:53] [TRANSFER] Data transfer complete
[2024-12-09 14:23:54] [INFO] Peer is online and operational
[2024-12-09 14:23:55] [DEBUG] Listening for incoming packets...

Press Ctrl+C to exit


EXAMPLE 2: With Discovery Filtering
────────────────────────────────────

$ ./build/litep2p_peer 2>&1 | grep -i discovery
[2024-12-09 14:23:49] [DISCOVERY] Starting discovery service
[2024-12-09 14:23:50] [DISCOVERY] Broadcasting discovery packet
[2024-12-09 14:23:51] [DISCOVERY] Waiting for peer responses


EXAMPLE 3: With Data Transfer Filtering
────────────────────────────────────────

$ ./build/litep2p_peer 2>&1 | grep -i "transfer\|send"
[2024-12-09 14:23:51] [TRANSFER] Preparing test data: 1024 bytes
[2024-12-09 14:23:52] [TRANSFER] Sending data packet
[2024-12-09 14:23:52] [TRANSPORT] Packet sent: 1024 bytes


════════════════════════════════════════════════════════════════════════════════
STEP 10: MULTIPLE PEERS ON SAME MACHINE
════════════════════════════════════════════════════════════════════════════════

Terminal 1 - Start peer-1:
  $ ./build/litep2p_peer --port 9001 --name peer-1

Terminal 2 - Start peer-2:
  $ ./build/litep2p_peer --port 9002 --name peer-2 --bootstrap 127.0.0.1:9001

Terminal 3 - Monitor output:
  $ tail -f peer1.log & tail -f peer2.log

Expected output:
  peer-1 listens on port 9001
  peer-2 connects to peer-1 on port 9001
  peer-2 discovers peer-1
  peer-1 acknowledges peer-2
  Peers exchange discovery packets
  Data transfer begins


════════════════════════════════════════════════════════════════════════════════
STEP 11: BUILDING FOR DIFFERENT PLATFORMS
════════════════════════════════════════════════════════════════════════════════

For Linux/macOS:
  $ cmake -DCMAKE_BUILD_TYPE=Debug ..
  $ make -j$(nproc)

For Android (if you have NDK):
  $ cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
          -DANDROID_ABI=arm64-v8a \
          -DCMAKE_BUILD_TYPE=Debug ..
  $ make -j$(nproc)

For different architectures:
  $ cmake -DCMAKE_SYSTEM_PROCESSOR=arm64 ..
  $ cmake -DCMAKE_SYSTEM_PROCESSOR=x86_64 ..


════════════════════════════════════════════════════════════════════════════════
STEP 12: QUICK START COMMANDS (COPY & PASTE)
════════════════════════════════════════════════════════════════════════════════

Full build and run:
  cd /Users/Shiva/StudioProjects/Litep2p && \
  mkdir -p build && cd build && \
  cmake -DCMAKE_BUILD_TYPE=Debug .. && \
  make -j$(nproc) && \
  ./litep2p_peer

Build and save output:
  cd /Users/Shiva/StudioProjects/Litep2p/build && \
  make -j$(nproc) && \
  ./litep2p_peer | tee litep2p_run.log

Build and filter discovery:
  cd /Users/Shiva/StudioProjects/Litep2p/build && \
  make -j$(nproc) && \
  ./litep2p_peer 2>&1 | grep -i discovery

Build and filter transfers:
  cd /Users/Shiva/StudioProjects/Litep2p/build && \
  make -j$(nproc) && \
  ./litep2p_peer 2>&1 | grep -i transfer


════════════════════════════════════════════════════════════════════════════════
TROUBLESHOOTING
════════════════════════════════════════════════════════════════════════════════

Problem: "executable not found"
Solution:
  $ find build -type f -executable
  $ ls -la build/
  $ cmake --build build

Problem: "command not found: cmake"
Solution:
  $ brew install cmake (on macOS)
  $ sudo apt-get install cmake (on Ubuntu)

Problem: "No such file or directory"
Solution:
  $ pwd (check current directory)
  $ ls -la (list files)
  $ cd build (navigate to build folder)

Problem: "Permission denied"
Solution:
  $ chmod +x ./litep2p_peer
  $ ./litep2p_peer

Problem: "Port already in use"
Solution:
  $ lsof -i :9000 (find what's using port)
  $ kill -9 <PID> (kill the process)
  $ ./litep2p_peer --port 9001 (use different port)

Problem: "No logs appearing"
Solution:
  $ ./litep2p_peer --verbose (enable verbose)
  $ ./litep2p_peer --debug (enable debug mode)
  $ LOG_LEVEL=DEBUG ./litep2p_peer (set env variable)


════════════════════════════════════════════════════════════════════════════════
SUMMARY - SIMPLEST WORKFLOW
════════════════════════════════════════════════════════════════════════════════

1. Open Terminal

2. Navigate to project:
   $ cd /Users/Shiva/StudioProjects/Litep2p

3. Build:
   $ mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc)

4. Run:
   $ ./litep2p_peer

5. Watch output (Discovery + Data packets):
   Press Enter and watch the terminal

6. Filter discovery (in another terminal):
   $ tail -f litep2p_run.log | grep -i discovery

7. Filter transfers (in another terminal):
   $ tail -f litep2p_run.log | grep -i transfer

════════════════════════════════════════════════════════════════════════════════

Done! You should now see real-time logs of your LiteP2P peer running locally.

════════════════════════════════════════════════════════════════════════════════

GUIDE

exit 0
