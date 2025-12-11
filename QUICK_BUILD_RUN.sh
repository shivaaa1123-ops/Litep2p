#!/bin/bash

# Quick Command Reference - Copy and Paste These

cat << 'COMMANDS'

════════════════════════════════════════════════════════════════════════════════
                    LITEP2P - BUILD AND RUN COMMANDS
════════════════════════════════════════════════════════════════════════════════

OPTION 1: SIMPLE BUILD AND RUN (Recommended)
──────────────────────────────────────────────

Copy and paste this entire command block:

cd /Users/Shiva/StudioProjects/Litep2p && \
mkdir -p build && cd build && \
cmake -DCMAKE_BUILD_TYPE=Debug .. && \
make -j$(nproc) && \
./litep2p_peer

Or use the automatic script:
  bash run.sh


OPTION 2: STEP BY STEP
────────────────────────

Step 1: Navigate to project
  cd /Users/Shiva/StudioProjects/Litep2p

Step 2: Create build folder
  mkdir -p build && cd build

Step 3: Configure with CMake
  cmake -DCMAKE_BUILD_TYPE=Debug ..

Step 4: Build project
  make -j$(nproc)

Step 5: Run executable
  ./litep2p_peer

OR find the executable first:
  find . -type f -executable -name "*litep2p*"
  
Then run it:
  ./path/to/executable


OPTION 3: BUILD AND SAVE OUTPUT
────────────────────────────────

cd /Users/Shiva/StudioProjects/Litep2p && \
mkdir -p build && cd build && \
cmake -DCMAKE_BUILD_TYPE=Debug .. && \
make -j$(nproc) && \
./litep2p_peer 2>&1 | tee execution.log


OPTION 4: BUILD AND FILTER DISCOVERY LOGS
────────────────────────────────────────────

cd /Users/Shiva/StudioProjects/Litep2p && \
mkdir -p build && cd build && \
cmake -DCMAKE_BUILD_TYPE=Debug .. && \
make -j$(nproc) && \
./litep2p_peer 2>&1 | grep -i "discovery\|start\|init"


OPTION 5: BUILD AND FILTER DATA TRANSFER LOGS
────────────────────────────────────────────────

cd /Users/Shiva/StudioProjects/Litep2p && \
mkdir -p build && cd build && \
cmake -DCMAKE_BUILD_TYPE=Debug .. && \
make -j$(nproc) && \
./litep2p_peer 2>&1 | grep -i "transfer\|send\|recv\|data"


OPTION 6: BUILD AND FILTER ERRORS
────────────────────────────────────

cd /Users/Shiva/StudioProjects/Litep2p && \
mkdir -p build && cd build && \
cmake -DCMAKE_BUILD_TYPE=Debug .. && \
make -j$(nproc) && \
./litep2p_peer 2>&1 | grep --color -i "error\|failed\|warn"


OPTION 7: QUICK REBUILD (After first build)
──────────────────────────────────────────────

If you already built once, just rebuild and run:
  cd /Users/Shiva/StudioProjects/Litep2p/build && \
  make -j$(nproc) && \
  ./litep2p_peer


OPTION 8: VERBOSE OUTPUT
────────────────────────

If your executable supports verbose flag:
  ./litep2p_peer --verbose
  ./litep2p_peer --debug
  ./litep2p_peer -v


════════════════════════════════════════════════════════════════════════════════

WHAT YOU'LL SEE:

[INFO] LiteP2P Peer starting...
[DISCOVERY] Broadcasting discovery announcement
[TRANSPORT] Binding to port 9000
[TRANSFER] Sending data packet
[DEBUG] Packet sent: 1024 bytes
...

════════════════════════════════════════════════════════════════════════════════

SAVE OUTPUT TO FILE:

Save everything:
  ./litep2p_peer > output.log 2>&1

View saved output:
  cat output.log
  tail -100 output.log
  grep "DISCOVERY" output.log
  grep "TRANSFER" output.log

Follow output in another terminal:
  tail -f output.log

════════════════════════════════════════════════════════════════════════════════

QUICK TERMINAL COPY-PASTE:

1. Navigate:
cd /Users/Shiva/StudioProjects/Litep2p

2. Build:
mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc)

3. Run (one of these):
./litep2p_peer
./litep2p_peer 2>&1 | tee run.log
./litep2p_peer 2>&1 | grep -i discovery

════════════════════════════════════════════════════════════════════════════════

COMMANDS
