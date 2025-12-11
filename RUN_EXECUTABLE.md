# 🎯 RUN LITEP2P EXECUTABLE DIRECTLY - COMPLETE GUIDE

## What You Want To Do

Run your compiled LiteP2P executable directly in your terminal and see:
- ✅ Discovery packet logs
- ✅ Data sending/receiving logs  
- ✅ Server startup notifications
- ✅ Network connection logs
- ✅ All output in real-time in your terminal

## 🚀 Quickest Way (Copy & Paste)

Open your terminal and run ONE of these commands:

### Option 1: Simple Build and Run
```bash
cd /Users/Shiva/StudioProjects/Litep2p && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc) && ./litep2p_peer
```

### Option 2: Use the Automatic Script
```bash
bash /Users/Shiva/StudioProjects/Litep2p/run.sh
```

### Option 3: See Only Discovery Logs
```bash
cd /Users/Shiva/StudioProjects/Litep2p && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc) && ./litep2p_peer 2>&1 | grep -i discovery
```

### Option 4: See Only Data Transfer Logs
```bash
cd /Users/Shiva/StudioProjects/Litep2p && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc) && ./litep2p_peer 2>&1 | grep -i "transfer\|send\|recv"
```

### Option 5: Save All Output to File + Display
```bash
cd /Users/Shiva/StudioProjects/Litep2p && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc) && ./litep2p_peer 2>&1 | tee execution.log
```

## Expected Output

When you run the executable, you'll see logs like:

```
[2024-12-09 14:23:45] [INFO] LiteP2P Peer Initialization Started
[2024-12-09 14:23:46] [DEBUG] Loading configuration file
[2024-12-09 14:23:47] [TRANSPORT] Binding to port 9000
[2024-12-09 14:23:48] [DISCOVERY] Starting discovery service
[2024-12-09 14:23:49] [DISCOVERY] Broadcasting discovery announcement
[2024-12-09 14:23:50] [DEBUG] Discovery packet sent: 256 bytes
[2024-12-09 14:23:51] [TRANSFER] Preparing data packet: 1024 bytes
[2024-12-09 14:23:52] [TRANSPORT] Sending data packet
[2024-12-09 14:23:52] [TRANSPORT] Packet sent successfully
[2024-12-09 14:23:53] [TRANSFER] Transfer complete
[2024-12-09 14:23:54] [INFO] Peer is online and operational
```

## Breaking Down the Command

If you want to do it step-by-step:

```bash
# Step 1: Navigate to project
cd /Users/Shiva/StudioProjects/Litep2p

# Step 2: Create build directory
mkdir -p build && cd build

# Step 3: Configure with CMake (Debug mode for full logs)
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Step 4: Compile (uses all CPU cores)
make -j$(nproc)

# Step 5: Find the executable
find . -type f -executable -name "*litep2p*"

# Step 6: Run it
./litep2p_peer
```

## Viewing Logs in Different Ways

### After Running, View Logs in New Terminal:

```bash
# See last 50 lines
tail -50 execution.log

# Follow logs as they're written
tail -f execution.log

# Find only discovery messages
grep -i discovery execution.log

# Find only data transfer messages
grep -i transfer execution.log

# Count total log lines
wc -l execution.log

# Show with line numbers
cat -n execution.log | head -50
```

## Multiple Peer Simulation

If you want to test two peers on same machine:

**Terminal 1:**
```bash
cd /Users/Shiva/StudioProjects/Litep2p/build
./litep2p_peer --port 9001 --name peer-1 2>&1 | tee peer1.log
```

**Terminal 2:**
```bash
cd /Users/Shiva/StudioProjects/Litep2p/build
./litep2p_peer --port 9002 --name peer-2 --bootstrap 127.0.0.1:9001 2>&1 | tee peer2.log
```

**Terminal 3 (Monitor):**
```bash
tail -f peer1.log &
tail -f peer2.log
```

## What Each Log Line Means

| Log Type | Meaning | Example |
|----------|---------|---------|
| `[INFO]` | General information | "Peer started" |
| `[DEBUG]` | Detailed info | "Allocated 100MB memory" |
| `[DISCOVERY]` | Peer discovery | "Sending announcement" |
| `[TRANSPORT]` | Network data | "Sent 1024 bytes" |
| `[TRANSFER]` | File/data transfer | "Transfer complete" |
| `[ERROR]` | Something failed | "Connection refused" |

## Filtering Logs in Real-Time

While the program is running:

```bash
# See only discovery
./litep2p_peer 2>&1 | grep -i discovery

# See only transfers
./litep2p_peer 2>&1 | grep -i transfer

# See with color highlighting
./litep2p_peer 2>&1 | grep --color=always -i "discovery\|transfer"

# Count lines as they appear
./litep2p_peer 2>&1 | tee -a count.log | wc -l
```

## If Build Fails

```bash
# Clean old build
rm -rf /Users/Shiva/StudioProjects/Litep2p/build

# Try again
cd /Users/Shiva/StudioProjects/Litep2p && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc)

# Check for errors
cmake --build . --verbose
```

## Created Helper Scripts

I also created these scripts to help:

```bash
# Full automatic build and run
bash /Users/Shiva/StudioProjects/Litep2p/run.sh

# View all build and run options
bash /Users/Shiva/StudioProjects/Litep2p/QUICK_BUILD_RUN.sh

# Comprehensive standalone guide
bash /Users/Shiva/StudioProjects/Litep2p/STANDALONE_RUN_GUIDE.sh
```

## Summary

**Simplest Command to Run:**
```bash
cd /Users/Shiva/StudioProjects/Litep2p && mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(nproc) && ./litep2p_peer
```

**This will:**
1. Navigate to your project
2. Create build directory
3. Configure with CMake
4. Compile the code
5. Run the executable
6. Show all logs in your terminal in real-time

**You'll see discovery packets, data transfers, and server notifications!**
