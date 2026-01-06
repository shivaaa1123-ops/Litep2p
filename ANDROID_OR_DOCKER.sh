#!/bin/bash

################################################################################
#
# LiteP2P Android APK - BUILD AND RUN/TEST GUIDE
#
# This is an Android project. The compiled output is an APK (Android app)
# not a standalone C++ executable.
#
################################################################################

cat << 'GUIDE'

╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║           LiteP2P IS AN ANDROID PROJECT - APK INSTALLATION                ║
║                                                                            ║
║  Your LiteP2P is built as an Android APK, not a desktop executable.       ║
║  The APK is already compiled and ready to use!                            ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════════════════════════
PROJECT STRUCTURE
════════════════════════════════════════════════════════════════════════════════

Your project is ANDROID:
  ✓ Language: Kotlin + C++ (JNI)
  ✓ Build system: Gradle (Android Gradle Plugin)
  ✓ Output: APK (Android Package)
  ✓ Built APK: app/build/outputs/apk/debug/app-debug.apk

This is NOT a standalone C++ executable project.
It's a complete Android application.


════════════════════════════════════════════════════════════════════════════════
OPTION 1: VIEW LOGS FROM ALREADY COMPILED APK
════════════════════════════════════════════════════════════════════════════════

The APK is already built! (6.6 MB)

Location:
  /Users/Shiva/StudioProjects/Litep2p/app/build/outputs/apk/debug/app-debug.apk

Verify it exists:
  $ ls -lh /Users/Shiva/StudioProjects/Litep2p/app/build/outputs/apk/debug/app-debug.apk


════════════════════════════════════════════════════════════════════════════════
OPTION 2: INSTALL AND RUN ON ANDROID DEVICE/EMULATOR
════════════════════════════════════════════════════════════════════════════════

You need an Android device or emulator connected.

Check if device is connected:
  $ adb devices

Install APK:
  $ adb install -r /Users/Shiva/StudioProjects/Litep2p/app/build/outputs/apk/debug/app-debug.apk

View logs while running:
  $ adb logcat | grep -i litep2p

Run specific activity:
  $ adb shell am start -n com.litep2p/.MainActivity


════════════════════════════════════════════════════════════════════════════════
OPTION 3: VIEW LOGS FROM GRADLE BUILD (Desktop Terminal)
════════════════════════════════════════════════════════════════════════════════

Rebuild and see logs:
  $ cd /Users/Shiva/StudioProjects/Litep2p
  $ ./gradlew clean assembleDebug --info 2>&1 | tee build.log

View build logs:
  $ cat build.log | grep -i "litep2p\|discovery\|transfer\|error"

Follow build:
  $ tail -f build.log


════════════════════════════════════════════════════════════════════════════════
OPTION 4: RUN UNIT TESTS (If you have them)
════════════════════════════════════════════════════════════════════════════════

Run all tests:
  $ ./gradlew test

Run specific test:
  $ ./gradlew testDebugUnitTest

View test output:
  $ cat app/build/outputs/test_results/debugUnitTest/index.html


════════════════════════════════════════════════════════════════════════════════
OPTION 5: USE DOCKER TO RUN EMULATOR AND SEE LOGS
════════════════════════════════════════════════════════════════════════════════

You already have Docker setup! Use the Docker environment:
  $ cd /Users/Shiva/StudioProjects/Litep2p/docker
  $ bash quickstart.sh start

This runs 5 peer nodes in Docker with complete logging!


════════════════════════════════════════════════════════════════════════════════
IF YOU WANT A STANDALONE EXECUTABLE...
════════════════════════════════════════════════════════════════════════════════

To test the native C++ code directly (without Android):

1. Create a C++ main executable

Create file: app/src/main/cpp/main.cpp

#include <iostream>
#include "litep2p.h"

int main() {
    std::cout << "[INFO] LiteP2P Standalone Executable\n";
    
    // Initialize peer
    LiteP2P::Peer peer;
    peer.initialize();
    
    std::cout << "[DISCOVERY] Starting discovery\n";
    peer.startDiscovery();
    
    std::cout << "[TRANSFER] Sending test packet\n";
    peer.sendPacket("test_data", 9);
    
    std::cout << "[INFO] Peer is running\n";
    
    return 0;
}

2. Update CMakeLists.txt to build executable

add_executable(litep2p_peer app/src/main/cpp/main.cpp)
target_link_libraries(litep2p_peer litep2p_core litep2p_crypto)

3. Build and run:

cd /Users/Shiva/StudioProjects/Litep2p && \
mkdir -p build && cd build && \
cmake .. && \
make -j$(sysctl -n hw.ncpu) && \
./litep2p_peer


════════════════════════════════════════════════════════════════════════════════
SUMMARY - YOUR OPTIONS
════════════════════════════════════════════════════════════════════════════════

Option 1: Run the Docker environment (RECOMMENDED)
  $ cd docker && bash quickstart.sh start
  Shows: 5 peers, discovery, data transfer, routing - all in terminal logs

Option 2: Install APK on Android device/emulator
  $ adb install -r app/build/outputs/apk/debug/app-debug.apk
  $ adb logcat | grep litep2p

Option 3: Rebuild and view build logs
  $ ./gradlew clean assembleDebug --info 2>&1 | tee build.log
  $ grep -i litep2p build.log

Option 4: Create standalone C++ executable
  Create main.cpp and update CMakeLists.txt
  Then build and run as shown above


════════════════════════════════════════════════════════════════════════════════

The EASIEST and BEST way to see all your logs is:

  cd /Users/Shiva/StudioProjects/Litep2p/docker
  bash quickstart.sh start
  bash quickstart.sh monitor

This shows everything you asked for in your terminal!

════════════════════════════════════════════════════════════════════════════════

GUIDE

exit 0
