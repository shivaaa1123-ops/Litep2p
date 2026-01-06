#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "╔════════════════════════════════════════════════════╗"
echo "║   LiteP2P Desktop - Linux Build Script            ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Check for cmake
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}[✗] CMake not found${NC}"
    echo "Install with: sudo apt-get install cmake"
    exit 1
fi

echo -e "${BLUE}[→] CMake version:${NC} $(cmake --version | head -n1)"

# Check for compiler
if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
    echo -e "${RED}[✗] C++ compiler not found${NC}"
    echo "Install with: sudo apt-get install build-essential"
    exit 1
fi

echo ""

# Create build directory
BUILD_DIR="build_linux"
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${BLUE}[→] Creating build directory...${NC}"
    mkdir -p "$BUILD_DIR"
fi

# Navigate to build directory
cd "$BUILD_DIR"

# Generate build files WITH DESKTOP BUILD TARGET
echo -e "${BLUE}[→] Generating build files for DESKTOP...${NC}"
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TARGET=DESKTOP

if [ $? -ne 0 ]; then
    echo -e "${RED}[✗] CMake generation failed${NC}"
    exit 1
fi

echo ""

# Compile
echo -e "${BLUE}[→] Compiling (Desktop - No Android/JNI)...${NC}"
NPROC=$(nproc)
make -j${NPROC}

if [ $? -ne 0 ]; then
    echo -e "${RED}[✗] Build failed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}[✓] Build successful!${NC}"
echo -e "${GREEN}[✓] Output: $(pwd)/bin/litep2p_peer_linux${NC}"
echo ""
echo "Run with:"
echo "  ./bin/litep2p_peer_linux --port 30001"
echo ""
echo "Note: Android/JNI code was NOT compiled (BUILD_TARGET=DESKTOP)"
echo ""

