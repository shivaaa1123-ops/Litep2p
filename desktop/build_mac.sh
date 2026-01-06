#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔════════════════════════════════════════════════════╗"
echo "║    LiteP2P Desktop - macOS Build Script           ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Parse command line arguments
SINGLE_THREAD_MODE="OFF"
for arg in "$@"; do
    case $arg in
        --single-thread)
            SINGLE_THREAD_MODE="ON"
            shift
            ;;
        --help|-h)
            echo "Usage: ./build_mac.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --single-thread   Enable single-thread mode (10 threads vs 18)"
            echo "  --help, -h        Show this help message"
            echo ""
            exit 0
            ;;
    esac
done

# Check for cmake
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}[✗] CMake not found${NC}"
    echo "Install with: brew install cmake"
    exit 1
fi

echo -e "${BLUE}[→] CMake version:${NC} $(cmake --version | head -n1)"
if [ "$SINGLE_THREAD_MODE" = "ON" ]; then
    echo -e "${YELLOW}[→] Single-thread mode: ENABLED (reduced thread count)${NC}"
else
    echo -e "${BLUE}[→] Single-thread mode: disabled (use --single-thread to enable)${NC}"
fi
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create build directory
BUILD_DIR="$SCRIPT_DIR/build_mac"
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${BLUE}[→] Creating build directory...${NC}"
    mkdir -p "$BUILD_DIR"
fi

# Navigate to build directory
cd "$BUILD_DIR"

# Generate build files WITH DESKTOP BUILD TARGET
echo -e "${BLUE}[→] Generating build files for DESKTOP...${NC}"
cmake "$SCRIPT_DIR" -DCMAKE_BUILD_TYPE=Release -DBUILD_TARGET=DESKTOP -DSINGLE_THREAD_MODE=$SINGLE_THREAD_MODE

if [ $? -ne 0 ]; then
    echo -e "${RED}[✗] CMake generation failed${NC}"
    exit 1
fi

echo ""

# Compile
echo -e "${BLUE}[→] Compiling (Desktop - No Android/JNI)...${NC}"
NPROC=$(sysctl -n hw.ncpu)
make -j${NPROC}

if [ $? -ne 0 ]; then
    echo -e "${RED}[✗] Build failed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}[✓] Build successful!${NC}"
echo -e "${GREEN}[✓] Output: $(pwd)/bin/litep2p_peer_mac${NC}"
echo ""
echo "Run with:"
echo "  ./bin/litep2p_peer_mac --port 30001"
echo ""
echo "Note: Android/JNI code was NOT compiled (BUILD_TARGET=DESKTOP)"
echo ""

