#!/bin/bash

################################################################################
#
# LiteP2P Quick Build and Run Script
#
# Simply execute this script to build and run the LiteP2P executable
# with full logging output to terminal
#
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

################################################################################
# Main Execution
################################################################################

log_info "LiteP2P Standalone Build and Run"
log_info "=================================="

# Get project root
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="$PROJECT_ROOT/build"

log_info "Project Root: $PROJECT_ROOT"

# Create build directory
log_info "Creating build directory..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Run CMake
log_info "Running CMake with Debug mode..."
cmake -DCMAKE_BUILD_TYPE=Debug "$PROJECT_ROOT" || {
    log_error "CMake failed"
    exit 1
}

# Build
log_info "Building project (using all CPU cores)..."
make -j$(nproc) || {
    log_error "Build failed"
    exit 1
}

log_success "Build completed successfully!"

# Find executable
log_info "Looking for executable..."
EXECUTABLE=$(find . -type f -executable -name "*litep2p*" -o -name "*peer*" 2>/dev/null | head -1)

if [ -z "$EXECUTABLE" ]; then
    log_error "Could not find executable"
    log_info "Available files:"
    ls -la
    exit 1
fi

log_success "Found executable: $EXECUTABLE"

# Run
log_info "Running executable..."
log_info "====================================="
log_info "Starting LiteP2P Peer"
log_info "====================================="
echo ""

# Run with output redirection for both stdout and stderr
"$EXECUTABLE" 2>&1 || true

echo ""
log_info "====================================="
log_info "Execution finished"
log_info "====================================="
