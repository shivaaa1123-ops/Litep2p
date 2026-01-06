# litep2p Modular Build System
# Master CMakeLists.txt for Core P2P + Plugins Architecture

cmake_minimum_required(VERSION 3.22.1)
project("litep2p")

# ==========================================================================
# OPTIONAL MODULES
# ==========================================================================

option(ENABLE_PROXY_MODULE "Enable Proxy (relay) module" ON)

if(ENABLE_PROXY_MODULE)
    add_compile_definitions(ENABLE_PROXY_MODULE=1)
else()
    add_compile_definitions(ENABLE_PROXY_MODULE=0)
endif()

# Position independent code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Add include path for nlohmann json
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)

# Check for required libraries
find_library(log-lib log)
if(NOT log-lib)
    message(WARNING "⚠ log library not found (Android NDK not available). Continuing with native build...")
    set(log-lib "")
endif()

find_library(sodium-lib sodium)
set(HAVE_SODIUM FALSE)
if(sodium-lib)
    set(HAVE_SODIUM TRUE)
    message(STATUS "✓ libsodium found: ${sodium-lib}")
else()
    message(WARNING "✗ libsodium not found. Noise Protocol will not be compiled.")
endif()

# ============================================================================
# CORE P2P LAYERS (Foundation + Infrastructure + Core Services)
# ============================================================================

# Layer 1: Foundation (no dependencies)
add_subdirectory(corep2p/core)

# Layer 2: Infrastructure (depends on CORE)
add_subdirectory(corep2p/crypto)
add_subdirectory(corep2p/reactor)

# Layer 3: Core Services (depends on infrastructure)
add_subdirectory(corep2p/transport)
add_subdirectory(corep2p/security)

# Aggregated Parent Module: CoreP2P (combines all 5 core layers)
add_subdirectory(corep2p)

# ============================================================================
# PLUGINS (Optional extension modules)
# ============================================================================

# Layer 4: Orchestration Plugins (coordinates lower layers)
add_subdirectory(plugins/discovery)
add_subdirectory(plugins/session)
add_subdirectory(plugins/routing)
add_subdirectory(plugins/optimization)
add_subdirectory(plugins/file_transfer)

if(ENABLE_PROXY_MODULE)
    add_subdirectory(plugins/proxy)
    # Session owns message dispatch, so it pulls in proxy objects when enabled.
    target_link_libraries(litep2p_session PUBLIC litep2p_proxy)
endif()

# Layer 5: Interface Plugin (Android/Kotlin interop)
add_subdirectory(plugins/jni)

# ============================================================================
# Create final litep2p library with CoreP2P aggregation
# ============================================================================

add_library(litep2p SHARED
    $<TARGET_OBJECTS:litep2p_corep2p>
)

# Link all module dependencies
target_link_libraries(litep2p
    ${log-lib}
    litep2p_session
)

if(HAVE_SODIUM)
    target_link_libraries(litep2p ${sodium-lib})
    add_compile_definitions(HAVE_NOISE_PROTOCOL=1)
else()
    add_compile_definitions(HAVE_NOISE_PROTOCOL=0)
endif()

# Set C++ standard and properties
set_target_properties(litep2p PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p PRIVATE
    -Wall -Wextra -Wpedantic
)

# Build information
message(STATUS "")
message(STATUS "════════════════════════════════════════════════════════════")
message(STATUS "  LiteP2P: Core + Plugins Architecture")
message(STATUS "════════════════════════════════════════════════════════════")
message(STATUS "  C++ Standard: 17")
message(STATUS "  Noise Protocol: ${HAVE_NOISE_PROTOCOL}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "  CORE P2P Layers:")
message(STATUS "    ✓ litep2p_core (Foundation)")
message(STATUS "    ✓ litep2p_crypto (Infrastructure)")
message(STATUS "    ✓ litep2p_reactor (Infrastructure)")
message(STATUS "    ✓ litep2p_transport (Core Services)")
message(STATUS "    ✓ litep2p_security (Core Services)")
message(STATUS "    ✓ litep2p_corep2p (Aggregator)")
message(STATUS "")
message(STATUS "  PLUGINS (Optional):")
message(STATUS "    ✓ litep2p_discovery (Peer discovery)")
message(STATUS "    ✓ litep2p_session (Session management)")
message(STATUS "    ✓ litep2p_routing (NAT traversal)")
message(STATUS "    ✓ litep2p_optimization (Battery/CPU optimization)")
message(STATUS "    ✓ litep2p_file_transfer (File transfer)")
message(STATUS "    ✓ litep2p_jni (Android/Kotlin interop)")

if(ENABLE_PROXY_MODULE)
    message(STATUS "    ✓ litep2p_proxy (Proxy / Relay)")
else()
    message(STATUS "    - litep2p_proxy (Proxy / Relay) [DISABLED]")
endif()
message(STATUS "")
message(STATUS "  Final Library: litep2p (shared)")
message(STATUS "════════════════════════════════════════════════════════════")
message(STATUS "")
