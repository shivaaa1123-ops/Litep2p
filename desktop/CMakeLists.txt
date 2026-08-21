cmake_minimum_required(VERSION 3.16)
project(LiteP2P_Desktop C CXX)

# Single source of truth for the SDK version (mirrors gradle.properties
# LITEP2P_VERSION). Override with: cmake -DLITEP2P_VERSION=x.y.z ..
if(NOT DEFINED LITEP2P_VERSION)
    set(LITEP2P_VERSION "0.4.0")
endif()

# Derive the ABI version macros so desktop tests exercise the same version
# string/macros as the Android build.
string(REPLACE "." ";" _litep2p_version_parts "${LITEP2P_VERSION}")
list(LENGTH _litep2p_version_parts _litep2p_version_part_count)
if(_litep2p_version_part_count EQUAL 3)
    list(GET _litep2p_version_parts 0 LITEP2P_VERSION_MAJOR)
    list(GET _litep2p_version_parts 1 LITEP2P_VERSION_MINOR)
    list(GET _litep2p_version_parts 2 LITEP2P_VERSION_PATCH)
    add_compile_definitions(
        LITEP2P_VERSION_MAJOR=${LITEP2P_VERSION_MAJOR}
        LITEP2P_VERSION_MINOR=${LITEP2P_VERSION_MINOR}
        LITEP2P_VERSION_PATCH=${LITEP2P_VERSION_PATCH}
        LITEP2P_VERSION_STRING="${LITEP2P_VERSION}"
    )
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optional compile-time module: Proxy / Relay
option(ENABLE_PROXY_MODULE "Enable Proxy (relay) module" ON)

# Optional compile-time module: Multi-hop overlay (LPX2)
# NOTE: declared BEFORE the compile-definitions block below — CMake evaluates
# `if(ENABLE_OVERLAY_MODULE)` at its position, and an undeclared variable
# evaluates to false (silently disabling the module).
option(ENABLE_OVERLAY_MODULE "Enable multi-hop overlay module (LPX2)" ON)

# Single-thread mode: reduces thread count for efficiency
# Enable with: cmake -DSINGLE_THREAD_MODE=ON ..
option(SINGLE_THREAD_MODE "Enable single-thread mode for reduced resource usage" OFF)

# Parser fuzzing (libFuzzer). Requires Clang. Builds desktop/fuzz/* targets.
#   cmake -S desktop -B desktop/build-fuzz -DLITEP2P_FUZZING=ON \
#         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
option(LITEP2P_FUZZING "Build libFuzzer harnesses for the wire parsers" OFF)
option(LITEP2P_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(LITEP2P_TSAN "Enable ThreadSanitizer (cannot be combined with other sanitizers)" OFF)

if(LITEP2P_SANITIZERS AND LITEP2P_TSAN)
    message(FATAL_ERROR "LITEP2P_SANITIZERS and LITEP2P_TSAN cannot be enabled together")
endif()
if(LITEP2P_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()
if(LITEP2P_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=thread)
endif()

# ============================================================================
# BUILD TARGET SELECTION - Pass -DBUILD_TARGET=DESKTOP to build for desktop
# If not passed, defaults to DESKTOP (since this is the desktop CMakeLists)
# ============================================================================
if(NOT DEFINED BUILD_TARGET)
    set(BUILD_TARGET "DESKTOP")
    message(STATUS "BUILD_TARGET not specified, defaulting to: ${BUILD_TARGET}")
endif()

message(STATUS "Build target: ${BUILD_TARGET}")

if(NOT (BUILD_TARGET STREQUAL "DESKTOP"))
    message(FATAL_ERROR "This CMakeLists is for desktop builds only. Use BUILD_TARGET=DESKTOP")
endif()

# Platform detection
if(APPLE)
    message(STATUS "Building for macOS")
    set(PLATFORM "mac")
elseif(UNIX AND NOT APPLE)
    message(STATUS "Building for Linux")
    set(PLATFORM "linux")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# Find packages
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(nlohmann_json REQUIRED)
pkg_check_modules(LIBSODIUM libsodium)

if(NOT LIBSODIUM_FOUND)
    message(FATAL_ERROR "libsodium not found. Install with: brew install libsodium")
endif()

# Desktop-specific compile definitions
# Ensure Android-specific code is NOT compiled
add_compile_definitions(
    BUILD_TARGET_DESKTOP=1
    HAVE_JNI=0
    HAVE_NOISE_PROTOCOL=1
    HAVE_FILE_TRANSFER=1
    HAVE_VOICE_CALL=1
)

if(SINGLE_THREAD_MODE)
    add_compile_definitions(LITEP2P_SINGLE_THREAD_MODE_COMPILE=1)
    message(STATUS "Single-thread mode: ENABLED (reduced thread count)")
else()
    add_compile_definitions(LITEP2P_SINGLE_THREAD_MODE_COMPILE=0)
    message(STATUS "Single-thread mode: DISABLED (normal multi-threaded)")
endif()

if(ENABLE_PROXY_MODULE)
    add_compile_definitions(ENABLE_PROXY_MODULE=1)
else()
    add_compile_definitions(ENABLE_PROXY_MODULE=0)
endif()

if(ENABLE_OVERLAY_MODULE)
    add_compile_definitions(ENABLE_OVERLAY_MODULE=1)
else()
    add_compile_definitions(ENABLE_OVERLAY_MODULE=0)
endif()

# On Linux, find uuid
if(UNIX AND NOT APPLE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(UUID uuid)
    if(NOT UUID_FOUND)
        message(WARNING "UUID library not found. Install with: sudo apt-get install uuid-dev")
    endif()
endif()

# ============================================================================
# DESKTOP BUILD - SAME P2P ENGINE AS ANDROID, BUT OUTPUTS LOGS TO TERMINAL
# ============================================================================

set(DESKTOP_SOURCES
    src/main.cpp
    src/p2p_node.cpp
    src/terminal_cli.cpp
)

# Core logging (uses conditional compilation for platform-specific output)
set(CORE_SOURCES
    ../litep2p-core/src/main/cpp/modules/corep2p/core/src/logger.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/core/src/device_utils.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/monitoring/src/anomaly_reporter.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/monitoring/src/crash_handler.cpp
)

# Session Manager and related components
set(SESSION_SOURCES
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/session_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/event_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/unified_event_loop.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/peer_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/peer_state_machine.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/nat_traversal_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/engine_handler.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/message_handler.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/wire_codec.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/peer_lifecycle_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/maintenance_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/local_peer_db.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/sqlite3_dyn.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/session_cache.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/tier_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/rugged_recovery_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/session/src/reliable_send_manager.cpp
)

# Transport layer
set(TRANSPORT_SOURCES
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/src/connection_manager.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/src/udp_connection_manager.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/src/tcp_message.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/src/udp_message.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/src/quic_message.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/src/quic_connection_manager.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/src/real_quic_transport.cpp
)

# Security and crypto
set(CRYPTO_SOURCES
    ../litep2p-core/src/main/cpp/modules/corep2p/crypto/src/noise_key_store.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/crypto/src/noise_nk.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/crypto/src/noise_protocol.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/crypto/src/crypto_utils.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/crypto/src/sha1_md5.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/crypto/src/aes.c
)

set(SECURITY_SOURCES
    ../litep2p-core/src/main/cpp/modules/corep2p/security/src/secure_session.cpp
)

# Reactor and event handling
set(REACTOR_SOURCES
    ../litep2p-core/src/main/cpp/modules/corep2p/reactor/src/event_thread_pool.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/reactor/src/epoll_reactor.cpp
)

# Optimization/Routing plugins
set(OPTIMIZATION_SOURCES
    ../litep2p-core/src/main/cpp/modules/plugins/optimization/src/battery_optimizer.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/optimization/src/peer_index.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/optimization/src/message_batcher.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/optimization/src/adaptive_scaler.cpp
)

set(ROUTING_SOURCES
    ../litep2p-core/src/main/cpp/modules/plugins/routing/src/nat_traversal.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/routing/src/nat_stun.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/routing/src/peer_reconnect_policy.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/routing/src/peer_tier_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/routing/src/tier_system_failsafe.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/routing/src/upnp_controller.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/routing/src/turn_client.cpp
)

set(PROXY_SOURCES)
if(ENABLE_PROXY_MODULE)
    set(PROXY_SOURCES
        ../litep2p-core/src/main/cpp/modules/plugins/proxy/src/proxy_endpoint.cpp
    )
endif()

# Multi-hop overlay (LPX2)
set(OVERLAY_SOURCES)
if(ENABLE_OVERLAY_MODULE)
    set(OVERLAY_SOURCES
        ../litep2p-core/src/main/cpp/modules/plugins/overlay/src/overlay_frame.cpp
        ../litep2p-core/src/main/cpp/modules/plugins/overlay/src/overlay_mailbox.cpp
        ../litep2p-core/src/main/cpp/modules/plugins/overlay/src/overlay_router.cpp
    )
endif()

# File transfer
set(FILE_TRANSFER_SOURCES
    ../litep2p-core/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_paths.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_congestion.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_chunks.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_checkpoint.cpp
)

# Voice calls
set(VOICE_CALL_SOURCES
    ../litep2p-core/src/main/cpp/modules/plugins/voice_call/src/voice_call_manager.cpp
)

# Core P2P
set(CORE_P2P_SOURCES
    ../litep2p-core/src/main/cpp/modules/corep2p/core/src/config_manager.cpp
    ../litep2p-core/src/main/cpp/modules/corep2p/core/src/telemetry.cpp
)

# Discovery
set(DISCOVERY_SOURCES
    ../litep2p-core/src/main/cpp/modules/plugins/discovery/src/broadcast_discovery_manager.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/discovery/src/discovery.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/discovery/src/signaling_client.cpp
    ../litep2p-core/src/main/cpp/modules/plugins/discovery/src/peer_cache_lru.cpp
)

# Network OS module (Phase 1 skeleton). Desktop uses the NullPlatformAdapter.
set(NETWORKOS_SOURCES
    ../litep2p-core/src/main/cpp/modules/networkos/runtime/src/NetworkRuntime.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/identity/src/FileIdentityStore.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/scheduler/src/Scheduler.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/platform/desktop/NullPlatformAdapter.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/capability/src/capability.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/session/src/SessionFacade.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/object/src/object_id.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/object/src/envelope.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/object/src/e2e.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/objectstore/src/ObjectStore.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/handoff/src/handoff_frames.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/handoff/src/HandoffManager.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/delivery/src/delivery_frames.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/delivery/src/DeliveryManager.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/anti_entropy/src/anti_entropy_frames.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/anti_entropy/src/AntiEntropyManager.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/replication/src/ReplicaPlanner.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/resources/src/ResourceManager.cpp
    ../litep2p-core/src/main/cpp/modules/networkos/discovery/src/DiscoveryManager.cpp
)

set(ENGINE_SOURCES
    ${CORE_SOURCES}
    ${SESSION_SOURCES}
    ${TRANSPORT_SOURCES}
    ${CRYPTO_SOURCES}
    ${SECURITY_SOURCES}
    ${REACTOR_SOURCES}
    ${OPTIMIZATION_SOURCES}
    ${ROUTING_SOURCES}
    ${FILE_TRANSFER_SOURCES}
    ${VOICE_CALL_SOURCES}
    ${PROXY_SOURCES}
    ${OVERLAY_SOURCES}
    ${CORE_P2P_SOURCES}
    ${DISCOVERY_SOURCES}
    ${NETWORKOS_SOURCES}
    # Public C ABI (litep2p.h) — compiled into the engine so desktop tests can
    # exercise the exact contract integrators use.
    ../litep2p-core/src/main/cpp/src/litep2p_c_api.cpp
)

# ---------------------------------------------------------------------------
# Build the engine once and link it into all desktop binaries/tests.
# This avoids recompiling ${ENGINE_SOURCES} for every target.
# ---------------------------------------------------------------------------

add_library(litep2p_engine STATIC ${ENGINE_SOURCES})

target_include_directories(litep2p_engine PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
    ../litep2p-core/src/main/cpp/include
    ../litep2p-core/src/main/cpp/modules/plugins/discovery/include
    ../litep2p-core/src/main/cpp/modules/corep2p/core/include
    ../litep2p-core/src/main/cpp/modules/corep2p/transport/include
    ../litep2p-core/src/main/cpp/modules/corep2p/reactor/include
    ../litep2p-core/src/main/cpp/modules/corep2p/security/include
    ../litep2p-core/src/main/cpp/modules/corep2p/crypto/include
    ../litep2p-core/src/main/cpp/modules/corep2p/monitoring/include
    ../litep2p-core/src/main/cpp/modules/corep2p/include
    ../litep2p-core/src/main/cpp/modules/plugins/session/include
    ../litep2p-core/src/main/cpp/modules/plugins/session/src
    ../litep2p-core/src/main/cpp/modules/plugins/optimization/include
    ../litep2p-core/src/main/cpp/modules/plugins/routing/include
    ../litep2p-core/src/main/cpp/modules/plugins/file_transfer/include
    ../litep2p-core/src/main/cpp/modules/plugins/voice_call/include
    ../litep2p-core/src/main/cpp/modules/plugins/proxy/include
    ../litep2p-core/src/main/cpp/modules/plugins/overlay/include
    ../litep2p-core/src/main/cpp/modules/networkos/include
    ../litep2p-core/src/main/cpp/modules/networkos/capability/include
    ../litep2p-core/src/main/cpp/modules/networkos/session/include
    ../litep2p-core/src/main/cpp/modules/networkos/object/include
    ../litep2p-core/src/main/cpp/modules/networkos/objectstore/include
    ../litep2p-core/src/main/cpp/modules/networkos/handoff/include
    ../litep2p-core/src/main/cpp/modules/networkos/delivery/include
    ../litep2p-core/src/main/cpp/modules/networkos/anti_entropy/include
    ../litep2p-core/src/main/cpp/modules/networkos/replication/include
    ../litep2p-core/src/main/cpp/modules/networkos/resources/include
    ../litep2p-core/src/main/cpp/modules/networkos/discovery/include
)

target_link_libraries(litep2p_engine PUBLIC
    Threads::Threads
    nlohmann_json::nlohmann_json
    ${LIBSODIUM_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

# wss:// signaling TLS support (optional). Enabled when OpenSSL is available;
# the Android AAR build does not link OpenSSL and compiles the wss:// code path
# out (a wss URL is then rejected with a clear log).
find_package(OpenSSL)
if(OPENSSL_FOUND)
    target_compile_definitions(litep2p_engine PUBLIC HAVE_OPENSSL=1)
    target_link_libraries(litep2p_engine PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "wss:// signaling: ENABLED (OpenSSL found)")
else()
    message(STATUS "wss:// signaling: DISABLED (OpenSSL not found)")
endif()

# ---------------------------------------------------------------------------
# Real QUIC (RFC 9000) via picoquic + picotls (minicrypto).
# Enabled automatically when third_party/picoquic has been built
# (see third_party/README-style notes in CMake output). Disable explicitly
# with -DLITEP2P_ENABLE_REAL_QUIC=OFF.
# ---------------------------------------------------------------------------
option(LITEP2P_ENABLE_REAL_QUIC "Enable real QUIC transport (picoquic)" ON)

set(PICOQUIC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/picoquic")
set(PICOTLS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/picotls")

if(LITEP2P_ENABLE_REAL_QUIC)
    if(NOT EXISTS "${PICOQUIC_ROOT}/build/libpicoquic-core.a" OR
       NOT EXISTS "${PICOTLS_ROOT}/build/libpicotls-core.a" OR
       NOT EXISTS "${PICOTLS_ROOT}/build/libpicotls-minicrypto.a")
        message(WARNING
            "Real QUIC (picoquic) libraries not found under third_party/ - "
            "disabling real QUIC. Build them with:\n"
            "  cd third_party/picotls && cmake -S . -B build -DPTLS_BUILD_TESTS=OFF && make -C build\n"
            "  cd third_party/picoquic && cmake -S . -B build -DWITH_OPENSSL=OFF \\\n"
            "    -Dpicoquic_BUILD_TESTS=OFF -DBUILD_DEMO=OFF -DBUILD_HTTP=OFF \\\n"
            "    -DBUILD_PQBENCH=OFF -DBUILD_LOGLIB=OFF -DBUILD_LOGREADER=OFF \\\n"
            "    -DPTLS_PREFIX=${PICOTLS_ROOT}/build && make -C build")
        set(LITEP2P_ENABLE_REAL_QUIC OFF)
    endif()
endif()

if(LITEP2P_ENABLE_REAL_QUIC)
    add_compile_definitions(LITEP2P_ENABLE_REAL_QUIC=1)

    target_include_directories(litep2p_engine PUBLIC
        ${PICOQUIC_ROOT}
        ${PICOQUIC_ROOT}/picoquic
        ${PICOTLS_ROOT}/include
    )

    # Link order matters: picoquic-log depends on picoquic-core which depends
    # on picotls-core + minicrypto.
    target_link_libraries(litep2p_engine PUBLIC
        ${PICOQUIC_ROOT}/build/libpicoquic-log.a
        ${PICOQUIC_ROOT}/build/libpicoquic-core.a
        ${PICOTLS_ROOT}/build/libpicotls-core.a
        ${PICOTLS_ROOT}/build/libpicotls-minicrypto.a
    )
    message(STATUS "Real QUIC: ENABLED (picoquic + picotls minicrypto)")
endif()

if(UNIX AND NOT APPLE AND UUID_FOUND)
    target_link_libraries(litep2p_engine PUBLIC ${UUID_LIBRARIES})
    target_include_directories(litep2p_engine PUBLIC ${UUID_INCLUDE_DIRS})
endif()

target_compile_options(litep2p_engine PRIVATE -Wall -Wextra -fPIC)

# ---------------------------------------------------------------------------
# Parser fuzzing (LITEP2P_FUZZING=ON, clang only)
# ---------------------------------------------------------------------------
if(LITEP2P_FUZZING)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "LITEP2P_FUZZING requires Clang (libFuzzer). "
                            "Pass -DCMAKE_CXX_COMPILER=clang++.")
    endif()
    # Instrument the whole engine for coverage + sanitizers, but only link
    # libFuzzer into the fuzz executables (not the engine lib).
    target_compile_options(litep2p_engine PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined
        -fno-omit-frame-pointer
        -g
    )
    target_link_options(litep2p_engine PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    message(STATUS "Parser fuzzing ENABLED (libFuzzer + ASan/UBSan)")
endif()

# Create executable
add_executable(litep2p_peer_${PLATFORM} ${DESKTOP_SOURCES})

target_include_directories(litep2p_peer_${PLATFORM} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(litep2p_peer_${PLATFORM} PRIVATE litep2p_engine)

target_compile_options(litep2p_peer_${PLATFORM} PRIVATE -Wall -Wextra -fPIC)

message(STATUS "✓ LiteP2P Desktop (${PLATFORM}) - Same Engine as Android")
message(STATUS "  Target: ${BUILD_TARGET}")
message(STATUS "  Output: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/litep2p_peer_${PLATFORM}")
message(STATUS "  Note: Desktop logger outputs to terminal (no timestamps)")

add_executable(nat_traversal_test tests/nat_traversal_test.cpp)
target_include_directories(nat_traversal_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(nat_traversal_test PRIVATE litep2p_engine)

add_executable(file_transfer_test tests/file_transfer_test.cpp)
target_include_directories(file_transfer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(file_transfer_test PRIVATE litep2p_engine)

add_executable(voice_call_test tests/voice_call_test.cpp)
target_include_directories(voice_call_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(voice_call_test PRIVATE litep2p_engine)

add_executable(crypto_test tests/crypto_test.cpp)
target_include_directories(crypto_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(crypto_test PRIVATE litep2p_engine)

add_executable(session_manager_test tests/session_manager_test.cpp)
target_include_directories(session_manager_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(session_manager_test PRIVATE litep2p_engine)

add_executable(c_api_test tests/c_api_test.cpp)
target_include_directories(c_api_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(c_api_test PRIVATE litep2p_engine)

# Deterministic parser robustness regression (malformed-input corpus). Runs in
# normal CI builds; complements the libFuzzer harnesses in desktop/fuzz/.
add_executable(malformed_input_test tests/malformed_input_test.cpp)
target_include_directories(malformed_input_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(malformed_input_test PRIVATE litep2p_engine)

# Live diagnostic: drives the AnomalyReporter stall detector (see stall_probe.cpp).
add_executable(stall_probe tools/stall_probe.cpp)
target_include_directories(stall_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(stall_probe PRIVATE litep2p_engine)

# Live diagnostic: validates native crash capture + next-run upload (see crash_probe.cpp).
add_executable(crash_probe tools/crash_probe.cpp)
target_include_directories(crash_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(crash_probe PRIVATE litep2p_engine)

# Post-crash symbolizer: resolves crash_*.json backtraces via atos/addr2line.
add_executable(symbolize_crash tools/symbolize_crash.cpp)
target_include_directories(symbolize_crash PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(symbolize_crash PRIVATE litep2p_engine)

add_executable(wan_integration_runner tests/wan_integration_runner.cpp)
target_include_directories(wan_integration_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(wan_integration_runner PRIVATE litep2p_engine)

add_executable(message_size_runner tests/message_size_runner.cpp)
target_include_directories(message_size_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(message_size_runner PRIVATE litep2p_engine)

# Phase 0 measurement harness (idle-cost + latency baseline; not production code)
add_executable(message_latency_runner tests/message_latency_runner.cpp)
target_include_directories(message_latency_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(message_latency_runner PRIVATE litep2p_engine)

# Network OS Phase 1 verification: runtime/identity/scheduler/platform tests.
add_executable(network_runtime_test tests/network_runtime_test.cpp)
target_include_directories(network_runtime_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(network_runtime_test PRIVATE litep2p_engine)

# Network OS Phase 2 verification: capability negotiation + session bounds.
add_executable(capability_negotiation_test tests/capability_negotiation_test.cpp)
target_include_directories(capability_negotiation_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(capability_negotiation_test PRIVATE litep2p_engine)

# Network OS Phase 3 verification: network object envelope + E2E key model.
add_executable(object_envelope_test tests/object_envelope_test.cpp)
target_include_directories(object_envelope_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(object_envelope_test PRIVATE litep2p_engine)

# Network OS Phase 3 verification: SQLite object store.
add_executable(object_store_test tests/object_store_test.cpp)
target_include_directories(object_store_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(object_store_test PRIVATE litep2p_engine)

add_executable(handoff_test tests/handoff_test.cpp)
target_include_directories(handoff_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(handoff_test PRIVATE litep2p_engine)

# Network OS Phase 5 verification: direct delivery + signed receipts.
add_executable(delivery_test tests/delivery_test.cpp)
target_include_directories(delivery_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(delivery_test PRIVATE litep2p_engine)

# Network OS Phase 6 verification: anti-entropy inventory/WANT reconciliation.
add_executable(anti_entropy_test tests/anti_entropy_test.cpp)
target_include_directories(anti_entropy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(anti_entropy_test PRIVATE litep2p_engine)

# Network OS Phase 7 test: adaptive replication + peer scoring harness.
add_executable(replication_test tests/replication_test.cpp)
target_include_directories(replication_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(replication_test PRIVATE litep2p_engine)

# Network OS Phase 8 test: resource manager + profiles + wakeup budget.
add_executable(resource_manager_test tests/resource_manager_test.cpp)
target_include_directories(resource_manager_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(resource_manager_test PRIVATE litep2p_engine)

# Network OS Phase 9 test: modular discovery + graceful degradation + NAT layering.
add_executable(discovery_manager_test tests/discovery_manager_test.cpp)
target_include_directories(discovery_manager_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(discovery_manager_test PRIVATE litep2p_engine)

# Network OS Phase 3 crash-consistency probe (driven by object_store_kill_test.sh).
add_executable(object_store_kill_probe tools/object_store_kill_probe.cpp)
target_include_directories(object_store_kill_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(object_store_kill_probe PRIVATE litep2p_engine)

# Network OS Phase 5 durable-delivery probe (driven by p5_milestone_scenario.sh):
# proves delivery state + signed receipt survive process death (invariant 4/17).
add_executable(delivery_kill_probe tools/delivery_kill_probe.cpp)
target_include_directories(delivery_kill_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(delivery_kill_probe PRIVATE litep2p_engine)

# Network OS Phase 3 fuzz substitute (Apple clang lacks the libFuzzer runtime;
# runs the envelope parser against randomized input for --seconds).
add_executable(envelope_fuzz_smoke tools/envelope_fuzz_smoke.cpp)
target_include_directories(envelope_fuzz_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(envelope_fuzz_smoke PRIVATE litep2p_engine)

# Network OS Phase 6 fuzz substitute: runs the anti-entropy frame codecs
# (INVENTORY / OBJECT_WANT) against randomized/bit-flipped/truncated input for
# --seconds (see fuzz_wire_codec.cpp for the libFuzzer coverage).
add_executable(anti_entropy_fuzz_smoke tools/anti_entropy_fuzz_smoke.cpp)
target_include_directories(anti_entropy_fuzz_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(anti_entropy_fuzz_smoke PRIVATE litep2p_engine)

# Network OS Phase 3 performance probe (put/get throughput, open latency,
# size overhead, commit latency).
add_executable(store_bench tools/store_bench.cpp)
target_include_directories(store_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(store_bench PRIVATE litep2p_engine)

# Phase 4 SIGKILL harness probe (carrier-side handoff with durability markers).
add_executable(handoff_kill_probe tools/handoff_kill_probe.cpp)
target_include_directories(handoff_kill_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(handoff_kill_probe PRIVATE litep2p_engine)

# Phase 4 live two-peer handoff tool (real session over loopback).
add_executable(handoff_live tools/handoff_live.cpp)
target_include_directories(handoff_live PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(handoff_live PRIVATE litep2p_engine)

# Network OS Phase 1 SIGKILL restore probe (driven by sigkill_restore_test.sh).
add_executable(network_runtime_kill_probe tools/network_runtime_kill_probe.cpp)
target_include_directories(network_runtime_kill_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(network_runtime_kill_probe PRIVATE litep2p_engine)

if(LITEP2P_ENABLE_REAL_QUIC)
    add_executable(quic_test tests/quic_test.cpp)
    target_include_directories(quic_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(quic_test PRIVATE litep2p_engine)
endif()

if(ENABLE_OVERLAY_MODULE)
    add_executable(overlay_test tests/overlay_test.cpp)
    target_include_directories(overlay_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(overlay_test PRIVATE litep2p_engine)
endif()

if(ENABLE_PROXY_MODULE)
    add_executable(proxy_test tests/proxy_test.cpp)
    target_include_directories(proxy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(proxy_test PRIVATE litep2p_engine)

    add_executable(proxy_stdio
        tools/proxy_stdio.cpp
        ../litep2p-core/src/main/cpp/modules/plugins/proxy/src/proxy_endpoint.cpp
        ../litep2p-core/src/main/cpp/modules/plugins/session/src/wire_codec.cpp
        ../litep2p-core/src/main/cpp/modules/corep2p/core/src/logger.cpp
    )

    target_include_directories(proxy_stdio PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${LIBSODIUM_INCLUDE_DIRS}
        ../litep2p-core/src/main/cpp/modules/corep2p/core/include
        ../litep2p-core/src/main/cpp/modules/plugins/session/include
        ../litep2p-core/src/main/cpp/modules/plugins/session/src
        ../litep2p-core/src/main/cpp/modules/plugins/proxy/include
    )

    target_link_libraries(proxy_stdio PRIVATE
        Threads::Threads
        nlohmann_json::nlohmann_json
        ${LIBSODIUM_LIBRARIES}
    )

    if(UNIX AND NOT APPLE AND UUID_FOUND)
        target_link_libraries(proxy_stdio PRIVATE ${UUID_LIBRARIES})
        target_include_directories(proxy_stdio PRIVATE ${UUID_INCLUDE_DIRS})
    endif()

    add_executable(proxy_netbench
        tools/proxy_netbench.cpp
    )

    target_include_directories(proxy_netbench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(proxy_netbench PRIVATE litep2p_engine)

    # Local SOCKS5 endpoint over the proxy tunnel (exit-node mode)
    add_executable(proxy_socks5
        tools/proxy_socks5.cpp
    )

    target_include_directories(proxy_socks5 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(proxy_socks5 PRIVATE litep2p_engine)

    # Interactive proxy peer test tool for network transition scenarios
    add_executable(proxy_peer_test
        tools/proxy_peer_test.cpp
    )

    target_include_directories(proxy_peer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(proxy_peer_test PRIVATE litep2p_engine)
endif()

# ---------------------------------------------------------------------------
# libFuzzer harnesses for the wire parsers (desktop/fuzz/). Build with:
#   cmake -S desktop -B desktop/build-fuzz -DLITEP2P_FUZZING=ON \
#         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
#   cmake --build desktop/build-fuzz --target fuzz_wire_codec fuzz_discovery \
#         fuzz_noise_handshake
# Then run, e.g.: ./desktop/build-fuzz/bin/fuzz_wire_codec -runs=100000
# ---------------------------------------------------------------------------
if(LITEP2P_FUZZING)
    set(FUZZ_TARGETS fuzz_wire_codec fuzz_discovery fuzz_noise_handshake)
    foreach(target IN LISTS FUZZ_TARGETS)
        # EXCLUDE_FROM_ALL: building `all` never requires libFuzzer (Apple clang
        # lacks the runtime); build each fuzz target explicitly.
        add_executable(${target} EXCLUDE_FROM_ALL fuzz/${target}.cpp)
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(${target} PRIVATE litep2p_engine)
        target_compile_options(${target} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer
            -g
        )
        target_link_options(${target} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer
        )
    endforeach()
endif()

