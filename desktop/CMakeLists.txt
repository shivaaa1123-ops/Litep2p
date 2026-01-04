cmake_minimum_required(VERSION 3.16)
project(LiteP2P_Desktop C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optional compile-time module: Proxy / Relay
option(ENABLE_PROXY_MODULE "Enable Proxy (relay) module" ON)

# Single-thread mode: reduces thread count for efficiency
# Enable with: cmake -DSINGLE_THREAD_MODE=ON ..
option(SINGLE_THREAD_MODE "Enable single-thread mode for reduced resource usage" OFF)

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
    ../app/src/main/cpp/modules/corep2p/core/src/logger.cpp
    ../app/src/main/cpp/modules/corep2p/core/src/device_utils.cpp
)

# Session Manager and related components
set(SESSION_SOURCES
    ../app/src/main/cpp/modules/plugins/session/src/session_manager.cpp
    ../app/src/main/cpp/modules/plugins/session/src/event_manager.cpp
    ../app/src/main/cpp/modules/plugins/session/src/unified_event_loop.cpp
    ../app/src/main/cpp/modules/plugins/session/src/peer_manager.cpp
    ../app/src/main/cpp/modules/plugins/session/src/peer_state_machine.cpp
    ../app/src/main/cpp/modules/plugins/session/src/nat_traversal_manager.cpp
    ../app/src/main/cpp/modules/plugins/session/src/engine_handler.cpp
    ../app/src/main/cpp/modules/plugins/session/src/message_handler.cpp
    ../app/src/main/cpp/modules/plugins/session/src/wire_codec.cpp
    ../app/src/main/cpp/modules/plugins/session/src/peer_lifecycle_manager.cpp
    ../app/src/main/cpp/modules/plugins/session/src/maintenance_manager.cpp
    ../app/src/main/cpp/modules/plugins/session/src/local_peer_db.cpp
    ../app/src/main/cpp/modules/plugins/session/src/sqlite3_dyn.cpp
    ../app/src/main/cpp/modules/plugins/session/src/session_cache.cpp
    ../app/src/main/cpp/modules/plugins/session/src/tier_manager.cpp
)

# Transport layer
set(TRANSPORT_SOURCES
    ../app/src/main/cpp/modules/corep2p/transport/src/connection_manager.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/udp_connection_manager.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/network.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/batch_connection_manager.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/multi_socket_manager.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/tcp_message.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/udp_message.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/quic_message.cpp
    ../app/src/main/cpp/modules/corep2p/transport/src/quic_connection_manager.cpp
)

# Security and crypto
set(CRYPTO_SOURCES
    ../app/src/main/cpp/modules/corep2p/crypto/src/noise_key_store.cpp
    ../app/src/main/cpp/modules/corep2p/crypto/src/noise_nk.cpp
    ../app/src/main/cpp/modules/corep2p/crypto/src/noise_protocol.cpp
    ../app/src/main/cpp/modules/corep2p/crypto/src/crypto_utils.cpp
    ../app/src/main/cpp/modules/corep2p/crypto/src/aes.cpp
    ../app/src/main/cpp/modules/corep2p/crypto/src/aes.c
)

set(SECURITY_SOURCES
    ../app/src/main/cpp/modules/corep2p/security/src/secure_session.cpp
)

# Reactor and event handling
set(REACTOR_SOURCES
    ../app/src/main/cpp/modules/corep2p/reactor/src/event_thread_pool.cpp
    ../app/src/main/cpp/modules/corep2p/reactor/src/epoll_reactor.cpp
)

# Optimization/Routing plugins
set(OPTIMIZATION_SOURCES
    ../app/src/main/cpp/modules/plugins/optimization/src/battery_optimizer.cpp
    ../app/src/main/cpp/modules/plugins/optimization/src/peer_index.cpp
    ../app/src/main/cpp/modules/plugins/optimization/src/message_batcher.cpp
    ../app/src/main/cpp/modules/plugins/optimization/src/adaptive_scaler.cpp
)

set(ROUTING_SOURCES
    ../app/src/main/cpp/modules/plugins/routing/src/nat_traversal.cpp
    ../app/src/main/cpp/modules/plugins/routing/src/nat_stun.cpp
    ../app/src/main/cpp/modules/plugins/routing/src/peer_reconnect_policy.cpp
    ../app/src/main/cpp/modules/plugins/routing/src/peer_tier_manager.cpp
    ../app/src/main/cpp/modules/plugins/routing/src/tier_system_failsafe.cpp
    ../app/src/main/cpp/modules/plugins/routing/src/upnp_controller.cpp
    ../app/src/main/cpp/modules/plugins/routing/src/turn_client.cpp
)

set(PROXY_SOURCES)
if(ENABLE_PROXY_MODULE)
    set(PROXY_SOURCES
        ../app/src/main/cpp/modules/plugins/proxy/src/proxy_endpoint.cpp
    )
endif()

# File transfer
set(FILE_TRANSFER_SOURCES
    ../app/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_manager.cpp
    ../app/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_paths.cpp
    ../app/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_congestion.cpp
    ../app/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_chunks.cpp
    ../app/src/main/cpp/modules/plugins/file_transfer/src/file_transfer_checkpoint.cpp
)

# Core P2P
set(CORE_P2P_SOURCES
    ../app/src/main/cpp/modules/corep2p/core/src/config_manager.cpp
    ../app/src/main/cpp/modules/corep2p/core/src/telemetry.cpp
)

# Discovery
set(DISCOVERY_SOURCES
    ../app/src/main/cpp/modules/plugins/discovery/src/broadcast_discovery_manager.cpp
    ../app/src/main/cpp/modules/plugins/discovery/src/discovery.cpp
    ../app/src/main/cpp/modules/plugins/discovery/src/signaling_client.cpp
    ../app/src/main/cpp/modules/plugins/discovery/src/peer_cache_lru.cpp
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
    ${PROXY_SOURCES}
    ${CORE_P2P_SOURCES}
    ${DISCOVERY_SOURCES}
)

# ---------------------------------------------------------------------------
# Build the engine once and link it into all desktop binaries/tests.
# This avoids recompiling ${ENGINE_SOURCES} for every target.
# ---------------------------------------------------------------------------

add_library(litep2p_engine STATIC ${ENGINE_SOURCES})

target_include_directories(litep2p_engine PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
    ../app/src/main/cpp/modules/plugins/discovery/include
    ../app/src/main/cpp/modules/corep2p/core/include
    ../app/src/main/cpp/modules/corep2p/transport/include
    ../app/src/main/cpp/modules/corep2p/reactor/include
    ../app/src/main/cpp/modules/corep2p/security/include
    ../app/src/main/cpp/modules/corep2p/crypto/include
    ../app/src/main/cpp/modules/corep2p/include
    ../app/src/main/cpp/modules/plugins/session/include
    ../app/src/main/cpp/modules/plugins/session/src
    ../app/src/main/cpp/modules/plugins/optimization/include
    ../app/src/main/cpp/modules/plugins/routing/include
    ../app/src/main/cpp/modules/plugins/file_transfer/include
    ../app/src/main/cpp/modules/plugins/proxy/include
)

target_link_libraries(litep2p_engine PUBLIC
    Threads::Threads
    nlohmann_json::nlohmann_json
    ${LIBSODIUM_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

if(UNIX AND NOT APPLE AND UUID_FOUND)
    target_link_libraries(litep2p_engine PUBLIC ${UUID_LIBRARIES})
    target_include_directories(litep2p_engine PUBLIC ${UUID_INCLUDE_DIRS})
endif()

target_compile_options(litep2p_engine PRIVATE -Wall -Wextra -fPIC)

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

add_executable(crypto_test tests/crypto_test.cpp)
target_include_directories(crypto_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(crypto_test PRIVATE litep2p_engine)

add_executable(session_manager_test tests/session_manager_test.cpp)
target_include_directories(session_manager_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(session_manager_test PRIVATE litep2p_engine)

add_executable(wan_integration_runner tests/wan_integration_runner.cpp)
target_include_directories(wan_integration_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(wan_integration_runner PRIVATE litep2p_engine)

add_executable(message_size_runner tests/message_size_runner.cpp)
target_include_directories(message_size_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(message_size_runner PRIVATE litep2p_engine)

if(ENABLE_PROXY_MODULE)
    add_executable(proxy_test tests/proxy_test.cpp)
    target_include_directories(proxy_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(proxy_test PRIVATE litep2p_engine)

    add_executable(proxy_stdio
        tools/proxy_stdio.cpp
        ../app/src/main/cpp/modules/plugins/proxy/src/proxy_endpoint.cpp
        ../app/src/main/cpp/modules/plugins/session/src/wire_codec.cpp
        ../app/src/main/cpp/modules/corep2p/core/src/logger.cpp
    )

    target_include_directories(proxy_stdio PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${LIBSODIUM_INCLUDE_DIRS}
        ../app/src/main/cpp/modules/corep2p/core/include
        ../app/src/main/cpp/modules/plugins/session/include
        ../app/src/main/cpp/modules/plugins/session/src
        ../app/src/main/cpp/modules/plugins/proxy/include
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

