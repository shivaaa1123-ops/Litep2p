# CMakeLists.txt for LiteP2P Android Project

cmake_minimum_required(VERSION 3.22.1)

# Project name and version
if(NOT DEFINED LITEP2P_VERSION)
    set(LITEP2P_VERSION "0.3.0")
endif()
project(litep2p VERSION ${LITEP2P_VERSION})

# Derive the ABI version macros from the single LITEP2P_VERSION string so the
# engine reports exactly the same version as the Maven publication.
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

# Module Configuration Options - Enable/Disable features
option(LITEP2P_ENABLE_NETWORK_TRAVERSAL "Enable NAT traversal and network traversal features" ON)
option(LITEP2P_ENABLE_NOISE_PROTOCOL "Enable Noise protocol for encrypted communication" ON)
option(LITEP2P_ENABLE_DISCOVERY "Enable peer discovery service" ON)
option(LITEP2P_ENABLE_FILE_TRANSFER "Enable file transfer capabilities" ON)
option(LITEP2P_ENABLE_OPTIMIZATION "Enable battery and network optimization" ON)
option(LITEP2P_ENABLE_ROUTING "Enable routing capabilities" ON)

# Optional compile-time module: Proxy / Relay
option(ENABLE_PROXY_MODULE "Enable Proxy (relay) module" ON)

# Optional compile-time module: Multi-hop overlay (LPX2)
option(ENABLE_OVERLAY_MODULE "Enable multi-hop overlay module (LPX2)" ON)

# LPX2 sealing requires libsodium; if Noise is compiled out, force overlay off.
if(ENABLE_OVERLAY_MODULE AND NOT LITEP2P_ENABLE_NOISE_PROTOCOL)
    set(ENABLE_OVERLAY_MODULE OFF)
    message(STATUS "Overlay module requires Noise/libsodium; disabled.")
endif()

# Single-thread mode: reduces thread count for efficiency
option(SINGLE_THREAD_MODE "Enable single-thread mode for reduced resource usage" OFF)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compile definitions based on configuration
if(LITEP2P_ENABLE_NETWORK_TRAVERSAL)
    add_compile_definitions(HAVE_NETWORK_TRAVERSAL)
endif()

if(LITEP2P_ENABLE_NOISE_PROTOCOL)
    add_compile_definitions(HAVE_NOISE_PROTOCOL)
endif()

if(LITEP2P_ENABLE_DISCOVERY)
    add_compile_definitions(HAVE_DISCOVERY)
endif()

if(LITEP2P_ENABLE_FILE_TRANSFER)
    add_compile_definitions(HAVE_FILE_TRANSFER)
endif()

if(LITEP2P_ENABLE_OPTIMIZATION)
    add_compile_definitions(HAVE_OPTIMIZATION)
endif()

if(LITEP2P_ENABLE_ROUTING)
    add_compile_definitions(HAVE_ROUTING)
endif()

# Propagate proxy module toggle as a numeric macro for conditional compilation.
if(ENABLE_PROXY_MODULE)
    add_compile_definitions(ENABLE_PROXY_MODULE=1)
else()
    add_compile_definitions(ENABLE_PROXY_MODULE=0)
endif()

# Propagate overlay module toggle the same way.
if(ENABLE_OVERLAY_MODULE)
    add_compile_definitions(ENABLE_OVERLAY_MODULE=1)
else()
    add_compile_definitions(ENABLE_OVERLAY_MODULE=0)
endif()

# Single-thread mode compile definition
if(SINGLE_THREAD_MODE)
    add_compile_definitions(LITEP2P_SINGLE_THREAD_MODE_COMPILE=1)
    message(STATUS "Single-thread mode: ENABLED")
else()
    message(STATUS "Single-thread mode: DISABLED")
endif()

# Add compile definitions for JNI
add_compile_definitions(HAVE_JNI)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/crypto/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/reactor/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/transport/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/security/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/session/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/overlay/include
)

if(ENABLE_PROXY_MODULE)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/proxy/include)
endif()

if(LITEP2P_ENABLE_DISCOVERY)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/discovery/include)
endif()

if(LITEP2P_ENABLE_ROUTING)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/routing/include)
endif()

if(LITEP2P_ENABLE_OPTIMIZATION)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/optimization/include)
endif()

if(LITEP2P_ENABLE_FILE_TRANSFER)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/file_transfer/include)
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/jni/include
)

# CoreP2P library
# NOTE: CONFIGURE_DEPENDS makes CMake re-glob at build time. Without it, adding or
# deleting a source file leaves a stale Ninja graph that still compiles removed files.
file(GLOB_RECURSE COREP2P_SOURCES CONFIGURE_DEPENDS
    "modules/corep2p/core/src/*.cpp"
    "modules/corep2p/crypto/src/*.cpp"
    "modules/corep2p/crypto/src/*.c"
    "modules/corep2p/reactor/src/*.cpp"
    "modules/corep2p/transport/src/*.cpp"
    "modules/corep2p/security/src/*.cpp"
)

# If Noise is disabled, don't compile the libsodium-dependent sources.
if(NOT LITEP2P_ENABLE_NOISE_PROTOCOL)
    list(FILTER COREP2P_SOURCES EXCLUDE REGEX ".*/noise_.*\\.(c|cpp)$")
endif()

add_library(litep2p_corep2p STATIC ${COREP2P_SOURCES})
target_link_libraries(litep2p_corep2p PUBLIC)

# Add missing static libraries for modules
file(GLOB_RECURSE CRYPTO_SOURCES CONFIGURE_DEPENDS "modules/corep2p/crypto/src/*.cpp" "modules/corep2p/crypto/src/*.c")
if(NOT LITEP2P_ENABLE_NOISE_PROTOCOL)
    list(FILTER CRYPTO_SOURCES EXCLUDE REGEX ".*/noise_.*\\.(c|cpp)$")
endif()
add_library(litep2p_crypto STATIC ${CRYPTO_SOURCES})
target_link_libraries(litep2p_crypto PUBLIC)

# Add missing static libraries for modules
file(GLOB_RECURSE SECURITY_SOURCES CONFIGURE_DEPENDS "modules/corep2p/security/src/*.cpp")
add_library(litep2p_security STATIC ${SECURITY_SOURCES})
target_link_libraries(litep2p_security PUBLIC)

file(GLOB_RECURSE REACTOR_SOURCES CONFIGURE_DEPENDS "modules/corep2p/reactor/src/*.cpp")
add_library(litep2p_reactor STATIC ${REACTOR_SOURCES})
target_link_libraries(litep2p_reactor PUBLIC)

file(GLOB_RECURSE TRANSPORT_SOURCES CONFIGURE_DEPENDS "modules/corep2p/transport/src/*.cpp")
add_library(litep2p_transport STATIC ${TRANSPORT_SOURCES})
target_link_libraries(litep2p_transport PUBLIC)

# Plugin libraries
if(LITEP2P_ENABLE_DISCOVERY)
    file(GLOB_RECURSE DISCOVERY_SOURCES CONFIGURE_DEPENDS "modules/plugins/discovery/src/*.cpp")
    add_library(litep2p_discovery STATIC ${DISCOVERY_SOURCES})
    target_link_libraries(litep2p_discovery litep2p_corep2p)
endif()

if(LITEP2P_ENABLE_ROUTING)
    file(GLOB_RECURSE ROUTING_SOURCES CONFIGURE_DEPENDS "modules/plugins/routing/src/*.cpp")
    add_library(litep2p_routing STATIC ${ROUTING_SOURCES})
    target_link_libraries(litep2p_routing litep2p_corep2p)
endif()

# Session library is always required (core functionality)
set(SESSION_SOURCES
    "modules/plugins/session/src/session_manager.cpp"
    "modules/plugins/session/src/engine_handler.cpp"
    "modules/plugins/session/src/session_cache.cpp"
    "modules/plugins/session/src/peer_manager.cpp"
    "modules/plugins/session/src/event_manager.cpp"
    "modules/plugins/session/src/unified_event_loop.cpp"
    "modules/plugins/session/src/peer_state_machine.cpp"
    "modules/plugins/session/src/nat_traversal_manager.cpp"
    "modules/plugins/session/src/tier_manager.cpp"
    "modules/plugins/session/src/message_handler.cpp"
    "modules/plugins/session/src/wire_codec.cpp"
    "modules/plugins/session/src/peer_lifecycle_manager.cpp"
    "modules/plugins/session/src/maintenance_manager.cpp"
    "modules/plugins/session/src/local_peer_db.cpp"
    "modules/plugins/session/src/sqlite3_dyn.cpp"
    "modules/plugins/session/src/rugged_recovery_manager.cpp"
)
add_library(litep2p_session STATIC ${SESSION_SOURCES})
target_link_libraries(litep2p_session litep2p_corep2p)

if(ENABLE_PROXY_MODULE)
    file(GLOB_RECURSE PROXY_SOURCES CONFIGURE_DEPENDS "modules/plugins/proxy/src/*.cpp")
    add_library(litep2p_proxy STATIC ${PROXY_SOURCES})
    target_link_libraries(litep2p_proxy litep2p_corep2p)
    target_include_directories(litep2p_proxy PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/proxy/include
        ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/session/include
    )
    target_link_libraries(litep2p_session litep2p_proxy)
endif()

if(ENABLE_OVERLAY_MODULE)
    file(GLOB_RECURSE OVERLAY_SOURCES CONFIGURE_DEPENDS "modules/plugins/overlay/src/*.cpp")
    add_library(litep2p_overlay STATIC ${OVERLAY_SOURCES})
    target_link_libraries(litep2p_overlay litep2p_corep2p)
    target_include_directories(litep2p_overlay PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/overlay/include
        ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/session/include
        ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/core/include
        ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/crypto/include
    )
    target_link_libraries(litep2p_session litep2p_overlay)
endif()

if(LITEP2P_ENABLE_DISCOVERY)
    target_link_libraries(litep2p_session litep2p_discovery)
endif()

if(LITEP2P_ENABLE_ROUTING)
    target_link_libraries(litep2p_session litep2p_routing)
endif()

if(LITEP2P_ENABLE_OPTIMIZATION)
    file(GLOB_RECURSE OPTIMIZATION_SOURCES CONFIGURE_DEPENDS "modules/plugins/optimization/src/*.cpp")
    add_library(litep2p_optimization STATIC ${OPTIMIZATION_SOURCES})
    target_link_libraries(litep2p_optimization litep2p_corep2p)
endif()

if(LITEP2P_ENABLE_FILE_TRANSFER)
    file(GLOB_RECURSE FILE_TRANSFER_SOURCES CONFIGURE_DEPENDS "modules/plugins/file_transfer/src/*.cpp")
    add_library(litep2p_file_transfer STATIC ${FILE_TRANSFER_SOURCES})
    target_link_libraries(litep2p_file_transfer litep2p_corep2p)
endif()

# Add prebuilt libsodium for current ABI (required when Noise is enabled).
set(LIBSODIUM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/libsodium")
set(LIBSODIUM_LIB "")
set(LIBSODIUM_INCLUDE "")

if(LITEP2P_ENABLE_NOISE_PROTOCOL)
    if(NOT DEFINED ANDROID_ABI OR "${ANDROID_ABI}" STREQUAL "")
        message(FATAL_ERROR "ANDROID_ABI is not set. This CMake project is intended to be built via Android Gradle/NDK.")
    endif()
    if(ANDROID_ABI STREQUAL "arm64-v8a")
        set(LIBSODIUM_LIB "${LIBSODIUM_ROOT}/arm64-v8a/lib/libsodium.a")
        set(LIBSODIUM_INCLUDE "${LIBSODIUM_ROOT}/arm64-v8a/include")
    elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
        set(LIBSODIUM_LIB "${LIBSODIUM_ROOT}/armeabi-v7a/lib/libsodium.a")
        set(LIBSODIUM_INCLUDE "${LIBSODIUM_ROOT}/armeabi-v7a/include")
    elseif(ANDROID_ABI STREQUAL "x86")
        set(LIBSODIUM_LIB "${LIBSODIUM_ROOT}/x86/lib/libsodium.a")
        set(LIBSODIUM_INCLUDE "${LIBSODIUM_ROOT}/x86/include")
    elseif(ANDROID_ABI STREQUAL "x86_64")
        set(LIBSODIUM_LIB "${LIBSODIUM_ROOT}/x86_64/lib/libsodium.a")
        set(LIBSODIUM_INCLUDE "${LIBSODIUM_ROOT}/x86_64/include")
    else()
        message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
    endif()

    if(NOT EXISTS "${LIBSODIUM_LIB}")
        message(FATAL_ERROR
            "libsodium is required for Noise (LITEP2P_ENABLE_NOISE_PROTOCOL=ON), but the static library is missing.\n"
            "Expected: ${LIBSODIUM_LIB}\n"
            "Fix: build or place libsodium.a for each ABI under litep2p-core/src/main/cpp/libsodium/<abi>/lib/.\n"
            "Hint: run tools/build_libsodium_android.sh to generate the missing libsodium.a files.")
    endif()
    if(NOT EXISTS "${LIBSODIUM_INCLUDE}/sodium.h")
        message(FATAL_ERROR
            "libsodium headers are missing for ABI ${ANDROID_ABI}.\n"
            "Expected: ${LIBSODIUM_INCLUDE}/sodium.h")
    endif()

    add_library(sodium STATIC IMPORTED)
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION "${LIBSODIUM_LIB}")
    target_include_directories(sodium INTERFACE "${LIBSODIUM_INCLUDE}")

    # Ensure targets that compile Noise sources see libsodium headers.
    target_link_libraries(litep2p_corep2p PUBLIC sodium)
    target_link_libraries(litep2p_crypto PUBLIC sodium)
endif()

# Main shared library
add_library(litep2p SHARED
    src/jni_bridge.cpp
    src/litep2p_c_api.cpp
    modules/plugins/jni/src/jni_helpers.cpp
)

# Link all static libraries and modules to the shared library
target_link_libraries(litep2p
    litep2p_corep2p
    litep2p_security
    litep2p_reactor
    litep2p_transport
    litep2p_session
    $<$<BOOL:${LITEP2P_ENABLE_NOISE_PROTOCOL}>:sodium>
    log
    dl
)

if(ENABLE_PROXY_MODULE)
    target_link_libraries(litep2p litep2p_proxy)
endif()

if(LITEP2P_ENABLE_DISCOVERY)
    target_link_libraries(litep2p litep2p_discovery)
endif()

if(LITEP2P_ENABLE_ROUTING)
    target_link_libraries(litep2p litep2p_routing)
endif()

if(LITEP2P_ENABLE_OPTIMIZATION)
    target_link_libraries(litep2p litep2p_optimization)
endif()

if(LITEP2P_ENABLE_FILE_TRANSFER)
    target_link_libraries(litep2p litep2p_file_transfer)
endif()

# Compiler options
target_compile_options(litep2p PRIVATE
    -fexceptions
    -DHAVE_JNI
)