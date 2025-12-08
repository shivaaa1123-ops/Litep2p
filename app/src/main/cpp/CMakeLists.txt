cmake_minimum_required(VERSION 3.22.1)

project("litep2p")

# Check for required libraries
find_library(log-lib log)
if(NOT log-lib)
    message(FATAL_ERROR "log library not found. Please install Android NDK.")
endif()

find_library(sodium-lib sodium)
set(HAVE_SODIUM FALSE)
if(sodium-lib)
    set(HAVE_SODIUM TRUE)
    message(STATUS "libsodium found: ${sodium-lib}")
else()
    message(WARNING "libsodium not found. Noise Protocol will not be compiled. Install with: vcpkg or pre-built NDK version")
endif()

set(SOURCES
    src/jni_bridge.cpp
    src/discovery.cpp
    src/session_manager.cpp
    src/connection_manager.cpp
    src/udp_connection_manager.cpp
    src/logger.cpp
    src/aes.c
    src/aes.cpp
    src/crypto_utils.cpp
    src/jni_helpers.cpp
    src/epoll_reactor.cpp
    src/network.cpp
    src/peer_manager.cpp
    src/battery_optimizer.cpp
    src/session_cache.cpp
    src/message_batcher.cpp)

if(HAVE_SODIUM)
    list(APPEND SOURCES
        src/noise_protocol.cpp
        src/secure_session.cpp
        src/noise_nk.cpp
        src/noise_key_store.cpp)
    add_compile_definitions(HAVE_NOISE_PROTOCOL=1)
else()
    add_compile_definitions(HAVE_NOISE_PROTOCOL=0)
endif()

add_library(litep2p SHARED ${SOURCES})

target_include_directories(litep2p PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Enable C++17 for modern language features
set_target_properties(litep2p PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)

target_link_libraries(litep2p
        ${log-lib})

if(HAVE_SODIUM)
    target_link_libraries(litep2p ${sodium-lib})
endif()

