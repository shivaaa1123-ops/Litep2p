# CMakeLists.txt for LiteP2P Android Project

cmake_minimum_required(VERSION 3.22.1)

# Project name and version
project(litep2p VERSION 0.2.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compile definitions for JNI
add_compile_definitions(HAVE_JNI)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/crypto/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/reactor/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/transport/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/corep2p/security/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/discovery/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/routing/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/session/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/optimization/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/file_transfer/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/modules/plugins/jni/include
    ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/arm64-v8a/include
)

# CoreP2P library
file(GLOB_RECURSE COREP2P_SOURCES
    "modules/corep2p/core/src/*.cpp"
    "modules/corep2p/crypto/src/*.cpp"
    "modules/corep2p/crypto/src/*.c"
    "modules/corep2p/reactor/src/*.cpp"
    "modules/corep2p/transport/src/*.cpp"
    "modules/corep2p/security/src/*.cpp"
)

add_library(litep2p_corep2p STATIC ${COREP2P_SOURCES})
target_link_libraries(litep2p_corep2p PUBLIC)

# Add missing static libraries for modules
file(GLOB_RECURSE CRYPTO_SOURCES "modules/corep2p/crypto/src/*.cpp" "modules/corep2p/crypto/src/*.c")
add_library(litep2p_crypto STATIC ${CRYPTO_SOURCES})
target_link_libraries(litep2p_crypto PUBLIC)

# Add missing static libraries for modules
file(GLOB_RECURSE SECURITY_SOURCES "modules/corep2p/security/src/*.cpp")
add_library(litep2p_security STATIC ${SECURITY_SOURCES})
target_link_libraries(litep2p_security PUBLIC)

file(GLOB_RECURSE REACTOR_SOURCES "modules/corep2p/reactor/src/*.cpp")
add_library(litep2p_reactor STATIC ${REACTOR_SOURCES})
target_link_libraries(litep2p_reactor PUBLIC)

file(GLOB_RECURSE TRANSPORT_SOURCES "modules/corep2p/transport/src/*.cpp")
add_library(litep2p_transport STATIC ${TRANSPORT_SOURCES})
target_link_libraries(litep2p_transport PUBLIC)

# Plugin libraries
file(GLOB_RECURSE DISCOVERY_SOURCES "modules/plugins/discovery/src/*.cpp")
add_library(litep2p_discovery STATIC ${DISCOVERY_SOURCES})
target_link_libraries(litep2p_discovery litep2p_corep2p)

file(GLOB_RECURSE ROUTING_SOURCES "modules/plugins/routing/src/*.cpp")
add_library(litep2p_routing STATIC ${ROUTING_SOURCES})
target_link_libraries(litep2p_routing litep2p_corep2p)

file(GLOB_RECURSE SESSION_SOURCES "modules/plugins/session/src/*.cpp")
add_library(litep2p_session STATIC ${SESSION_SOURCES})
target_link_libraries(litep2p_session litep2p_corep2p)

file(GLOB_RECURSE OPTIMIZATION_SOURCES "modules/plugins/optimization/src/*.cpp")
add_library(litep2p_optimization STATIC ${OPTIMIZATION_SOURCES})
target_link_libraries(litep2p_optimization litep2p_corep2p)

file(GLOB_RECURSE FILE_TRANSFER_SOURCES "modules/plugins/file_transfer/src/*.cpp")
add_library(litep2p_file_transfer STATIC ${FILE_TRANSFER_SOURCES})
target_link_libraries(litep2p_file_transfer litep2p_corep2p)

# Add prebuilt libsodium for current ABI
add_library(sodium STATIC IMPORTED)
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/arm64-v8a/lib/libsodium.a)
    target_include_directories(sodium INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/arm64-v8a/include)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/armeabi-v7a/lib/libsodium.a)
    target_include_directories(sodium INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/armeabi-v7a/include)
elseif(ANDROID_ABI STREQUAL "x86")
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/x86/lib/libsodium.a)
    target_include_directories(sodium INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/x86/include)
elseif(ANDROID_ABI STREQUAL "x86_64")
    set_target_properties(sodium PROPERTIES IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/x86_64/lib/libsodium.a)
    target_include_directories(sodium INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/x86_64/include)
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

# Main shared library
add_library(litep2p SHARED
    src/jni_bridge.cpp
    modules/plugins/jni/src/jni_helpers.cpp
)

# Link all static libraries and modules to the shared library
target_link_libraries(litep2p
    litep2p_corep2p
    litep2p_security
    litep2p_reactor
    litep2p_transport
    litep2p_discovery
    litep2p_routing
    litep2p_session
    litep2p_optimization
    litep2p_file_transfer
    sodium
    log
)

# Compiler options
target_compile_options(litep2p PRIVATE
    -fexceptions
    -DHAVE_JNI
)