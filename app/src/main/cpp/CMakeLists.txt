cmake_minimum_required(VERSION 3.22.1)

project("litep2p")

add_library(litep2p SHARED
        src/jni_bridge.cpp
        src/discovery.cpp
        src/session_manager.cpp
        src/connection_manager.cpp
        src/udp_connection_manager.cpp
        src/logger.cpp
        src/aes.c
        src/aes.cpp
        src/jni_helpers.cpp)

target_include_directories(litep2p PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_library(log-lib
        log)

target_link_libraries(litep2p
        ${log-lib})
