cmake_minimum_required(VERSION 3.10.2)
project("litep2p_native")

# set library name
set(LIB_NAME litep2p)

add_library(litep2p SHARED
        src/p2p_api.cpp
        src/discovery.cpp
        src/network.cpp
        src/peer_manager.cpp
        src/logger.cpp
        src/heartbeat.cpp
        src/jni_glue.cpp
        src/jni_helpers.cpp
        src/message_router.cpp
        src/protocol.cpp
)


# include directories
target_include_directories(${LIB_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# c++ settings
set_target_properties(${LIB_NAME} PROPERTIES
        CXX_STANDARD 17
        CXX_EXTENSIONS OFF
)

find_library(log-lib log)
target_link_libraries(${LIB_NAME}
        ${log-lib}
)

# --- added LiteP2P session & handshake implementation ---
set(LITEP2P_EXTRA_SRCS
    src/session_manager.cpp
    src/handshake_server.cpp
)

target_sources(${LIB_NAME} PRIVATE ${LITEP2P_EXTRA_SRCS})
target_include_directories(${LIB_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
