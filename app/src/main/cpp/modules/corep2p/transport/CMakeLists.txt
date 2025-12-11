# litep2p TRANSPORT Module
# Network communication: TCP/UDP sockets, connections, message framing

add_library(litep2p_transport OBJECT
    src/network.cpp
    src/connection_manager.cpp
    src/udp_connection_manager.cpp
    src/multi_socket_manager.cpp
    src/batch_connection_manager.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_transport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link core module dependencies - include paths propagate through target_link_libraries
target_link_libraries(litep2p_transport PUBLIC
    litep2p_core
    litep2p_reactor
    litep2p_crypto
)

set_target_properties(litep2p_transport PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_transport PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_transport PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_transport (Network Communication)")
