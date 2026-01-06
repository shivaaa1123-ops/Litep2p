# litep2p DISCOVERY Module
# Peer discovery & caching: LAN discovery, broadcast, mDNS

add_library(litep2p_discovery OBJECT
    src/discovery.cpp
    src/broadcast_discovery_manager.cpp
    src/peer_cache_lru.cpp
    src/signaling_client.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_discovery PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../corep2p/core/include
)

# Link core module dependencies - include paths propagate through target_link_libraries
target_link_libraries(litep2p_discovery PUBLIC
    litep2p_core
    litep2p_transport
    litep2p_reactor
)

set_target_properties(litep2p_discovery PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_discovery PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_discovery PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_discovery (Peer Discovery)")
