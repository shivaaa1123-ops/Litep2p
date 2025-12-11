# litep2p ROUTING Module
# NAT traversal & routing: NAT hole-punching, tier system, reconnection

add_library(litep2p_routing OBJECT
    src/nat_traversal.cpp
    src/nat_stun.cpp
    src/peer_reconnect_policy.cpp
    src/peer_tier_manager.cpp
    src/tier_system_failsafe.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_routing PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../corep2p/core/include
)

# Link core module dependencies - include paths propagate through target_link_libraries
target_link_libraries(litep2p_routing PUBLIC
    litep2p_core
    litep2p_transport
    litep2p_session
)

set_target_properties(litep2p_routing PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_routing PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_routing PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_routing (NAT & Routing)")
