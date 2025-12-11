# litep2p SESSION Module
# Main orchestrator: Session lifecycle, peer state, event handling

add_library(litep2p_session OBJECT
    src/session_manager.cpp
    src/session_cache.cpp
    src/peer_manager.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_session PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../optimization/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../routing/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../file_transfer/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../discovery/include
)

# Link core module dependencies and other plugins
# Include paths from all linked libraries automatically propagate
target_link_libraries(litep2p_session PUBLIC
    litep2p_core
    litep2p_transport
    litep2p_reactor
    litep2p_crypto
    litep2p_security
    litep2p_discovery
)

set_target_properties(litep2p_session PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_session PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_session PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_session (Session Management)")
