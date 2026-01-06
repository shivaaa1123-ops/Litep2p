# litep2p COREP2P Module
# Aggregated parent module: Combines core, crypto, reactor, transport, security layers
# Provides unified interface to all 5 core P2P layers

add_library(litep2p_corep2p OBJECT
    src/corep2p.cpp
    $<TARGET_OBJECTS:litep2p_dynamic_config>
)

add_subdirectory(dynamic_config)

# Include paths for all 5 core modules AND parent-level includes
target_include_directories(litep2p_corep2p PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    # Layer 1: Foundation
    ${CMAKE_CURRENT_SOURCE_DIR}/core/include
    # Layer 2: Infrastructure
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/include
    ${CMAKE_CURRENT_SOURCE_DIR}/reactor/include
    # Layer 3: Core Services
    ${CMAKE_CURRENT_SOURCE_DIR}/transport/include
    ${CMAKE_CURRENT_SOURCE_DIR}/security/include
)

# Link all 5 core module dependencies - their include directories propagate
target_link_libraries(litep2p_corep2p PUBLIC
    litep2p_core
    litep2p_crypto
    litep2p_reactor
    litep2p_transport
    litep2p_security
)

set_target_properties(litep2p_corep2p PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_corep2p PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_corep2p PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_corep2p (Aggregated Core P2P)")
