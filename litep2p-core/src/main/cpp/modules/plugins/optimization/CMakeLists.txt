# litep2p OPTIMIZATION Module
# Battery & performance optimization: CPU, battery, message batching

add_library(litep2p_optimization OBJECT
    src/battery_optimizer.cpp
    src/message_batcher.cpp
    src/peer_index.cpp
    src/adaptive_scaler.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_optimization PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../session/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../corep2p/core/include
)

# Link core module dependencies - include paths propagate through target_link_libraries
target_link_libraries(litep2p_optimization PUBLIC
    litep2p_core
    litep2p_session
)

set_target_properties(litep2p_optimization PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_optimization PRIVATE
    -Wall -Wextra
)

message(STATUS "✓ Module: litep2p_optimization (Optimization)")
