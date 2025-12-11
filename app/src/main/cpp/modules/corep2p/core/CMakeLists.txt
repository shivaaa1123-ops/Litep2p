# litep2p CORE Module
# Foundation layer: Logging, configuration, common types

add_library(litep2p_core OBJECT
    src/config_manager.cpp
    src/logger.cpp
)

# Expose include directory with proper scope propagation
target_include_directories(litep2p_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/plugins/jni/include
)

set_target_properties(litep2p_core PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_core PRIVATE
    -Wall -Wextra
)

message(STATUS "✓ Module: litep2p_core (Foundation)")
