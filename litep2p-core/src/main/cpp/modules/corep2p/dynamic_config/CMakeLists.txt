# Dynamic Configuration module CMake configuration

add_library(litep2p_dynamic_config OBJECT
    src/dynamic_configuration_manager.cpp
)

target_include_directories(litep2p_dynamic_config PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(litep2p_dynamic_config PUBLIC
    litep2p_core
)

target_compile_features(litep2p_dynamic_config PUBLIC cxx_std_17)

target_compile_options(litep2p_dynamic_config PRIVATE
    -Wall -Wextra -Wpedantic
)

message(STATUS "✓ Module: litep2p_dynamic_config (Dynamic Configuration)")
