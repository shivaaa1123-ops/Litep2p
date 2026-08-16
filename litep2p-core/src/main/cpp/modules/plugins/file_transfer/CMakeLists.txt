# litep2p FILE_TRANSFER Module
# File transfer: 32KB chunks, resume, multiplexing, congestion control

add_library(litep2p_file_transfer OBJECT
    src/file_transfer_manager.cpp
    src/file_transfer_chunks.cpp
    src/file_transfer_checkpoint.cpp
    src/file_transfer_congestion.cpp
    src/file_transfer_paths.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_file_transfer PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link core module dependencies - include paths propagate through target_link_libraries
target_link_libraries(litep2p_file_transfer PUBLIC
    litep2p_core
    litep2p_transport
)

set_target_properties(litep2p_file_transfer PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_file_transfer PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_file_transfer PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_file_transfer (File Transfer)")
