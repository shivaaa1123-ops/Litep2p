# litep2p VOICE_CALL Module
# Realtime voice calls: offer/accept control plane + fire-and-forget audio frames.

add_library(litep2p_voice_call OBJECT
    src/voice_call_manager.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_voice_call PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link core module dependencies - include paths propagate through target_link_libraries
target_link_libraries(litep2p_voice_call PUBLIC
    litep2p_core
    litep2p_transport
)

set_target_properties(litep2p_voice_call PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_voice_call PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_voice_call PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_voice_call (Voice Calls)")
