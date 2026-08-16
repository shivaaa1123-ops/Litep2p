# litep2p OVERLAY Module (Optional)
# Multi-hop onion-routed overlay messaging (LPX2): relay forwarding,
# store-and-forward mailboxes, bounded-reliable overlay sends.

add_library(litep2p_overlay OBJECT
    src/overlay_frame.cpp
    src/overlay_mailbox.cpp
    src/overlay_router.cpp
)

target_include_directories(litep2p_overlay PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../session/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../corep2p/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../corep2p/crypto/include
)

# sodium headers (LPX2 sealing). On Android use the prebuilt per-ABI headers;
# elsewhere rely on system sodium via litep2p_crypto's propagated includes or
# fall back to the repo's bundled headers.
if(ANDROID)
    target_include_directories(litep2p_overlay PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../libsodium/${ANDROID_ABI}/include
    )
else()
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    if(SODIUM_INCLUDE_DIR)
        target_include_directories(litep2p_overlay PRIVATE ${SODIUM_INCLUDE_DIR})
    endif()
endif()

target_link_libraries(litep2p_overlay PUBLIC
    litep2p_core
)

set_target_properties(litep2p_overlay PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_overlay PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_overlay PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_overlay (multi-hop overlay / LPX2)")
