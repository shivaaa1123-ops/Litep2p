# litep2p CRYPTO Module
# Cryptography layer: AES, Noise NK, key management

add_library(litep2p_crypto OBJECT
    src/aes.c
    src/aes.cpp
    src/crypto_utils.cpp
    src/noise_protocol.cpp
    src/noise_nk.cpp
    src/noise_key_store.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link core module - this propagates core's include directories
target_link_libraries(litep2p_crypto PUBLIC
    litep2p_core
)

set_target_properties(litep2p_crypto PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_crypto PRIVATE
    -Wall -Wextra
)

# Optional: Link libsodium if available
if(HAVE_SODIUM)
    target_link_libraries(litep2p_crypto PRIVATE ${sodium-lib})
endif()

message(STATUS "✓ Module: litep2p_crypto (Cryptography)")
