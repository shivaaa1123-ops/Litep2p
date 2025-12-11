# litep2p SECURITY Module
# Encrypted sessions: Secure session establishment and management

add_library(litep2p_security OBJECT
    src/secure_session.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_security PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link core module dependencies - include paths propagate through target_link_libraries
target_link_libraries(litep2p_security PUBLIC
    litep2p_core
    litep2p_crypto
    litep2p_transport
)

set_target_properties(litep2p_security PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_security PRIVATE
    -Wall -Wextra
)

message(STATUS "✓ Module: litep2p_security (Secure Sessions)")
