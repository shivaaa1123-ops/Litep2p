# litep2p PROXY Module (Optional)
# Application-level proxy/relay: proxy client + proxy gateway

add_library(litep2p_proxy OBJECT
    src/proxy_endpoint.cpp
)

target_include_directories(litep2p_proxy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../session/include
)

target_link_libraries(litep2p_proxy PUBLIC
    litep2p_core
)

set_target_properties(litep2p_proxy PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_proxy PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_proxy PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_proxy (Proxy / Relay)")
