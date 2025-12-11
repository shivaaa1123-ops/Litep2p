# litep2p REACTOR Module
# Event-driven I/O infrastructure: Epoll, timers, event loop

add_library(litep2p_reactor OBJECT
    src/epoll_reactor.cpp
    src/event_thread_pool.cpp
)

# Expose include directories with proper scope propagation
target_include_directories(litep2p_reactor PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link core module - this propagates core's include directories
target_link_libraries(litep2p_reactor PUBLIC
    litep2p_core
)

set_target_properties(litep2p_reactor PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_compile_options(litep2p_reactor PRIVATE
    -Wall -Wextra
)

find_package(Threads REQUIRED)
target_link_libraries(litep2p_reactor PRIVATE Threads::Threads)

message(STATUS "✓ Module: litep2p_reactor (Event-Driven I/O)")
