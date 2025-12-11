# litep2p JNI Module
# Android/Kotlin interop: JNI bindings, native methods, UI callbacks

# Check for JNI support - first try system JNI, then fallback to local headers
find_package(JNI)

# If system JNI not found, check for local JNI headers
if(NOT JNI_FOUND)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../jni_include/jni.h")
        set(JNI_FOUND TRUE)
        set(JNI_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/../../jni_include")
        message(STATUS "Using local JNI headers from ${JNI_INCLUDE_DIRS}")
    endif()
endif()

if(JNI_FOUND)
    message(STATUS "✓ JNI found - building JNI module")
    
    add_library(litep2p_jni OBJECT
        src/jni_bridge.cpp
        src/jni_helpers.cpp
        src/p2p_api.cpp
        src/p2p_entry.cpp
    )

    # Expose include directories with proper scope propagation
    target_include_directories(litep2p_jni PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${JNI_INCLUDE_DIRS}
    )

    # Link all module dependencies - include paths propagate through target_link_libraries
    target_link_libraries(litep2p_jni PUBLIC
        litep2p_core
        litep2p_session
        litep2p_routing
        litep2p_file_transfer
        litep2p_optimization
        litep2p_discovery
        litep2p_transport
    )

    set_target_properties(litep2p_jni PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )

    target_compile_options(litep2p_jni PRIVATE
        -Wall -Wextra
    )

    find_package(Threads REQUIRED)
    target_link_libraries(litep2p_jni PRIVATE Threads::Threads)

    message(STATUS "✓ Module: litep2p_jni (JNI Interop)")
else()
    message(STATUS "⚠ JNI not found - skipping JNI module (requires Android NDK)")
    
    # Create a dummy target so the build system doesn't fail
    add_library(litep2p_jni OBJECT IMPORTED)
endif()
