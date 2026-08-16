# FindSodium.cmake
# This script locates the libsodium library provided by the libsodium-jni AAR.

find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    HINTS ${CMAKE_CURRENT_BINARY_DIR}/../../../../../libsodium-jni/jni/include
    DOC "Path to sodium.h header"
)

find_library(SODIUM_LIBRARY
    NAMES libsodium.a
    HINTS ${CMAKE_CURRENT_BINARY_DIR}/../../../../../libsodium-jni/jni/libs/${ANDROID_ABI}
    DOC "Path to libsodium static library"
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sodium
    REQUIRED_VARS SODIUM_LIBRARY SODIUM_INCLUDE_DIR
    FAIL_MESSAGE "Could not find libsodium. Make sure the libsodium-jni dependency is correctly configured in Gradle."
)

if(SODIUM_FOUND AND NOT TARGET Sodium::sodium)
    add_library(Sodium::sodium STATIC IMPORTED)
    set_target_properties(Sodium::sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
    )
endif()
