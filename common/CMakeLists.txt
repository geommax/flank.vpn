cmake_minimum_required(VERSION 3.16)

# Common library containing shared functionality
add_library(flunk_common STATIC
    src/crypto.cpp
    src/utils.cpp
    src/logger.cpp
    src/config.cpp
    src/network.cpp
)

target_include_directories(flunk_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBSODIUM_INCLUDE_DIRS}
)

target_link_libraries(flunk_common
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LIBSODIUM_LIBRARIES}
    Threads::Threads
)

target_compile_definitions(flunk_common PRIVATE
    ${LIBSODIUM_CFLAGS_OTHER}
)

# Set properties
set_target_properties(flunk_common PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
)