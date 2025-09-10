cmake_minimum_required(VERSION 3.16)

# VPN Client executable
add_executable(flunk_client
    src/main.cpp
    src/vpn_client.cpp
)

target_include_directories(flunk_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/include
    ${LIBSODIUM_INCLUDE_DIRS}
)

target_link_libraries(flunk_client
    flunk_common
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LIBSODIUM_LIBRARIES}
    Threads::Threads
)

target_compile_definitions(flunk_client PRIVATE
    ${LIBSODIUM_CFLAGS_OTHER}
)

# Install client binary
install(TARGETS flunk_client DESTINATION bin)

# Install client configuration
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../configs/client.conf DESTINATION etc/flunk_vpn)