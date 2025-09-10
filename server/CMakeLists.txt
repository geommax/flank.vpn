cmake_minimum_required(VERSION 3.16)

# VPN Server executable
add_executable(flunk_server
    src/main.cpp
    src/vpn_server.cpp
)

target_include_directories(flunk_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/include
    ${LIBSODIUM_INCLUDE_DIRS}
)

target_link_libraries(flunk_server
    flunk_common
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LIBSODIUM_LIBRARIES}
    Threads::Threads
)

target_compile_definitions(flunk_server PRIVATE
    ${LIBSODIUM_CFLAGS_OTHER}
)

# Install server binary
install(TARGETS flunk_server DESTINATION bin)

# Install server configuration
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../configs/server.conf DESTINATION etc/flunk_vpn)