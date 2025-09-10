cmake_minimum_required(VERSION 3.16)
project(flunk_vpn VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build configuration
set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")

# Compiler flags for security and optimization
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -fstack-protector-strong")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DDEBUG")
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Check for libsodium with fallback
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBSODIUM libsodium)
endif()

if(NOT LIBSODIUM_FOUND)
    # Fallback to find_library for systems without pkg-config
    find_library(LIBSODIUM_LIBRARIES NAMES sodium libsodium)
    find_path(LIBSODIUM_INCLUDE_DIRS NAMES sodium.h)
    if(LIBSODIUM_LIBRARIES AND LIBSODIUM_INCLUDE_DIRS)
        set(LIBSODIUM_FOUND TRUE)
        message(STATUS "Found libsodium: ${LIBSODIUM_LIBRARIES}")
    else()
        message(FATAL_ERROR "libsodium not found. Please install libsodium development package.")
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# Add subdirectories
add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(client)

# Install configuration
install(DIRECTORY configs/ DESTINATION etc/flunk_vpn
        FILES_MATCHING PATTERN "*.conf" PATTERN "*.json")

# CPack configuration
set(CPACK_PACKAGE_NAME "flunk-vpn")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced VPN with anti-censorship capabilities")
set(CPACK_PACKAGE_VENDOR "FlunkVPN Team")
set(CPACK_GENERATOR "DEB;RPM;TGZ")

include(CPack)