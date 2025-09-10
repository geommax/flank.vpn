#!/bin/bash

# FlunkVPN Build Script
# This script builds the complete FlunkVPN project

set -e  # Exit on any error

echo "FlunkVPN Build Script"
echo "===================="

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "Error: This script must be run on Linux"
    exit 1
fi

# Check for required tools
echo "Checking build dependencies..."
command -v cmake >/dev/null 2>&1 || { echo "Error: cmake is required but not installed"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "Error: make is required but not installed"; exit 1; }
command -v pkg-config >/dev/null 2>&1 || { echo "Error: pkg-config is required but not installed"; exit 1; }

# Check for required libraries
echo "Checking library dependencies..."
pkg-config --exists openssl || { echo "Error: OpenSSL development libraries not found"; exit 1; }
pkg-config --exists libsodium || { echo "Error: libsodium development libraries not found"; exit 1; }

# Determine build type
BUILD_TYPE=${1:-Release}
if [[ "$BUILD_TYPE" != "Debug" && "$BUILD_TYPE" != "Release" && "$BUILD_TYPE" != "RelWithDebInfo" ]]; then
    echo "Error: Invalid build type '$BUILD_TYPE'. Use Debug, Release, or RelWithDebInfo"
    exit 1
fi

echo "Build type: $BUILD_TYPE"

# Create build directory
BUILD_DIR="build"
if [ -d "$BUILD_DIR" ]; then
    echo "Removing existing build directory..."
    rm -rf "$BUILD_DIR"
fi

echo "Creating build directory..."
mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with CMake
echo "Configuring project with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_CXX_STANDARD=20

# Build the project
echo "Building project..."
make -j$(nproc)

echo ""
echo "Build completed successfully!"
echo ""
echo "Binaries created:"
echo "  Server: $BUILD_DIR/server/flunk_server"
echo "  Client: $BUILD_DIR/client/flunk_client"
echo ""
echo "To install system-wide, run:"
echo "  sudo make install"
echo ""
echo "To test the build:"
echo "  ./server/flunk_server --version"
echo "  ./client/flunk_client --version"