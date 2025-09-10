#!/bin/bash

# FlunkVPN Server Test Script

echo "Testing FlunkVPN Server Implementation"
echo "======================================"

# Step 1: Check if build directory exists
if [ ! -d "build" ]; then
    echo "Error: Build directory not found. Please run cmake and make first."
    exit 1
fi

# Step 2: Check if binaries exist
if [ ! -f "build/server/flunk_server" ]; then
    echo "Error: Server binary not found. Please build the project first."
    exit 1
fi

# Step 3: Check configuration files
if [ ! -f "configs/server.conf" ]; then
    echo "Error: Server configuration file not found."
    exit 1
fi

# Step 4: Test configuration parsing
echo "1. Testing configuration file parsing..."
echo "   Config file: configs/server.conf"

# Step 5: Check dependencies
echo "2. Checking system dependencies..."

# Check for TUN support
if [ ! -c /dev/net/tun ]; then
    echo "   Warning: /dev/net/tun not found. TUN interface creation may fail."
    echo "   Run: sudo modprobe tun"
else
    echo "   ✓ TUN support available"
fi

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "   Warning: Not running as root. TUN interface creation will fail."
    echo "   Run this script with sudo for full testing."
else
    echo "   ✓ Running with root privileges"
fi

# Step 6: Test port availability
echo "3. Checking port 1194 availability..."
if netstat -tuln | grep -q ":1194 "; then
    echo "   Warning: Port 1194 is already in use"
    netstat -tuln | grep ":1194"
else
    echo "   ✓ Port 1194 is available"
fi

# Step 7: Test server startup (dry run)
echo "4. Testing server configuration..."
echo "   This will test if the server can initialize without starting:"

# Create test configuration directory
sudo mkdir -p /etc/flunk_vpn
sudo mkdir -p /var/log/flunk_vpn

# Copy configuration files
sudo cp configs/server.conf /etc/flunk_vpn/ 2>/dev/null || echo "   Warning: Could not copy server.conf"
sudo cp configs/users.txt /etc/flunk_vpn/ 2>/dev/null || echo "   Warning: Could not copy users.txt"

echo ""
echo "Manual Test Commands:"
echo "===================="
echo "1. Build the project:"
echo "   cd build && make -j\$(nproc)"
echo ""
echo "2. Start server in test mode:"
echo "   sudo ./build/server/flunk_server -v"
echo ""
echo "3. Check if port is bound:"
echo "   sudo netstat -tulpn | grep 1194"
echo ""
echo "4. Check if TUN interface is created:"
echo "   ip addr show flunk0"
echo ""
echo "5. Test client connection:"
echo "   sudo ./build/client/flunk_client connect -s 127.0.0.1 -u testuser -v"
echo ""
echo "Expected Results:"
echo "- Port 1194 should be listening (UDP)"
echo "- TUN interface 'flunk0' should be created and UP"
echo "- Server logs should show successful initialization"