# FlunkVPN Deployment Guide

## Overview

FlunkVPN is an advanced VPN solution with anti-censorship capabilities, designed for cloud Linux servers with Ubuntu clients. This guide covers the complete deployment process.

## System Requirements

### Server Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended, CentOS 8+, Debian 11+)
- **Memory**: Minimum 512MB RAM, 1GB+ recommended
- **CPU**: 1 core minimum, 2+ cores recommended for 5-10 clients
- **Storage**: 100MB for installation, additional space for logs
- **Network**: Public IP address, root access required

### Client Requirements
- **Operating System**: Ubuntu 18.04+ (primary), other Linux distributions
- **Memory**: Minimum 128MB RAM
- **Network**: Internet connection
- **Privileges**: Root access for TUN interface creation

### Dependencies
- OpenSSL 1.1.1+
- libsodium 1.0.18+
- CMake 3.16+
- GCC 9+ or Clang 10+
- pkg-config

## Server Deployment

### 1. Install Dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config
sudo apt install -y libssl-dev libsodium-dev
sudo apt install -y git wget curl
```

#### CentOS/RHEL:
```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake pkg-config
sudo dnf install -y openssl-devel libsodium-devel
sudo dnf install -y git wget curl
```

### 2. Build FlunkVPN Server

```bash
# Clone or extract the source code
cd /opt
sudo git clone <repository_url> flunk-vpn
# OR extract from archive:
# sudo tar -xzf flunk-vpn.tar.gz

# Build the project
cd flunk-vpn
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install binaries and configuration files
sudo make install
```

### 3. Configure the Server

```bash
# Create configuration directory
sudo mkdir -p /etc/flunk_vpn
sudo mkdir -p /var/log/flunk_vpn

# Copy configuration files
sudo cp configs/server.conf /etc/flunk_vpn/
sudo cp configs/users.txt /etc/flunk_vpn/

# Set proper permissions
sudo chmod 640 /etc/flunk_vpn/server.conf
sudo chmod 600 /etc/flunk_vpn/users.txt
sudo chown root:root /etc/flunk_vpn/*
```

### 4. Create User Accounts

Edit `/etc/flunk_vpn/users.txt`:

```bash
sudo nano /etc/flunk_vpn/users.txt
```

Add users in the format: `username:password_hash`

```
user1:$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBdXFS5/k2OdK6
user2:$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBdXFS5/k2OdK6
```

Generate password hashes:
```bash
# Using Python (bcrypt)
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your_password', bcrypt.gensalt()).decode())"
```

### 5. Configure Firewall

```bash
# Allow VPN port
sudo ufw allow 1194/udp
sudo ufw allow 1194/tcp

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Configure iptables for NAT
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A INPUT -i flunk0 -j ACCEPT
sudo iptables -A FORWARD -i flunk0 -j ACCEPT
sudo iptables -A FORWARD -o flunk0 -j ACCEPT

# Save iptables rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### 6. Create Systemd Service

Create `/etc/systemd/system/flunk-vpn.service`:

```ini
[Unit]
Description=FlunkVPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/flunk_server -c /etc/flunk_vpn/server.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable flunk-vpn
sudo systemctl start flunk-vpn
sudo systemctl status flunk-vpn
```

### 7. Verify Installation

```bash
# Check service status
sudo systemctl status flunk-vpn

# Check logs
sudo journalctl -u flunk-vpn -f

# Check listening ports
sudo netstat -tulpn | grep 1194

# Check TUN interface
ip addr show flunk0
```

## Client Deployment

### 1. Install Dependencies

#### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config
sudo apt install -y libssl-dev libsodium-dev
```

### 2. Build FlunkVPN Client

```bash
# Extract or clone source code
cd ~/
tar -xzf flunk-vpn.tar.gz
cd flunk-vpn

# Build client only
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make flunk_client

# Install client binary
sudo cp client/flunk_client /usr/local/bin/
sudo chmod +x /usr/local/bin/flunk_client
```

### 3. Configure Client

```bash
# Create client configuration directory
mkdir -p ~/.flunk_vpn

# Copy client configuration
cp configs/client.conf ~/.flunk_vpn/

# Edit configuration
nano ~/.flunk_vpn/client.conf
```

Update server details in `client.conf`:
```ini
[client]
server_host = YOUR_SERVER_IP
server_port = 1194
username = your_username
```

### 4. Connect to VPN

```bash
# Connect to VPN server
sudo flunk_client connect -s YOUR_SERVER_IP -u your_username

# Connect with evasion enabled
sudo flunk_client connect -s YOUR_SERVER_IP -u your_username -e

# Check connection status
flunk_client status

# Disconnect
flunk_client disconnect
```

## Advanced Configuration

### SSL/TLS Certificates (Optional)

Generate self-signed certificates for enhanced security:

```bash
# Generate CA certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt

# Generate server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# Copy certificates
sudo cp ca.crt server.crt server.key /etc/flunk_vpn/
sudo chmod 600 /etc/flunk_vpn/*.key
```

### Multiple Server Instances

To run multiple server instances on different ports:

```bash
# Copy configuration
sudo cp /etc/flunk_vpn/server.conf /etc/flunk_vpn/server-2.conf

# Edit port and TUN device
sudo nano /etc/flunk_vpn/server-2.conf

# Create separate systemd service
sudo cp /etc/systemd/system/flunk-vpn.service /etc/systemd/system/flunk-vpn-2.service
sudo nano /etc/systemd/system/flunk-vpn-2.service

# Start second instance
sudo systemctl enable flunk-vpn-2
sudo systemctl start flunk-vpn-2
```

### Domain Fronting Setup

Configure domain fronting through CDN:

1. Set up CloudFlare/CloudFront distribution
2. Point frontend domain to your server
3. Update server configuration:

```ini
[evasion]
domain_fronting = true
frontend_domains = cdn.example.com,assets.example.com
```

## Monitoring and Maintenance

### Log Monitoring

```bash
# Real-time server logs
sudo tail -f /var/log/flunk_vpn/server.log

# System journal logs
sudo journalctl -u flunk-vpn -f

# Client logs
tail -f ~/.flunk_vpn/client.log
```

### Performance Monitoring

```bash
# Check active connections
sudo netstat -an | grep :1194

# Monitor TUN interface traffic
sudo iftop -i flunk0

# Check system resources
htop
```

### Maintenance Tasks

```bash
# Update server configuration
sudo systemctl reload flunk-vpn

# Rotate logs
sudo logrotate /etc/logrotate.d/flunk-vpn

# Update user database
sudo nano /etc/flunk_vpn/users.txt
sudo systemctl reload flunk-vpn
```

## Troubleshooting

### Common Server Issues

1. **Port binding fails**:
   ```bash
   sudo netstat -tulpn | grep 1194
   sudo systemctl stop conflicting-service
   ```

2. **TUN interface creation fails**:
   ```bash
   sudo modprobe tun
   ls -la /dev/net/tun
   ```

3. **Permission denied**:
   ```bash
   sudo chown root:root /usr/local/bin/flunk_server
   sudo chmod u+s /usr/local/bin/flunk_server
   ```

### Common Client Issues

1. **Connection timeout**:
   - Check server firewall rules
   - Verify server is running
   - Test network connectivity

2. **Authentication failed**:
   - Verify username/password
   - Check server user database

3. **TUN interface creation fails**:
   ```bash
   sudo modprobe tun
   sudo chmod 666 /dev/net/tun
   ```

### Performance Optimization

1. **Increase connection limits**:
   ```bash
   echo '* soft nofile 65536' | sudo tee -a /etc/security/limits.conf
   echo '* hard nofile 65536' | sudo tee -a /etc/security/limits.conf
   ```

2. **Kernel optimization**:
   ```bash
   echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
   echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```

## Security Considerations

1. **Regular Updates**: Keep OpenSSL and libsodium updated
2. **Strong Passwords**: Use complex passwords for user accounts
3. **Certificate Validation**: Use proper SSL certificates in production
4. **Firewall Rules**: Restrict access to management interfaces
5. **Log Monitoring**: Monitor for suspicious activity
6. **Key Rotation**: Regularly rotate encryption keys

## Support and Documentation

For additional support:
- Check server logs: `/var/log/flunk_vpn/server.log`
- Client logs: `~/.flunk_vpn/client.log`
- System logs: `sudo journalctl -u flunk-vpn`

For advanced configurations and troubleshooting, refer to the source code documentation and configuration file comments.