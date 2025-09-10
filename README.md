# FlunkVPN - Advanced VPN with Anti-Censorship Capabilities

FlunkVPN is a high-performance, security-focused VPN solution designed for cloud Linux servers and Ubuntu clients. It features advanced anti-censorship techniques, perfect forward secrecy, and support for 5-10 concurrent clients with minimal resource usage.

## Key Features

### Security Features
- **AES-256-GCM Encryption** with ChaCha20-Poly1305 fallback
- **Perfect Forward Secrecy** using ECDH key exchange
- **Anti-replay protection** with sequence numbers and timestamps
- **Secure key derivation** using PBKDF2 and HKDF

### Anti-Censorship & DPI Bypass
- **HTTP/HTTPS Traffic Masquerading** - Appears as legitimate web traffic
- **TLS-in-TLS Tunneling** - Multiple encryption layers
- **Domain Fronting** - Route through CDN endpoints
- **Traffic Randomization** - Variable packet sizes and timing
- **Custom TLS Fingerprinting** - Mimics popular browsers
- **Protocol Flexibility** - Dynamic switching between TCP/UDP/HTTP

### Advanced Evasion
- **Steganographic Payload Hiding** - Embed VPN data in fake HTTP content
- **Connection Pattern Randomization** - Avoid detection patterns
- **Decoy Traffic Generation** - Generate realistic background traffic
- **DNS over HTTPS (DoH)** - Encrypted DNS resolution

## Project Structure

```
flunk.vpn/
├── CMakeLists.txt              # Main build configuration
├── README.md                   # This file
├── DEPLOYMENT.md               # Deployment guide
├── common/                     # Shared libraries
│   ├── CMakeLists.txt
│   ├── include/flunk/          # Header files
│   │   ├── crypto.h           # Cryptographic functions
│   │   ├── network.h          # Network management
│   │   ├── evasion.h          # Anti-censorship techniques
│   │   ├── steganography.h    # Data hiding
│   │   ├── doh_resolver.h     # DNS over HTTPS
│   │   ├── protocol.h         # VPN protocol
│   │   ├── config.h           # Configuration management
│   │   ├── logger.h           # Logging system
│   │   └── utils.h            # Utility functions
│   └── src/                   # Implementation files
│       ├── crypto.cpp
│       ├── utils.cpp
│       └── ... (other .cpp files)
├── server/                     # VPN Server
│   ├── CMakeLists.txt
│   ├── include/
│   │   └── vpn_server.h
│   └── src/
│       ├── main.cpp           # Server entry point
│       ├── vpn_server.cpp
│       └── ... (other server files)
├── client/                     # VPN Client
│   ├── CMakeLists.txt
│   ├── include/
│   │   └── vpn_client.h
│   └── src/
│       ├── main.cpp           # Client CLI entry point
│       ├── vpn_client.cpp
│       └── ... (other client files)
├── configs/                    # Configuration files
│   ├── server.conf            # Server configuration
│   └── client.conf            # Client configuration
└── third_party/               # Third-party dependencies
```

## Quick Start

### Prerequisites

**Server (Linux):**
- Ubuntu 20.04+ or CentOS 8+
- Root access
- OpenSSL 1.1.1+, libsodium 1.0.18+
- CMake 3.16+, GCC 9+

**Client (Ubuntu):**
- Ubuntu 18.04+
- Root access for TUN interface
- Same dependencies as server

### Build and Install

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential cmake pkg-config libssl-dev libsodium-dev

# Build the project
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install
sudo make install
```

### Server Setup

```bash
# Configure server
sudo mkdir -p /etc/flunk_vpn /var/log/flunk_vpn
sudo cp configs/server.conf /etc/flunk_vpn/

# Create user accounts
echo "user1:$2b$12$..." | sudo tee /etc/flunk_vpn/users.txt

# Start server
sudo flunk_server -c /etc/flunk_vpn/server.conf
```

### Client Usage

```bash
# Connect to VPN server
sudo flunk_client connect -s YOUR_SERVER_IP -u username

# Connect with anti-censorship features
sudo flunk_client connect -s YOUR_SERVER_IP -u username -e

# Check status
flunk_client status

# Disconnect
flunk_client disconnect
```

## Advanced Usage

### Anti-Censorship Features

Enable evasion techniques to bypass firewalls and DPI:

```bash
# HTTP masquerading
flunk_client connect -s server.com -u user -e --http-masquerade

# Domain fronting through CDN
flunk_client connect -s cdn.example.com -u user --domain-fronting

# Steganographic data hiding
flunk_client connect -s server.com -u user --steganography
```

### Server Configuration

Key configuration options in `server.conf`:

```ini
[evasion]
enabled = true
http_masquerade = true
tls_fingerprint = chrome
domain_fronting = true
steganography = true
decoy_traffic = true

[security]
cipher = AES-256-GCM
perfect_forward_secrecy = true
key_rotation_interval = 3600
```

## Performance

FlunkVPN is optimized for small-scale deployments:

- **Memory Usage**: ~50MB base, +10MB per client
- **CPU Usage**: Minimal overhead, scales with encryption
- **Throughput**: Depends on server specs and network
- **Latency**: <10ms additional latency for evasion features

## Security

FlunkVPN implements multiple layers of security:

1. **Encryption**: AES-256-GCM with ChaCha20-Poly1305 fallback
2. **Key Exchange**: ECDH with Curve25519
3. **Authentication**: PBKDF2 with 100,000 iterations
4. **Perfect Forward Secrecy**: New keys for each session
5. **Anti-Replay**: Sequence numbers and timestamps
6. **DNS Security**: DNS over HTTPS (DoH)

## Anti-Censorship Techniques

### Traffic Masquerading
- HTTP/HTTPS requests that appear legitimate
- Custom User-Agent strings mimicking real browsers
- Fake HTTP headers and responses

### Protocol Obfuscation
- TLS-in-TLS tunneling
- Custom TLS fingerprints matching popular browsers
- Dynamic protocol switching

### Infrastructure Evasion
- Domain fronting through CDNs
- Connection through legitimate edge servers
- Multiple endpoint redundancy

### Steganography
- Hide VPN data in HTML pages
- Embed traffic in JSON API responses
- Use fake PNG metadata for data transport

## Dependencies

- **OpenSSL 1.1.1+**: Cryptographic operations
- **libsodium 1.0.18+**: Additional crypto primitives
- **CMake 3.16+**: Build system
- **GCC 9+ or Clang 10+**: C++20 compiler
- **pkg-config**: Dependency management

## Platform Support

- **Primary**: Ubuntu 20.04+ (server and client)
- **Server**: CentOS 8+, Debian 11+, RHEL 8+
- **Client**: Ubuntu 18.04+, Debian 10+
- **Architecture**: x86_64, ARM64

## License

This project is released under a custom license. See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with proper testing
4. Submit a pull request

## Support

For deployment issues, see `DEPLOYMENT.md`.
For technical questions, check the source code documentation.

## Changelog

### Version 1.0.0
- Initial release
- Full VPN functionality with anti-censorship features
- Support for 5-10 concurrent clients
- Complete CLI interface
- Comprehensive configuration system