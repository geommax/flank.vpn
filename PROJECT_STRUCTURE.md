# FlunkVPN Project Structure

This document provides a complete overview of the FlunkVPN project structure and components.

## Directory Structure

```
flunk.vpn/
├── CMakeLists.txt                     # Main build configuration
├── README.md                          # Project overview and quick start
├── DEPLOYMENT.md                      # Complete deployment guide
├── build.sh                          # Build script for Linux
├── common/                           # Shared libraries and components
│   ├── CMakeLists.txt               # Common library build config
│   ├── include/flunk/               # Public header files
│   │   ├── crypto.h                # Cryptographic operations
│   │   ├── network.h               # Network management
│   │   ├── evasion.h               # Anti-censorship techniques
│   │   ├── steganography.h         # Data hiding methods
│   │   ├── doh_resolver.h          # DNS over HTTPS
│   │   ├── protocol.h              # VPN protocol definitions
│   │   ├── config.h                # Configuration management
│   │   ├── logger.h                # Logging system
│   │   └── utils.h                 # Utility functions
│   └── src/                        # Implementation files
│       ├── crypto.cpp              # Crypto implementation
│       ├── utils.cpp               # Utilities implementation
│       ├── network.cpp             # Network implementation
│       ├── evasion.cpp             # Evasion implementation
│       ├── steganography.cpp       # Steganography implementation
│       ├── doh_resolver.cpp        # DoH implementation
│       ├── protocol.cpp            # Protocol implementation
│       ├── config.cpp              # Config implementation
│       └── logger.cpp              # Logger implementation
├── server/                         # VPN Server components
│   ├── CMakeLists.txt             # Server build configuration
│   ├── include/                   # Server header files
│   │   ├── vpn_server.h          # Main server class
│   │   ├── client_manager.h      # Client connection management
│   │   ├── auth_manager.h        # Authentication handling
│   │   ├── tunnel_manager.h      # Tunnel management
│   │   └── session_manager.h     # Session management
│   └── src/                      # Server implementation
│       ├── main.cpp              # Server entry point
│       ├── vpn_server.cpp        # Server implementation
│       ├── client_manager.cpp    # Client management
│       ├── auth_manager.cpp      # Authentication logic
│       ├── tunnel_manager.cpp    # Tunnel handling
│       └── session_manager.cpp   # Session management
├── client/                        # VPN Client components
│   ├── CMakeLists.txt            # Client build configuration
│   ├── include/                  # Client header files
│   │   ├── vpn_client.h         # Main client class
│   │   ├── connection_manager.h  # Connection management
│   │   └── tunnel_client.h      # Client-side tunnel
│   └── src/                     # Client implementation
│       ├── main.cpp             # CLI entry point
│       ├── vpn_client.cpp       # Client implementation
│       ├── connection_manager.cpp # Connection logic
│       └── tunnel_client.cpp    # Tunnel client
├── configs/                      # Configuration files
│   ├── server.conf              # Server configuration template
│   ├── client.conf              # Client configuration template
│   └── users.txt                # User database example
└── third_party/                 # Third-party dependencies (empty)
```

## Component Overview

### Common Library (`common/`)

The common library contains shared functionality used by both server and client:

- **Crypto Module**: AES-256-GCM, ChaCha20-Poly1305, ECDH key exchange, PBKDF2/HKDF
- **Network Module**: Socket management, TUN/TAP interfaces, protocol handling
- **Evasion Module**: HTTP masquerading, TLS fingerprinting, domain fronting, traffic randomization
- **Steganography Module**: Data hiding in HTTP content, JSON, PNG metadata
- **DoH Resolver**: DNS over HTTPS with multiple provider support
- **Protocol Module**: VPN protocol message handling and session management
- **Config Module**: Configuration file parsing and management
- **Logger Module**: Comprehensive logging system
- **Utils Module**: Utility functions for strings, crypto, file operations

### Server (`server/`)

The VPN server handles incoming client connections and provides VPN services:

- **Main Server**: Core server logic, client acceptance, service management
- **Client Manager**: Individual client connection handling
- **Auth Manager**: User authentication and authorization
- **Tunnel Manager**: VPN tunnel creation and management
- **Session Manager**: Session lifecycle and state management

### Client (`client/`)

The VPN client provides a command-line interface for connecting to servers:

- **CLI Interface**: Command-line argument parsing and user interaction
- **VPN Client**: Core client logic and server communication
- **Connection Manager**: Server connection establishment and maintenance
- **Tunnel Client**: Client-side tunnel management

### Configuration (`configs/`)

Pre-configured templates for deployment:

- **Server Config**: Complete server configuration with all features
- **Client Config**: Client configuration template
- **Users Database**: Example user account database

## Key Features Implementation

### Security Features

1. **AES-256-GCM Encryption**: Implemented in `crypto.cpp` with OpenSSL
2. **ChaCha20-Poly1305 Fallback**: Using libsodium for compatibility
3. **Perfect Forward Secrecy**: ECDH key exchange with Curve25519
4. **Anti-replay Protection**: Sequence numbers and timestamp validation
5. **Secure Key Derivation**: PBKDF2 with HKDF for key expansion

### Anti-Censorship Features

1. **HTTP/HTTPS Masquerading**: Traffic appears as legitimate web requests
2. **TLS-in-TLS Tunneling**: Multiple encryption layers for deep packet inspection bypass
3. **Domain Fronting**: Route through CDN endpoints to hide real destination
4. **Custom TLS Fingerprinting**: Mimic popular browser TLS signatures
5. **Protocol Flexibility**: Dynamic switching between TCP/UDP/HTTP protocols

### Advanced Evasion

1. **Steganographic Hiding**: Embed VPN data in HTML, JSON, and PNG content
2. **Traffic Randomization**: Variable packet sizes and timing patterns
3. **Decoy Traffic**: Generate realistic background traffic
4. **Connection Pattern Randomization**: Avoid predictable connection patterns
5. **DNS over HTTPS**: Encrypted DNS resolution to prevent DNS-based blocking

## Build Process

The project uses CMake for cross-platform building:

1. **Main CMakeLists.txt**: Configures the entire project, finds dependencies
2. **Common Library**: Built as static library linked to server and client
3. **Server/Client**: Built as separate executables
4. **Installation**: Installs binaries and configuration files

## Dependencies

- **OpenSSL 1.1.1+**: Primary cryptographic library
- **libsodium 1.0.18+**: Additional crypto primitives
- **CMake 3.16+**: Build system
- **C++20 Compiler**: GCC 9+ or Clang 10+
- **pkg-config**: Dependency management

## Deployment

The project is designed for:

- **Server**: Cloud Linux servers (VPS/dedicated)
- **Client**: Ubuntu desktop/server systems
- **Scale**: 5-10 concurrent clients
- **Resources**: Minimal RAM and CPU usage

## Usage Scenarios

1. **Basic VPN**: Standard encrypted tunnel for privacy
2. **Censorship Circumvention**: Full evasion features for restricted networks
3. **Corporate Access**: Secure remote access to internal networks
4. **Privacy Protection**: Anonymous browsing and location masking

This comprehensive implementation provides enterprise-grade VPN functionality with advanced anti-censorship capabilities in a lightweight, efficient package.