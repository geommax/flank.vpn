#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace flunk {

enum class ProtocolType {
    TCP,
    UDP,
    HTTP,
    HTTPS,
    TLS_IN_TLS
};

enum class PacketType {
    HANDSHAKE_INIT = 0x01,
    HANDSHAKE_RESPONSE = 0x02,
    HANDSHAKE_COMPLETE = 0x03,
    DATA = 0x04,
    KEEPALIVE = 0x05,
    DISCONNECT = 0x06,
    ERROR = 0xFF
};

struct NetworkEndpoint {
    std::string host;
    uint16_t port;
    ProtocolType protocol;
};

struct PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint8_t type;
    uint8_t flags;
    uint32_t length;
    uint64_t sequence;
    uint64_t timestamp;
    uint32_t checksum;
} __attribute__((packed));

constexpr uint32_t FLUNK_MAGIC = 0x464C4E4B; // "FLNK"
constexpr uint16_t PROTOCOL_VERSION = 0x0100;

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();

    // Connection management
    bool connect(const NetworkEndpoint& endpoint, int timeout_ms = 10000);
    bool bind(const NetworkEndpoint& endpoint);
    bool listen(int backlog = 5);
    std::unique_ptr<NetworkManager> accept();
    void disconnect();
    bool is_connected() const;

    // Data transmission
    ssize_t send(const void* data, size_t length);
    ssize_t receive(void* buffer, size_t buffer_size);
    ssize_t send_packet(const std::vector<uint8_t>& data, PacketType type, uint64_t sequence);
    ssize_t receive_packet(std::vector<uint8_t>& data, PacketHeader& header);

    // Network information
    std::string get_local_address() const;
    uint16_t get_local_port() const;
    std::string get_remote_address() const;
    uint16_t get_remote_port() const;

    // Protocol switching
    bool switch_protocol(ProtocolType new_protocol);
    ProtocolType get_current_protocol() const;

    // Socket options
    bool set_non_blocking(bool non_blocking);
    bool set_keep_alive(bool enable);
    bool set_tcp_nodelay(bool enable);
    bool set_receive_timeout(int timeout_ms);
    bool set_send_timeout(int timeout_ms);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

// TUN/TAP interface management for VPN
class TunInterface {
public:
    TunInterface();
    ~TunInterface();

    bool create_interface(const std::string& name = "");
    bool configure_ip(const std::string& ip, const std::string& netmask);
    bool add_route(const std::string& dest, const std::string& gateway);
    bool bring_up();
    bool bring_down();

    ssize_t read_packet(void* buffer, size_t buffer_size);
    ssize_t write_packet(const void* data, size_t length);

    std::string get_interface_name() const;
    int get_file_descriptor() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

// Network utilities
std::vector<NetworkEndpoint> resolve_hostname(const std::string& hostname, uint16_t port);
bool is_valid_ip_address(const std::string& ip);
std::string get_default_gateway();
std::vector<std::string> get_local_ip_addresses();

} // namespace flunk