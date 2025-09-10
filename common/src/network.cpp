#include "flunk/network.h"
#include "flunk/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <cstdlib>
#include <stdexcept>

namespace flunk {

// NetworkManager::Impl class
class NetworkManager::Impl {
public:
    int socket_fd = -1;
    ProtocolType current_protocol = ProtocolType::UDP;
    NetworkEndpoint local_endpoint;
    NetworkEndpoint remote_endpoint;
    bool is_server = false;
    bool connected = false;

    ~Impl() {
        if (socket_fd >= 0) {
            close(socket_fd);
        }
    }

    bool create_socket(ProtocolType protocol) {
        if (socket_fd >= 0) {
            close(socket_fd);
        }

        int domain = AF_INET;
        int type = (protocol == ProtocolType::TCP) ? SOCK_STREAM : SOCK_DGRAM;
        int proto = (protocol == ProtocolType::TCP) ? IPPROTO_TCP : IPPROTO_UDP;

        socket_fd = socket(domain, type, proto);
        if (socket_fd < 0) {
            LOG_ERROR("Failed to create socket: " + std::string(strerror(errno)));
            return false;
        }

        // Set socket options
        int opt = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            LOG_WARN("Failed to set SO_REUSEADDR: " + std::string(strerror(errno)));
        }

        current_protocol = protocol;
        return true;
    }

    struct sockaddr_in create_sockaddr(const std::string& host, uint16_t port) {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (host == "0.0.0.0" || host.empty()) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
                // Try hostname resolution
                struct hostent* he = gethostbyname(host.c_str());
                if (he == nullptr) {
                    throw std::runtime_error("Failed to resolve hostname: " + host);
                }
                memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
            }
        }

        return addr;
    }
};

// TunInterface::Impl class
class TunInterface::Impl {
public:
    int tun_fd = -1;
    std::string interface_name;

    ~Impl() {
        if (tun_fd >= 0) {
            close(tun_fd);
        }
    }

    bool create_tun_interface(const std::string& name) {
        tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            LOG_ERROR("Failed to open /dev/net/tun: " + std::string(strerror(errno)));
            return false;
        }

        struct ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        if (!name.empty()) {
            strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        }

        if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
            LOG_ERROR("Failed to create TUN interface: " + std::string(strerror(errno)));
            close(tun_fd);
            tun_fd = -1;
            return false;
        }

        interface_name = ifr.ifr_name;
        LOG_INFO("Created TUN interface: " + interface_name);
        return true;
    }

    bool execute_command(const std::string& cmd) {
        LOG_DEBUG("Executing command: " + cmd);
        int result = system(cmd.c_str());
        if (result != 0) {
            LOG_ERROR("Command failed with exit code: " + std::to_string(result));
            return false;
        }
        return true;
    }
};

// NetworkManager implementation
NetworkManager::NetworkManager() : pimpl(std::make_unique<Impl>()) {}

NetworkManager::~NetworkManager() = default;

bool NetworkManager::connect(const NetworkEndpoint& endpoint, int /* timeout_ms */) {
    if (!pimpl->create_socket(endpoint.protocol)) {
        return false;
    }

    try {
        struct sockaddr_in addr = pimpl->create_sockaddr(endpoint.host, endpoint.port);
        
        if (endpoint.protocol == ProtocolType::TCP) {
            if (::connect(pimpl->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                LOG_ERROR("Failed to connect to " + endpoint.host + ":" + std::to_string(endpoint.port) + 
                         ": " + std::string(strerror(errno)));
                return false;
            }
        }

        pimpl->remote_endpoint = endpoint;
        pimpl->connected = true;
        
        LOG_INFO("Connected to " + endpoint.host + ":" + std::to_string(endpoint.port));
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Connection failed: " + std::string(e.what()));
        return false;
    }
}

bool NetworkManager::bind(const NetworkEndpoint& endpoint) {
    if (!pimpl->create_socket(endpoint.protocol)) {
        return false;
    }

    try {
        struct sockaddr_in addr = pimpl->create_sockaddr(endpoint.host, endpoint.port);

        if (::bind(pimpl->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            LOG_ERROR("Failed to bind to " + endpoint.host + ":" + std::to_string(endpoint.port) + 
                     ": " + std::string(strerror(errno)));
            return false;
        }

        pimpl->local_endpoint = endpoint;
        pimpl->is_server = true;
        
        LOG_INFO("Bound to " + endpoint.host + ":" + std::to_string(endpoint.port));
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Bind failed: " + std::string(e.what()));
        return false;
    }
}

bool NetworkManager::listen(int backlog) {
    if (!pimpl->is_server || pimpl->current_protocol != ProtocolType::TCP) {
        LOG_ERROR("Listen called on non-server or non-TCP socket");
        return false;
    }

    if (::listen(pimpl->socket_fd, backlog) < 0) {
        LOG_ERROR("Failed to listen: " + std::string(strerror(errno)));
        return false;
    }

    LOG_INFO("Listening for connections with backlog: " + std::to_string(backlog));
    return true;
}

std::unique_ptr<NetworkManager> NetworkManager::accept() {
    if (!pimpl->is_server) {
        return nullptr;
    }

    struct sockaddr_in client_addr{};
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = ::accept(pimpl->socket_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        LOG_ERROR("Failed to accept connection: " + std::string(strerror(errno)));
        return nullptr;
    }

    auto client_manager = std::make_unique<NetworkManager>();
    client_manager->pimpl->socket_fd = client_fd;
    client_manager->pimpl->connected = true;
    client_manager->pimpl->current_protocol = pimpl->current_protocol;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    client_manager->pimpl->remote_endpoint.host = client_ip;
    client_manager->pimpl->remote_endpoint.port = ntohs(client_addr.sin_port);

    LOG_INFO("Accepted connection from " + std::string(client_ip) + ":" + 
             std::to_string(ntohs(client_addr.sin_port)));
    
    return client_manager;
}

void NetworkManager::disconnect() {
    if (pimpl->socket_fd >= 0) {
        close(pimpl->socket_fd);
        pimpl->socket_fd = -1;
    }
    pimpl->connected = false;
    LOG_DEBUG("Network connection closed");
}

bool NetworkManager::is_connected() const {
    return pimpl->connected && pimpl->socket_fd >= 0;
}

ssize_t NetworkManager::send(const void* data, size_t length) {
    if (!is_connected()) {
        return -1;
    }

    ssize_t bytes_sent = ::send(pimpl->socket_fd, data, length, MSG_NOSIGNAL);
    if (bytes_sent < 0) {
        LOG_ERROR("Send failed: " + std::string(strerror(errno)));
    }
    return bytes_sent;
}

ssize_t NetworkManager::receive(void* buffer, size_t buffer_size) {
    if (!is_connected()) {
        return -1;
    }

    ssize_t bytes_received = ::recv(pimpl->socket_fd, buffer, buffer_size, 0);
    if (bytes_received < 0) {
        LOG_ERROR("Receive failed: " + std::string(strerror(errno)));
    }
    return bytes_received;
}

ssize_t NetworkManager::send_packet(const std::vector<uint8_t>& data, PacketType type, uint64_t sequence) {
    PacketHeader header{};
    header.magic = FLUNK_MAGIC;
    header.version = PROTOCOL_VERSION;
    header.type = static_cast<uint8_t>(type);
    header.flags = 0;
    header.length = static_cast<uint32_t>(data.size());
    header.sequence = sequence;
    header.timestamp = static_cast<uint64_t>(time(nullptr));
    header.checksum = 0; // TODO: Calculate actual checksum

    // Send header
    ssize_t header_sent = send(&header, sizeof(header));
    if (header_sent != sizeof(header)) {
        return -1;
    }

    // Send data
    if (!data.empty()) {
        ssize_t data_sent = send(data.data(), data.size());
        if (data_sent < 0) {
            return -1;
        }
        return header_sent + data_sent;
    }

    return header_sent;
}

ssize_t NetworkManager::receive_packet(std::vector<uint8_t>& data, PacketHeader& header) {
    // Receive header
    ssize_t header_received = receive(&header, sizeof(header));
    if (header_received != sizeof(header)) {
        return -1;
    }

    // Validate header
    if (header.magic != FLUNK_MAGIC) {
        LOG_ERROR("Invalid packet magic");
        return -1;
    }

    // Receive data
    if (header.length > 0) {
        data.resize(header.length);
        ssize_t data_received = receive(data.data(), header.length);
        if (data_received != static_cast<ssize_t>(header.length)) {
            return -1;
        }
        return header_received + data_received;
    }

    data.clear();
    return header_received;
}

std::string NetworkManager::get_local_address() const {
    if (pimpl->socket_fd < 0) return "";
    
    struct sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);
    if (getsockname(pimpl->socket_fd, (struct sockaddr*)&addr, &addr_len) < 0) {
        return "";
    }
    
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, INET_ADDRSTRLEN);
    return ip;
}

uint16_t NetworkManager::get_local_port() const {
    if (pimpl->socket_fd < 0) return 0;
    
    struct sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);
    if (getsockname(pimpl->socket_fd, (struct sockaddr*)&addr, &addr_len) < 0) {
        return 0;
    }
    
    return ntohs(addr.sin_port);
}

std::string NetworkManager::get_remote_address() const {
    return pimpl->remote_endpoint.host;
}

uint16_t NetworkManager::get_remote_port() const {
    return pimpl->remote_endpoint.port;
}

bool NetworkManager::switch_protocol(ProtocolType /* new_protocol */) {
    // TODO: Implement protocol switching
    return false;
}

ProtocolType NetworkManager::get_current_protocol() const {
    return pimpl->current_protocol;
}

bool NetworkManager::set_non_blocking(bool non_blocking) {
    if (pimpl->socket_fd < 0) return false;
    
    int flags = fcntl(pimpl->socket_fd, F_GETFL, 0);
    if (flags < 0) return false;
    
    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    return fcntl(pimpl->socket_fd, F_SETFL, flags) >= 0;
}

bool NetworkManager::set_keep_alive(bool enable) {
    if (pimpl->socket_fd < 0) return false;
    
    int opt = enable ? 1 : 0;
    return setsockopt(pimpl->socket_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) >= 0;
}

bool NetworkManager::set_tcp_nodelay(bool enable) {
    if (pimpl->socket_fd < 0 || pimpl->current_protocol != ProtocolType::TCP) {
        return false;
    }
    
    int opt = enable ? 1 : 0;
    return setsockopt(pimpl->socket_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) >= 0;
}

bool NetworkManager::set_receive_timeout(int timeout_ms) {
    if (pimpl->socket_fd < 0) return false;
    
    struct timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    return setsockopt(pimpl->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) >= 0;
}

bool NetworkManager::set_send_timeout(int timeout_ms) {
    if (pimpl->socket_fd < 0) return false;
    
    struct timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    return setsockopt(pimpl->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) >= 0;
}

// TunInterface implementation
TunInterface::TunInterface() : pimpl(std::make_unique<Impl>()) {}

TunInterface::~TunInterface() = default;

bool TunInterface::create_interface(const std::string& name) {
    return pimpl->create_tun_interface(name);
}

bool TunInterface::configure_ip(const std::string& ip, const std::string& netmask) {
    if (pimpl->interface_name.empty()) {
        LOG_ERROR("TUN interface not created");
        return false;
    }

    std::string cmd = "ip addr add " + ip + "/" + netmask + " dev " + pimpl->interface_name;
    return pimpl->execute_command(cmd);
}

bool TunInterface::add_route(const std::string& dest, const std::string& gateway) {
    std::string cmd = "ip route add " + dest + " via " + gateway;
    return pimpl->execute_command(cmd);
}

bool TunInterface::bring_up() {
    if (pimpl->interface_name.empty()) {
        LOG_ERROR("TUN interface not created");
        return false;
    }

    std::string cmd = "ip link set " + pimpl->interface_name + " up";
    return pimpl->execute_command(cmd);
}

bool TunInterface::bring_down() {
    if (pimpl->interface_name.empty()) {
        LOG_ERROR("TUN interface not created");
        return false;
    }

    std::string cmd = "ip link set " + pimpl->interface_name + " down";
    return pimpl->execute_command(cmd);
}

ssize_t TunInterface::read_packet(void* buffer, size_t buffer_size) {
    if (pimpl->tun_fd < 0) {
        return -1;
    }

    return read(pimpl->tun_fd, buffer, buffer_size);
}

ssize_t TunInterface::write_packet(const void* data, size_t length) {
    if (pimpl->tun_fd < 0) {
        return -1;
    }

    return write(pimpl->tun_fd, data, length);
}

std::string TunInterface::get_interface_name() const {
    return pimpl->interface_name;
}

int TunInterface::get_file_descriptor() const {
    return pimpl->tun_fd;
}

// Network utilities
std::vector<NetworkEndpoint> resolve_hostname(const std::string& hostname, uint16_t port) {
    std::vector<NetworkEndpoint> endpoints;
    
    struct hostent* he = gethostbyname(hostname.c_str());
    if (he == nullptr) {
        return endpoints;
    }
    
    for (int i = 0; he->h_addr_list[i] != nullptr; ++i) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, he->h_addr_list[i], ip, INET_ADDRSTRLEN);
        
        NetworkEndpoint endpoint;
        endpoint.host = ip;
        endpoint.port = port;
        endpoint.protocol = ProtocolType::UDP;
        endpoints.push_back(endpoint);
    }
    
    return endpoints;
}

bool is_valid_ip_address(const std::string& ip) {
    struct sockaddr_in sa{};
    return inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1;
}

std::string get_default_gateway() {
    // TODO: Implement proper gateway detection
    return "0.0.0.0";
}

std::vector<std::string> get_local_ip_addresses() {
    // TODO: Implement proper interface enumeration
    return {"127.0.0.1"};
}

} // namespace flunk