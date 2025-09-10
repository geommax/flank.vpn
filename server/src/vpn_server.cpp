#include "vpn_server.h"
#include "flunk/logger.h"
#include "flunk/utils.h"
#include "flunk/network.h"
#include "flunk/config.h"
#include <chrono>
#include <thread>
#include <memory>
#include <mutex>

namespace flunk {

// VPNServer::Impl class for pimpl pattern
class VPNServer::Impl {
public:
    Impl() : running_(false), start_time_(0), config_manager_(std::make_unique<ConfigManager>()),
             network_manager_(std::make_unique<NetworkManager>()),
             tun_interface_(std::make_unique<TunInterface>()) {}
    
    ~Impl() {
        stop();
    }
    
    bool initialize(const std::string& config_file) {
        config_file_ = config_file;
        LOG_INFO("Server initializing with config: " + config_file);
        
        // Load configuration file
        if (!config_manager_->load_from_file(config_file)) {
            LOG_ERROR("Failed to load configuration file: " + config_file);
            return false;
        }
        
        // Validate configuration
        if (!config_manager_->validate_config()) {
            LOG_ERROR("Configuration validation failed");
            auto errors = config_manager_->get_validation_errors();
            for (const auto& error : errors) {
                LOG_ERROR("Config error: " + error);
            }
            return false;
        }
        
        LOG_INFO("Configuration loaded and validated successfully");
        return true;
    }
    
    bool start() {
        if (running_) {
            LOG_WARN("Server is already running");
            return false;
        }
        
        LOG_INFO("Starting VPN server...");
        
        // Get configuration values
        std::string bind_address = config_manager_->get<std::string>("server.bind_address", "0.0.0.0");
        int port = config_manager_->get<int>("server.port", 1194);
        std::string tun_device = config_manager_->get<std::string>("server.tun_device", "flunk0");
        std::string vpn_subnet = config_manager_->get<std::string>("server.vpn_subnet", "10.8.0.0/24");
        std::string vpn_gateway = config_manager_->get<std::string>("server.vpn_gateway", "10.8.0.1");
        
        // Create and configure TUN interface
        LOG_INFO("Creating TUN interface: " + tun_device);
        if (!tun_interface_->create_interface(tun_device)) {
            LOG_ERROR("Failed to create TUN interface");
            return false;
        }
        
        // Extract IP and netmask from subnet
        size_t slash_pos = vpn_subnet.find('/');
        if (slash_pos == std::string::npos) {
            LOG_ERROR("Invalid VPN subnet format: " + vpn_subnet);
            return false;
        }
        
        std::string netmask = vpn_subnet.substr(slash_pos + 1);
        
        // Configure TUN interface IP
        if (!tun_interface_->configure_ip(vpn_gateway, netmask)) {
            LOG_ERROR("Failed to configure TUN interface IP");
            return false;
        }
        
        // Bring up TUN interface
        if (!tun_interface_->bring_up()) {
            LOG_ERROR("Failed to bring up TUN interface");
            return false;
        }
        
        LOG_INFO("TUN interface " + tun_interface_->get_interface_name() + " created and configured");
        
        // Create listening socket
        NetworkEndpoint endpoint;
        endpoint.host = bind_address;
        endpoint.port = static_cast<uint16_t>(port);
        endpoint.protocol = ProtocolType::UDP;
        
        LOG_INFO("Binding to " + bind_address + ":" + std::to_string(port));
        if (!network_manager_->bind(endpoint)) {
            LOG_ERROR("Failed to bind to " + bind_address + ":" + std::to_string(port));
            return false;
        }
        
        running_ = true;
        start_time_ = time(nullptr);
        
        // Start server thread for handling clients
        server_thread_ = std::thread(&Impl::server_worker, this);
        
        LOG_INFO("VPN server started successfully on " + bind_address + ":" + std::to_string(port));
        return true;
    }
    
    void stop() {
        if (!running_) {
            return;
        }
        
        LOG_INFO("Stopping VPN server...");
        running_ = false;
        
        // Stop network manager
        if (network_manager_) {
            network_manager_->disconnect();
        }
        
        // Bring down TUN interface
        if (tun_interface_) {
            tun_interface_->bring_down();
        }
        
        // Wait for server thread to finish
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
        
        // Disconnect all clients
        for (auto& client : active_clients_) {
            if (client) {
                client->disconnect();
            }
        }
        active_clients_.clear();
        
        LOG_INFO("VPN server stopped");
    }
    
    bool is_running() const {
        return running_;
    }
    
    VPNServer::ServerStats get_statistics() const {
        VPNServer::ServerStats stats{};
        stats.total_clients_served = total_clients_served_;
        stats.current_active_clients = current_active_clients_;
        stats.total_bytes_transferred = total_bytes_transferred_;
        stats.start_time = start_time_;
        
        if (start_time_ > 0) {
            stats.uptime_seconds = time(nullptr) - start_time_;
        } else {
            stats.uptime_seconds = 0;
        }
        
        return stats;
    }
    
private:
    std::atomic<bool> running_;
    std::string config_file_;
    time_t start_time_;
    
    // Core components
    std::unique_ptr<ConfigManager> config_manager_;
    std::unique_ptr<NetworkManager> network_manager_;
    std::unique_ptr<TunInterface> tun_interface_;
    
    // Threading
    std::thread server_thread_;
    
    // Client management
    std::vector<std::unique_ptr<ClientConnection>> active_clients_;
    std::mutex clients_mutex_;
    
    // Statistics
    std::atomic<uint64_t> total_clients_served_{0};
    std::atomic<uint64_t> current_active_clients_{0};
    std::atomic<uint64_t> total_bytes_transferred_{0};
    
    void server_worker() {
        LOG_INFO("Server worker thread started");
        
        while (running_) {
            // Receive packet from client
            std::vector<uint8_t> packet_data;
            PacketHeader header;
            
            ssize_t bytes_received = network_manager_->receive_packet(packet_data, header);
            if (bytes_received > 0) {
                LOG_DEBUG("Received packet from client: type=" + std::to_string(header.type) + 
                         ", length=" + std::to_string(header.length));
                
                total_bytes_transferred_ += bytes_received;
                
                // Handle different packet types
                switch (static_cast<PacketType>(header.type)) {
                    case PacketType::HANDSHAKE_INIT: {
                        LOG_INFO("Received client handshake");
                        if (!packet_data.empty()) {
                            std::string hello_msg(packet_data.begin(), packet_data.end());
                            LOG_INFO("Client hello: " + hello_msg);
                        }
                        
                        // Send handshake response
                        std::string response = "FLUNK_SERVER_HELLO:Welcome";
                        std::vector<uint8_t> response_data(response.begin(), response.end());
                        network_manager_->send_packet(response_data, PacketType::HANDSHAKE_RESPONSE, header.sequence + 1);
                        
                        current_active_clients_ = 1; // Simple single-client handling for now
                        total_clients_served_++;
                        LOG_INFO("Sent handshake response to client");
                        break;
                    }
                    
                    case PacketType::DATA: {
                        LOG_DEBUG("Received data packet from client");
                        // Echo data back (tunnel simulation)
                        network_manager_->send_packet(packet_data, PacketType::DATA, header.sequence + 1);
                        break;
                    }
                    
                    case PacketType::KEEPALIVE: {
                        LOG_DEBUG("Received keepalive from client");
                        // Send keepalive response
                        std::vector<uint8_t> keepalive_data;
                        network_manager_->send_packet(keepalive_data, PacketType::KEEPALIVE, header.sequence + 1);
                        break;
                    }
                    
                    case PacketType::DISCONNECT: {
                        LOG_INFO("Client requested disconnect");
                        current_active_clients_ = 0;
                        break;
                    }
                    
                    default:
                        LOG_WARN("Unknown packet type received: " + std::to_string(header.type));
                        break;
                }
                
            } else if (bytes_received < 0) {
                // Non-blocking socket would return -1 with EAGAIN/EWOULDBLOCK
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        
        LOG_INFO("Server worker thread stopped");
    }
};

// VPNServer implementation
VPNServer::VPNServer() : pimpl(std::make_unique<Impl>()) {}

VPNServer::~VPNServer() = default;

bool VPNServer::initialize(const std::string& config_file) {
    return pimpl->initialize(config_file);
}

bool VPNServer::start() {
    return pimpl->start();
}

void VPNServer::stop() {
    pimpl->stop();
}

bool VPNServer::is_running() const {
    return pimpl->is_running();
}

bool VPNServer::accept_client(uint32_t client_id) {
    // TODO: Implement client acceptance logic
    LOG_DEBUG("Client connection attempt for ID: " + std::to_string(client_id));
    return false;
}

bool VPNServer::disconnect_client(uint32_t client_id) {
    // TODO: Implement client disconnection logic
    LOG_DEBUG("Disconnecting client " + std::to_string(client_id));
    return false;
}

size_t VPNServer::get_client_count() const {
    // TODO: Return actual client count
    return 0;
}

bool VPNServer::reload_config() {
    // TODO: Implement configuration reloading
    LOG_INFO("Configuration reload requested");
    return false;
}

const ConfigManager& VPNServer::get_config() const {
    // TODO: Return actual config manager
    static ConfigManager dummy_config;
    return dummy_config;
}

VPNServer::ServerStats VPNServer::get_statistics() const {
    return pimpl->get_statistics();
}

// ClientConnection implementation (basic stub)
ClientConnection::ClientConnection(uint32_t id)
    : client_id(id), authenticated(false), tunnel_established(false),
      connection_start_time(time(nullptr)) {
}

ClientConnection::~ClientConnection() {
    disconnect();
}

bool ClientConnection::handshake() {
    LOG_DEBUG("Performing handshake for client " + std::to_string(client_id));
    // TODO: Implement VPN handshake protocol
    return false;
}

bool ClientConnection::authenticate() {
    LOG_DEBUG("Authenticating client " + std::to_string(client_id));
    // TODO: Implement client authentication
    return false;
}

bool ClientConnection::establish_tunnel() {
    LOG_DEBUG("Establishing tunnel for client " + std::to_string(client_id));
    // TODO: Implement tunnel establishment
    return false;
}

void ClientConnection::disconnect() {
    if (running) {
        running = false;
        LOG_INFO("Client " + std::to_string(client_id) + " disconnected");
        
        if (client_thread.joinable()) {
            client_thread.join();
        }
    }
}

bool ClientConnection::process_client_data() {
    // TODO: Implement client data processing
    return false;
}

bool ClientConnection::send_to_client(const std::vector<uint8_t>& data) {
    // TODO: Implement data sending to client
    bytes_sent += data.size();
    return false;
}

bool ClientConnection::is_authenticated() const {
    return authenticated;
}

bool ClientConnection::is_connected() const {
    return running;
}

std::string ClientConnection::get_assigned_ip() const {
    return assigned_ip;
}

std::string ClientConnection::get_remote_address() const {
    // TODO: Return actual remote address
    return "0.0.0.0";
}

uint64_t ClientConnection::get_bytes_sent() const {
    return bytes_sent;
}

uint64_t ClientConnection::get_bytes_received() const {
    return bytes_received;
}

time_t ClientConnection::get_connection_time() const {
    return connection_start_time;
}

void ClientConnection::client_worker() {
    // TODO: Implement client worker thread
    LOG_DEBUG("Client worker thread started for client " + std::to_string(client_id));
    
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // TODO: Process client data
    }
}

bool ClientConnection::process_handshake() {
    // TODO: Implement handshake processing
    return false;
}

bool ClientConnection::process_authentication() {
    // TODO: Implement authentication processing
    return false;
}

bool ClientConnection::setup_tunnel() {
    // TODO: Implement tunnel setup
    return false;
}

} // namespace flunk