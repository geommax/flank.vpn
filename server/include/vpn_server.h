#pragma once

#include "flunk/network.h"
#include "flunk/crypto.h"
#include "flunk/protocol.h"
#include "flunk/evasion.h"
#include "flunk/config.h"
#include <memory>
#include <vector>
#include <thread>
#include <atomic>

namespace flunk {

class ClientManager;
class AuthManager;
class TunnelManager;
class SessionManager;

class VPNServer {
public:
    VPNServer();
    ~VPNServer();

    // Server lifecycle
    bool initialize(const std::string& config_file);
    bool start();
    void stop();
    bool is_running() const;

    // Client management
    bool accept_client(uint32_t client_id);
    bool disconnect_client(uint32_t client_id);
    size_t get_client_count() const;

    // Configuration
    bool reload_config();
    const ConfigManager& get_config() const;

    // Statistics
    struct ServerStats {
        uint64_t total_clients_served;
        uint64_t current_active_clients;
        uint64_t total_bytes_transferred;
        uint64_t uptime_seconds;
        time_t start_time;
    };
    
    ServerStats get_statistics() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

class ClientConnection {
public:
    ClientConnection(uint32_t id);
    ~ClientConnection();

    // Connection management
    bool handshake();
    bool authenticate();
    bool establish_tunnel();
    void disconnect();

    // Data handling
    bool process_client_data();
    bool send_to_client(const std::vector<uint8_t>& data);

    // Getters
    uint32_t get_id() const { return client_id; }
    bool is_authenticated() const;
    bool is_connected() const;
    std::string get_assigned_ip() const;
    std::string get_remote_address() const;

    // Statistics
    uint64_t get_bytes_sent() const;
    uint64_t get_bytes_received() const;
    time_t get_connection_time() const;

private:
    uint32_t client_id;
    // TODO: Implement actual network connection management
    // std::unique_ptr<NetworkManager> connection;
    // std::unique_ptr<VPNSession> session;
    // std::unique_ptr<TunInterface> tun_interface;
    
    bool authenticated;
    bool tunnel_established;
    std::string assigned_ip;
    time_t connection_start_time;
    
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    
    std::thread client_thread;
    std::atomic<bool> running{false};
    
    void client_worker();
    bool process_handshake();
    bool process_authentication();
    bool setup_tunnel();
};

} // namespace flunk