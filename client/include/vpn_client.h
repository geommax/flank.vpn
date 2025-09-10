#pragma once

#include "flunk/network.h"
#include "flunk/crypto.h"
#include "flunk/protocol.h"
#include "flunk/evasion.h"
#include "flunk/config.h"
#include <memory>
#include <atomic>
#include <thread>

namespace flunk {

class ConnectionManager;
class TunnelClient;

class VPNClient {
public:
    VPNClient();
    ~VPNClient();

    // Client lifecycle
    bool initialize(const std::string& config_file);
    bool connect_to_server(const std::string& server_host, uint16_t server_port, 
                          const std::string& username, const std::string& password);
    bool disconnect();
    bool is_connected() const;

    // Auto-reconnection
    void enable_auto_reconnect(bool enable, int retry_interval = 30);
    bool reconnect();

    // Tunnel management
    bool establish_tunnel();
    bool tear_down_tunnel();
    bool is_tunnel_active() const;

    // Configuration
    bool reload_config();
    const ConfigManager& get_config() const;

    // Connection information
    std::string get_server_address() const;
    std::string get_assigned_ip() const;
    std::string get_tunnel_interface() const;

    // Statistics
    struct ClientStats {
        bool connected;
        bool tunnel_active;
        std::string server_address;
        std::string assigned_ip;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        time_t connection_time;
        time_t last_activity;
    };
    
    ClientStats get_statistics() const;

    // Evasion control
    bool enable_evasion(bool enable);
    bool switch_evasion_technique();
    std::string get_current_evasion_technique() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

} // namespace flunk