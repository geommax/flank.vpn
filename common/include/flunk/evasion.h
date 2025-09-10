#pragma once

#include <string>
#include <vector>
#include <memory>
#include <random>
#include <chrono>
#include <thread>
#include "network.h"

namespace flunk {

// HTTP/HTTPS Traffic Masquerading
class HTTPMasquerader {
public:
    HTTPMasquerader();
    ~HTTPMasquerader();

    // Generate fake HTTP requests
    std::string generate_fake_request(const std::string& host, const std::string& path = "/");
    std::string generate_fake_response(int status_code = 200);
    
    // Embed VPN data in HTTP content
    bool embed_data_in_http(const std::vector<uint8_t>& vpn_data, std::string& http_content);
    bool extract_data_from_http(const std::string& http_content, std::vector<uint8_t>& vpn_data);

    // Common browser headers
    std::vector<std::string> get_browser_headers(const std::string& browser_type = "chrome");

private:
    std::mt19937 rng;
    std::vector<std::string> fake_paths;
    std::vector<std::string> fake_user_agents;
};

// TLS Fingerprint Mimicking
class TLSFingerprinter {
public:
    TLSFingerprinter();
    ~TLSFingerprinter();

    // Mimic popular browser TLS fingerprints
    bool mimic_chrome_fingerprint();
    bool mimic_firefox_fingerprint();
    bool mimic_safari_fingerprint();
    
    // Custom TLS handshake
    bool perform_custom_handshake(NetworkManager& connection, const std::string& target_host);

private:
    struct TLSConfig {
        std::vector<uint16_t> cipher_suites;
        std::vector<uint16_t> extensions;
        std::vector<uint16_t> elliptic_curves;
        std::vector<uint8_t> signature_algorithms;
    };
    
    TLSConfig chrome_config;
    TLSConfig firefox_config;
    TLSConfig safari_config;
};

// Domain Fronting
class DomainFronter {
public:
    DomainFronter();
    ~DomainFronter();

    // CDN endpoint management
    bool add_cdn_endpoint(const std::string& frontend_domain, const std::string& backend_host);
    bool remove_cdn_endpoint(const std::string& frontend_domain);
    
    // Connection through domain fronting
    std::unique_ptr<NetworkManager> connect_through_cdn(const std::string& frontend_domain, 
                                                       const std::string& backend_host, 
                                                       uint16_t backend_port);

    // Popular CDN endpoints
    void load_default_cdn_endpoints();

private:
    struct CDNEndpoint {
        std::string frontend_domain;
        std::string backend_host;
        std::vector<std::string> edge_servers;
    };
    
    std::vector<CDNEndpoint> cdn_endpoints;
};

// Traffic Randomization
class TrafficRandomizer {
public:
    TrafficRandomizer();
    ~TrafficRandomizer();

    // Packet size randomization
    size_t randomize_packet_size(size_t original_size, size_t min_size = 64, size_t max_size = 1400);
    
    // Timing randomization
    std::chrono::milliseconds randomize_delay(std::chrono::milliseconds base_delay, 
                                            double variance = 0.3);
    
    // Generate decoy traffic
    void start_decoy_traffic(const NetworkEndpoint& endpoint, 
                           std::chrono::seconds interval = std::chrono::seconds(30));
    void stop_decoy_traffic();

    // Connection pattern randomization
    std::vector<NetworkEndpoint> randomize_connection_pattern(const std::vector<NetworkEndpoint>& endpoints);

private:
    std::mt19937 rng;
    bool decoy_active;
    std::thread decoy_thread;
    
    void decoy_traffic_worker(const NetworkEndpoint& endpoint, std::chrono::seconds interval);
};

// Protocol Flexibility Manager
class ProtocolManager {
public:
    ProtocolManager();
    ~ProtocolManager();

    // Dynamic protocol switching
    bool switch_to_best_protocol(NetworkManager& connection, 
                                const std::vector<ProtocolType>& preferred_protocols);
    
    // Protocol health monitoring
    void monitor_protocol_health(NetworkManager& connection);
    ProtocolType get_best_protocol() const;
    
    // Protocol-specific optimizations
    bool optimize_for_protocol(NetworkManager& connection, ProtocolType protocol);

private:
    struct ProtocolStats {
        ProtocolType type;
        double latency;
        double packet_loss;
        double throughput;
        time_t last_test;
    };
    
    std::vector<ProtocolStats> protocol_stats;
    
    bool test_protocol_performance(NetworkManager& connection, ProtocolType protocol, ProtocolStats& stats);
};

// Main Evasion Manager
class EvasionManager {
public:
    EvasionManager();
    ~EvasionManager();

    // Initialize all evasion techniques
    bool initialize();
    
    // Apply evasion to connection
    bool apply_evasion(NetworkManager& connection, const NetworkEndpoint& target);
    
    // Dynamic evasion switching
    bool switch_evasion_technique();
    
    // Get components
    HTTPMasquerader& get_http_masquerader() { return *http_masquerader; }
    TLSFingerprinter& get_tls_fingerprinter() { return *tls_fingerprinter; }
    DomainFronter& get_domain_fronter() { return *domain_fronter; }
    TrafficRandomizer& get_traffic_randomizer() { return *traffic_randomizer; }
    ProtocolManager& get_protocol_manager() { return *protocol_manager; }

private:
    std::unique_ptr<HTTPMasquerader> http_masquerader;
    std::unique_ptr<TLSFingerprinter> tls_fingerprinter;
    std::unique_ptr<DomainFronter> domain_fronter;
    std::unique_ptr<TrafficRandomizer> traffic_randomizer;
    std::unique_ptr<ProtocolManager> protocol_manager;
};

} // namespace flunk