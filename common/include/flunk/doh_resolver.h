#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace flunk {

// DNS over HTTPS resolver for encrypted DNS queries
class DoHResolver {
public:
    DoHResolver();
    ~DoHResolver();

    // Configure DoH providers
    bool add_doh_provider(const std::string& name, const std::string& url);
    bool remove_doh_provider(const std::string& name);
    void load_default_providers();

    // DNS resolution
    std::vector<std::string> resolve_a_record(const std::string& hostname);
    std::vector<std::string> resolve_aaaa_record(const std::string& hostname);
    std::string resolve_txt_record(const std::string& hostname);

    // Advanced resolution with fallback
    std::vector<std::string> resolve_with_fallback(const std::string& hostname);
    
    // Async resolution
    using ResolveCallback = std::function<void(const std::vector<std::string>&)>;
    bool resolve_async(const std::string& hostname, ResolveCallback callback);

    // Provider management
    bool test_provider_health(const std::string& provider_name);
    std::string get_fastest_provider();
    void rotate_providers();

private:
    struct DoHProvider {
        std::string name;
        std::string url;
        bool healthy;
        double avg_response_time;
        time_t last_check;
    };

    std::vector<DoHProvider> providers;
    size_t current_provider_index;

    // HTTP client for DoH requests
    bool send_doh_request(const std::string& provider_url, 
                         const std::string& query,
                         std::string& response);
    
    // DNS message parsing
    std::vector<std::string> parse_dns_response(const std::string& response);
    std::string build_dns_query(const std::string& hostname, uint16_t record_type);

    // Provider health checking
    void check_provider_health();
    std::thread health_check_thread;
    bool health_check_running;
};

} // namespace flunk