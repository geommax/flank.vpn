#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <variant>
#include <vector>

namespace flunk {

using ConfigValue = std::variant<std::string, int, double, bool>;

class ConfigManager {
public:
    ConfigManager();
    ~ConfigManager();

    // Configuration loading
    bool load_from_file(const std::string& config_path);
    bool load_from_json(const std::string& json_content);
    bool save_to_file(const std::string& config_path);

    // Value access
    template<typename T>
    T get(const std::string& key, const T& default_value = T{}) const;
    
    bool set(const std::string& key, const ConfigValue& value);
    bool has_key(const std::string& key) const;
    bool remove_key(const std::string& key);

    // Section management
    bool create_section(const std::string& section_name);
    std::vector<std::string> get_sections() const;
    std::vector<std::string> get_keys_in_section(const std::string& section) const;

    // Environment variable substitution
    void enable_env_substitution(bool enable = true);
    std::string substitute_env_vars(const std::string& value) const;

    // Validation
    bool validate_config() const;
    std::vector<std::string> get_validation_errors() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

// Default configuration values
struct DefaultConfig {
    // Server configuration
    static constexpr const char* SERVER_BIND_ADDRESS = "server.bind_address";
    static constexpr const char* SERVER_PORT = "server.port";
    static constexpr const char* SERVER_MAX_CLIENTS = "server.max_clients";
    static constexpr const char* SERVER_TUN_DEVICE = "server.tun_device";
    static constexpr const char* SERVER_VPN_SUBNET = "server.vpn_subnet";
    
    // Client configuration
    static constexpr const char* CLIENT_SERVER_HOST = "client.server_host";
    static constexpr const char* CLIENT_SERVER_PORT = "client.server_port";
    static constexpr const char* CLIENT_USERNAME = "client.username";
    static constexpr const char* CLIENT_AUTO_RECONNECT = "client.auto_reconnect";
    
    // Security configuration
    static constexpr const char* CRYPTO_CIPHER = "crypto.cipher";
    static constexpr const char* CRYPTO_KEY_DERIVATION = "crypto.key_derivation";
    static constexpr const char* CRYPTO_PERFECT_FORWARD_SECRECY = "crypto.perfect_forward_secrecy";
    
    // Evasion configuration
    static constexpr const char* EVASION_ENABLED = "evasion.enabled";
    static constexpr const char* EVASION_HTTP_MASQUERADE = "evasion.http_masquerade";
    static constexpr const char* EVASION_TLS_FINGERPRINT = "evasion.tls_fingerprint";
    static constexpr const char* EVASION_DOMAIN_FRONTING = "evasion.domain_fronting";
    static constexpr const char* EVASION_STEGANOGRAPHY = "evasion.steganography";
    
    // DoH configuration
    static constexpr const char* DOH_ENABLED = "doh.enabled";
    static constexpr const char* DOH_PROVIDERS = "doh.providers";
    
    // Logging configuration
    static constexpr const char* LOG_LEVEL = "logging.level";
    static constexpr const char* LOG_FILE = "logging.file";
    static constexpr const char* LOG_MAX_SIZE = "logging.max_size";
};

} // namespace flunk