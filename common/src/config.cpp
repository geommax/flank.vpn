#include "flunk/config.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>
#include <algorithm>

namespace flunk {

class ConfigManager::Impl {
public:
    std::unordered_map<std::string, ConfigValue> config_map;
    std::vector<std::string> validation_errors;
    bool env_substitution_enabled = true;
    
    std::string trim(const std::string& str) {
        const std::string whitespace = " \t\r\n";
        size_t start = str.find_first_not_of(whitespace);
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(whitespace);
        return str.substr(start, end - start + 1);
    }
    
    std::pair<std::string, std::string> parse_line(const std::string& line) {
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            return {"", ""};
        }
        
        std::string key = trim(line.substr(0, eq_pos));
        std::string value = trim(line.substr(eq_pos + 1));
        
        // Remove quotes if present
        if (value.length() >= 2 && value.front() == '\"' && value.back() == '\"') {
            value = value.substr(1, value.length() - 2);
        }
        
        return {key, value};
    }
    
    ConfigValue parse_value(const std::string& str_value) {
        std::string value = trim(str_value);
        
        // Try boolean
        if (value == "true" || value == "True" || value == "TRUE") {
            return true;
        }
        if (value == "false" || value == "False" || value == "FALSE") {
            return false;
        }
        
        // Try integer
        try {
            size_t pos;
            int int_val = std::stoi(value, &pos);
            if (pos == value.length()) {
                return int_val;
            }
        } catch (...) {}
        
        // Try double
        try {
            size_t pos;
            double double_val = std::stod(value, &pos);
            if (pos == value.length()) {
                return double_val;
            }
        } catch (...) {}
        
        // Default to string
        return value;
    }
};

ConfigManager::ConfigManager() : pimpl(std::make_unique<Impl>()) {
    // Set default values
    set(DefaultConfig::SERVER_BIND_ADDRESS, std::string("0.0.0.0"));
    set(DefaultConfig::SERVER_PORT, 1194);
    set(DefaultConfig::SERVER_MAX_CLIENTS, 10);
    set(DefaultConfig::SERVER_TUN_DEVICE, std::string("tun0"));
    set(DefaultConfig::SERVER_VPN_SUBNET, std::string("10.8.0.0/24"));
    
    set(DefaultConfig::CLIENT_AUTO_RECONNECT, true);
    
    set(DefaultConfig::CRYPTO_CIPHER, std::string("AES-256-GCM"));
    set(DefaultConfig::CRYPTO_PERFECT_FORWARD_SECRECY, true);
    
    set(DefaultConfig::EVASION_ENABLED, false);
    set(DefaultConfig::DOH_ENABLED, false);
    
    set(DefaultConfig::LOG_LEVEL, std::string("INFO"));
    set(DefaultConfig::LOG_MAX_SIZE, 104857600); // 100MB
}

ConfigManager::~ConfigManager() = default;

bool ConfigManager::load_from_file(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        line = pimpl->trim(line);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        auto [key, value] = pimpl->parse_line(line);
        if (!key.empty() && !value.empty()) {
            ConfigValue parsed_value = pimpl->parse_value(value);
            if (pimpl->env_substitution_enabled) {
                if (std::holds_alternative<std::string>(parsed_value)) {
                    std::string str_val = std::get<std::string>(parsed_value);
                    parsed_value = substitute_env_vars(str_val);
                }
            }
            pimpl->config_map[key] = parsed_value;
        }
    }
    
    return true;
}

bool ConfigManager::load_from_json(const std::string& /* json_content */) {
    // TODO: Implement JSON parsing
    // For now, just return false as this is a stub implementation
    return false;
}

bool ConfigManager::save_to_file(const std::string& config_path) {
    std::ofstream file(config_path);
    if (!file.is_open()) {
        return false;
    }
    
    for (const auto& [key, value] : pimpl->config_map) {
        file << key << " = ";
        
        std::visit([&file](const auto& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::string>) {
                file << "\"" << v << "\"";
            } else {
                file << v;
            }
        }, value);
        
        file << "\n";
    }
    
    return true;
}

template<typename T>
T ConfigManager::get(const std::string& key, const T& default_value) const {
    auto it = pimpl->config_map.find(key);
    if (it == pimpl->config_map.end()) {
        return default_value;
    }
    
    try {
        return std::get<T>(it->second);
    } catch (const std::bad_variant_access&) {
        return default_value;
    }
}

// Explicit template instantiations
template std::string ConfigManager::get<std::string>(const std::string&, const std::string&) const;
template int ConfigManager::get<int>(const std::string&, const int&) const;
template double ConfigManager::get<double>(const std::string&, const double&) const;
template bool ConfigManager::get<bool>(const std::string&, const bool&) const;

bool ConfigManager::set(const std::string& key, const ConfigValue& value) {
    pimpl->config_map[key] = value;
    return true;
}

bool ConfigManager::has_key(const std::string& key) const {
    return pimpl->config_map.find(key) != pimpl->config_map.end();
}

bool ConfigManager::remove_key(const std::string& key) {
    return pimpl->config_map.erase(key) > 0;
}

bool ConfigManager::create_section(const std::string& /* section_name */) {
    // TODO: Implement section support
    return false;
}

std::vector<std::string> ConfigManager::get_sections() const {
    // TODO: Implement section support
    return {};
}

std::vector<std::string> ConfigManager::get_keys_in_section(const std::string& /* section */) const {
    // TODO: Implement section support
    return {};
}

void ConfigManager::enable_env_substitution(bool enable) {
    pimpl->env_substitution_enabled = enable;
}

std::string ConfigManager::substitute_env_vars(const std::string& value) const {
    std::string result = value;
    size_t pos = 0;
    
    while ((pos = result.find("${", pos)) != std::string::npos) {
        size_t end_pos = result.find("}", pos);
        if (end_pos == std::string::npos) {
            break;
        }
        
        std::string var_name = result.substr(pos + 2, end_pos - pos - 2);
        const char* env_value = std::getenv(var_name.c_str());
        std::string replacement = env_value ? env_value : "";
        
        result.replace(pos, end_pos - pos + 1, replacement);
        pos += replacement.length();
    }
    
    return result;
}

bool ConfigManager::validate_config() const {
    pimpl->validation_errors.clear();
    
    // Basic validation - check required keys exist
    std::vector<std::string> required_keys = {
        DefaultConfig::SERVER_BIND_ADDRESS,
        DefaultConfig::SERVER_PORT,
        DefaultConfig::CRYPTO_CIPHER
    };
    
    for (const std::string& key : required_keys) {
        if (!has_key(key)) {
            pimpl->validation_errors.push_back("Missing required configuration key: " + key);
        }
    }
    
    return pimpl->validation_errors.empty();
}

std::vector<std::string> ConfigManager::get_validation_errors() const {
    return pimpl->validation_errors;
}

} // namespace flunk