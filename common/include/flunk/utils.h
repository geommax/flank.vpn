#pragma once

#include <string>
#include <chrono>
#include <random>
#include <vector>
#include <memory>
#include <cstdint>

namespace flunk {

class Utils {
public:
    // Time utilities
    static std::string get_current_timestamp();
    static uint64_t get_current_unix_timestamp();
    static std::string format_duration(std::chrono::milliseconds duration);
    
    // String utilities
    static std::string trim(const std::string& str);
    static std::vector<std::string> split(const std::string& str, char delimiter);
    static std::string join(const std::vector<std::string>& strings, const std::string& delimiter);
    static bool starts_with(const std::string& str, const std::string& prefix);
    static bool ends_with(const std::string& str, const std::string& suffix);
    static std::string to_lower(const std::string& str);
    static std::string to_upper(const std::string& str);
    
    // Base64 encoding/decoding
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& encoded);
    
    // URL encoding/decoding
    static std::string url_encode(const std::string& str);
    static std::string url_decode(const std::string& str);
    
    // Random generation
    static std::string generate_random_string(size_t length, const std::string& charset = "");
    static std::vector<uint8_t> generate_random_bytes(size_t length);
    static int generate_random_int(int min, int max);
    
    // File utilities
    static bool file_exists(const std::string& path);
    static bool create_directory(const std::string& path);
    static std::string read_file(const std::string& path);
    static bool write_file(const std::string& path, const std::string& content);
    static size_t get_file_size(const std::string& path);
    
    // Network utilities
    static bool is_valid_ipv4(const std::string& ip);
    static bool is_valid_ipv6(const std::string& ip);
    static bool is_private_ip(const std::string& ip);
    static std::string get_hostname();
    
    // System utilities
    static bool is_root();
    static std::string get_username();
    static std::string get_home_directory();
    static int execute_command(const std::string& command);
    
    // Crypto utilities
    static std::string calculate_sha256(const std::vector<uint8_t>& data);
    static std::string calculate_md5(const std::vector<uint8_t>& data);
    static bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    // Memory utilities
    static void secure_memzero(void* ptr, size_t size);
    static void* secure_malloc(size_t size);
    static void secure_free(void* ptr, size_t size);

private:
    static std::mt19937& get_rng();
};

// RAII wrapper for secure memory
class SecureMemory {
public:
    explicit SecureMemory(size_t size);
    ~SecureMemory();
    
    void* get() { return ptr; }
    const void* get() const { return ptr; }
    size_t size() const { return size_; }
    
    // Non-copyable
    SecureMemory(const SecureMemory&) = delete;
    SecureMemory& operator=(const SecureMemory&) = delete;
    
    // Movable
    SecureMemory(SecureMemory&& other) noexcept;
    SecureMemory& operator=(SecureMemory&& other) noexcept;

private:
    void* ptr;
    size_t size_;
};

// Scope guard for cleanup
template<typename F>
class ScopeGuard {
public:
    explicit ScopeGuard(F&& f) : f_(std::forward<F>(f)), active_(true) {}
    
    ~ScopeGuard() {
        if (active_) {
            f_();
        }
    }
    
    void dismiss() { active_ = false; }
    
    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    
    ScopeGuard(ScopeGuard&& other) noexcept 
        : f_(std::move(other.f_)), active_(other.active_) {
        other.active_ = false;
    }

private:
    F f_;
    bool active_;
};

template<typename F>
ScopeGuard<F> make_scope_guard(F&& f) {
    return ScopeGuard<F>(std::forward<F>(f));
}

} // namespace flunk