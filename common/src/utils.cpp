#include "flunk/utils.h"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <random>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sodium.h>

namespace flunk {

std::string Utils::get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

uint64_t Utils::get_current_unix_timestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string Utils::format_duration(std::chrono::milliseconds duration) {
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    duration -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
    duration -= minutes;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    
    std::stringstream ss;
    if (hours.count() > 0) {
        ss << hours.count() << "h ";
    }
    if (minutes.count() > 0 || hours.count() > 0) {
        ss << minutes.count() << "m ";
    }
    ss << seconds.count() << "s";
    
    return ss.str();
}

std::string Utils::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

std::vector<std::string> Utils::split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string Utils::join(const std::vector<std::string>& strings, const std::string& delimiter) {
    if (strings.empty()) return "";
    
    std::stringstream ss;
    ss << strings[0];
    for (size_t i = 1; i < strings.size(); ++i) {
        ss << delimiter << strings[i];
    }
    
    return ss.str();
}

bool Utils::starts_with(const std::string& str, const std::string& prefix) {
    return str.length() >= prefix.length() && 
           str.compare(0, prefix.length(), prefix) == 0;
}

bool Utils::ends_with(const std::string& str, const std::string& suffix) {
    return str.length() >= suffix.length() && 
           str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

std::string Utils::to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string Utils::to_upper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::string Utils::base64_encode(const std::vector<uint8_t>& data) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0, valb = -6;
    
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        encoded.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    
    return encoded;
}

std::vector<uint8_t> Utils::base64_decode(const std::string& encoded) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> decoded;
    int val = 0, valb = -8;
    
    for (char c : encoded) {
        if (c == '=') break;
        auto pos = chars.find(c);
        if (pos == std::string::npos) continue;
        
        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            decoded.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    return decoded;
}

std::string Utils::url_encode(const std::string& str) {
    std::stringstream encoded;
    encoded << std::hex;
    
    for (char c : str) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    
    return encoded.str();
}

std::string Utils::url_decode(const std::string& str) {
    std::string decoded;
    
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            std::string hex = str.substr(i + 1, 2);
            char c = static_cast<char>(std::stoul(hex, nullptr, 16));
            decoded += c;
            i += 2;
        } else if (str[i] == '+') {
            decoded += ' ';
        } else {
            decoded += str[i];
        }
    }
    
    return decoded;
}

std::mt19937& Utils::get_rng() {
    static thread_local std::mt19937 rng(std::random_device{}());
    return rng;
}

std::string Utils::generate_random_string(size_t length, const std::string& charset) {
    std::string default_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const std::string& chars = charset.empty() ? default_charset : charset;
    
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    std::string result;
    result.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        result += chars[dis(get_rng())];
    }
    
    return result;
}

std::vector<uint8_t> Utils::generate_random_bytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    randombytes_buf(bytes.data(), length);
    return bytes;
}

int Utils::generate_random_int(int min, int max) {
    std::uniform_int_distribution<> dis(min, max);
    return dis(get_rng());
}

bool Utils::file_exists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

bool Utils::create_directory(const std::string& path) {
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

std::string Utils::read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    
    return std::string((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
}

bool Utils::write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    
    file << content;
    return file.good();
}

size_t Utils::get_file_size(const std::string& path) {
    struct stat stat_buf;
    return (stat(path.c_str(), &stat_buf) == 0) ? stat_buf.st_size : 0;
}

bool Utils::is_valid_ipv4(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

bool Utils::is_valid_ipv6(const std::string& ip) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 0;
}

bool Utils::is_private_ip(const std::string& ip) {
    if (!is_valid_ipv4(ip)) return false;
    
    auto parts = split(ip, '.');
    if (parts.size() != 4) return false;
    
    int first = std::stoi(parts[0]);
    int second = std::stoi(parts[1]);
    
    return (first == 10) ||
           (first == 172 && second >= 16 && second <= 31) ||
           (first == 192 && second == 168);
}

std::string Utils::get_hostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "";
}

bool Utils::is_root() {
    return geteuid() == 0;
}

std::string Utils::get_username() {
    const char* username = getenv("USER");
    return username ? std::string(username) : "";
}

std::string Utils::get_home_directory() {
    const char* home = getenv("HOME");
    return home ? std::string(home) : "";
}

int Utils::execute_command(const std::string& command) {
    return system(command.c_str());
}

std::string Utils::calculate_sha256(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

std::string Utils::calculate_md5(const std::vector<uint8_t>& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

bool Utils::constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

void Utils::secure_memzero(void* ptr, size_t size) {
    sodium_memzero(ptr, size);
}

void* Utils::secure_malloc(size_t size) {
    return sodium_malloc(size);
}

void Utils::secure_free(void* ptr, size_t /* size */) {
    sodium_free(ptr);
}

// SecureMemory implementation
SecureMemory::SecureMemory(size_t size) : ptr(nullptr), size_(size) {
    if (size > 0) {
        ptr = sodium_malloc(size);
        if (!ptr) {
            throw std::bad_alloc();
        }
    }
}

SecureMemory::~SecureMemory() {
    if (ptr) {
        sodium_free(ptr);
    }
}

SecureMemory::SecureMemory(SecureMemory&& other) noexcept 
    : ptr(other.ptr), size_(other.size_) {
    other.ptr = nullptr;
    other.size_ = 0;
}

SecureMemory& SecureMemory::operator=(SecureMemory&& other) noexcept {
    if (this != &other) {
        if (ptr) {
            sodium_free(ptr);
        }
        ptr = other.ptr;
        size_ = other.size_;
        other.ptr = nullptr;
        other.size_ = 0;
    }
    return *this;
}

} // namespace flunk