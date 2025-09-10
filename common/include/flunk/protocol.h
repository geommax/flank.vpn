#pragma once

#include "crypto.h"
#include "network.h"
#include <cstdint>
#include <vector>
#include <memory>

namespace flunk {

// VPN Protocol Messages
enum class MessageType : uint8_t {
    // Handshake messages
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    KEY_EXCHANGE = 0x03,
    AUTH_REQUEST = 0x04,
    AUTH_RESPONSE = 0x05,
    SESSION_ESTABLISHED = 0x06,
    
    // Data messages
    DATA_PACKET = 0x10,
    KEEPALIVE = 0x11,
    
    // Control messages
    DISCONNECT = 0x20,
    RECONNECT = 0x21,
    ERROR_MSG = 0x22,
    
    // Evasion messages
    HTTP_WRAPPED = 0x30,
    TLS_WRAPPED = 0x31,
    STEGANOGRAPHIC = 0x32
};

struct ProtocolMessage {
    MessageType type;
    uint32_t length;
    uint64_t sequence;
    uint64_t timestamp;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> mac;
};

// Client Hello Message
struct ClientHelloMessage {
    uint16_t protocol_version;
    std::vector<uint8_t> client_random;
    std::vector<uint8_t> client_public_key;
    std::vector<std::string> supported_ciphers;
    std::vector<std::string> supported_features;
    std::string username;
};

// Server Hello Message
struct ServerHelloMessage {
    uint16_t protocol_version;
    std::vector<uint8_t> server_random;
    std::vector<uint8_t> server_public_key;
    std::string selected_cipher;
    std::vector<std::string> enabled_features;
    uint32_t session_id;
};

// Authentication Request
struct AuthRequestMessage {
    std::string username;
    std::vector<uint8_t> challenge_response;
    std::vector<uint8_t> proof_of_work;
};

// Authentication Response
struct AuthResponseMessage {
    bool success;
    std::string error_message;
    std::vector<uint8_t> session_key;
    std::string assigned_ip;
    std::string dns_servers;
    uint32_t session_timeout;
};

// VPN Protocol Handler
class ProtocolHandler {
public:
    ProtocolHandler();
    ~ProtocolHandler();

    // Message serialization
    std::vector<uint8_t> serialize_message(const ProtocolMessage& message);
    bool deserialize_message(const std::vector<uint8_t>& data, ProtocolMessage& message);

    // Specific message handling
    std::vector<uint8_t> create_client_hello(const ClientHelloMessage& hello);
    bool parse_client_hello(const std::vector<uint8_t>& data, ClientHelloMessage& hello);

    std::vector<uint8_t> create_server_hello(const ServerHelloMessage& hello);
    bool parse_server_hello(const std::vector<uint8_t>& data, ServerHelloMessage& hello);

    std::vector<uint8_t> create_auth_request(const AuthRequestMessage& auth);
    bool parse_auth_request(const std::vector<uint8_t>& data, AuthRequestMessage& auth);

    std::vector<uint8_t> create_auth_response(const AuthResponseMessage& response);
    bool parse_auth_response(const std::vector<uint8_t>& data, AuthResponseMessage& response);

    // Data packet handling
    std::vector<uint8_t> create_data_packet(const std::vector<uint8_t>& payload, 
                                           uint64_t sequence, 
                                           const CryptoKeys& keys);
    bool parse_data_packet(const std::vector<uint8_t>& data, 
                          std::vector<uint8_t>& payload,
                          uint64_t& sequence,
                          const CryptoKeys& keys);

    // Message authentication
    bool authenticate_message(ProtocolMessage& message, const CryptoKeys& keys);
    bool verify_message_auth(const ProtocolMessage& message, const CryptoKeys& keys);

    // Evasion wrapper handling
    std::vector<uint8_t> wrap_in_http(const ProtocolMessage& message);
    bool unwrap_from_http(const std::vector<uint8_t>& http_data, ProtocolMessage& message);

    std::vector<uint8_t> wrap_in_tls(const ProtocolMessage& message);
    bool unwrap_from_tls(const std::vector<uint8_t>& tls_data, ProtocolMessage& message);

private:
    std::unique_ptr<CryptoEngine> crypto_engine;
    
    // Message validation
    bool validate_message_structure(const ProtocolMessage& message);
    bool validate_sequence_number(uint64_t sequence, uint64_t expected);
    bool validate_timestamp(uint64_t timestamp);
    
    // Compression (optional)
    std::vector<uint8_t> compress_payload(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> decompress_payload(const std::vector<uint8_t>& compressed);
};

// Session Management
class VPNSession {
public:
    VPNSession();
    ~VPNSession();

    // Session lifecycle
    bool initialize_client_session(const std::string& server_host, uint16_t server_port);
    bool initialize_server_session();
    bool establish_connection();
    void terminate_session();

    // Key management
    bool perform_key_exchange();
    bool derive_session_keys(const std::vector<uint8_t>& shared_secret);
    bool rotate_keys();

    // Session state
    bool is_established() const;
    uint32_t get_session_id() const;
    std::string get_assigned_ip() const;
    time_t get_creation_time() const;
    time_t get_last_activity() const;

    // Statistics
    uint64_t get_bytes_sent() const;
    uint64_t get_bytes_received() const;
    uint64_t get_packets_sent() const;
    uint64_t get_packets_received() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

} // namespace flunk