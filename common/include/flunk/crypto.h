#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <array>

namespace flunk {

// AES-256-GCM key size
constexpr size_t AES_KEY_SIZE = 32;
constexpr size_t AES_IV_SIZE = 12;
constexpr size_t AES_TAG_SIZE = 16;

// ChaCha20-Poly1305 key size
constexpr size_t CHACHA_KEY_SIZE = 32;
constexpr size_t CHACHA_NONCE_SIZE = 12;
constexpr size_t CHACHA_TAG_SIZE = 16;

// ECDH key sizes
constexpr size_t ECDH_PRIVATE_KEY_SIZE = 32;
constexpr size_t ECDH_PUBLIC_KEY_SIZE = 32;

// Derived key sizes
constexpr size_t DERIVED_KEY_SIZE = 64;
constexpr size_t SALT_SIZE = 32;

using SecureBytes = std::vector<uint8_t>;
using KeyArray = std::array<uint8_t, AES_KEY_SIZE>;
using IVArray = std::array<uint8_t, AES_IV_SIZE>;

struct CryptoKeys {
    KeyArray encryption_key;
    KeyArray mac_key;
    uint64_t sequence_number;
    time_t creation_time;
};

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Key derivation
    bool derive_keys(const std::string& password, const SecureBytes& salt, CryptoKeys& keys);
    bool hkdf_expand(const SecureBytes& prk, const std::string& info, size_t length, SecureBytes& output);

    // ECDH key exchange
    bool generate_ecdh_keypair(SecureBytes& private_key, SecureBytes& public_key);
    bool compute_shared_secret(const SecureBytes& private_key, const SecureBytes& peer_public_key, SecureBytes& shared_secret);

    // AES-256-GCM encryption/decryption
    bool encrypt_aes_gcm(const SecureBytes& plaintext, const KeyArray& key, 
                        const IVArray& iv, SecureBytes& ciphertext, SecureBytes& tag);
    bool decrypt_aes_gcm(const SecureBytes& ciphertext, const SecureBytes& tag, 
                        const KeyArray& key, const IVArray& iv, SecureBytes& plaintext);

    // ChaCha20-Poly1305 encryption/decryption (fallback)
    bool encrypt_chacha20_poly1305(const SecureBytes& plaintext, const KeyArray& key,
                                  const SecureBytes& nonce, SecureBytes& ciphertext);
    bool decrypt_chacha20_poly1305(const SecureBytes& ciphertext, const KeyArray& key,
                                  const SecureBytes& nonce, SecureBytes& plaintext);

    // Secure random generation
    bool generate_random(SecureBytes& output, size_t length);
    bool generate_random_iv(IVArray& iv);

    // Anti-replay protection
    bool validate_sequence_number(uint64_t sequence, uint64_t expected);
    bool validate_timestamp(time_t timestamp, time_t current_time, uint32_t window = 300);

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

// Utility functions
void secure_zero(void* ptr, size_t size);
std::string bytes_to_hex(const SecureBytes& bytes);
SecureBytes hex_to_bytes(const std::string& hex);

} // namespace flunk