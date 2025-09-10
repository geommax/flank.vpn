#include "flunk/crypto.h"
#include "flunk/utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace flunk {

class CryptoEngine::Impl {
public:
    Impl() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    ~Impl() = default;
};

CryptoEngine::CryptoEngine() : pimpl(std::make_unique<Impl>()) {}

CryptoEngine::~CryptoEngine() = default;

bool CryptoEngine::derive_keys(const std::string& password, const SecureBytes& salt, CryptoKeys& keys) {
    if (password.empty() || salt.size() != SALT_SIZE) {
        return false;
    }

    // Use PBKDF2 for initial key derivation
    SecureBytes derived_key(DERIVED_KEY_SIZE);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          100000, // iterations
                          EVP_sha256(),
                          DERIVED_KEY_SIZE,
                          derived_key.data()) != 1) {
        return false;
    }

    // Split derived key into encryption and MAC keys using HKDF
    SecureBytes enc_key_bytes, mac_key_bytes;
    if (!hkdf_expand(derived_key, "flunk-encryption", AES_KEY_SIZE, enc_key_bytes) ||
        !hkdf_expand(derived_key, "flunk-mac", AES_KEY_SIZE, mac_key_bytes)) {
        return false;
    }

    std::memcpy(keys.encryption_key.data(), enc_key_bytes.data(), AES_KEY_SIZE);
    std::memcpy(keys.mac_key.data(), mac_key_bytes.data(), AES_KEY_SIZE);
    keys.sequence_number = 0;
    keys.creation_time = time(nullptr);

    // Secure cleanup
    secure_zero(derived_key.data(), derived_key.size());
    secure_zero(enc_key_bytes.data(), enc_key_bytes.size());
    secure_zero(mac_key_bytes.data(), mac_key_bytes.size());

    return true;
}

bool CryptoEngine::hkdf_expand(const SecureBytes& prk, const std::string& info, size_t length, SecureBytes& output) {
    output.resize(length);
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) return false;

    auto cleanup = make_scope_guard([ctx]() { EVP_PKEY_CTX_free(ctx); });

    if (EVP_PKEY_derive_init(ctx) <= 0) return false;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) return false;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, prk.data(), prk.size()) <= 0) return false;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, 
                                   reinterpret_cast<const unsigned char*>(info.c_str()), 
                                   info.length()) <= 0) return false;

    size_t outlen = length;
    return EVP_PKEY_derive(ctx, output.data(), &outlen) > 0 && outlen == length;
}

bool CryptoEngine::generate_ecdh_keypair(SecureBytes& private_key, SecureBytes& public_key) {
    private_key.resize(ECDH_PRIVATE_KEY_SIZE);
    public_key.resize(ECDH_PUBLIC_KEY_SIZE);

    // Use Curve25519 for ECDH
    return crypto_box_keypair(public_key.data(), private_key.data()) == 0;
}

bool CryptoEngine::compute_shared_secret(const SecureBytes& private_key, 
                                        const SecureBytes& peer_public_key, 
                                        SecureBytes& shared_secret) {
    if (private_key.size() != ECDH_PRIVATE_KEY_SIZE || 
        peer_public_key.size() != ECDH_PUBLIC_KEY_SIZE) {
        return false;
    }

    shared_secret.resize(32); // Curve25519 shared secret size
    return crypto_scalarmult(shared_secret.data(), private_key.data(), peer_public_key.data()) == 0;
}

bool CryptoEngine::encrypt_aes_gcm(const SecureBytes& plaintext, const KeyArray& key, 
                                  const IVArray& iv, SecureBytes& ciphertext, SecureBytes& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    auto cleanup = make_scope_guard([ctx]() { EVP_CIPHER_CTX_free(ctx); });

    ciphertext.resize(plaintext.size());
    tag.resize(AES_TAG_SIZE);
    int len, ciphertext_len;

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) return false;
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) return false;

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) return false;
    ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) return false;
    ciphertext_len += len;

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag.data()) != 1) return false;

    ciphertext.resize(ciphertext_len);
    return true;
}

bool CryptoEngine::decrypt_aes_gcm(const SecureBytes& ciphertext, const SecureBytes& tag, 
                                  const KeyArray& key, const IVArray& iv, SecureBytes& plaintext) {
    if (tag.size() != AES_TAG_SIZE) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    auto cleanup = make_scope_guard([ctx]() { EVP_CIPHER_CTX_free(ctx); });

    plaintext.resize(ciphertext.size());
    int len, plaintext_len;

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) return false;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) return false;

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) return false;
    plaintext_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, 
                           const_cast<uint8_t*>(tag.data())) != 1) return false;

    // Finalize decryption and verify tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret <= 0) return false;

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    return true;
}

bool CryptoEngine::encrypt_chacha20_poly1305(const SecureBytes& plaintext, const KeyArray& key,
                                            const SecureBytes& nonce, SecureBytes& ciphertext) {
    if (nonce.size() != CHACHA_NONCE_SIZE) return false;

    ciphertext.resize(plaintext.size() + CHACHA_TAG_SIZE);
    unsigned long long ciphertext_len;

    return crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        nullptr, 0, // no additional data
        nullptr, // no secret nonce
        nonce.data(),
        key.data()
    ) == 0;
}

bool CryptoEngine::decrypt_chacha20_poly1305(const SecureBytes& ciphertext, const KeyArray& key,
                                            const SecureBytes& nonce, SecureBytes& plaintext) {
    if (nonce.size() != CHACHA_NONCE_SIZE || ciphertext.size() < CHACHA_TAG_SIZE) return false;

    plaintext.resize(ciphertext.size() - CHACHA_TAG_SIZE);
    unsigned long long plaintext_len;

    return crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext.data(), &plaintext_len,
        nullptr, // no secret nonce
        ciphertext.data(), ciphertext.size(),
        nullptr, 0, // no additional data
        nonce.data(),
        key.data()
    ) == 0;
}

bool CryptoEngine::generate_random(SecureBytes& output, size_t length) {
    output.resize(length);
    return RAND_bytes(output.data(), length) == 1;
}

bool CryptoEngine::generate_random_iv(IVArray& iv) {
    return RAND_bytes(iv.data(), AES_IV_SIZE) == 1;
}

bool CryptoEngine::validate_sequence_number(uint64_t sequence, uint64_t expected) {
    // Allow for some reordering but prevent major replay attacks
    const uint64_t window = 100;
    return sequence >= expected && sequence <= expected + window;
}

bool CryptoEngine::validate_timestamp(time_t timestamp, time_t current_time, uint32_t window) {
    time_t diff = std::abs(current_time - timestamp);
    return diff <= window;
}

void secure_zero(void* ptr, size_t size) {
    sodium_memzero(ptr, size);
}

std::string bytes_to_hex(const SecureBytes& bytes) {
    std::string hex;
    hex.reserve(bytes.size() * 2);
    
    for (uint8_t byte : bytes) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex += buf;
    }
    
    return hex;
}

SecureBytes hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        return {};
    }
    
    SecureBytes bytes;
    bytes.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

} // namespace flunk