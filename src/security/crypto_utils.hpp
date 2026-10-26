#pragma once
/// @file crypto_utils.hpp
/// @brief Cryptographic utilities for AKE: X25519, HKDF-SHA256, and ChaCha20-Poly1305 (Stage 4).

#include "common/types.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace p2p::security {

inline constexpr std::size_t X25519_KEY_SIZE = 32;
inline constexpr std::size_t AEAD_KEY_SIZE = 32;
inline constexpr std::size_t AEAD_NONCE_SIZE = 12;
inline constexpr std::size_t AEAD_TAG_SIZE = 16;
inline constexpr std::size_t NONCE_SIZE = 32;

/// Ephemeral X25519 keypair for Diffie-Hellman key exchange.
struct X25519Keypair {
    std::array<uint8_t, X25519_KEY_SIZE> public_key{};
    std::array<uint8_t, X25519_KEY_SIZE> secret_key{};

    /// Generate a fresh random X25519 keypair.
    static X25519Keypair generate();

    /// Securely wipes secret key on destruction.
    ~X25519Keypair();

    X25519Keypair() = default;
    X25519Keypair(X25519Keypair&&) noexcept = default;
    X25519Keypair& operator=(X25519Keypair&&) noexcept = default;
    X25519Keypair(const X25519Keypair&) = delete;
    X25519Keypair& operator=(const X25519Keypair&) = delete;
};

/// Perform X25519 Diffie-Hellman to compute 32-byte shared secret.
/// Returns std::nullopt if scalar multiplication fails or peer public key is low-order.
[[nodiscard]] std::optional<std::array<uint8_t, 32>> x25519_diffie_hellman(
    const std::array<uint8_t, X25519_KEY_SIZE>& my_secret_key,
    const std::array<uint8_t, X25519_KEY_SIZE>& peer_public_key);

/// Generate cryptographically secure random 32-byte nonce.
[[nodiscard]] std::array<uint8_t, NONCE_SIZE> generate_nonce();

/// Standard HMAC-SHA256 (RFC 2104).
[[nodiscard]] std::array<uint8_t, 32> hmac_sha256(
    const uint8_t* key, std::size_t key_len,
    const uint8_t* data, std::size_t data_len);

/// HKDF-Extract (RFC 5869): PRK = HMAC-Hash(salt, IKM).
[[nodiscard]] std::array<uint8_t, 32> hkdf_extract(
    const uint8_t* salt, std::size_t salt_len,
    const uint8_t* ikm, std::size_t ikm_len);

/// HKDF-Expand (RFC 5869): OKM = HKDF-Expand(PRK, info, L).
[[nodiscard]] Bytes hkdf_expand(
    const std::array<uint8_t, 32>& prk,
    std::string_view info,
    std::size_t length);

/// Derived directional session keys.
struct SessionKeys {
    std::array<uint8_t, AEAD_KEY_SIZE> key_a_to_b{};
    std::array<uint8_t, AEAD_KEY_SIZE> key_b_to_a{};
};

/// Derive directional session keys from shared secret and random nonces via HKDF-SHA256.
[[nodiscard]] SessionKeys derive_session_keys(
    const std::array<uint8_t, 32>& shared_secret,
    const std::array<uint8_t, NONCE_SIZE>& nonce_a,
    const std::array<uint8_t, NONCE_SIZE>& nonce_b);

/// Construct 12-byte AEAD nonce from 64-bit sequence number.
/// Format: 4 bytes zero prefix || 8 bytes sequence number in big-endian.
[[nodiscard]] std::array<uint8_t, AEAD_NONCE_SIZE> construct_aead_nonce(uint64_t seq);

/// Encrypt plaintext using ChaCha20-Poly1305 IETF.
/// @param plaintext Buffer to encrypt.
/// @param aad Additional authenticated data (e.g. frame header).
/// @param nonce 12-byte nonce.
/// @param key 32-byte symmetric key.
/// @return Ciphertext followed by 16-byte Poly1305 authentication tag.
[[nodiscard]] Bytes chacha20_poly1305_encrypt(
    const uint8_t* plaintext, std::size_t plaintext_len,
    const uint8_t* aad, std::size_t aad_len,
    const std::array<uint8_t, AEAD_NONCE_SIZE>& nonce,
    const std::array<uint8_t, AEAD_KEY_SIZE>& key);

/// Decrypt ciphertext with ChaCha20-Poly1305 IETF.
/// @param ciphertext_and_tag Buffer containing ciphertext + 16-byte Poly1305 tag.
/// @param aad Additional authenticated data.
/// @param nonce 12-byte nonce.
/// @param key 32-byte symmetric key.
/// @return Decrypted plaintext, or nullopt if authentication tag fails.
[[nodiscard]] std::optional<Bytes> chacha20_poly1305_decrypt(
    const uint8_t* ciphertext_and_tag, std::size_t ciphertext_and_tag_len,
    const uint8_t* aad, std::size_t aad_len,
    const std::array<uint8_t, AEAD_NONCE_SIZE>& nonce,
    const std::array<uint8_t, AEAD_KEY_SIZE>& key);

} // namespace p2p::security
