#pragma once
/// @file keypair.hpp
/// @brief Ed25519 identity keypair management.
///
/// Each node has a persistent Ed25519 keypair:
///   - Created once at first startup
///   - Stored in the node's data directory
///   - Private key never leaves the process / never sent over network
///   - Public key used for identity verification and NodeID computation

#include "common/types.hpp"
#include "identity/node_id.hpp"

#include <array>
#include <filesystem>
#include <optional>
#include <string>

namespace p2p::identity {

/// Ed25519 key sizes (libsodium).
inline constexpr std::size_t ED25519_PK_SIZE = 32;
inline constexpr std::size_t ED25519_SK_SIZE = 64; // libsodium stores seed+pk
inline constexpr std::size_t ED25519_SIG_SIZE = 64;

/// Ed25519 identity keypair for a node.
class Keypair {
public:
    /// Generate a new random keypair.
    static Keypair generate();

    /// Load from files in the given directory.
    /// Looks for "identity.pub" and "identity.key" files.
    /// Returns nullopt if files don't exist.
    static std::optional<Keypair> load(const std::filesystem::path& dir);

    /// Save to files in the given directory.
    /// Creates "identity.pub" and "identity.key" files.
    /// Sets restrictive permissions on the private key file.
    void save(const std::filesystem::path& dir) const;

    /// Load or generate: try loading from dir, generate if not found.
    static Keypair load_or_generate(const std::filesystem::path& dir);

    /// Get the public key (32 bytes).
    [[nodiscard]] const std::array<uint8_t, ED25519_PK_SIZE>& public_key() const {
        return public_key_;
    }

    /// Compute the NodeID from this keypair's public key.
    [[nodiscard]] NodeID node_id() const {
        return compute_node_id(public_key_);
    }

    /// Sign a message with the private key.
    /// Returns 64-byte Ed25519 signature.
    [[nodiscard]] std::array<uint8_t, ED25519_SIG_SIZE> sign(
        const uint8_t* message, std::size_t len) const;

    [[nodiscard]] std::array<uint8_t, ED25519_SIG_SIZE> sign(
        const Bytes& message) const {
        return sign(message.data(), message.size());
    }

    /// Verify a signature against a public key (static utility).
    [[nodiscard]] static bool verify(
        const std::array<uint8_t, ED25519_SIG_SIZE>& signature,
        const uint8_t* message, std::size_t len,
        const std::array<uint8_t, ED25519_PK_SIZE>& public_key);

    /// Securely zero out the private key material.
    ~Keypair();

    // Move-only (no copying of private keys)
    Keypair(Keypair&& other) noexcept;
    Keypair& operator=(Keypair&& other) noexcept;
    Keypair(const Keypair&) = delete;
    Keypair& operator=(const Keypair&) = delete;

private:
    Keypair() = default;

    std::array<uint8_t, ED25519_PK_SIZE> public_key_{};
    std::array<uint8_t, ED25519_SK_SIZE> secret_key_{};
};

} // namespace p2p::identity
