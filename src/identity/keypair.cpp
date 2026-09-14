/// @file keypair.cpp
/// @brief Ed25519 keypair implementation using libsodium.

#include "identity/keypair.hpp"

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <fstream>
#include <stdexcept>

namespace p2p::identity {

// ─── Generate ───────────────────────────────────────────────────────

Keypair Keypair::generate() {
    // Ensure libsodium is initialized
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    Keypair kp;
    crypto_sign_ed25519_keypair(kp.public_key_.data(), kp.secret_key_.data());

    spdlog::info("Generated new Ed25519 keypair, NodeID={}",
                 kp.node_id().to_short_hex());
    return kp;
}

// ─── Load / Save ────────────────────────────────────────────────────

std::optional<Keypair> Keypair::load(const std::filesystem::path& dir) {
    auto pub_path = dir / "identity.pub";
    auto key_path = dir / "identity.key";

    if (!std::filesystem::exists(pub_path) ||
        !std::filesystem::exists(key_path)) {
        return std::nullopt;
    }

    Keypair kp;

    // Read public key
    {
        std::ifstream f(pub_path, std::ios::binary);
        if (!f || !f.read(reinterpret_cast<char*>(kp.public_key_.data()),
                          ED25519_PK_SIZE)) {
            spdlog::error("Failed to read public key from {}", pub_path.string());
            return std::nullopt;
        }
    }

    // Read secret key
    {
        std::ifstream f(key_path, std::ios::binary);
        if (!f || !f.read(reinterpret_cast<char*>(kp.secret_key_.data()),
                          ED25519_SK_SIZE)) {
            spdlog::error("Failed to read secret key from {}", key_path.string());
            return std::nullopt;
        }
    }

    // Verify consistency: the public key embedded in the secret key
    // must match the stored public key
    // libsodium stores sk as [seed(32) || pk(32)]
    if (sodium_memcmp(kp.secret_key_.data() + 32,
                      kp.public_key_.data(), ED25519_PK_SIZE) != 0) {
        spdlog::error("Public key / secret key mismatch in {}", dir.string());
        sodium_memzero(kp.secret_key_.data(), ED25519_SK_SIZE);
        return std::nullopt;
    }

    spdlog::info("Loaded identity from {}, NodeID={}",
                 dir.string(), kp.node_id().to_short_hex());
    return kp;
}

void Keypair::save(const std::filesystem::path& dir) const {
    std::filesystem::create_directories(dir);

    auto pub_path = dir / "identity.pub";
    auto key_path = dir / "identity.key";

    // Write public key
    {
        std::ofstream f(pub_path, std::ios::binary | std::ios::trunc);
        if (!f) {
            throw std::runtime_error("Cannot write " + pub_path.string());
        }
        f.write(reinterpret_cast<const char*>(public_key_.data()),
                ED25519_PK_SIZE);
    }

    // Write secret key
    {
        std::ofstream f(key_path, std::ios::binary | std::ios::trunc);
        if (!f) {
            throw std::runtime_error("Cannot write " + key_path.string());
        }
        f.write(reinterpret_cast<const char*>(secret_key_.data()),
                ED25519_SK_SIZE);
    }

    // Note: On Unix, we would chmod 600 the key file.
    // On Windows, ACLs would be used. For this prototype,
    // .gitignore prevents committing key files.

    spdlog::debug("Saved identity to {}", dir.string());
}

Keypair Keypair::load_or_generate(const std::filesystem::path& dir) {
    auto loaded = load(dir);
    if (loaded) {
        return std::move(*loaded);
    }

    spdlog::info("No identity found in {}, generating new keypair", dir.string());
    auto kp = generate();
    kp.save(dir);
    return kp;
}

// ─── Sign / Verify ──────────────────────────────────────────────────

std::array<uint8_t, ED25519_SIG_SIZE> Keypair::sign(
    const uint8_t* message, std::size_t len) const
{
    std::array<uint8_t, ED25519_SIG_SIZE> sig{};
    unsigned long long sig_len = 0;

    // crypto_sign_ed25519_detached produces a 64-byte detached signature
    if (crypto_sign_ed25519_detached(sig.data(), &sig_len,
                                      message, len,
                                      secret_key_.data()) != 0) {
        throw std::runtime_error("Ed25519 signing failed");
    }

    return sig;
}

bool Keypair::verify(
    const std::array<uint8_t, ED25519_SIG_SIZE>& signature,
    const uint8_t* message, std::size_t len,
    const std::array<uint8_t, ED25519_PK_SIZE>& public_key)
{
    return crypto_sign_ed25519_verify_detached(
        signature.data(), message, len, public_key.data()) == 0;
}

// ─── Destruction (secure zeroing) ───────────────────────────────────

Keypair::~Keypair() {
    sodium_memzero(secret_key_.data(), ED25519_SK_SIZE);
}

Keypair::Keypair(Keypair&& other) noexcept {
    public_key_ = other.public_key_;
    secret_key_ = other.secret_key_;
    sodium_memzero(other.secret_key_.data(), ED25519_SK_SIZE);
}

Keypair& Keypair::operator=(Keypair&& other) noexcept {
    if (this != &other) {
        sodium_memzero(secret_key_.data(), ED25519_SK_SIZE);
        public_key_ = other.public_key_;
        secret_key_ = other.secret_key_;
        sodium_memzero(other.secret_key_.data(), ED25519_SK_SIZE);
    }
    return *this;
}

} // namespace p2p::identity

// ─── RequestID generation (uses libsodium randomness) ───────────────

namespace p2p {

RequestID RequestID::generate() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    RequestID rid;
    randombytes_buf(rid.data.data(), SIZE);
    return rid;
}

} // namespace p2p
