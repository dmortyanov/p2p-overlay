/// @file node_id.cpp
/// @brief NodeID computation and XOR-metric utilities using libsodium.

#include "identity/node_id.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>

namespace p2p::identity {

// ─── SHA-256 ────────────────────────────────────────────────────────

std::array<uint8_t, 32> sha256(const uint8_t* data, std::size_t len) {
    std::array<uint8_t, 32> hash{};
    crypto_hash_sha256(hash.data(), data, len);
    return hash;
}

std::array<uint8_t, 32> sha256(const std::string& data) {
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ─── NodeID computation ─────────────────────────────────────────────

NodeID compute_node_id(const std::array<uint8_t, 32>& public_key) {
    // NodeID = SHA-256(canonical_encode(identity_public_key))
    // canonical_encode = raw 32-byte Ed25519 public key
    NodeID id;
    auto hash = sha256(public_key.data(), public_key.size());
    id.data = hash;
    return id;
}

bool verify_node_id(const NodeID& claimed_id,
                    const std::array<uint8_t, 32>& public_key) {
    NodeID computed = compute_node_id(public_key);
    // Constant-time comparison to prevent timing attacks
    return sodium_memcmp(claimed_id.data.data(), computed.data.data(),
                         NodeID::SIZE) == 0;
}

// ─── XOR metric ─────────────────────────────────────────────────────

NodeID xor_distance(const NodeID& a, const NodeID& b) {
    return a.xor_distance(b);
}

bool is_closer(const NodeID& dist_a, const NodeID& dist_b) {
    // Lexicographic comparison (big-endian) of XOR distances
    return dist_a < dist_b;
}

void sort_by_distance(std::vector<PeerInfo>& peers, const NodeID& target) {
    std::sort(peers.begin(), peers.end(),
        [&target](const PeerInfo& a, const PeerInfo& b) {
            auto dist_a = target.xor_distance(a.node_id);
            auto dist_b = target.xor_distance(b.node_id);
            return dist_a < dist_b;
        }
    );
}

// ─── DHT key derivation ────────────────────────────────────────────

NodeID compute_record_key(const NodeID& node_id) {
    // key = SHA-256("node:" || NodeID_hex)
    std::string input = "node:" + node_id.to_hex();
    NodeID key;
    auto hash = sha256(input);
    key.data = hash;
    return key;
}

NodeID compute_alias_key(const std::string& alias) {
    // key = SHA-256("alias:" || normalize(alias))
    std::string input = "alias:" + normalize_alias(alias);
    NodeID key;
    auto hash = sha256(input);
    key.data = hash;
    return key;
}

std::string normalize_alias(const std::string& alias) {
    std::string result;
    result.reserve(alias.size());

    // Trim leading whitespace
    auto start = alias.find_first_not_of(" \t\n\r");
    auto end = alias.find_last_not_of(" \t\n\r");

    if (start == std::string::npos) return "";

    for (std::size_t i = start; i <= end; ++i) {
        result += static_cast<char>(std::tolower(static_cast<unsigned char>(alias[i])));
    }
    return result;
}

} // namespace p2p::identity
