#pragma once
/// @file node_id.hpp
/// @brief NodeID computation and XOR-metric utilities.
///
/// NodeID = SHA-256(canonical_encode(identity_public_key))
/// where canonical_encode is the raw 32-byte Ed25519 public key.

#include "common/types.hpp"

#include <array>
#include <string>
#include <vector>

namespace p2p::identity {

/// Compute NodeID from an Ed25519 public key.
/// NodeID = SHA-256(public_key_bytes)
[[nodiscard]] NodeID compute_node_id(const std::array<uint8_t, 32>& public_key);

/// Verify that a claimed NodeID matches the given public key.
[[nodiscard]] bool verify_node_id(const NodeID& claimed_id,
                                  const std::array<uint8_t, 32>& public_key);

/// Compute XOR distance between two NodeIDs.
[[nodiscard]] NodeID xor_distance(const NodeID& a, const NodeID& b);

/// Compare two XOR distances — returns true if dist_a < dist_b.
[[nodiscard]] bool is_closer(const NodeID& dist_a, const NodeID& dist_b);

/// Sort a list of peers by XOR distance to a target.
void sort_by_distance(std::vector<PeerInfo>& peers, const NodeID& target);

/// Compute SHA-256 of arbitrary data.
[[nodiscard]] std::array<uint8_t, 32> sha256(const uint8_t* data, std::size_t len);
[[nodiscard]] std::array<uint8_t, 32> sha256(const std::string& data);

/// Compute DHT key for a NodeRecord.
/// key = SHA-256("node:" || NodeID_hex)
[[nodiscard]] NodeID compute_record_key(const NodeID& node_id);

/// Compute DHT key for an alias.
/// key = SHA-256("alias:" || normalize(alias))
[[nodiscard]] NodeID compute_alias_key(const std::string& alias);

/// Normalize an alias: lowercase, trim whitespace.
[[nodiscard]] std::string normalize_alias(const std::string& alias);

} // namespace p2p::identity
