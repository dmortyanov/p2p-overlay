#pragma once
/// @file node_record.hpp
/// @brief Signed DHT node and alias records (E3-1, E3-2, E3-8).

#include "common/types.hpp"
#include "identity/keypair.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace p2p::dht {

/// Default TTL for DHT records in seconds (E3-6).
inline constexpr uint64_t DEFAULT_RECORD_TTL_SEC = 180;

/// Validation error categories for records (E3-2).
enum class RecordValidationError {
    None = 0,
    InvalidSize,
    IdentityMismatch,     ///< node_id != SHA256(identity_public_key)
    InvalidSignature,     ///< Ed25519 signature verification failed
    Expired,              ///< now > expires_at
    NotYetValid,          ///< now < issued_at - tolerance
    EmptyAddresses,       ///< addresses list is empty
    InvalidAddress,       ///< address host empty or port == 0
    RollbackDetected,     ///< sequence_number <= current_seq
};

[[nodiscard]] std::string record_validation_error_name(RecordValidationError err);

/// Compute deterministic DHT key for a node address record: SHA256("node:" || node_id).
[[nodiscard]] NodeID node_record_key(const NodeID& node_id);

/// Normalize an alias string (lowercase, trimmed) for deterministic hashing (E3-8).
[[nodiscard]] std::string normalize_alias(std::string_view alias);

/// Compute deterministic DHT key for an alias record: SHA256("alias:" || normalize(alias)).
[[nodiscard]] NodeID alias_record_key(std::string_view alias);

/// Signed DHT Address & Alias record (E3-1, E3-2, E3-8).
struct NodeRecord {
    NodeID                  node_id;
    std::array<uint8_t, 32> identity_public_key{};
    std::vector<PeerAddress> addresses;
    uint64_t                sequence_number = 0;
    uint64_t                issued_at = 0;   ///< Seconds since UNIX epoch
    uint64_t                expires_at = 0;  ///< Seconds since UNIX epoch
    std::string             alias;           ///< Optional alias / handle (E3-8)
    std::array<uint8_t, 64> signature{};     ///< Ed25519 signature

    bool operator==(const NodeRecord& other) const = default;

    /// Produces a deterministic canonical byte representation of record fields
    /// (excluding signature) for Ed25519 signing and verification.
    [[nodiscard]] Bytes canonical_bytes() const;

    /// Sign this record using the given Ed25519 keypair.
    void sign(const identity::Keypair& keypair);

    /// Verify signature and internal cryptographic consistency (node_id == SHA256(public_key)).
    [[nodiscard]] bool verify_signature() const;

    /// Check if record is currently valid according to given timestamp (with 30s skew tolerance).
    [[nodiscard]] bool is_time_valid(uint64_t current_time_sec) const;

    /// Perform full validation check (E3-2).
    [[nodiscard]] RecordValidationError validate(uint64_t current_time_sec) const;

    /// Serialize to CBOR payload.
    [[nodiscard]] Bytes to_cbor() const;

    /// Deserialize from CBOR payload.
    [[nodiscard]] static std::optional<NodeRecord> from_cbor(ByteSpan bytes);
};

} // namespace p2p::dht
