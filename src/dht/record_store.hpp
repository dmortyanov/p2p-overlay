#pragma once
/// @file record_store.hpp
/// @brief Thread-safe local DHT storage with anti-rollback and TTL expiration (E3-2, E3-6, E3-7).

#include "dht/node_record.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace p2p::dht {

/// Local node storage for DHT records.
class RecordStore {
public:
    RecordStore() = default;

    /// Attempt to store a record under the given DHT key.
    /// Enforces:
    ///   - Cryptographic signature & format validation (E3-2)
    ///   - Monotonic sequence_number / anti-rollback (E3-6)
    ///   - Non-expired TTL window
    [[nodiscard]] RecordValidationError put(const NodeID& key,
                                           const NodeRecord& record,
                                           uint64_t current_time_sec);

    /// Retrieve record by DHT key.
    /// Returns nullopt if not found or if the entry has expired.
    [[nodiscard]] std::optional<NodeRecord> get(const NodeID& key,
                                                uint64_t current_time_sec);

    /// Retrieve record by NodeID (if known).
    [[nodiscard]] std::optional<NodeRecord> get_by_node_id(const NodeID& node_id,
                                                           uint64_t current_time_sec);

    /// Retrieve record by alias (if known).
    [[nodiscard]] std::optional<NodeRecord> get_by_alias(std::string_view alias,
                                                         uint64_t current_time_sec);

    /// Purge expired records from storage (E3-7).
    /// Returns count of removed records.
    std::size_t purge_expired(uint64_t current_time_sec);

    /// Get total number of stored records.
    [[nodiscard]] std::size_t size() const;

    /// Clear all records.
    void clear();

private:
    mutable std::mutex mutex_;
    // Primary key -> record
    std::unordered_map<NodeID, NodeRecord> records_;
    // Key -> highest sequence_number seen
    std::unordered_map<NodeID, uint64_t> highest_seq_;
};

} // namespace p2p::dht
