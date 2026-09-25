#pragma once
/// @file routing_table.hpp
/// @brief Kademlia routing table with 256 k-buckets and XOR distance sorting.

#include "common/types.hpp"
#include "dht/k_bucket.hpp"

#include <array>
#include <mutex>
#include <optional>
#include <vector>

namespace p2p::dht {

/// Kademlia routing table containing 256 buckets for 256-bit NodeID distance space.
class RoutingTable {
public:
    static constexpr std::size_t NUM_BUCKETS = 256;

    /// Construct routing table for a given local NodeID.
    explicit RoutingTable(NodeID local_id, std::size_t k = 4);

    /// Local node ID.
    [[nodiscard]] const NodeID& local_id() const { return local_id_; }

    /// Bucket capacity (K).
    [[nodiscard]] std::size_t k() const { return k_; }

    /// Add or update a peer contact.
    /// Returns true if added/updated in the bucket, false if bucket is full or peer is self.
    bool add_or_update(const PeerInfo& peer);

    /// Remove a contact by NodeID.
    bool remove(const NodeID& id);

    /// Find peer information by NodeID.
    [[nodiscard]] std::optional<PeerInfo> find(const NodeID& id) const;

    /// Find up to `count` closest contacts to the given `target` node ID,
    /// sorted in ascending order of XOR distance.
    [[nodiscard]] std::vector<PeerInfo> find_closest(const NodeID& target,
                                                     std::size_t count = 4) const;

    /// Total number of unique contacts across all buckets.
    [[nodiscard]] std::size_t total_contacts() const;

    /// Distribution of contacts across all 256 buckets (useful for metrics & proof of non-degeneracy).
    [[nodiscard]] std::vector<std::size_t> bucket_distribution() const;

    /// Export routing table state to JSON string (for metrics and E2-8 verification).
    [[nodiscard]] std::string to_json() const;

    /// Get index of bucket for a given NodeID relative to local node (0..255).
    /// Returns -1 if `id == local_id_`.
    [[nodiscard]] int get_bucket_index(const NodeID& id) const;

    /// Get the least recently seen contact from the bucket corresponding to `id`.
    [[nodiscard]] std::optional<PeerInfo> least_recently_seen_in_bucket(const NodeID& id) const;

    /// Mark query failure for a contact in its respective bucket.
    void mark_failed(const NodeID& id);

    /// Clear all buckets.
    void clear();

private:
    NodeID local_id_;
    std::size_t k_;
    mutable std::mutex mutex_;
    std::array<KBucket, NUM_BUCKETS> buckets_;
};

} // namespace p2p::dht
