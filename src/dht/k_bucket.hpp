#pragma once
/// @file k_bucket.hpp
/// @brief Kademlia k-bucket implementation with LRU ordering and replacement cache.

#include "common/types.hpp"

#include <chrono>
#include <deque>
#include <optional>
#include <vector>

namespace p2p::dht {

/// Represents a contact entry within a k-bucket.
struct Contact {
    PeerInfo peer;
    std::chrono::steady_clock::time_point last_seen;
    int failed_queries = 0;

    bool operator==(const Contact& other) const {
        return peer.node_id == other.peer.node_id;
    }
};

/// A single k-bucket storing up to k contacts ordered by last-seen time (LRU).
/// Head = least recently seen, Tail = most recently seen.
class KBucket {
public:
    explicit KBucket(std::size_t capacity = 4, std::size_t max_replacements = 8);

    /// Add or update a peer in the bucket.
    /// If peer exists in bucket: moves to tail (most recently seen), resets failed queries, returns true.
    /// If peer does not exist and bucket is not full: appends to tail, returns true.
    /// If bucket is full: adds to replacement cache, returns false (caller may ping head contact).
    bool add_or_update(const PeerInfo& peer);

    /// Remove a peer by NodeID from the bucket.
    /// If removed and replacement cache has candidates, promotes the first candidate.
    /// Returns true if peer was removed.
    bool remove(const NodeID& id);

    /// Check if peer with given NodeID is in the bucket.
    [[nodiscard]] bool contains(const NodeID& id) const;

    /// Find peer information by NodeID.
    [[nodiscard]] std::optional<PeerInfo> find(const NodeID& id) const;

    /// Get the least recently seen contact (candidate for eviction check).
    [[nodiscard]] std::optional<PeerInfo> least_recently_seen() const;

    /// Record a query failure for a contact.
    void mark_failed(const NodeID& id);

    /// Update last_seen timestamp for contact without reinserting.
    void touch(const NodeID& id);

    /// Get all peers currently stored in the bucket (ordered from least to most recently seen).
    [[nodiscard]] std::vector<PeerInfo> get_peers() const;

    /// Get all contacts with metadata.
    [[nodiscard]] const std::vector<Contact>& get_contacts() const { return contacts_; }

    /// Current number of contacts in bucket.
    [[nodiscard]] std::size_t size() const { return contacts_.size(); }

    /// Maximum capacity of bucket (K).
    [[nodiscard]] std::size_t capacity() const { return capacity_; }

    /// Check if bucket has reached maximum capacity.
    [[nodiscard]] bool is_full() const { return contacts_.size() >= capacity_; }

    /// Number of replacement candidates queued.
    [[nodiscard]] std::size_t replacement_count() const { return replacements_.size(); }

    /// Clear all contacts and replacements.
    void clear();

private:
    std::size_t capacity_;
    std::size_t max_replacements_;
    std::vector<Contact> contacts_;
    std::deque<Contact> replacements_;
};

} // namespace p2p::dht
