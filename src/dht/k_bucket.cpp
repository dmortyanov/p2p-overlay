/// @file k_bucket.cpp
/// @brief Kademlia k-bucket implementation.

#include "dht/k_bucket.hpp"

#include <algorithm>

namespace p2p::dht {

KBucket::KBucket(std::size_t capacity, std::size_t max_replacements)
    : capacity_(capacity)
    , max_replacements_(max_replacements)
{
    contacts_.reserve(capacity_);
}

bool KBucket::add_or_update(const PeerInfo& peer) {
    auto now = std::chrono::steady_clock::now();

    // Check if peer is already in active contacts
    auto it = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& c) {
        return c.peer.node_id == peer.node_id;
    });

    if (it != contacts_.end()) {
        // Move to the back (most recently seen)
        Contact updated = *it;
        updated.peer = peer; // Update address if changed
        updated.last_seen = now;
        updated.failed_queries = 0;
        contacts_.erase(it);
        contacts_.push_back(updated);
        return true;
    }

    // If bucket is not full, insert at tail
    if (contacts_.size() < capacity_) {
        contacts_.push_back(Contact{
            .peer = peer,
            .last_seen = now,
            .failed_queries = 0
        });
        return true;
    }

    // Bucket is full: insert/update in replacement cache
    auto rep_it = std::find_if(replacements_.begin(), replacements_.end(), [&](const Contact& c) {
        return c.peer.node_id == peer.node_id;
    });

    if (rep_it != replacements_.end()) {
        rep_it->peer = peer;
        rep_it->last_seen = now;
        rep_it->failed_queries = 0;
    } else {
        if (replacements_.size() >= max_replacements_) {
            replacements_.pop_front();
        }
        replacements_.push_back(Contact{
            .peer = peer,
            .last_seen = now,
            .failed_queries = 0
        });
    }

    return false; // Not added to main bucket (needs ping check)
}

bool KBucket::remove(const NodeID& id) {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& c) {
        return c.peer.node_id == id;
    });

    if (it == contacts_.end()) {
        // Also check replacement cache
        auto rep_it = std::find_if(replacements_.begin(), replacements_.end(), [&](const Contact& c) {
            return c.peer.node_id == id;
        });
        if (rep_it != replacements_.end()) {
            replacements_.erase(rep_it);
            return true;
        }
        return false;
    }

    contacts_.erase(it);

    // Promote first candidate from replacement cache if available
    if (!replacements_.empty()) {
        contacts_.push_back(replacements_.front());
        replacements_.pop_front();
    }

    return true;
}

bool KBucket::contains(const NodeID& id) const {
    return std::any_of(contacts_.begin(), contacts_.end(), [&](const Contact& c) {
        return c.peer.node_id == id;
    });
}

std::optional<PeerInfo> KBucket::find(const NodeID& id) const {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& c) {
        return c.peer.node_id == id;
    });
    if (it != contacts_.end()) {
        return it->peer;
    }
    return std::nullopt;
}

std::optional<PeerInfo> KBucket::least_recently_seen() const {
    if (contacts_.empty()) {
        return std::nullopt;
    }
    return contacts_.front().peer;
}

void KBucket::mark_failed(const NodeID& id) {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& c) {
        return c.peer.node_id == id;
    });
    if (it != contacts_.end()) {
        it->failed_queries++;
    }
}

void KBucket::touch(const NodeID& id) {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& c) {
        return c.peer.node_id == id;
    });
    if (it != contacts_.end()) {
        Contact updated = *it;
        updated.last_seen = std::chrono::steady_clock::now();
        updated.failed_queries = 0;
        contacts_.erase(it);
        contacts_.push_back(updated);
    }
}

std::vector<PeerInfo> KBucket::get_peers() const {
    std::vector<PeerInfo> peers;
    peers.reserve(contacts_.size());
    for (const auto& contact : contacts_) {
        peers.push_back(contact.peer);
    }
    return peers;
}

void KBucket::clear() {
    contacts_.clear();
    replacements_.clear();
}

} // namespace p2p::dht
