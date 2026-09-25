/// @file routing_table.cpp
/// @brief Kademlia routing table implementation.

#include "dht/routing_table.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>

namespace p2p::dht {

RoutingTable::RoutingTable(NodeID local_id, std::size_t k)
    : local_id_(local_id)
    , k_(k)
{
    for (auto& bucket : buckets_) {
        bucket = KBucket(k_);
    }
}

int RoutingTable::get_bucket_index(const NodeID& id) const {
    return local_id_.bucket_index(id);
}

bool RoutingTable::add_or_update(const PeerInfo& peer) {
    if (peer.node_id == local_id_) {
        return false; // Do not add self to routing table
    }

    int idx = get_bucket_index(peer.node_id);
    if (idx < 0 || static_cast<std::size_t>(idx) >= NUM_BUCKETS) {
        return false;
    }

    std::lock_guard lock(mutex_);
    return buckets_[idx].add_or_update(peer);
}

bool RoutingTable::remove(const NodeID& id) {
    if (id == local_id_) {
        return false;
    }

    int idx = get_bucket_index(id);
    if (idx < 0 || static_cast<std::size_t>(idx) >= NUM_BUCKETS) {
        return false;
    }

    std::lock_guard lock(mutex_);
    return buckets_[idx].remove(id);
}

std::optional<PeerInfo> RoutingTable::find(const NodeID& id) const {
    if (id == local_id_) {
        return std::nullopt;
    }

    int idx = get_bucket_index(id);
    if (idx < 0 || static_cast<std::size_t>(idx) >= NUM_BUCKETS) {
        return std::nullopt;
    }

    std::lock_guard lock(mutex_);
    return buckets_[idx].find(id);
}

std::vector<PeerInfo> RoutingTable::find_closest(const NodeID& target,
                                                 std::size_t count) const {
    std::vector<PeerInfo> all_contacts;

    {
        std::lock_guard lock(mutex_);
        // Gather contacts across all buckets
        for (const auto& bucket : buckets_) {
            if (bucket.size() == 0) continue;
            auto peers = bucket.get_peers();
            all_contacts.insert(all_contacts.end(), peers.begin(), peers.end());
        }
    }

    // Sort by XOR distance to target in ascending order
    std::sort(all_contacts.begin(), all_contacts.end(),
              [&target](const PeerInfo& a, const PeerInfo& b) {
                  auto dist_a = a.node_id.xor_distance(target);
                  auto dist_b = b.node_id.xor_distance(target);
                  return dist_a < dist_b;
              });

    if (all_contacts.size() > count) {
        all_contacts.resize(count);
    }

    return all_contacts;
}

std::size_t RoutingTable::total_contacts() const {
    std::lock_guard lock(mutex_);
    std::size_t total = 0;
    for (const auto& bucket : buckets_) {
        total += bucket.size();
    }
    return total;
}

std::vector<std::size_t> RoutingTable::bucket_distribution() const {
    std::lock_guard lock(mutex_);
    std::vector<std::size_t> dist;
    dist.reserve(NUM_BUCKETS);
    for (const auto& bucket : buckets_) {
        dist.push_back(bucket.size());
    }
    return dist;
}

std::optional<PeerInfo> RoutingTable::least_recently_seen_in_bucket(const NodeID& id) const {
    int idx = get_bucket_index(id);
    if (idx < 0 || static_cast<std::size_t>(idx) >= NUM_BUCKETS) {
        return std::nullopt;
    }
    std::lock_guard lock(mutex_);
    return buckets_[idx].least_recently_seen();
}

void RoutingTable::mark_failed(const NodeID& id) {
    int idx = get_bucket_index(id);
    if (idx < 0 || static_cast<std::size_t>(idx) >= NUM_BUCKETS) {
        return;
    }
    std::lock_guard lock(mutex_);
    buckets_[idx].mark_failed(id);
}

std::string RoutingTable::to_json() const {
    std::lock_guard lock(mutex_);
    nlohmann::json root;
    root["local_id"] = local_id_.to_hex();
    root["k"] = k_;
    root["total_contacts"] = 0;

    nlohmann::json buckets_arr = nlohmann::json::array();
    std::size_t total = 0;

    for (std::size_t i = 0; i < NUM_BUCKETS; ++i) {
        if (buckets_[i].size() == 0) continue;

        nlohmann::json b_obj;
        b_obj["bucket_index"] = i;
        b_obj["size"] = buckets_[i].size();
        b_obj["replacements"] = buckets_[i].replacement_count();

        nlohmann::json contacts_arr = nlohmann::json::array();
        for (const auto& peer : buckets_[i].get_peers()) {
            contacts_arr.push_back({
                {"node_id", peer.node_id.to_hex()},
                {"host",    peer.address.host},
                {"port",    peer.address.port}
            });
            total++;
        }
        b_obj["contacts"] = contacts_arr;
        buckets_arr.push_back(b_obj);
    }

    root["total_contacts"] = total;
    root["active_buckets"] = buckets_arr;
    return root.dump(2);
}

} // namespace p2p::dht
