/// @file tunnel_pool.cpp
/// @brief Tunnel Pool implementation.

#include "tunnel/tunnel_pool.hpp"

namespace p2p::tunnel {

TunnelPool::TunnelPool(std::size_t target_pool_size)
    : target_pool_size_(target_pool_size)
{
}

void TunnelPool::add_tunnel(std::shared_ptr<Tunnel> tunnel) {
    if (!tunnel) return;
    std::lock_guard<std::mutex> lock(mutex_);
    tunnels_[tunnel->circuit_id()] = tunnel;
}

bool TunnelPool::remove_tunnel(const CircuitID& circuit_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tunnels_.erase(circuit_id) > 0;
}

std::shared_ptr<Tunnel> TunnelPool::get_tunnel(const CircuitID& circuit_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tunnels_.find(circuit_id);
    if (it != tunnels_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<Tunnel> TunnelPool::pick_tunnel(const NodeID& destination_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (tunnels_.empty()) return nullptr;

    std::vector<std::shared_ptr<Tunnel>> candidates;
    for (const auto& [cid, t] : tunnels_) {
        if (t->state() == TunnelState::ACTIVE && !t->is_expired()) {
            if (t->destination_id() == destination_id) {
                return t; // Exact match found
            }
            candidates.push_back(t);
        }
    }

    if (candidates.empty()) return nullptr;

    // Round-robin selection among active circuits
    round_robin_idx_ %= candidates.size();
    auto selected = candidates[round_robin_idx_];
    round_robin_idx_ = (round_robin_idx_ + 1) % candidates.size();
    return selected;
}

std::size_t TunnelPool::active_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t count = 0;
    for (const auto& [cid, t] : tunnels_) {
        if (t->state() == TunnelState::ACTIVE && !t->is_expired()) {
            ++count;
        }
    }
    return count;
}

std::vector<CircuitID> TunnelPool::prune_stale_tunnels() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CircuitID> stale;

    for (auto it = tunnels_.begin(); it != tunnels_.end(); ) {
        bool should_remove = false;
        if (it->second->is_expired()) {
            it->second->set_state(TunnelState::EXPIRED);
            should_remove = true;
        } else if (it->second->failure_count() >= 3) {
            it->second->set_state(TunnelState::FAILED);
            should_remove = true;
        } else if (it->second->state() == TunnelState::CLOSED || it->second->state() == TunnelState::FAILED) {
            should_remove = true;
        }

        if (should_remove) {
            stale.push_back(it->first);
            it = tunnels_.erase(it);
        } else {
            ++it;
        }
    }

    return stale;
}

std::vector<std::shared_ptr<Tunnel>> TunnelPool::all_tunnels() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<Tunnel>> result;
    result.reserve(tunnels_.size());
    for (const auto& [cid, t] : tunnels_) {
        result.push_back(t);
    }
    return result;
}

} // namespace p2p::tunnel

