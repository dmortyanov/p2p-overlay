#pragma once
/// @file tunnel_pool.hpp
/// @brief Tunnel Pool managing a target number of pre-built, active circuits (Stage 5).

#include "tunnel/tunnel.hpp"
#include <unordered_map>
#include <memory>
#include <mutex>
#include <vector>

namespace p2p::tunnel {

class TunnelPool {
public:
    explicit TunnelPool(std::size_t target_pool_size = 3);

    /// Add an established tunnel to the pool.
    void add_tunnel(std::shared_ptr<Tunnel> tunnel);

    /// Remove a tunnel by CircuitID.
    bool remove_tunnel(const CircuitID& circuit_id);

    /// Retrieve an active tunnel by CircuitID.
    [[nodiscard]] std::shared_ptr<Tunnel> get_tunnel(const CircuitID& circuit_id) const;

    /// Pick an active tunnel for a specific destination (or any active tunnel).
    [[nodiscard]] std::shared_ptr<Tunnel> pick_tunnel(const NodeID& destination_id) const;

    /// Get total number of active tunnels currently in pool.
    [[nodiscard]] std::size_t active_count() const;

    /// Check which tunnels have expired or exceeded failure count, and remove them.
    /// Returns vector of expired/stale CircuitIDs.
    std::vector<CircuitID> prune_stale_tunnels();

    /// Get all tunnels.
    [[nodiscard]] std::vector<std::shared_ptr<Tunnel>> all_tunnels() const;

    /// Target pool size.
    [[nodiscard]] std::size_t target_size() const { return target_pool_size_; }

private:
    std::size_t target_pool_size_;
    mutable std::mutex mutex_;
    std::unordered_map<CircuitID, std::shared_ptr<Tunnel>> tunnels_;
    mutable std::size_t round_robin_idx_{0};
};

} // namespace p2p::tunnel

