#pragma once
/// @file tunnel.hpp
/// @brief Tunnel (Circuit) class representing an end-to-end multi-hop onion path (Stage 5).

#include "common/types.hpp"
#include "tunnel/tunnel_types.hpp"
#include "tunnel/onion_packet.hpp"

#include <vector>
#include <chrono>
#include <atomic>
#include <functional>

namespace p2p::tunnel {

class Tunnel {
public:
    Tunnel(CircuitID circuit_id,
           std::vector<TunnelHop> hops,
           NodeID destination_id,
           std::chrono::seconds ttl = std::chrono::seconds(300));

    [[nodiscard]] const CircuitID& circuit_id() const { return circuit_id_; }
    [[nodiscard]] const std::vector<TunnelHop>& hops() const { return hops_; }
    [[nodiscard]] const NodeID& destination_id() const { return destination_id_; }
    [[nodiscard]] TunnelState state() const { return state_; }
    [[nodiscard]] std::size_t hop_count() const { return hops_.size(); }

    void set_state(TunnelState s) { state_ = s; }

    /// Check if circuit has expired its TTL.
    [[nodiscard]] bool is_expired() const;

    /// Next sequence number for data frames sent through this tunnel.
    [[nodiscard]] uint64_t next_sequence();

    /// Encrypt and pack data through all layers for destination.
    [[nodiscard]] Bytes wrap_payload(ByteSpan payload);

    /// Record activity (resets idle timer).
    void touch();

    /// Get first hop contact info to which initiator sends outer packets.
    [[nodiscard]] const TunnelHop& entry_hop() const { return hops_.front(); }

    /// Consecutive delivery failures on this tunnel.
    [[nodiscard]] std::size_t failure_count() const { return failure_count_; }
    void increment_failures() { ++failure_count_; }
    void reset_failures() { failure_count_ = 0; }

private:
    CircuitID circuit_id_;
    std::vector<TunnelHop> hops_;
    NodeID destination_id_;
    std::chrono::seconds ttl_;
    std::chrono::steady_clock::time_point created_at_;
    std::chrono::steady_clock::time_point last_active_;
    TunnelState state_{TunnelState::BUILDING};
    std::atomic<uint64_t> sequence_{1};
    std::size_t failure_count_{0};
};

} // namespace p2p::tunnel

