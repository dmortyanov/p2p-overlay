#pragma once
/// @file relay_profiler.hpp
/// @brief Relay node profiling, EMA calculations, and subnet diversity filtering (Stage 5).

#include "common/types.hpp"
#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>

namespace p2p::tunnel {

/// Profile metrics for a single relay candidate.
struct RelayProfile {
    NodeID node_id{};
    PeerAddress address{};
    double ema_latency_ms{50.0};       ///< Initial default RTT
    double ema_success_rate{1.0};      ///< Initial 100% success rate
    std::size_t consecutive_failures{0};
    std::size_t total_requests{0};
    std::chrono::steady_clock::time_point last_updated{};
};

class RelayProfiler {
public:
    explicit RelayProfiler(double alpha_latency = 0.2, double alpha_success = 0.3);

    /// Record a measured round-trip latency for a relay.
    void record_latency(const NodeID& node_id, double rtt_ms);

    /// Record success or failure of a relay hop or tunnel build.
    void record_result(const NodeID& node_id, bool success);

    /// Update or register contact information.
    void register_relay(const NodeID& node_id, const PeerAddress& address);

    /// Get profile for a specific relay.
    [[nodiscard]] std::optional<RelayProfile> get_profile(const NodeID& node_id) const;

    /// Extract IPv4 /24 subnet string from an IP string (e.g. "192.168.1.45" -> "192.168.1").
    [[nodiscard]] static std::string extract_subnet_24(const std::string& ip_str);

    /// Check if a candidate node respects subnet diversity against existing chosen hops.
    [[nodiscard]] static bool is_subnet_diverse(
        const PeerAddress& candidate,
        const std::vector<PeerAddress>& existing_hops);

    /// Select optimal hops for an onion circuit matching constraints.
    /// @param candidates List of known nodes to choose from.
    /// @param count Required number of hops (e.g. 3).
    /// @param excluded Nodes to exclude (e.g. local node, destination).
    /// @return Ordered vector of selected relay candidates, or empty if insufficient candidates.
    [[nodiscard]] std::vector<PeerInfo> select_hops(
        const std::vector<PeerInfo>& candidates,
        std::size_t count,
        const std::vector<NodeID>& excluded = {}) const;

private:
    double alpha_latency_;
    double alpha_success_;
    mutable std::mutex mutex_;
    std::unordered_map<NodeID, RelayProfile> profiles_;
};

} // namespace p2p::tunnel

