#pragma once
/// @file lookup_engine.hpp
/// @brief Kademlia iterative lookup state machine with alpha parallelism.

#include "common/types.hpp"

#include <chrono>
#include <vector>

namespace p2p::dht {

/// State of a node candidate in the lookup shortlist.
enum class CandidateState {
    UNQUERIED,
    IN_FLIGHT,
    RESPONDED,
    FAILED
};

/// Candidate entry in the lookup shortlist.
struct LookupCandidate {
    PeerInfo peer;
    CandidateState state = CandidateState::UNQUERIED;
};

/// Metrics and trace data captured during an iterative lookup.
struct LookupMetrics {
    std::string lookup_id;
    NodeID target;
    std::size_t total_rpcs = 0;
    std::size_t iterations = 0;
    std::vector<NodeID> queried_nodes;
    std::chrono::milliseconds duration{0};
    bool success = false;
};

/// Manages an iterative lookup session for a single target NodeID.
class LookupSession {
public:
    LookupSession(NodeID target, NodeID local_id, std::size_t alpha = 3, std::size_t k = 4);

    /// Target node ID being searched.
    [[nodiscard]] const NodeID& target() const { return target_; }

    /// Add initial or discovered candidate peers to the shortlist.
    void add_candidates(const std::vector<PeerInfo>& peers);

    /// Pick up to alpha unqueried candidates closest to target.
    /// Transitions picked candidates to IN_FLIGHT state.
    [[nodiscard]] std::vector<PeerInfo> pick_next_queries();

    /// Process successful response from a queried candidate.
    void on_response(const NodeID& from, const std::vector<PeerInfo>& returned_peers);

    /// Process timeout or error from a queried candidate.
    void on_failure(const NodeID& from);

    /// Check if the iterative lookup process has converged and completed.
    [[nodiscard]] bool is_complete() const;

    /// Get up to k closest peers that responded successfully.
    [[nodiscard]] std::vector<PeerInfo> get_closest(std::size_t count = 4) const;

    /// Number of queries currently in flight.
    [[nodiscard]] std::size_t in_flight_count() const;

    /// Lookup metrics.
    [[nodiscard]] const LookupMetrics& metrics() const { return metrics_; }
    [[nodiscard]] LookupMetrics& metrics() { return metrics_; }

private:
    void sort_shortlist();

    NodeID target_;
    NodeID local_id_;
    std::size_t alpha_;
    std::size_t k_;
    std::vector<LookupCandidate> shortlist_;
    LookupMetrics metrics_;
    std::chrono::steady_clock::time_point start_time_;
};

} // namespace p2p::dht
