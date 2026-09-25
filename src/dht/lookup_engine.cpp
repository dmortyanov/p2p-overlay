/// @file lookup_engine.cpp
/// @brief Kademlia iterative lookup state machine implementation.

#include "dht/lookup_engine.hpp"

#include <algorithm>

namespace p2p::dht {

LookupSession::LookupSession(NodeID target, NodeID local_id, std::size_t alpha, std::size_t k)
    : target_(target)
    , local_id_(local_id)
    , alpha_(alpha)
    , k_(k)
    , start_time_(std::chrono::steady_clock::now())
{
    metrics_.target = target;
    metrics_.lookup_id = RequestID::generate().to_hex();
}

void LookupSession::sort_shortlist() {
    std::sort(shortlist_.begin(), shortlist_.end(),
              [this](const LookupCandidate& a, const LookupCandidate& b) {
                  auto dist_a = a.peer.node_id.xor_distance(target_);
                  auto dist_b = b.peer.node_id.xor_distance(target_);
                  return dist_a < dist_b;
              });
}

void LookupSession::add_candidates(const std::vector<PeerInfo>& peers) {
    bool added = false;
    for (const auto& peer : peers) {
        if (peer.node_id == local_id_) {
            continue; // Skip self
        }

        auto it = std::find_if(shortlist_.begin(), shortlist_.end(),
                               [&peer](const LookupCandidate& c) {
                                   return c.peer.node_id == peer.node_id;
                               });
        if (it == shortlist_.end()) {
            shortlist_.push_back(LookupCandidate{
                .peer = peer,
                .state = CandidateState::UNQUERIED
            });
            added = true;
        }
    }

    if (added) {
        sort_shortlist();
    }
}

std::vector<PeerInfo> LookupSession::pick_next_queries() {
    std::vector<PeerInfo> picked;
    std::size_t in_flight = in_flight_count();

    for (auto& cand : shortlist_) {
        if (cand.state == CandidateState::UNQUERIED) {
            cand.state = CandidateState::IN_FLIGHT;
            picked.push_back(cand.peer);
            metrics_.total_rpcs++;
            metrics_.queried_nodes.push_back(cand.peer.node_id);

            in_flight++;
            if (picked.size() >= alpha_ || in_flight >= alpha_) {
                break;
            }
        }
    }

    if (!picked.empty()) {
        metrics_.iterations++;
    }

    return picked;
}

void LookupSession::on_response(const NodeID& from, const std::vector<PeerInfo>& returned_peers) {
    auto it = std::find_if(shortlist_.begin(), shortlist_.end(),
                           [&from](const LookupCandidate& c) {
                               return c.peer.node_id == from;
                           });
    if (it != shortlist_.end()) {
        it->state = CandidateState::RESPONDED;
    }

    add_candidates(returned_peers);

    metrics_.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_);
    metrics_.success = !get_closest(1).empty();
}

void LookupSession::on_failure(const NodeID& from) {
    auto it = std::find_if(shortlist_.begin(), shortlist_.end(),
                           [&from](const LookupCandidate& c) {
                               return c.peer.node_id == from;
                           });
    if (it != shortlist_.end()) {
        it->state = CandidateState::FAILED;
    }

    metrics_.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time_);
}

bool LookupSession::is_complete() const {
    // If there are still queries in flight, we are not done
    if (in_flight_count() > 0) {
        return false;
    }

    // Count how many of the k closest candidates have responded
    std::size_t responded_count = 0;
    std::size_t considered = 0;

    for (const auto& cand : shortlist_) {
        if (considered >= k_) break;

        if (cand.state == CandidateState::UNQUERIED) {
            // There are still unqueried candidates within the top-k!
            return false;
        }

        if (cand.state == CandidateState::RESPONDED) {
            responded_count++;
        }
        considered++;
    }

    // If all top-k have responded (or failed) and no unqueried candidates remain in top-k
    // Check if there are any unqueried candidates at all
    bool has_unqueried = std::any_of(shortlist_.begin(), shortlist_.end(),
                                     [](const LookupCandidate& c) {
                                         return c.state == CandidateState::UNQUERIED;
                                     });

    if (responded_count >= k_) {
        return true;
    }

    return !has_unqueried;
}

std::vector<PeerInfo> LookupSession::get_closest(std::size_t count) const {
    std::vector<PeerInfo> result;
    for (const auto& cand : shortlist_) {
        if (cand.state == CandidateState::RESPONDED) {
            result.push_back(cand.peer);
            if (result.size() >= count) {
                break;
            }
        }
    }
    return result;
}

std::size_t LookupSession::in_flight_count() const {
    return std::count_if(shortlist_.begin(), shortlist_.end(),
                         [](const LookupCandidate& c) {
                             return c.state == CandidateState::IN_FLIGHT;
                         });
}

} // namespace p2p::dht
