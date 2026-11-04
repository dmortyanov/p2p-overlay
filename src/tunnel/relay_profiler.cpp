/// @file relay_profiler.cpp
/// @brief Relay node profiling, EMA calculations, and subnet diversity filtering implementation.

#include "tunnel/relay_profiler.hpp"
#include <algorithm>
#include <sstream>

namespace p2p::tunnel {

RelayProfiler::RelayProfiler(double alpha_latency, double alpha_success)
    : alpha_latency_(alpha_latency)
    , alpha_success_(alpha_success)
{
}

void RelayProfiler::register_relay(const NodeID& node_id, const PeerAddress& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& p = profiles_[node_id];
    p.node_id = node_id;
    p.address = address;
    p.last_updated = std::chrono::steady_clock::now();
}

void RelayProfiler::record_latency(const NodeID& node_id, double rtt_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = profiles_.find(node_id);
    if (it != profiles_.end()) {
        it->second.ema_latency_ms = (1.0 - alpha_latency_) * it->second.ema_latency_ms + alpha_latency_ * rtt_ms;
        it->second.last_updated = std::chrono::steady_clock::now();
    }
}

void RelayProfiler::record_result(const NodeID& node_id, bool success) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = profiles_.find(node_id);
    if (it != profiles_.end()) {
        double val = success ? 1.0 : 0.0;
        it->second.ema_success_rate = (1.0 - alpha_success_) * it->second.ema_success_rate + alpha_success_ * val;
        it->second.total_requests++;
        if (success) {
            it->second.consecutive_failures = 0;
        } else {
            it->second.consecutive_failures++;
        }
        it->second.last_updated = std::chrono::steady_clock::now();
    }
}

std::optional<RelayProfile> RelayProfiler::get_profile(const NodeID& node_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = profiles_.find(node_id);
    if (it != profiles_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string RelayProfiler::extract_subnet_24(const std::string& ip_str) {
    // E.g. "192.168.1.50" -> "192.168.1"
    // "127.0.0.1" -> "127.0.0"
    std::vector<std::string> parts;
    std::stringstream ss(ip_str);
    std::string item;
    while (std::getline(ss, item, '.')) {
        parts.push_back(item);
    }
    if (parts.size() >= 3) {
        return parts[0] + "." + parts[1] + "." + parts[2];
    }
    return ip_str;
}

bool RelayProfiler::is_subnet_diverse(
    const PeerAddress& candidate,
    const std::vector<PeerAddress>& existing_hops)
{
    // Special case for local testing: loopback addresses (127.0.0.1) with different ports
    // can be considered diverse if testing on a single machine, but for IPv4 /24 standard:
    // If hosts are identical and not loopback, reject.
    std::string cand_subnet = extract_subnet_24(candidate.host);
    bool is_loopback = (cand_subnet == "127.0.0" || candidate.host == "localhost");

    for (const auto& hop : existing_hops) {
        if (is_loopback) {
            // For loopback simulation, check port diversity to avoid hitting same process
            if (hop.host == candidate.host && hop.port == candidate.port) {
                return false;
            }
        } else {
            std::string hop_subnet = extract_subnet_24(hop.host);
            if (hop_subnet == cand_subnet) {
                return false;
            }
        }
    }
    return true;
}

std::vector<PeerInfo> RelayProfiler::select_hops(
    const std::vector<PeerInfo>& candidates,
    std::size_t count,
    const std::vector<NodeID>& excluded) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Filter out excluded nodes and inactive/failed candidates
    std::vector<PeerInfo> available;
    for (const auto& c : candidates) {
        if (std::find(excluded.begin(), excluded.end(), c.node_id) != excluded.end()) {
            continue;
        }

        auto it = profiles_.find(c.node_id);
        if (it != profiles_.end()) {
            if (it->second.consecutive_failures >= 3) {
                continue; // Skip failed relay
            }
        }
        available.push_back(c);
    }

    if (available.size() < count) {
        return {};
    }

    // Sort available candidates by score: higher success rate, lower latency
    auto score = [this](const PeerInfo& p) -> double {
        auto it = profiles_.find(p.node_id);
        if (it != profiles_.end()) {
            // Score = SuccessRate * 1000.0 / (Latency + 1.0)
            return (it->second.ema_success_rate * 1000.0) / (it->second.ema_latency_ms + 1.0);
        }
        return 10.0; // Default baseline score for unprofiled peer
    };

    std::sort(available.begin(), available.end(), [&](const PeerInfo& a, const PeerInfo& b) {
        return score(a) > score(b);
    });

    // Select 'count' hops respecting subnet diversity
    std::vector<PeerInfo> selected;
    std::vector<PeerAddress> selected_addrs;

    for (const auto& cand : available) {
        if (is_subnet_diverse(cand.address, selected_addrs)) {
            selected.push_back(cand);
            selected_addrs.push_back(cand.address);
            if (selected.size() == count) {
                break;
            }
        }
    }

    // If strict subnet diversity couldn't yield enough hops, fall back to any distinct nodes
    if (selected.size() < count && available.size() >= count) {
        selected.clear();
        for (const auto& cand : available) {
            bool duplicate = false;
            for (const auto& s : selected) {
                if (s.node_id == cand.node_id) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                selected.push_back(cand);
                if (selected.size() == count) {
                    break;
                }
            }
        }
    }

    if (selected.size() == count) {
        return selected;
    }

    return {};
}

} // namespace p2p::tunnel

