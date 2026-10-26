#pragma once
/// @file replay_cache.hpp
/// @brief Sliding window anti-replay protection for encrypted sessions (E4-5).

#include <cstdint>
#include <mutex>
#include <vector>

namespace p2p::security {

/// Sliding window anti-replay filter based on RFC 6479 / RFC 4303.
/// Allows slightly out-of-order packets within the window, but strictly drops duplicates.
class ReplayCache {
public:
    explicit ReplayCache(std::size_t window_size = 128);

    /// Check if a packet with the given sequence number is valid (not replayed and within window),
    /// and if valid, atomically mark it as seen and update the window.
    /// @return true if accepted, false if replayed or too old.
    [[nodiscard]] bool update_and_check(uint64_t seq);

    /// Check without updating state.
    [[nodiscard]] bool check(uint64_t seq) const;

    /// Reset cache state.
    void reset();

    /// Highest sequence number seen so far.
    [[nodiscard]] uint64_t highest_seq() const;

    /// Window size in packets.
    [[nodiscard]] std::size_t window_size() const { return window_size_; }

private:
    mutable std::mutex mutex_;
    std::size_t window_size_{128};
    uint64_t highest_seq_{0};
    bool initialized_{false};
    // Circular bitmask bitmap for packets within the window
    std::vector<bool> window_bitmap_;
};

} // namespace p2p::security
