#include "security/replay_cache.hpp"

#include <algorithm>

namespace p2p::security {

ReplayCache::ReplayCache(std::size_t window_size)
    : window_size_(std::max<std::size_t>(window_size, 32)),
      window_bitmap_(window_size_, false) {}

bool ReplayCache::update_and_check(uint64_t seq) {
    std::lock_guard lock(mutex_);
    if (!initialized_) {
        initialized_ = true;
        highest_seq_ = seq;
        window_bitmap_[seq % window_size_] = true;
        return true;
    }

    if (seq > highest_seq_) {
        uint64_t diff = seq - highest_seq_;
        if (diff >= window_size_) {
            std::fill(window_bitmap_.begin(), window_bitmap_.end(), false);
        } else {
            for (uint64_t s = highest_seq_ + 1; s <= seq; ++s) {
                window_bitmap_[s % window_size_] = false;
            }
        }
        highest_seq_ = seq;
        window_bitmap_[seq % window_size_] = true;
        return true;
    }

    if (highest_seq_ - seq >= window_size_) {
        // Packet too old, outside sliding window
        return false;
    }

    std::size_t idx = seq % window_size_;
    if (window_bitmap_[idx]) {
        // Replayed packet
        return false;
    }

    window_bitmap_[idx] = true;
    return true;
}

bool ReplayCache::check(uint64_t seq) const {
    std::lock_guard lock(mutex_);
    if (!initialized_) return true;
    if (seq > highest_seq_) return true;
    if (highest_seq_ - seq >= window_size_) return false;
    return !window_bitmap_[seq % window_size_];
}

void ReplayCache::reset() {
    std::lock_guard lock(mutex_);
    initialized_ = false;
    highest_seq_ = 0;
    std::fill(window_bitmap_.begin(), window_bitmap_.end(), false);
}

uint64_t ReplayCache::highest_seq() const {
    std::lock_guard lock(mutex_);
    return highest_seq_;
}

} // namespace p2p::security
