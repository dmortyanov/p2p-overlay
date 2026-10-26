#include "dht/record_store.hpp"

namespace p2p::dht {

RecordValidationError RecordStore::put(const NodeID& key,
                                       const NodeRecord& record,
                                       uint64_t current_time_sec) {
    // 1. Full cryptographic, format, and time validation
    auto err = record.validate(current_time_sec);
    if (err != RecordValidationError::None) {
        return err;
    }

    std::lock_guard lock(mutex_);

    // 2. Anti-rollback check (E3-6)
    // Check if we've seen a higher or equal sequence number for this key
    auto seq_it = highest_seq_.find(key);
    if (seq_it != highest_seq_.end()) {
        if (record.sequence_number <= seq_it->second) {
            return RecordValidationError::RollbackDetected;
        }
    }

    // 3. Check existing record under this exact key
    auto it = records_.find(key);
    if (it != records_.end()) {
        if (record.sequence_number <= it->second.sequence_number) {
            return RecordValidationError::RollbackDetected;
        }
    }

    // 4. Update storage and sequence tracker
    records_[key] = record;
    highest_seq_[key] = record.sequence_number;

    return RecordValidationError::None;
}

std::optional<NodeRecord> RecordStore::get(const NodeID& key,
                                           uint64_t current_time_sec) {
    std::lock_guard lock(mutex_);
    auto it = records_.find(key);
    if (it == records_.end()) {
        return std::nullopt;
    }

    // If expired, purge entry immediately (E3-6)
    if (!it->second.is_time_valid(current_time_sec)) {
        records_.erase(it);
        return std::nullopt;
    }

    return it->second;
}

std::optional<NodeRecord> RecordStore::get_by_node_id(const NodeID& node_id,
                                                      uint64_t current_time_sec) {
    auto key = node_record_key(node_id);
    auto direct = get(key, current_time_sec);
    if (direct.has_value()) {
        return direct;
    }

    std::lock_guard lock(mutex_);
    for (auto it = records_.begin(); it != records_.end();) {
        if (!it->second.is_time_valid(current_time_sec)) {
            it = records_.erase(it);
            continue;
        }
        if (it->second.node_id == node_id) {
            return it->second;
        }
        ++it;
    }
    return std::nullopt;
}

std::optional<NodeRecord> RecordStore::get_by_alias(std::string_view alias,
                                                    uint64_t current_time_sec) {
    auto norm = normalize_alias(alias);
    if (norm.empty()) return std::nullopt;

    auto key = alias_record_key(alias);
    auto direct = get(key, current_time_sec);
    if (direct.has_value()) {
        return direct;
    }

    std::lock_guard lock(mutex_);
    for (auto it = records_.begin(); it != records_.end();) {
        if (!it->second.is_time_valid(current_time_sec)) {
            it = records_.erase(it);
            continue;
        }
        if (normalize_alias(it->second.alias) == norm) {
            return it->second;
        }
        ++it;
    }
    return std::nullopt;
}

std::size_t RecordStore::purge_expired(uint64_t current_time_sec) {
    std::lock_guard lock(mutex_);
    std::size_t purged = 0;
    for (auto it = records_.begin(); it != records_.end();) {
        if (!it->second.is_time_valid(current_time_sec)) {
            it = records_.erase(it);
            ++purged;
        } else {
            ++it;
        }
    }
    return purged;
}

std::size_t RecordStore::size() const {
    std::lock_guard lock(mutex_);
    return records_.size();
}

void RecordStore::clear() {
    std::lock_guard lock(mutex_);
    records_.clear();
    highest_seq_.clear();
}

} // namespace p2p::dht
