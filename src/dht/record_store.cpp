#include "dht/record_store.hpp"

namespace p2p::dht {

RecordValidationError RecordStore::put(const NodeID& key,
                                       const NodeRecord& record,
                                       uint64_t current_time_sec,
                                       std::size_t max_record_size) {
    // 1. Check serialized record size against config max_record_size (E3-2)
    if (max_record_size > 0 && record.to_cbor().size() > max_record_size) {
        return RecordValidationError::InvalidSize;
    }

    // 2. Key-to-record binding (E3-2): prevent storing record under an arbitrary/victim key
    bool matches_node_key = (key == node_record_key(record.node_id));
    bool matches_alias_key = (!record.alias.empty() && key == alias_record_key(record.alias));
    if (!matches_node_key && !matches_alias_key) {
        return RecordValidationError::KeyMismatch;
    }

    // 3. Full cryptographic, format, and time validation
    auto err = record.validate(current_time_sec);
    if (err != RecordValidationError::None) {
        return err;
    }

    std::lock_guard lock(mutex_);

    // 4. Owner-bound conflict check (E3-8): active record cannot be hijacked by another NodeID
    auto it = records_.find(key);
    if (it != records_.end()) {
        if (it->second.is_time_valid(current_time_sec)) {
            if (it->second.node_id != record.node_id ||
                it->second.identity_public_key != record.identity_public_key) {
                return RecordValidationError::AliasConflict;
            }
            if (record.sequence_number <= it->second.sequence_number) {
                return RecordValidationError::RollbackDetected;
            }
        } else {
            // Existing record expired — purge it so a new owner can claim if needed
            records_.erase(it);
        }
    }

    // 5. Anti-rollback check for the same owner (E3-6)
    auto seq_it = highest_seq_.find(key);
    if (seq_it != highest_seq_.end() && seq_it->second.first == record.node_id) {
        if (record.sequence_number <= seq_it->second.second) {
            return RecordValidationError::RollbackDetected;
        }
    }

    // 6. Update storage and sequence tracker
    records_[key] = record;
    highest_seq_[key] = {record.node_id, record.sequence_number};

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
