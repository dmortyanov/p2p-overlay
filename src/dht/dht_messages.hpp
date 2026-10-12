#pragma once
/// @file dht_messages.hpp
/// @brief CBOR serialization and deserialization for DHT RPC messages (FIND_NODE, STORE, FIND_VALUE).

#include "common/types.hpp"
#include "dht/node_record.hpp"

#include <optional>
#include <string>
#include <vector>

namespace p2p::dht {

// ─── FIND_NODE ──────────────────────────────────────────────────────

/// Payload for FIND_NODE_REQUEST message.
struct FindNodeRequest {
    NodeID target;
    PeerInfo sender;
};

/// Payload for FIND_NODE_RESPONSE message.
struct FindNodeResponse {
    std::vector<PeerInfo> closest_nodes;
};

[[nodiscard]] Bytes serialize_find_node_request(const FindNodeRequest& req);
[[nodiscard]] bool deserialize_find_node_request(ByteSpan payload, FindNodeRequest& out_req);

[[nodiscard]] Bytes serialize_find_node_response(const FindNodeResponse& resp);
[[nodiscard]] bool deserialize_find_node_response(ByteSpan payload, FindNodeResponse& out_resp);

// ─── STORE (E3-3) ───────────────────────────────────────────────────

/// Payload for STORE_REQUEST message.
struct StoreRequest {
    NodeID     key;
    NodeRecord record;
    PeerInfo   sender;
};

/// Payload for STORE_RESPONSE message.
struct StoreResponse {
    NodeID      key;
    bool        success = false;
    std::string message;
};

[[nodiscard]] Bytes serialize_store_request(const StoreRequest& req);
[[nodiscard]] bool deserialize_store_request(ByteSpan payload, StoreRequest& out_req);

[[nodiscard]] Bytes serialize_store_response(const StoreResponse& resp);
[[nodiscard]] bool deserialize_store_response(ByteSpan payload, StoreResponse& out_resp);

// ─── FIND_VALUE (E3-3) ──────────────────────────────────────────────

/// Payload for FIND_VALUE_REQUEST message.
struct FindValueRequest {
    NodeID   key;
    PeerInfo sender;
};

/// Payload for FIND_VALUE_RESPONSE message.
struct FindValueResponse {
    NodeID                  key;
    bool                    has_value = false;
    std::optional<NodeRecord> record;
    std::vector<PeerInfo>   closest_nodes;
};

[[nodiscard]] Bytes serialize_find_value_request(const FindValueRequest& req);
[[nodiscard]] bool deserialize_find_value_request(ByteSpan payload, FindValueRequest& out_req);

[[nodiscard]] Bytes serialize_find_value_response(const FindValueResponse& resp);
[[nodiscard]] bool deserialize_find_value_response(ByteSpan payload, FindValueResponse& out_resp);

} // namespace p2p::dht
