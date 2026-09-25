#pragma once
/// @file dht_messages.hpp
/// @brief CBOR serialization and deserialization for DHT RPC messages.

#include "common/types.hpp"

#include <vector>

namespace p2p::dht {

/// Payload for FIND_NODE_REQUEST message.
struct FindNodeRequest {
    NodeID target;
    PeerInfo sender;
};

/// Payload for FIND_NODE_RESPONSE message.
struct FindNodeResponse {
    std::vector<PeerInfo> closest_nodes;
};

/// Serialize FindNodeRequest to CBOR bytes.
[[nodiscard]] Bytes serialize_find_node_request(const FindNodeRequest& req);

/// Deserialize FindNodeRequest from CBOR payload.
[[nodiscard]] bool deserialize_find_node_request(ByteSpan payload, FindNodeRequest& out_req);

/// Serialize FindNodeResponse to CBOR bytes.
[[nodiscard]] Bytes serialize_find_node_response(const FindNodeResponse& resp);

/// Deserialize FindNodeResponse from CBOR payload.
[[nodiscard]] bool deserialize_find_node_response(ByteSpan payload, FindNodeResponse& out_resp);

} // namespace p2p::dht
