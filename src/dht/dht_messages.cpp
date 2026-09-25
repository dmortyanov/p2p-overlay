/// @file dht_messages.cpp
/// @brief CBOR serialization and deserialization for DHT RPC messages.

#include "dht/dht_messages.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace p2p::dht {

Bytes serialize_find_node_request(const FindNodeRequest& req) {
    nlohmann::json j;
    j["target"] = req.target.to_hex();
    j["sender"] = {
        {"node_id", req.sender.node_id.to_hex()},
        {"host",    req.sender.address.host},
        {"port",    req.sender.address.port}
    };
    return nlohmann::json::to_cbor(j);
}

bool deserialize_find_node_request(ByteSpan payload, FindNodeRequest& out_req) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("target") || !j.contains("sender")) {
            return false;
        }

        if (!NodeID::from_hex(j["target"].get<std::string>(), out_req.target)) {
            return false;
        }

        const auto& sender_j = j["sender"];
        if (!sender_j.contains("node_id") || !sender_j.contains("host") || !sender_j.contains("port")) {
            return false;
        }

        if (!NodeID::from_hex(sender_j["node_id"].get<std::string>(), out_req.sender.node_id)) {
            return false;
        }

        out_req.sender.address.host = sender_j["host"].get<std::string>();
        out_req.sender.address.port = sender_j["port"].get<uint16_t>();
        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_find_node_request exception: {}", e.what());
        return false;
    }
}

Bytes serialize_find_node_response(const FindNodeResponse& resp) {
    nlohmann::json j;
    nlohmann::json nodes_array = nlohmann::json::array();
    for (const auto& peer : resp.closest_nodes) {
        nodes_array.push_back({
            {"node_id", peer.node_id.to_hex()},
            {"host",    peer.address.host},
            {"port",    peer.address.port}
        });
    }
    j["nodes"] = nodes_array;
    return nlohmann::json::to_cbor(j);
}

bool deserialize_find_node_response(ByteSpan payload, FindNodeResponse& out_resp) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("nodes") || !j["nodes"].is_array()) {
            return false;
        }

        out_resp.closest_nodes.clear();
        for (const auto& item : j["nodes"]) {
            if (!item.contains("node_id") || !item.contains("host") || !item.contains("port")) {
                continue;
            }
            PeerInfo peer;
            if (NodeID::from_hex(item["node_id"].get<std::string>(), peer.node_id)) {
                peer.address.host = item["host"].get<std::string>();
                peer.address.port = item["port"].get<uint16_t>();
                out_resp.closest_nodes.push_back(peer);
            }
        }
        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_find_node_response exception: {}", e.what());
        return false;
    }
}

} // namespace p2p::dht
