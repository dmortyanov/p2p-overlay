/// @file dht_messages.cpp
/// @brief CBOR serialization and deserialization for DHT RPC messages.

#include "dht/dht_messages.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace p2p::dht {

// ─── FIND_NODE ──────────────────────────────────────────────────────

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

// ─── STORE (E3-3) ───────────────────────────────────────────────────

Bytes serialize_store_request(const StoreRequest& req) {
    nlohmann::json j;
    j["key"] = req.key.to_hex();
    j["sender"] = {
        {"node_id", req.sender.node_id.to_hex()},
        {"host",    req.sender.address.host},
        {"port",    req.sender.address.port}
    };
    auto rec_cbor = req.record.to_cbor();
    j["record"] = nlohmann::json::binary_t({rec_cbor.begin(), rec_cbor.end()});
    return nlohmann::json::to_cbor(j);
}

bool deserialize_store_request(ByteSpan payload, StoreRequest& out_req) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("key") || !j.contains("sender") || !j.contains("record")) {
            return false;
        }

        if (!NodeID::from_hex(j["key"].get<std::string>(), out_req.key)) {
            return false;
        }

        const auto& sender_j = j["sender"];
        if (!NodeID::from_hex(sender_j.value("node_id", ""), out_req.sender.node_id)) {
            return false;
        }
        out_req.sender.address.host = sender_j.value("host", "");
        out_req.sender.address.port = sender_j.value("port", static_cast<uint16_t>(0));

        auto rec_bytes = j["record"].get<nlohmann::json::binary_t>();
        auto maybe_rec = NodeRecord::from_cbor(rec_bytes);
        if (!maybe_rec) {
            return false;
        }
        out_req.record = *maybe_rec;
        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_store_request exception: {}", e.what());
        return false;
    }
}

Bytes serialize_store_response(const StoreResponse& resp) {
    nlohmann::json j;
    j["key"] = resp.key.to_hex();
    j["success"] = resp.success;
    j["message"] = resp.message;
    return nlohmann::json::to_cbor(j);
}

bool deserialize_store_response(ByteSpan payload, StoreResponse& out_resp) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("key") || !j.contains("success")) {
            return false;
        }
        if (!NodeID::from_hex(j["key"].get<std::string>(), out_resp.key)) {
            return false;
        }
        out_resp.success = j["success"].get<bool>();
        out_resp.message = j.value("message", "");
        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_store_response exception: {}", e.what());
        return false;
    }
}

// ─── FIND_VALUE (E3-3) ──────────────────────────────────────────────

Bytes serialize_find_value_request(const FindValueRequest& req) {
    nlohmann::json j;
    j["key"] = req.key.to_hex();
    j["sender"] = {
        {"node_id", req.sender.node_id.to_hex()},
        {"host",    req.sender.address.host},
        {"port",    req.sender.address.port}
    };
    return nlohmann::json::to_cbor(j);
}

bool deserialize_find_value_request(ByteSpan payload, FindValueRequest& out_req) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("key") || !j.contains("sender")) {
            return false;
        }
        if (!NodeID::from_hex(j["key"].get<std::string>(), out_req.key)) {
            return false;
        }
        const auto& sender_j = j["sender"];
        if (!NodeID::from_hex(sender_j.value("node_id", ""), out_req.sender.node_id)) {
            return false;
        }
        out_req.sender.address.host = sender_j.value("host", "");
        out_req.sender.address.port = sender_j.value("port", static_cast<uint16_t>(0));
        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_find_value_request exception: {}", e.what());
        return false;
    }
}

Bytes serialize_find_value_response(const FindValueResponse& resp) {
    nlohmann::json j;
    j["key"] = resp.key.to_hex();
    j["has_value"] = resp.has_value;

    if (resp.has_value && resp.record) {
        auto rec_cbor = resp.record->to_cbor();
        j["record"] = nlohmann::json::binary_t({rec_cbor.begin(), rec_cbor.end()});
    } else {
        nlohmann::json nodes_array = nlohmann::json::array();
        for (const auto& peer : resp.closest_nodes) {
            nodes_array.push_back({
                {"node_id", peer.node_id.to_hex()},
                {"host",    peer.address.host},
                {"port",    peer.address.port}
            });
        }
        j["nodes"] = nodes_array;
    }
    return nlohmann::json::to_cbor(j);
}

bool deserialize_find_value_response(ByteSpan payload, FindValueResponse& out_resp) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("key") || !j.contains("has_value")) {
            return false;
        }
        if (!NodeID::from_hex(j["key"].get<std::string>(), out_resp.key)) {
            return false;
        }
        out_resp.has_value = j["has_value"].get<bool>();

        if (out_resp.has_value && j.contains("record")) {
            auto rec_bytes = j["record"].get<nlohmann::json::binary_t>();
            out_resp.record = NodeRecord::from_cbor(rec_bytes);
            out_resp.closest_nodes.clear();
        } else if (j.contains("nodes") && j["nodes"].is_array()) {
            out_resp.record = std::nullopt;
            out_resp.closest_nodes.clear();
            for (const auto& item : j["nodes"]) {
                PeerInfo peer;
                if (NodeID::from_hex(item.value("node_id", ""), peer.node_id)) {
                    peer.address.host = item.value("host", "");
                    peer.address.port = item.value("port", static_cast<uint16_t>(0));
                    out_resp.closest_nodes.push_back(peer);
                }
            }
        }
        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_find_value_response exception: {}", e.what());
        return false;
    }
}

} // namespace p2p::dht
