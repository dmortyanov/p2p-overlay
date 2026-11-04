/// @file tunnel_types.cpp
/// @brief CBOR serialization implementation for Tunnel protocol messages.

#include "tunnel/tunnel_types.hpp"
#include <nlohmann/json.hpp>

namespace p2p::tunnel {

using json = nlohmann::json;

Bytes serialize_tunnel_build(const TunnelBuildMsg& msg) {
    json j = json::object();
    j["cid"] = json::binary_t({msg.circuit_id.data.begin(), msg.circuit_id.data.end()});
    j["idx"] = msg.hop_index;
    j["tot"] = msg.total_hops;
    j["eph"] = json::binary_t({msg.eph_public_key.begin(), msg.eph_public_key.end()});
    j["nxt_id"] = json::binary_t({msg.next_hop_node_id.data.begin(), msg.next_hop_node_id.data.end()});
    j["nxt_h"] = msg.next_hop_address.host;
    j["nxt_p"] = msg.next_hop_address.port;
    j["enc"] = json::binary_t({msg.encrypted_payload.begin(), msg.encrypted_payload.end()});
    return json::to_cbor(j);
}

bool deserialize_tunnel_build(ByteSpan payload, TunnelBuildMsg& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto cid_bin = j.at("cid").get_binary();
        if (cid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(cid_bin.begin(), RequestID::SIZE, out_msg.circuit_id.data.begin());

        out_msg.hop_index = j.at("idx").get<uint8_t>();
        out_msg.total_hops = j.at("tot").get<uint8_t>();

        auto eph_bin = j.at("eph").get_binary();
        if (eph_bin.size() != 32) return false;
        std::copy_n(eph_bin.begin(), 32, out_msg.eph_public_key.begin());

        auto nxt_bin = j.at("nxt_id").get_binary();
        if (nxt_bin.size() != NodeID::SIZE) return false;
        std::copy_n(nxt_bin.begin(), NodeID::SIZE, out_msg.next_hop_node_id.data.begin());

        out_msg.next_hop_address.host = j.at("nxt_h").get<std::string>();
        out_msg.next_hop_address.port = j.at("nxt_p").get<uint16_t>();

        auto enc_bin = j.at("enc").get_binary();
        out_msg.encrypted_payload.assign(enc_bin.begin(), enc_bin.end());

        return true;
    } catch (...) {
        return false;
    }
}

Bytes serialize_tunnel_build_ok(const TunnelBuildOkMsg& msg) {
    json j = json::object();
    j["cid"] = json::binary_t({msg.circuit_id.data.begin(), msg.circuit_id.data.end()});
    j["idx"] = msg.hop_index;
    j["eph"] = json::binary_t({msg.eph_public_key.begin(), msg.eph_public_key.end()});
    return json::to_cbor(j);
}

bool deserialize_tunnel_build_ok(ByteSpan payload, TunnelBuildOkMsg& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto cid_bin = j.at("cid").get_binary();
        if (cid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(cid_bin.begin(), RequestID::SIZE, out_msg.circuit_id.data.begin());

        out_msg.hop_index = j.at("idx").get<uint8_t>();

        auto eph_bin = j.at("eph").get_binary();
        if (eph_bin.size() != 32) return false;
        std::copy_n(eph_bin.begin(), 32, out_msg.eph_public_key.begin());

        return true;
    } catch (...) {
        return false;
    }
}

Bytes serialize_tunnel_build_fail(const TunnelBuildFailMsg& msg) {
    json j = json::object();
    j["cid"] = json::binary_t({msg.circuit_id.data.begin(), msg.circuit_id.data.end()});
    j["idx"] = msg.hop_index;
    j["rsn"] = msg.reason;
    return json::to_cbor(j);
}

bool deserialize_tunnel_build_fail(ByteSpan payload, TunnelBuildFailMsg& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto cid_bin = j.at("cid").get_binary();
        if (cid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(cid_bin.begin(), RequestID::SIZE, out_msg.circuit_id.data.begin());

        out_msg.hop_index = j.at("idx").get<uint8_t>();
        out_msg.reason = j.at("rsn").get<std::string>();
        return true;
    } catch (...) {
        return false;
    }
}

Bytes serialize_tunnel_data(const TunnelDataMsg& msg) {
    json j = json::object();
    j["cid"] = json::binary_t({msg.circuit_id.data.begin(), msg.circuit_id.data.end()});
    j["seq"] = msg.sequence_number;
    j["onp"] = json::binary_t({msg.onion_payload.begin(), msg.onion_payload.end()});
    return json::to_cbor(j);
}

bool deserialize_tunnel_data(ByteSpan payload, TunnelDataMsg& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto cid_bin = j.at("cid").get_binary();
        if (cid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(cid_bin.begin(), RequestID::SIZE, out_msg.circuit_id.data.begin());

        out_msg.sequence_number = j.at("seq").get<uint64_t>();

        auto onp_bin = j.at("onp").get_binary();
        out_msg.onion_payload.assign(onp_bin.begin(), onp_bin.end());
        return true;
    } catch (...) {
        return false;
    }
}

Bytes serialize_tunnel_ack(const TunnelAckMsg& msg) {
    json j = json::object();
    j["cid"] = json::binary_t({msg.circuit_id.data.begin(), msg.circuit_id.data.end()});
    j["seq"] = msg.sequence_number;
    j["ok"] = msg.success;
    return json::to_cbor(j);
}

bool deserialize_tunnel_ack(ByteSpan payload, TunnelAckMsg& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto cid_bin = j.at("cid").get_binary();
        if (cid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(cid_bin.begin(), RequestID::SIZE, out_msg.circuit_id.data.begin());

        out_msg.sequence_number = j.at("seq").get<uint64_t>();
        out_msg.success = j.at("ok").get<bool>();
        return true;
    } catch (...) {
        return false;
    }
}

Bytes serialize_tunnel_close(const TunnelCloseMsg& msg) {
    json j = json::object();
    j["cid"] = json::binary_t({msg.circuit_id.data.begin(), msg.circuit_id.data.end()});
    j["rsn"] = msg.reason;
    return json::to_cbor(j);
}

bool deserialize_tunnel_close(ByteSpan payload, TunnelCloseMsg& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto cid_bin = j.at("cid").get_binary();
        if (cid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(cid_bin.begin(), RequestID::SIZE, out_msg.circuit_id.data.begin());

        out_msg.reason = j.at("rsn").get<std::string>();
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace p2p::tunnel

