#include "security/ake_messages.hpp"
#include "identity/node_id.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <cstring>

namespace p2p::security {

namespace {

template <std::size_t N>
std::optional<std::array<uint8_t, N>> extract_binary(const nlohmann::json& j, const std::string& field) {
    if (!j.contains(field) || !j[field].is_binary()) {
        return std::nullopt;
    }
    const auto& b = j[field].get_binary();
    if (b.size() != N) {
        return std::nullopt;
    }
    std::array<uint8_t, N> arr;
    std::memcpy(arr.data(), b.data(), N);
    return arr;
}

template <std::size_t N>
nlohmann::json to_binary_json(const std::array<uint8_t, N>& arr) {
    return nlohmann::json::binary_t({arr.begin(), arr.end()});
}

} // namespace

Bytes compute_transcript_b(
    const HandshakeInit& init,
    const RequestID& session_id,
    const NodeID& resp_node_id,
    const std::array<uint8_t, 32>& resp_identity_pub,
    const std::array<uint8_t, 32>& resp_ephemeral_pub,
    const std::array<uint8_t, NONCE_SIZE>& resp_nonce) {
    static const std::string prefix = "P2P-AKE-V1-RESP";
    Bytes t;
    t.reserve(prefix.size() + 32*4 + 16 + 32*4);

    t.insert(t.end(), prefix.begin(), prefix.end());
    t.insert(t.end(), init.node_id.data.begin(), init.node_id.data.end());
    t.insert(t.end(), init.identity_public_key.begin(), init.identity_public_key.end());
    t.insert(t.end(), init.ephemeral_public_key.begin(), init.ephemeral_public_key.end());
    t.insert(t.end(), init.nonce.begin(), init.nonce.end());

    t.insert(t.end(), session_id.data.begin(), session_id.data.end());
    t.insert(t.end(), resp_node_id.data.begin(), resp_node_id.data.end());
    t.insert(t.end(), resp_identity_pub.begin(), resp_identity_pub.end());
    t.insert(t.end(), resp_ephemeral_pub.begin(), resp_ephemeral_pub.end());
    t.insert(t.end(), resp_nonce.begin(), resp_nonce.end());

    return t;
}

Bytes compute_transcript_a(const Bytes& transcript_b) {
    static const std::string prefix = "P2P-AKE-V1-COMP";
    Bytes t;
    t.reserve(prefix.size() + transcript_b.size());
    t.insert(t.end(), prefix.begin(), prefix.end());
    t.insert(t.end(), transcript_b.begin(), transcript_b.end());
    return t;
}

Bytes serialize_handshake_init(const HandshakeInit& msg) {
    nlohmann::json j;
    j["ver"] = msg.version;
    j["node_id"] = msg.node_id.to_hex();
    j["id_pk"] = to_binary_json(msg.identity_public_key);
    j["eph_pk"] = to_binary_json(msg.ephemeral_public_key);
    j["nonce"] = to_binary_json(msg.nonce);
    return nlohmann::json::to_cbor(j);
}

bool deserialize_handshake_init(const Bytes& payload, HandshakeInit& out) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("ver") || !j.contains("node_id")) return false;

        out.version = j["ver"].get<uint8_t>();
        if (!NodeID::from_hex(j["node_id"].get<std::string>(), out.node_id)) return false;

        auto id_pk = extract_binary<32>(j, "id_pk");
        if (!id_pk) return false;
        out.identity_public_key = *id_pk;

        auto eph_pk = extract_binary<32>(j, "eph_pk");
        if (!eph_pk) return false;
        out.ephemeral_public_key = *eph_pk;

        auto nonce = extract_binary<NONCE_SIZE>(j, "nonce");
        if (!nonce) return false;
        out.nonce = *nonce;

        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_handshake_init failed: {}", e.what());
        return false;
    }
}

Bytes serialize_handshake_response(const HandshakeResponse& msg) {
    nlohmann::json j;
    j["sid"] = msg.session_id.to_hex();
    j["node_id"] = msg.node_id.to_hex();
    j["id_pk"] = to_binary_json(msg.identity_public_key);
    j["eph_pk"] = to_binary_json(msg.ephemeral_public_key);
    j["nonce"] = to_binary_json(msg.nonce);
    j["sig"] = to_binary_json(msg.signature);
    return nlohmann::json::to_cbor(j);
}

bool deserialize_handshake_response(const Bytes& payload, HandshakeResponse& out) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("sid") || !j.contains("node_id")) return false;

        if (!RequestID::from_hex(j["sid"].get<std::string>(), out.session_id)) return false;
        if (!NodeID::from_hex(j["node_id"].get<std::string>(), out.node_id)) return false;

        auto id_pk = extract_binary<32>(j, "id_pk");
        if (!id_pk) return false;
        out.identity_public_key = *id_pk;

        auto eph_pk = extract_binary<32>(j, "eph_pk");
        if (!eph_pk) return false;
        out.ephemeral_public_key = *eph_pk;

        auto nonce = extract_binary<NONCE_SIZE>(j, "nonce");
        if (!nonce) return false;
        out.nonce = *nonce;

        auto sig = extract_binary<64>(j, "sig");
        if (!sig) return false;
        out.signature = *sig;

        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_handshake_response failed: {}", e.what());
        return false;
    }
}

Bytes serialize_handshake_complete(const HandshakeComplete& msg) {
    nlohmann::json j;
    j["sid"] = msg.session_id.to_hex();
    j["sig"] = to_binary_json(msg.signature);
    return nlohmann::json::to_cbor(j);
}

bool deserialize_handshake_complete(const Bytes& payload, HandshakeComplete& out) {
    if (payload.empty()) return false;
    try {
        auto j = nlohmann::json::from_cbor(payload);
        if (!j.contains("sid")) return false;

        if (!RequestID::from_hex(j["sid"].get<std::string>(), out.session_id)) return false;

        auto sig = extract_binary<64>(j, "sig");
        if (!sig) return false;
        out.signature = *sig;

        return true;
    } catch (const std::exception& e) {
        spdlog::debug("deserialize_handshake_complete failed: {}", e.what());
        return false;
    }
}

} // namespace p2p::security
