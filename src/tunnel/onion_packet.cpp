/// @file onion_packet.cpp
/// @brief Multi-layer Onion encryption and decryption engine implementation.

#include "tunnel/onion_packet.hpp"
#include <nlohmann/json.hpp>

namespace p2p::tunnel {

using json = nlohmann::json;

Bytes OnionPacket::wrap(
    ByteSpan innermost_payload,
    const std::vector<TunnelHop>& hops,
    const NodeID& destination_id,
    uint64_t seq)
{
    if (hops.empty()) {
        return Bytes(innermost_payload.begin(), innermost_payload.end());
    }

    // Start with innermost layer (for final hop hops.back() -> destination)
    // We wrap in reverse: from hops[n-1] down to hops[0]
    Bytes current_payload(innermost_payload.begin(), innermost_payload.end());

    for (int i = static_cast<int>(hops.size()) - 1; i >= 0; --i) {
        const auto& hop = hops[i];
        bool is_last_hop = (i == static_cast<int>(hops.size()) - 1);

        json header_json = json::object();
        if (is_last_hop) {
            header_json["flg"] = FLAG_TERMINAL;
            header_json["dst"] = json::binary_t(std::vector<uint8_t>(destination_id.data.begin(), destination_id.data.end()));
        } else {
            const auto& next_hop = hops[i + 1];
            header_json["flg"] = FLAG_FORWARD;
            header_json["nxt_id"] = json::binary_t(std::vector<uint8_t>(next_hop.node_id.data.begin(), next_hop.node_id.data.end()));
            header_json["nxt_h"] = next_hop.address.host;
            header_json["nxt_p"] = next_hop.address.port;
        }

        Bytes hdr_bytes = json::to_cbor(header_json);

        // Inner frame to encrypt: [uint16_t hdr_len][hdr_bytes][current_payload]
        Bytes layer_plaintext;
        uint16_t hdr_len = static_cast<uint16_t>(hdr_bytes.size());
        layer_plaintext.push_back(static_cast<uint8_t>((hdr_len >> 8) & 0xFF));
        layer_plaintext.push_back(static_cast<uint8_t>(hdr_len & 0xFF));
        layer_plaintext.insert(layer_plaintext.end(), hdr_bytes.begin(), hdr_bytes.end());
        layer_plaintext.insert(layer_plaintext.end(), current_payload.begin(), current_payload.end());

        // Derive nonce for this hop from sequence number and hop index
        auto nonce = security::construct_aead_nonce(seq + static_cast<uint64_t>(i));

        // Encrypt with this hop's layer_key
        static const std::string aad = "onion-layer-v1";
        current_payload = security::chacha20_poly1305_encrypt(
            layer_plaintext.data(), layer_plaintext.size(),
            reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
            nonce, hop.layer_key);
    }

    return current_payload;
}

std::optional<PeeledLayer> OnionPacket::peel(
    ByteSpan onion_payload,
    const std::array<uint8_t, security::AEAD_KEY_SIZE>& layer_key,
    uint64_t seq)
{
    if (onion_payload.size() < security::AEAD_TAG_SIZE + 2) {
        return std::nullopt;
    }

    // Try decrypting with layer_key.
    // The hop index isn't known explicitly by the relay; however, the initiator used seq + hop_index.
    // For intermediate relays forwarding packets, we check seq first, or we can use the sequence passed.
    // In our design, sequence_number in TunnelDataMsg is identical across the circuit or indexed.
    // We try decrypting with nonce = construct_aead_nonce(seq).
    // To allow matching whichever hop index was used, we try hop indices 0..7 if initial fails.
    static const std::string aad = "onion-layer-v1";
    std::optional<Bytes> decrypted;

    for (uint64_t hop_offset = 0; hop_offset < 8; ++hop_offset) {
        auto nonce = security::construct_aead_nonce(seq + hop_offset);
        decrypted = security::chacha20_poly1305_decrypt(
            onion_payload.data(), onion_payload.size(),
            reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
            nonce, layer_key);
        if (decrypted) break;
    }

    if (!decrypted || decrypted->size() < 2) {
        return std::nullopt;
    }

    uint16_t hdr_len = (static_cast<uint16_t>((*decrypted)[0]) << 8) | static_cast<uint16_t>((*decrypted)[1]);
    if (decrypted->size() < 2 + hdr_len) {
        return std::nullopt;
    }

    ByteSpan hdr_span(decrypted->data() + 2, hdr_len);
    Bytes next_payload(decrypted->data() + 2 + hdr_len, decrypted->data() + decrypted->size());

    try {
        auto j = json::from_cbor(hdr_span.begin(), hdr_span.end());
        if (!j.is_object()) return std::nullopt;

        uint8_t flg = j.at("flg").get<uint8_t>();
        PeeledLayer result;
        result.payload = std::move(next_payload);

        if (flg == FLAG_TERMINAL) {
            result.is_terminal = true;
            if (j.contains("dst")) {
                auto dst_bin = j.at("dst").get_binary();
                if (dst_bin.size() == NodeID::SIZE) {
                    std::copy_n(dst_bin.begin(), NodeID::SIZE, result.next_hop_node_id.data.begin());
                }
            }
        } else if (flg == FLAG_FORWARD) {
            result.is_terminal = false;
            auto nxt_bin = j.at("nxt_id").get_binary();
            if (nxt_bin.size() != NodeID::SIZE) return std::nullopt;
            std::copy_n(nxt_bin.begin(), NodeID::SIZE, result.next_hop_node_id.data.begin());
            result.next_hop_address.host = j.at("nxt_h").get<std::string>();
            result.next_hop_address.port = j.at("nxt_p").get<uint16_t>();
        } else {
            return std::nullopt;
        }

        return result;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace p2p::tunnel

