#pragma once
/// @file onion_packet.hpp
/// @brief Multi-layer Onion encryption and decryption engine (Stage 5).

#include "common/types.hpp"
#include "security/crypto_utils.hpp"
#include "tunnel/tunnel_types.hpp"

#include <vector>
#include <optional>
#include <array>

namespace p2p::tunnel {

/// Structure representing a peeled onion layer at an intermediate relay.
struct PeeledLayer {
    bool is_terminal{false};           ///< True if this is the final destination / exit node
    NodeID next_hop_node_id{};        ///< NodeID of the next hop (if !is_terminal)
    PeerAddress next_hop_address{};   ///< Address of the next hop (if !is_terminal)
    Bytes payload{};                  ///< Remaining onion payload (or inner plaintext if terminal)
};

class OnionPacket {
public:
    /// Wrap payload in layered ChaCha20-Poly1305 encryption.
    /// @param innermost_payload Data destined for final recipient.
    /// @param hops Ordered list of relays: hops[0] = R1, hops[1] = R2, ..., hops[n-1] = Rn.
    /// @param destination_id Final destination NodeID.
    /// @param seq Monotonic sequence number for nonce derivation.
    /// @return Multi-layered onion ciphertext ready to send to hops[0].
    [[nodiscard]] static Bytes wrap(
        ByteSpan innermost_payload,
        const std::vector<TunnelHop>& hops,
        const NodeID& destination_id,
        uint64_t seq = 0);

    /// Peel a single onion layer at relay hop R_i.
    /// @param onion_payload Multi-layer payload received from predecessor.
    /// @param layer_key Symmetric AEAD key for this relay.
    /// @param seq Monotonic sequence number for nonce derivation.
    /// @return PeeledLayer with routing instructions and forwarded payload, or std::nullopt on MAC failure.
    [[nodiscard]] static std::optional<PeeledLayer> peel(
        ByteSpan onion_payload,
        const std::array<uint8_t, security::AEAD_KEY_SIZE>& layer_key,
        uint64_t seq = 0);

private:
    static constexpr uint8_t FLAG_TERMINAL = 0x01;
    static constexpr uint8_t FLAG_FORWARD  = 0x02;
};

} // namespace p2p::tunnel

