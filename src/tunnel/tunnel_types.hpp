#pragma once
/// @file tunnel_types.hpp
/// @brief Message structures, CBOR serialization, and enums for Onion Tunnels (Stage 5).

#include "common/types.hpp"
#include "transport/message_types.hpp"
#include "security/crypto_utils.hpp"

#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace p2p::tunnel {

/// 16-byte unique identifier for an onion circuit/tunnel.
using CircuitID = RequestID;

/// Status of a tunnel circuit.
enum class TunnelState {
    BUILDING,   ///< Circuit build in progress
    ACTIVE,     ///< All hops acknowledged, ready for data
    EXPIRED,    ///< Exceeded TTL, queued for teardown
    FAILED,     ///< Build timed out or broken in transit
    CLOSED      ///< Explicitly torn down
};

/// Descriptor for a single hop in the tunnel route.
struct TunnelHop {
    NodeID node_id{};
    PeerAddress address{};
    std::array<uint8_t, security::AEAD_KEY_SIZE> layer_key{}; ///< Symmetric key for this layer
};

/// ─── Wire Messages ─────────────────────────────────────────────────────────

/// Payload for TUNNEL_BUILD (0x20).
/// Sent by initiator (or forwarded hop-by-hop) to establish the circuit.
struct TunnelBuildMsg {
    CircuitID circuit_id{};
    uint8_t hop_index{0};                 ///< Current hop index (0-based)
    uint8_t total_hops{3};                ///< Expected hops (>= 3)
    std::array<uint8_t, 32> eph_public_key{}; ///< X25519 ephemeral pubkey for DH with this relay
    NodeID next_hop_node_id{};            ///< Zero if this is the final exit relay
    PeerAddress next_hop_address{};       ///< Empty if final exit relay
    Bytes encrypted_payload{};            ///< Nested payload for subsequent hops
};

/// Payload for TUNNEL_BUILD_OK (0x21).
struct TunnelBuildOkMsg {
    CircuitID circuit_id{};
    uint8_t hop_index{0};
    std::array<uint8_t, 32> eph_public_key{}; ///< Relay's X25519 ephemeral pubkey
};

/// Payload for TUNNEL_BUILD_FAIL (0x22).
struct TunnelBuildFailMsg {
    CircuitID circuit_id{};
    uint8_t hop_index{0};
    std::string reason{};
};

/// Payload for TUNNEL_DATA (0x30).
struct TunnelDataMsg {
    CircuitID circuit_id{};
    uint64_t sequence_number{0};          ///< Monotonic sequence per circuit
    Bytes onion_payload{};                ///< Encrypted payload
};

/// Payload for TUNNEL_ACK (0x31).
struct TunnelAckMsg {
    CircuitID circuit_id{};
    uint64_t sequence_number{0};
    bool success{true};
};

/// Payload for TUNNEL_CLOSE (0x32).
struct TunnelCloseMsg {
    CircuitID circuit_id{};
    std::string reason{};
};

/// ─── CBOR Serialization ────────────────────────────────────────────────────

[[nodiscard]] Bytes serialize_tunnel_build(const TunnelBuildMsg& msg);
[[nodiscard]] bool deserialize_tunnel_build(ByteSpan payload, TunnelBuildMsg& out_msg);

[[nodiscard]] Bytes serialize_tunnel_build_ok(const TunnelBuildOkMsg& msg);
[[nodiscard]] bool deserialize_tunnel_build_ok(ByteSpan payload, TunnelBuildOkMsg& out_msg);

[[nodiscard]] Bytes serialize_tunnel_build_fail(const TunnelBuildFailMsg& msg);
[[nodiscard]] bool deserialize_tunnel_build_fail(ByteSpan payload, TunnelBuildFailMsg& out_msg);

[[nodiscard]] Bytes serialize_tunnel_data(const TunnelDataMsg& msg);
[[nodiscard]] bool deserialize_tunnel_data(ByteSpan payload, TunnelDataMsg& out_msg);

[[nodiscard]] Bytes serialize_tunnel_ack(const TunnelAckMsg& msg);
[[nodiscard]] bool deserialize_tunnel_ack(ByteSpan payload, TunnelAckMsg& out_msg);

[[nodiscard]] Bytes serialize_tunnel_close(const TunnelCloseMsg& msg);
[[nodiscard]] bool deserialize_tunnel_close(ByteSpan payload, TunnelCloseMsg& out_msg);

} // namespace p2p::tunnel

