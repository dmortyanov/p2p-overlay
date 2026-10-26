#pragma once
/// @file ake_messages.hpp
/// @brief Handshake message structures and CBOR serialization for AKE (Stage 4, E4-3).

#include "common/types.hpp"
#include "security/crypto_utils.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace p2p::security {

/// Message 1: HANDSHAKE_INIT (MessageType::HANDSHAKE_INIT, 0x50).
/// Sent by Initiator (Alice) to Responder (Bob).
struct HandshakeInit {
    uint8_t version{1};
    NodeID node_id{};
    std::array<uint8_t, 32> identity_public_key{};  // Ed25519
    std::array<uint8_t, 32> ephemeral_public_key{}; // X25519
    std::array<uint8_t, NONCE_SIZE> nonce{};         // 32-byte random nonce
};

/// Message 2: HANDSHAKE_RESPONSE (MessageType::HANDSHAKE_RESPONSE, 0x51).
/// Sent by Responder (Bob) to Initiator (Alice).
struct HandshakeResponse {
    RequestID session_id{};
    NodeID node_id{};
    std::array<uint8_t, 32> identity_public_key{};  // Ed25519
    std::array<uint8_t, 32> ephemeral_public_key{}; // X25519
    std::array<uint8_t, NONCE_SIZE> nonce{};         // 32-byte random nonce
    std::array<uint8_t, 64> signature{};            // Ed25519 signature over Responder transcript T_B
};

/// Message 3: HANDSHAKE_COMPLETE (MessageType::HANDSHAKE_COMPLETE, 0x52).
/// Sent by Initiator (Alice) to Responder (Bob).
struct HandshakeComplete {
    RequestID session_id{};
    std::array<uint8_t, 64> signature{};            // Ed25519 signature over Initiator transcript T_A
};

/// Compute the canonical transcript T_B for responder signature verification.
[[nodiscard]] Bytes compute_transcript_b(
    const HandshakeInit& init,
    const RequestID& session_id,
    const NodeID& resp_node_id,
    const std::array<uint8_t, 32>& resp_identity_pub,
    const std::array<uint8_t, 32>& resp_ephemeral_pub,
    const std::array<uint8_t, NONCE_SIZE>& resp_nonce);

/// Compute the canonical transcript T_A for initiator completion signature verification.
[[nodiscard]] Bytes compute_transcript_a(const Bytes& transcript_b);

/// CBOR serialization functions.
[[nodiscard]] Bytes serialize_handshake_init(const HandshakeInit& msg);
[[nodiscard]] bool deserialize_handshake_init(const Bytes& payload, HandshakeInit& out);

[[nodiscard]] Bytes serialize_handshake_response(const HandshakeResponse& msg);
[[nodiscard]] bool deserialize_handshake_response(const Bytes& payload, HandshakeResponse& out);

[[nodiscard]] Bytes serialize_handshake_complete(const HandshakeComplete& msg);
[[nodiscard]] bool deserialize_handshake_complete(const Bytes& payload, HandshakeComplete& out);

} // namespace p2p::security
