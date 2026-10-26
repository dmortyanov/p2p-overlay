#pragma once
/// @file secure_session.hpp
/// @brief Authenticated Key Exchange (AKE) state machine and AEAD frame encryption (Stage 4, E4-4, E4-5, E4-6).

#include "common/types.hpp"
#include "identity/keypair.hpp"
#include "security/crypto_utils.hpp"
#include "security/ake_messages.hpp"
#include "security/replay_cache.hpp"
#include "transport/frame.hpp"

#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace p2p::security {

enum class SessionRole {
    Initiator, // Alice: initiates handshake
    Responder  // Bob: responds to handshake
};

enum class SessionState {
    Uninitialized,
    HandshakeInitSent,
    HandshakeRespSent,
    Active,
    Closed,
    Failed
};

[[nodiscard]] constexpr std::string_view session_state_name(SessionState s) {
    switch (s) {
        case SessionState::Uninitialized:     return "Uninitialized";
        case SessionState::HandshakeInitSent: return "HandshakeInitSent";
        case SessionState::HandshakeRespSent: return "HandshakeRespSent";
        case SessionState::Active:            return "Active";
        case SessionState::Closed:            return "Closed";
        case SessionState::Failed:            return "Failed";
    }
    return "Unknown";
}

/// A secure end-to-end encrypted session between two peers.
class SecureSession {
public:
    using Ptr = std::shared_ptr<SecureSession>;

    SecureSession();
    ~SecureSession() = default;

    [[nodiscard]] SessionState state() const;
    [[nodiscard]] bool is_active() const;
    [[nodiscard]] SessionRole role() const;
    [[nodiscard]] const RequestID& session_id() const;
    [[nodiscard]] const NodeID& peer_node_id() const;
    [[nodiscard]] const std::array<uint8_t, 32>& peer_public_key() const;

    // ─── Initiator (Alice) Handshake API ─────────────────────────────────

    /// Step 1: Alice generates ephemeral X25519 keypair and creates HANDSHAKE_INIT.
    [[nodiscard]] HandshakeInit initiate_handshake(const identity::Keypair& local_keypair);

    /// Step 3: Alice verifies Bob's HANDSHAKE_RESPONSE, derives session keys, and generates HANDSHAKE_COMPLETE.
    /// Transition: HandshakeInitSent -> Active.
    [[nodiscard]] std::optional<HandshakeComplete> process_handshake_response(
        const HandshakeResponse& resp,
        const identity::Keypair& local_keypair);

    // ─── Responder (Bob) Handshake API ───────────────────────────────────

    /// Step 2: Bob processes Alice's HANDSHAKE_INIT, derives keys, signs transcript T_B, and returns HANDSHAKE_RESPONSE.
    /// Transition: Uninitialized -> HandshakeRespSent.
    [[nodiscard]] std::optional<HandshakeResponse> process_handshake_init(
        const HandshakeInit& init,
        const identity::Keypair& local_keypair);

    /// Step 4: Bob verifies Alice's HANDSHAKE_COMPLETE signature over transcript T_A.
    /// Transition: HandshakeRespSent -> Active.
    [[nodiscard]] bool process_handshake_complete(const HandshakeComplete& comp);

    // ─── AEAD Frame Protection (E4-4, E4-5) ──────────────────────────────

    /// Encrypt a Frame in-place using ChaCha20-Poly1305 with frame header as AAD.
    /// Sets FrameFlags::IS_ENCRYPTED and increments tx sequence counter.
    /// @return true if encrypted successfully, false if session not active or error.
    [[nodiscard]] bool encrypt_frame(transport::Frame& frame);

    /// Decrypt an encrypted Frame in-place and verify anti-replay sliding window.
    /// Clears FrameFlags::IS_ENCRYPTED and updates payload with original plaintext.
    /// @return true if decrypted and authenticated, false if replay, bad auth tag, or error.
    [[nodiscard]] bool decrypt_frame(transport::Frame& frame);

    /// Close the session.
    void close();

private:
    mutable std::mutex mutex_;
    SessionState state_{SessionState::Uninitialized};
    SessionRole role_{SessionRole::Initiator};

    RequestID session_id_{};
    NodeID peer_node_id_{};
    std::array<uint8_t, 32> peer_identity_pub_{};

    // Ephemeral handshake state
    std::optional<X25519Keypair> eph_keypair_;
    std::array<uint8_t, NONCE_SIZE> local_nonce_{};
    std::array<uint8_t, NONCE_SIZE> peer_nonce_{};
    std::optional<HandshakeInit> saved_init_;
    Bytes transcript_b_;

    // Session keys (derived via HKDF-SHA256)
    std::array<uint8_t, AEAD_KEY_SIZE> tx_key_{};
    std::array<uint8_t, AEAD_KEY_SIZE> rx_key_{};

    // Frame sequence tracking & replay protection
    uint64_t tx_seq_{0};
    ReplayCache replay_cache_{256};
};

} // namespace p2p::security
