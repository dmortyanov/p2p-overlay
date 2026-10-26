#include "security/secure_session.hpp"
#include "identity/node_id.hpp"

#include <cstring>
#include <spdlog/spdlog.h>

namespace p2p::security {

namespace {

std::array<uint8_t, 24> build_frame_aad(const transport::Frame& frame, uint32_t payload_len) {
    std::array<uint8_t, 24> aad{};
    aad[0] = frame.version;
    aad[1] = static_cast<uint8_t>(frame.type);
    uint16_t flags_val = static_cast<uint16_t>(frame.flags);
    aad[2] = static_cast<uint8_t>((flags_val >> 8) & 0xFF);
    aad[3] = static_cast<uint8_t>(flags_val & 0xFF);
    std::memcpy(aad.data() + 4, frame.request_id.data.data(), 16);
    aad[20] = static_cast<uint8_t>((payload_len >> 24) & 0xFF);
    aad[21] = static_cast<uint8_t>((payload_len >> 16) & 0xFF);
    aad[22] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);
    aad[23] = static_cast<uint8_t>(payload_len & 0xFF);
    return aad;
}

} // namespace

SecureSession::SecureSession() = default;

SessionState SecureSession::state() const {
    std::lock_guard lock(mutex_);
    return state_;
}

bool SecureSession::is_active() const {
    std::lock_guard lock(mutex_);
    return state_ == SessionState::Active;
}

SessionRole SecureSession::role() const {
    std::lock_guard lock(mutex_);
    return role_;
}

const RequestID& SecureSession::session_id() const {
    std::lock_guard lock(mutex_);
    return session_id_;
}

const NodeID& SecureSession::peer_node_id() const {
    std::lock_guard lock(mutex_);
    return peer_node_id_;
}

const std::array<uint8_t, 32>& SecureSession::peer_public_key() const {
    std::lock_guard lock(mutex_);
    return peer_identity_pub_;
}

// ─── Initiator Handshake (Alice) ─────────────────────────────────────────

HandshakeInit SecureSession::initiate_handshake(const identity::Keypair& local_keypair) {
    std::lock_guard lock(mutex_);
    role_ = SessionRole::Initiator;
    eph_keypair_ = X25519Keypair::generate();
    local_nonce_ = generate_nonce();

    HandshakeInit init{
        .version = 1,
        .node_id = local_keypair.node_id(),
        .identity_public_key = local_keypair.public_key(),
        .ephemeral_public_key = eph_keypair_->public_key,
        .nonce = local_nonce_
    };

    saved_init_ = init;
    state_ = SessionState::HandshakeInitSent;
    return init;
}

std::optional<HandshakeComplete> SecureSession::process_handshake_response(
    const HandshakeResponse& resp,
    const identity::Keypair& local_keypair) {
    std::lock_guard lock(mutex_);
    if (state_ != SessionState::HandshakeInitSent || !saved_init_ || !eph_keypair_) {
        spdlog::warn("Invalid state for process_handshake_response: {}", session_state_name(state_));
        state_ = SessionState::Failed;
        return std::nullopt;
    }

    // 1. Validate Responder NodeID == SHA256(identity_public_key)
    if (!identity::verify_node_id(resp.node_id, resp.identity_public_key)) {
        spdlog::warn("AKE handshake failed: Responder NodeID mismatch");
        state_ = SessionState::Failed;
        return std::nullopt;
    }

    // 2. Recompute transcript T_B
    transcript_b_ = compute_transcript_b(
        *saved_init_, resp.session_id, resp.node_id,
        resp.identity_public_key, resp.ephemeral_public_key, resp.nonce);

    // 3. Verify Bob's Ed25519 signature over T_B
    if (!identity::Keypair::verify(resp.signature, transcript_b_.data(), transcript_b_.size(), resp.identity_public_key)) {
        spdlog::warn("AKE handshake failed: Responder signature verification failed");
        state_ = SessionState::Failed;
        return std::nullopt;
    }

    // 4. Compute X25519 Diffie-Hellman shared secret
    auto shared_secret = x25519_diffie_hellman(eph_keypair_->secret_key, resp.ephemeral_public_key);
    if (!shared_secret) {
        spdlog::warn("AKE handshake failed: X25519 scalar multiplication failed or weak key");
        state_ = SessionState::Failed;
        return std::nullopt;
    }

    // 5. Derive session keys (Alice is Initiator: tx = A->B, rx = B->A)
    peer_nonce_ = resp.nonce;
    auto keys = derive_session_keys(*shared_secret, local_nonce_, peer_nonce_);
    tx_key_ = keys.key_a_to_b;
    rx_key_ = keys.key_b_to_a;

    session_id_ = resp.session_id;
    peer_node_id_ = resp.node_id;
    peer_identity_pub_ = resp.identity_public_key;

    // 6. Compute transcript T_A and sign with Alice's Ed25519 key
    auto transcript_a = compute_transcript_a(transcript_b_);
    auto sig_a = local_keypair.sign(transcript_a);

    state_ = SessionState::Active;
    spdlog::info("AKE session {} established with peer {} (Role: Initiator)",
                 session_id_.to_short_hex(), peer_node_id_.to_short_hex());

    return HandshakeComplete{
        .session_id = session_id_,
        .signature = sig_a
    };
}

// ─── Responder Handshake (Bob) ───────────────────────────────────────────

std::optional<HandshakeResponse> SecureSession::process_handshake_init(
    const HandshakeInit& init,
    const identity::Keypair& local_keypair) {
    std::lock_guard lock(mutex_);
    if (init.version != 1) {
        spdlog::warn("AKE handshake failed: unsupported version {}", init.version);
        state_ = SessionState::Failed;
        return std::nullopt;
    }

    // 1. Validate Initiator NodeID == SHA256(identity_public_key)
    if (!identity::verify_node_id(init.node_id, init.identity_public_key)) {
        spdlog::warn("AKE handshake failed: Initiator NodeID mismatch");
        state_ = SessionState::Failed;
        return std::nullopt;
    }

    role_ = SessionRole::Responder;
    peer_node_id_ = init.node_id;
    peer_identity_pub_ = init.identity_public_key;
    peer_nonce_ = init.nonce;

    // 2. Generate ephemeral X25519 keypair and local nonce
    eph_keypair_ = X25519Keypair::generate();
    local_nonce_ = generate_nonce();
    session_id_ = RequestID::generate();

    // 3. Compute X25519 Diffie-Hellman shared secret
    auto shared_secret = x25519_diffie_hellman(eph_keypair_->secret_key, init.ephemeral_public_key);
    if (!shared_secret) {
        spdlog::warn("AKE handshake failed: X25519 scalar multiplication failed or weak key");
        state_ = SessionState::Failed;
        return std::nullopt;
    }

    // 4. Derive session keys (Bob is Responder: tx = B->A, rx = A->B)
    auto keys = derive_session_keys(*shared_secret, init.nonce, local_nonce_);
    tx_key_ = keys.key_b_to_a;
    rx_key_ = keys.key_a_to_b;

    // 5. Compute transcript T_B and sign with Bob's Ed25519 key
    transcript_b_ = compute_transcript_b(
        init, session_id_, local_keypair.node_id(),
        local_keypair.public_key(), eph_keypair_->public_key, local_nonce_);

    auto sig_b = local_keypair.sign(transcript_b_);

    state_ = SessionState::HandshakeRespSent;
    return HandshakeResponse{
        .session_id = session_id_,
        .node_id = local_keypair.node_id(),
        .identity_public_key = local_keypair.public_key(),
        .ephemeral_public_key = eph_keypair_->public_key,
        .nonce = local_nonce_,
        .signature = sig_b
    };
}

bool SecureSession::process_handshake_complete(const HandshakeComplete& comp) {
    std::lock_guard lock(mutex_);
    if (state_ != SessionState::HandshakeRespSent) {
        spdlog::warn("Invalid state for process_handshake_complete: {}", session_state_name(state_));
        state_ = SessionState::Failed;
        return false;
    }

    if (comp.session_id != session_id_) {
        spdlog::warn("AKE handshake failed: session ID mismatch");
        state_ = SessionState::Failed;
        return false;
    }

    // Verify Alice's signature over transcript T_A
    auto transcript_a = compute_transcript_a(transcript_b_);
    if (!identity::Keypair::verify(comp.signature, transcript_a.data(), transcript_a.size(), peer_identity_pub_)) {
        spdlog::warn("AKE handshake failed: Initiator signature verification failed");
        state_ = SessionState::Failed;
        return false;
    }

    state_ = SessionState::Active;
    spdlog::info("AKE session {} established with peer {} (Role: Responder)",
                 session_id_.to_short_hex(), peer_node_id_.to_short_hex());
    return true;
}

// ─── AEAD Frame Protection (E4-4, E4-5) ──────────────────────────────────

bool SecureSession::encrypt_frame(transport::Frame& frame) {
    std::lock_guard lock(mutex_);
    if (state_ != SessionState::Active) {
        return false;
    }

    uint64_t seq = ++tx_seq_;
    auto nonce = construct_aead_nonce(seq);

    frame.flags |= transport::FrameFlags::IS_ENCRYPTED;
    uint32_t enc_payload_len = static_cast<uint32_t>(8 + frame.payload.size() + AEAD_TAG_SIZE);

    auto aad = build_frame_aad(frame, enc_payload_len);

    auto ciphertext = chacha20_poly1305_encrypt(
        frame.payload.data(), frame.payload.size(),
        aad.data(), aad.size(),
        nonce, tx_key_
    );

    Bytes new_payload(8 + ciphertext.size());
    uint64_t temp_seq = seq;
    for (int i = 7; i >= 0; --i) {
        new_payload[i] = static_cast<uint8_t>(temp_seq & 0xFF);
        temp_seq >>= 8;
    }
    std::memcpy(new_payload.data() + 8, ciphertext.data(), ciphertext.size());

    frame.payload = std::move(new_payload);
    return true;
}

bool SecureSession::decrypt_frame(transport::Frame& frame) {
    std::lock_guard lock(mutex_);
    if (state_ != SessionState::Active) {
        return false;
    }

    if (!(frame.flags & transport::FrameFlags::IS_ENCRYPTED)) {
        return false; // Not marked as encrypted
    }

    if (frame.payload.size() < 8 + AEAD_TAG_SIZE) {
        return false; // Truncated encrypted payload
    }

    // Extract big-endian sequence number
    uint64_t seq = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        seq = (seq << 8) | frame.payload[i];
    }

    // Anti-replay check
    if (!replay_cache_.update_and_check(seq)) {
        spdlog::warn("Replay detected or packet too old for seq={}", seq);
        return false;
    }

    auto nonce = construct_aead_nonce(seq);
    auto aad = build_frame_aad(frame, static_cast<uint32_t>(frame.payload.size()));

    auto plaintext = chacha20_poly1305_decrypt(
        frame.payload.data() + 8, frame.payload.size() - 8,
        aad.data(), aad.size(),
        nonce, rx_key_
    );

    if (!plaintext) {
        spdlog::warn("AEAD authentication failed (tampered ciphertext, corrupted tag, or invalid AAD)");
        return false;
    }

    frame.payload = std::move(*plaintext);
    frame.flags = static_cast<transport::FrameFlags>(
        static_cast<uint16_t>(frame.flags) & ~static_cast<uint16_t>(transport::FrameFlags::IS_ENCRYPTED)
    );
    return true;
}

void SecureSession::close() {
    std::lock_guard lock(mutex_);
    state_ = SessionState::Closed;
}

} // namespace p2p::security
