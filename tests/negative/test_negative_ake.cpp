/// @file test_negative_ake.cpp
/// @brief Negative security tests for Stage 4: AKE tampering, identity spoofing, bit-flipping, and frame replays (E4-7).

#include "security/crypto_utils.hpp"
#include "security/ake_messages.hpp"
#include "security/secure_session.hpp"
#include "identity/keypair.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

using namespace p2p;
using namespace p2p::security;

TEST_CASE("E4-7: Negative AKE Security Tests", "[security][negative][ake][stage4]") {
    REQUIRE(sodium_init() >= 0);

    auto alice_kp = identity::Keypair::generate();
    auto bob_kp = identity::Keypair::generate();
    auto eve_kp = identity::Keypair::generate();

    SECTION("Attack 1: Initiator identity spoofing (tampered NodeID != SHA256(pubkey))") {
        SecureSession alice_session;
        SecureSession bob_session;

        auto init = alice_session.initiate_handshake(alice_kp);
        // Attacker Eve replaces Alice's NodeID with her own NodeID, but keeps Alice's public key
        init.node_id = eve_kp.node_id();

        auto resp = bob_session.process_handshake_init(init, bob_kp);
        REQUIRE_FALSE(resp.has_value());
        REQUIRE(bob_session.state() == SessionState::Failed);
    }

    SECTION("Attack 2: Attacker tampers with ephemeral public key in HANDSHAKE_INIT") {
        SecureSession alice_session;
        SecureSession bob_session;

        auto init = alice_session.initiate_handshake(alice_kp);
        // Eve tampers with ephemeral public key
        init.ephemeral_public_key[0] ^= 0xFF;

        auto resp = bob_session.process_handshake_init(init, bob_kp);
        REQUIRE(resp.has_value()); // Bob can't know it's tampered yet

        // Alice receives Bob's response, but Bob's signature is over Eve's tampered key, so signature verification fails on Alice's side!
        auto comp = alice_session.process_handshake_response(*resp, alice_kp);
        REQUIRE_FALSE(comp.has_value());
        REQUIRE(alice_session.state() == SessionState::Failed);
    }

    SECTION("Attack 3: Responder signature tampering in HANDSHAKE_RESPONSE") {
        SecureSession alice_session;
        SecureSession bob_session;

        auto init = alice_session.initiate_handshake(alice_kp);
        auto resp = bob_session.process_handshake_init(init, bob_kp);
        REQUIRE(resp.has_value());

        // Attacker corrupts Bob's signature
        resp->signature[10] ^= 0x55;

        auto comp = alice_session.process_handshake_response(*resp, alice_kp);
        REQUIRE_FALSE(comp.has_value());
        REQUIRE(alice_session.state() == SessionState::Failed);
    }

    SECTION("Attack 4: Initiator signature tampering in HANDSHAKE_COMPLETE") {
        SecureSession alice_session;
        SecureSession bob_session;

        auto init = alice_session.initiate_handshake(alice_kp);
        auto resp = bob_session.process_handshake_init(init, bob_kp);
        REQUIRE(resp.has_value());

        auto comp = alice_session.process_handshake_response(*resp, alice_kp);
        REQUIRE(comp.has_value());

        // Attacker corrupts Alice's completion signature
        comp->signature[5] ^= 0xAA;

        REQUIRE_FALSE(bob_session.process_handshake_complete(*comp));
        REQUIRE(bob_session.state() == SessionState::Failed);
    }

    SECTION("Attack 5: Replay attack on encrypted data frames") {
        SecureSession alice_session;
        SecureSession bob_session;

        auto init = alice_session.initiate_handshake(alice_kp);
        auto resp = bob_session.process_handshake_init(init, bob_kp);
        auto comp = alice_session.process_handshake_response(*resp, alice_kp);
        REQUIRE(bob_session.process_handshake_complete(*comp));

        transport::Frame frame(transport::MessageType::APP_MESSAGE, RequestID::generate());
        frame.payload = Bytes{0x01, 0x02, 0x03, 0x04};
        REQUIRE(alice_session.encrypt_frame(frame));

        auto duplicate_frame = frame; // Clone wire frame

        // First frame delivery succeeds
        REQUIRE(bob_session.decrypt_frame(frame));

        // Replayed frame must be strictly rejected by ReplayCache!
        REQUIRE_FALSE(bob_session.decrypt_frame(duplicate_frame));
    }

    SECTION("Attack 6: Ciphertext bit-flipping attack on encrypted frame") {
        SecureSession alice_session;
        SecureSession bob_session;

        auto init = alice_session.initiate_handshake(alice_kp);
        auto resp = bob_session.process_handshake_init(init, bob_kp);
        auto comp = alice_session.process_handshake_response(*resp, alice_kp);
        REQUIRE(bob_session.process_handshake_complete(*comp));

        transport::Frame frame(transport::MessageType::APP_MESSAGE, RequestID::generate());
        frame.payload = Bytes{0x10, 0x20, 0x30, 0x40};
        REQUIRE(alice_session.encrypt_frame(frame));

        // Tamper with payload byte (either ciphertext or Poly1305 tag)
        frame.payload.back() ^= 0x01;

        // Decryption must fail due to AEAD Poly1305 verification failure
        REQUIRE_FALSE(bob_session.decrypt_frame(frame));
    }

    SECTION("Attack 7: Frame header tampering (AAD mismatch)") {
        SecureSession alice_session;
        SecureSession bob_session;

        auto init = alice_session.initiate_handshake(alice_kp);
        auto resp = bob_session.process_handshake_init(init, bob_kp);
        auto comp = alice_session.process_handshake_response(*resp, alice_kp);
        REQUIRE(bob_session.process_handshake_complete(*comp));

        transport::Frame frame(transport::MessageType::APP_MESSAGE, RequestID::generate());
        frame.payload = Bytes{0xAA, 0xBB, 0xCC};
        REQUIRE(alice_session.encrypt_frame(frame));

        // Attacker changes MessageType from APP_MESSAGE to PING in wire header
        frame.type = transport::MessageType::PING;

        // Decryption must fail because Frame header is bound as AAD!
        REQUIRE_FALSE(bob_session.decrypt_frame(frame));
    }
}
