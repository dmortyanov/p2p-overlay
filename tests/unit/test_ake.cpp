/// @file test_ake.cpp
/// @brief Unit tests for Stage 4: X25519, HKDF-SHA256, ChaCha20-Poly1305, ReplayCache, and SecureSession.

#include "security/crypto_utils.hpp"
#include "security/ake_messages.hpp"
#include "security/replay_cache.hpp"
#include "security/secure_session.hpp"
#include "identity/keypair.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <cstring>

using namespace p2p;
using namespace p2p::security;

TEST_CASE("E4-1: X25519 Diffie-Hellman Key Exchange", "[security][ake][stage4]") {
    REQUIRE(sodium_init() >= 0);

    auto kp_a = X25519Keypair::generate();
    auto kp_b = X25519Keypair::generate();

    REQUIRE(kp_a.public_key != kp_b.public_key);
    REQUIRE(kp_a.secret_key != kp_b.secret_key);

    auto ss_a = x25519_diffie_hellman(kp_a.secret_key, kp_b.public_key);
    auto ss_b = x25519_diffie_hellman(kp_b.secret_key, kp_a.public_key);

    REQUIRE(ss_a.has_value());
    REQUIRE(ss_b.has_value());
    REQUIRE(*ss_a == *ss_b);

    // Rejection of all-zero weak public key
    std::array<uint8_t, 32> zero_pk{};
    auto ss_weak = x25519_diffie_hellman(kp_a.secret_key, zero_pk);
    REQUIRE(!ss_weak.has_value());
}

TEST_CASE("E4-1: HKDF-SHA256 RFC 5869 compliance and session key derivation", "[security][hkdf][stage4]") {
    REQUIRE(sodium_init() >= 0);

    // RFC 5869 Test Case 1
    // IKM = 0x0b0b0b... (22 bytes)
    Bytes ikm(22, 0x0b);
    // Salt = 0x000102... (13 bytes)
    Bytes salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    // Info = 0xf0f1f2... (10 bytes)
    std::string info;
    info.push_back('\xf0'); info.push_back('\xf1'); info.push_back('\xf2'); info.push_back('\xf3');
    info.push_back('\xf4'); info.push_back('\xf5'); info.push_back('\xf6'); info.push_back('\xf7');
    info.push_back('\xf8'); info.push_back('\xf9');

    auto prk = hkdf_extract(salt.data(), salt.size(), ikm.data(), ikm.size());
    // Expected PRK from RFC 5869 Test Case 1:
    // 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    const std::string expected_prk_hex = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    std::string actual_prk_hex;
    for (uint8_t b : prk) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        actual_prk_hex += buf;
    }
    REQUIRE(actual_prk_hex == expected_prk_hex);

    auto okm = hkdf_expand(prk, info, 42);
    REQUIRE(okm.size() == 42);
    // First byte of expected OKM: 0x3c, second: 0xb2, third: 0x5f
    REQUIRE(okm[0] == 0x3c);
    REQUIRE(okm[1] == 0xb2);
    REQUIRE(okm[2] == 0x5f);

    SECTION("Directional session key derivation") {
        std::array<uint8_t, 32> shared_secret{};
        shared_secret.fill(0xAA);
        auto nonce_a = generate_nonce();
        auto nonce_b = generate_nonce();

        auto keys = derive_session_keys(shared_secret, nonce_a, nonce_b);
        REQUIRE(keys.key_a_to_b != keys.key_b_to_a);

        // Same inputs must yield deterministic keys
        auto keys2 = derive_session_keys(shared_secret, nonce_a, nonce_b);
        REQUIRE(keys.key_a_to_b == keys2.key_a_to_b);
        REQUIRE(keys.key_b_to_a == keys2.key_b_to_a);
    }
}

TEST_CASE("E4-4: ChaCha20-Poly1305 AEAD encryption and tampering detection", "[security][aead][stage4]") {
    REQUIRE(sodium_init() >= 0);

    std::array<uint8_t, 32> key{};
    randombytes_buf(key.data(), key.size());

    uint64_t seq = 42;
    auto nonce = construct_aead_nonce(seq);

    std::string plaintext_str = "Decentralized P2P Overlay Secret Message";
    Bytes plaintext(plaintext_str.begin(), plaintext_str.end());

    std::string aad_str = "HeaderAAD_Version1";
    Bytes aad(aad_str.begin(), aad_str.end());

    auto ciphertext = chacha20_poly1305_encrypt(
        plaintext.data(), plaintext.size(),
        aad.data(), aad.size(),
        nonce, key
    );

    REQUIRE(ciphertext.size() == plaintext.size() + AEAD_TAG_SIZE);

    SECTION("Successful decryption") {
        auto decrypted = chacha20_poly1305_decrypt(
            ciphertext.data(), ciphertext.size(),
            aad.data(), aad.size(),
            nonce, key
        );
        REQUIRE(decrypted.has_value());
        REQUIRE(*decrypted == plaintext);
    }

    SECTION("Tampered ciphertext rejected") {
        auto tampered = ciphertext;
        tampered[5] ^= 0xFF; // Flip a bit in ciphertext

        auto decrypted = chacha20_poly1305_decrypt(
            tampered.data(), tampered.size(),
            aad.data(), aad.size(),
            nonce, key
        );
        REQUIRE(!decrypted.has_value());
    }

    SECTION("Tampered AAD rejected") {
        Bytes wrong_aad = aad;
        wrong_aad[0] ^= 0x01;

        auto decrypted = chacha20_poly1305_decrypt(
            ciphertext.data(), ciphertext.size(),
            wrong_aad.data(), wrong_aad.size(),
            nonce, key
        );
        REQUIRE(!decrypted.has_value());
    }

    SECTION("Wrong nonce rejected") {
        auto wrong_nonce = construct_aead_nonce(seq + 1);

        auto decrypted = chacha20_poly1305_decrypt(
            ciphertext.data(), ciphertext.size(),
            aad.data(), aad.size(),
            wrong_nonce, key
        );
        REQUIRE(!decrypted.has_value());
    }
}

TEST_CASE("E4-5: ReplayCache sliding window and anti-replay protection", "[security][replay][stage4]") {
    ReplayCache cache(128);

    REQUIRE(cache.update_and_check(1));
    REQUIRE(cache.highest_seq() == 1);

    // Duplicate must be rejected
    REQUIRE_FALSE(cache.update_and_check(1));

    // Sequential packets accepted
    REQUIRE(cache.update_and_check(2));
    REQUIRE(cache.update_and_check(3));
    REQUIRE_FALSE(cache.update_and_check(2));
    REQUIRE_FALSE(cache.update_and_check(3));

    // Out-of-order packets within sliding window accepted once
    REQUIRE(cache.update_and_check(10));
    REQUIRE(cache.highest_seq() == 10);
    REQUIRE(cache.update_and_check(7));  // within window [10-128, 10]
    REQUIRE(cache.update_and_check(8));
    REQUIRE_FALSE(cache.update_and_check(7)); // duplicate rejected!
    REQUIRE_FALSE(cache.update_and_check(8)); // duplicate rejected!

    // Shift window significantly forward
    REQUIRE(cache.update_and_check(200));
    REQUIRE(cache.highest_seq() == 200);

    // Packet 10 is now older than window (200 - 10 = 190 >= 128) -> must be rejected
    REQUIRE_FALSE(cache.update_and_check(10));
    REQUIRE_FALSE(cache.update_and_check(50));

    // Packet 150 is within window (200 - 150 = 50 < 128) -> accepted once
    REQUIRE(cache.update_and_check(150));
    REQUIRE_FALSE(cache.update_and_check(150));
}

TEST_CASE("E4-6: SecureSession full end-to-end AKE and frame encryption", "[security][session][stage4]") {
    REQUIRE(sodium_init() >= 0);

    auto alice_kp = identity::Keypair::generate();
    auto bob_kp = identity::Keypair::generate();

    SecureSession alice_session;
    SecureSession bob_session;

    REQUIRE(alice_session.state() == SessionState::Uninitialized);
    REQUIRE(bob_session.state() == SessionState::Uninitialized);

    // Step 1: Alice generates HANDSHAKE_INIT
    auto init_msg = alice_session.initiate_handshake(alice_kp);
    REQUIRE(alice_session.state() == SessionState::HandshakeInitSent);
    REQUIRE(alice_session.role() == SessionRole::Initiator);

    // Test CBOR round-trip of HANDSHAKE_INIT
    auto init_cbor = serialize_handshake_init(init_msg);
    HandshakeInit parsed_init;
    REQUIRE(deserialize_handshake_init(init_cbor, parsed_init));
    REQUIRE(parsed_init.node_id == alice_kp.node_id());

    // Step 2: Bob processes HANDSHAKE_INIT and produces HANDSHAKE_RESPONSE
    auto resp_opt = bob_session.process_handshake_init(parsed_init, bob_kp);
    REQUIRE(resp_opt.has_value());
    REQUIRE(bob_session.state() == SessionState::HandshakeRespSent);
    REQUIRE(bob_session.role() == SessionRole::Responder);

    // Test CBOR round-trip of HANDSHAKE_RESPONSE
    auto resp_cbor = serialize_handshake_response(*resp_opt);
    HandshakeResponse parsed_resp;
    REQUIRE(deserialize_handshake_response(resp_cbor, parsed_resp));
    REQUIRE(parsed_resp.node_id == bob_kp.node_id());

    // Step 3: Alice processes HANDSHAKE_RESPONSE and produces HANDSHAKE_COMPLETE
    auto comp_opt = alice_session.process_handshake_response(parsed_resp, alice_kp);
    REQUIRE(comp_opt.has_value());
    REQUIRE(alice_session.is_active());
    REQUIRE(alice_session.peer_node_id() == bob_kp.node_id());

    // Test CBOR round-trip of HANDSHAKE_COMPLETE
    auto comp_cbor = serialize_handshake_complete(*comp_opt);
    HandshakeComplete parsed_comp;
    REQUIRE(deserialize_handshake_complete(comp_cbor, parsed_comp));

    // Step 4: Bob processes HANDSHAKE_COMPLETE
    REQUIRE(bob_session.process_handshake_complete(parsed_comp));
    REQUIRE(bob_session.is_active());
    REQUIRE(bob_session.peer_node_id() == alice_kp.node_id());

    // Both sessions are now ACTIVE and share the same session ID
    REQUIRE(alice_session.session_id() == bob_session.session_id());

    SECTION("Bidirectional encrypted frame exchange") {
        // Alice -> Bob frame
        auto rid1 = RequestID::generate();
        transport::Frame frame_a(transport::MessageType::APP_MESSAGE, rid1);
        std::string payload_a = "Secret payload from Alice to Bob";
        frame_a.payload = Bytes(payload_a.begin(), payload_a.end());

        REQUIRE(alice_session.encrypt_frame(frame_a));
        REQUIRE((frame_a.flags & transport::FrameFlags::IS_ENCRYPTED));
        REQUIRE(frame_a.payload != Bytes(payload_a.begin(), payload_a.end()));

        REQUIRE(bob_session.decrypt_frame(frame_a));
        REQUIRE_FALSE((frame_a.flags & transport::FrameFlags::IS_ENCRYPTED));
        REQUIRE(std::string(frame_a.payload.begin(), frame_a.payload.end()) == payload_a);

        // Bob -> Alice frame
        auto rid2 = RequestID::generate();
        transport::Frame frame_b(transport::MessageType::APP_ACK, rid2);
        std::string payload_b = "Secret ACK response from Bob to Alice";
        frame_b.payload = Bytes(payload_b.begin(), payload_b.end());

        REQUIRE(bob_session.encrypt_frame(frame_b));
        REQUIRE((frame_b.flags & transport::FrameFlags::IS_ENCRYPTED));

        REQUIRE(alice_session.decrypt_frame(frame_b));
        REQUIRE_FALSE((frame_b.flags & transport::FrameFlags::IS_ENCRYPTED));
        REQUIRE(std::string(frame_b.payload.begin(), frame_b.payload.end()) == payload_b);
    }
}
