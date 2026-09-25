/// @file test_negative_identity.cpp
/// @brief Negative tests for identity verification (E2-2).
///
/// Verifies that any peer presenting mismatched public keys, spoofed NodeIDs,
/// or tampered signatures is strictly rejected.

#include "identity/keypair.hpp"
#include "identity/node_id.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace p2p;
using namespace p2p::identity;

TEST_CASE("E2-2 Negative: Mismatched public key and NodeID must be rejected", "[negative][identity]") {
    // Generate two legitimate keypairs
    auto kp_alice = Keypair::generate();
    auto kp_mallory = Keypair::generate();

    NodeID alice_id = kp_alice.node_id();
    NodeID mallory_id = kp_mallory.node_id();

    REQUIRE(alice_id != mallory_id);

    // Legitimate verification succeeds
    REQUIRE(verify_node_id(alice_id, kp_alice.public_key()));
    REQUIRE(verify_node_id(mallory_id, kp_mallory.public_key()));

    // Mallory claims to be Alice by presenting Alice's NodeID with Mallory's public key -> MUST FAIL
    SECTION("Claimed NodeID belongs to victim, but public key is attacker's") {
        bool verified = verify_node_id(alice_id, kp_mallory.public_key());
        REQUIRE_FALSE(verified);
    }

    // Mallory presents her own NodeID with Alice's public key -> MUST FAIL
    SECTION("Claimed NodeID is attacker's, but public key is victim's") {
        bool verified = verify_node_id(mallory_id, kp_alice.public_key());
        REQUIRE_FALSE(verified);
    }

    // Tampered single bit in public key -> MUST FAIL
    SECTION("Single bit flipped in public key") {
        auto tampered_pk = kp_alice.public_key();
        tampered_pk[0] ^= 0x01;
        bool verified = verify_node_id(alice_id, tampered_pk);
        REQUIRE_FALSE(verified);
    }

    // Tampered single bit in NodeID -> MUST FAIL
    SECTION("Single bit flipped in NodeID") {
        auto tampered_id = alice_id;
        tampered_id.data[0] ^= 0x01;
        bool verified = verify_node_id(tampered_id, kp_alice.public_key());
        REQUIRE_FALSE(verified);
    }
}

TEST_CASE("E2-2 Negative: Signature tampering must be rejected", "[negative][identity]") {
    auto kp = Keypair::generate();
    std::string message = "FIND_NODE_REQUEST payload";
    auto sig = kp.sign(message);

    // Valid signature verifies
    REQUIRE(kp.verify(message, sig));

    // Tampered message fails
    SECTION("Modified payload fails verification") {
        std::string tampered_message = "FIND_NODE_REQUEST tampered";
        REQUIRE_FALSE(kp.verify(tampered_message, sig));
    }

    // Tampered signature byte fails
    SECTION("Corrupted signature fails verification") {
        auto tampered_sig = sig;
        tampered_sig[0] ^= 0x55;
        REQUIRE_FALSE(kp.verify(message, tampered_sig));
    }

    // Verification with another keypair's public key fails
    SECTION("Verification with another public key fails") {
        auto other_kp = Keypair::generate();
        REQUIRE_FALSE(other_kp.verify(message, sig));
    }
}
