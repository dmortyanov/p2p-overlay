/// @file test_node_record.cpp
/// @brief Unit and negative tests for NodeRecord (E3-1, E3-2, E3-8).

#include "dht/node_record.hpp"
#include "identity/keypair.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <chrono>

using namespace p2p;
using namespace p2p::dht;

static uint64_t get_current_time() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

TEST_CASE("E3-1: NodeRecord creation, signing, and verification", "[node_record][stage3]") {
    REQUIRE(sodium_init() >= 0);

    auto kp = identity::Keypair::generate();
    auto now = get_current_time();

    NodeRecord rec;
    rec.node_id = kp.node_id();
    rec.identity_public_key = kp.public_key();
    rec.addresses = {
        PeerAddress{.host = "127.0.0.1", .port = 9001},
        PeerAddress{.host = "192.168.1.10", .port = 9001}
    };
    rec.sequence_number = 1;
    rec.issued_at = now;
    rec.expires_at = now + 180;
    rec.alias = "test-node-1";

    SECTION("Sign and verify valid record") {
        rec.sign(kp);
        REQUIRE(rec.verify_signature());
        REQUIRE(rec.is_time_valid(now));
        REQUIRE(rec.validate(now) == RecordValidationError::None);
    }

    SECTION("Serialization roundtrip via CBOR") {
        rec.sign(kp);
        auto cbor_data = rec.to_cbor();
        REQUIRE(!cbor_data.empty());

        auto deserialized_opt = NodeRecord::from_cbor(cbor_data);
        REQUIRE(deserialized_opt.has_value());

        const auto& d = *deserialized_opt;
        REQUIRE(d.node_id == rec.node_id);
        REQUIRE(d.identity_public_key == rec.identity_public_key);
        REQUIRE(d.addresses.size() == 2);
        REQUIRE(d.addresses[0].host == "127.0.0.1");
        REQUIRE(d.addresses[0].port == 9001);
        REQUIRE(d.addresses[1].host == "192.168.1.10");
        REQUIRE(d.addresses[1].port == 9001);
        REQUIRE(d.sequence_number == 1);
        REQUIRE(d.issued_at == now);
        REQUIRE(d.expires_at == now + 180);
        REQUIRE(d.alias == "test-node-1");
        REQUIRE(d.signature == rec.signature);
        REQUIRE(d.verify_signature());
        REQUIRE(d.validate(now) == RecordValidationError::None);
    }
}

TEST_CASE("E3-2: Negative tests for NodeRecord validation errors", "[node_record][stage3][negative]") {
    REQUIRE(sodium_init() >= 0);

    auto kp = identity::Keypair::generate();
    auto now = get_current_time();

    NodeRecord rec;
    rec.node_id = kp.node_id();
    rec.identity_public_key = kp.public_key();
    rec.addresses = { PeerAddress{.host = "127.0.0.1", .port = 8000} };
    rec.sequence_number = 10;
    rec.issued_at = now;
    rec.expires_at = now + 120;
    rec.alias = "secure-node";
    rec.sign(kp);

    REQUIRE(rec.validate(now) == RecordValidationError::None);

    SECTION("Error: IdentityMismatch - node_id altered") {
        auto bad_rec = rec;
        bad_rec.node_id = identity::Keypair::generate().node_id();
        REQUIRE(bad_rec.validate(now) == RecordValidationError::IdentityMismatch);
    }

    SECTION("Error: InvalidSignature - tampered payload") {
        auto bad_rec = rec;
        bad_rec.addresses[0].port = 8001; // modified after signing
        REQUIRE(bad_rec.validate(now) == RecordValidationError::InvalidSignature);
    }

    SECTION("Error: InvalidSignature - corrupted signature bytes") {
        auto bad_rec = rec;
        bad_rec.signature[0] ^= 0xFF;
        REQUIRE(bad_rec.validate(now) == RecordValidationError::InvalidSignature);
    }

    SECTION("Error: Expired record") {
        auto expired_rec = rec;
        expired_rec.expires_at = now - 10; // expired 10s ago
        expired_rec.sign(kp);
        REQUIRE(expired_rec.validate(now) == RecordValidationError::Expired);
    }

    SECTION("Error: NotYetValid - future issued_at exceeding skew tolerance") {
        auto future_rec = rec;
        future_rec.issued_at = now + 60; // 60s in future (> 30s tolerance)
        future_rec.expires_at = now + 300;
        future_rec.sign(kp);
        REQUIRE(future_rec.validate(now) == RecordValidationError::NotYetValid);
    }

    SECTION("Error: EmptyAddresses") {
        auto empty_rec = rec;
        empty_rec.addresses.clear();
        empty_rec.sign(kp);
        REQUIRE(empty_rec.validate(now) == RecordValidationError::EmptyAddresses);
    }

    SECTION("Error: InvalidAddress - empty host") {
        auto inv_rec = rec;
        inv_rec.addresses = { PeerAddress{.host = "", .port = 9000} };
        inv_rec.sign(kp);
        REQUIRE(inv_rec.validate(now) == RecordValidationError::InvalidAddress);
    }

    SECTION("Error: InvalidAddress - port 0") {
        auto inv_rec = rec;
        inv_rec.addresses = { PeerAddress{.host = "127.0.0.1", .port = 0} };
        inv_rec.sign(kp);
        REQUIRE(inv_rec.validate(now) == RecordValidationError::InvalidAddress);
    }
}

TEST_CASE("E3-8: Alias normalization and deterministic DHT keys", "[node_record][stage3][alias]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("Alias normalization") {
        REQUIRE(normalize_alias("  AliceNode  ") == "alicenode");
        REQUIRE(normalize_alias("BOB_SERVER") == "bob_server");
        REQUIRE(normalize_alias("  \t Node-X \n ") == "node-x");
    }

    SECTION("Deterministic alias DHT key") {
        auto key1 = alias_record_key("  AliceNode  ");
        auto key2 = alias_record_key("alicenode");
        auto key3 = alias_record_key("bobnode");

        REQUIRE(key1 == key2);
        REQUIRE(key1 != key3);
        REQUIRE(!key1.is_zero());
    }

    SECTION("Deterministic node record DHT key") {
        auto id1 = identity::Keypair::generate().node_id();
        auto id2 = identity::Keypair::generate().node_id();

        auto k1 = node_record_key(id1);
        auto k1_repeat = node_record_key(id1);
        auto k2 = node_record_key(id2);

        REQUIRE(k1 == k1_repeat);
        REQUIRE(k1 != k2);
        REQUIRE(!k1.is_zero());
    }
}
