/// @file test_node_id.cpp
/// @brief Unit tests for NodeID computation, XOR metric, and key derivation.

#include <catch2/catch_test_macros.hpp>

#include "identity/node_id.hpp"
#include "identity/keypair.hpp"
#include "common/types.hpp"

#include <sodium.h>
#include <algorithm>
#include <vector>

using namespace p2p;
using namespace p2p::identity;

static struct SodiumInit {
    SodiumInit() { sodium_init(); }
} sodium_init_guard;

// ═══════════════════════════════════════════════════════════════════
//  NodeID computation from public key
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("NodeID is SHA-256 of public key", "[identity]") {
    auto kp = Keypair::generate();
    auto node_id = kp.node_id();

    // Manually compute SHA-256 of the public key
    auto expected = sha256(kp.public_key().data(), kp.public_key().size());

    CHECK(node_id.data == expected);
}

TEST_CASE("Same public key always produces same NodeID", "[identity]") {
    auto kp = Keypair::generate();
    auto id1 = compute_node_id(kp.public_key());
    auto id2 = compute_node_id(kp.public_key());

    CHECK(id1 == id2);
}

TEST_CASE("Different keys produce different NodeIDs", "[identity]") {
    auto kp1 = Keypair::generate();
    auto kp2 = Keypair::generate();

    CHECK(kp1.node_id() != kp2.node_id());
}

// ═══════════════════════════════════════════════════════════════════
//  NodeID verification
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("verify_node_id accepts correct ID", "[identity]") {
    auto kp = Keypair::generate();
    CHECK(verify_node_id(kp.node_id(), kp.public_key()));
}

TEST_CASE("verify_node_id rejects wrong ID", "[identity]") {
    auto kp = Keypair::generate();
    NodeID wrong_id;
    wrong_id.data.fill(0xFF);

    CHECK_FALSE(verify_node_id(wrong_id, kp.public_key()));
}

TEST_CASE("verify_node_id rejects wrong public key", "[identity]") {
    auto kp1 = Keypair::generate();
    auto kp2 = Keypair::generate();

    // kp1's NodeID with kp2's public key should fail
    CHECK_FALSE(verify_node_id(kp1.node_id(), kp2.public_key()));
}

// ═══════════════════════════════════════════════════════════════════
//  XOR metric
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("XOR distance is symmetric", "[xor]") {
    auto kp1 = Keypair::generate();
    auto kp2 = Keypair::generate();

    auto d12 = xor_distance(kp1.node_id(), kp2.node_id());
    auto d21 = xor_distance(kp2.node_id(), kp1.node_id());

    CHECK(d12 == d21);
}

TEST_CASE("XOR distance to self is zero", "[xor]") {
    auto kp = Keypair::generate();
    auto dist = xor_distance(kp.node_id(), kp.node_id());

    CHECK(dist.is_zero());
}

TEST_CASE("XOR distance to different node is non-zero", "[xor]") {
    auto kp1 = Keypair::generate();
    auto kp2 = Keypair::generate();

    auto dist = xor_distance(kp1.node_id(), kp2.node_id());

    CHECK_FALSE(dist.is_zero());
}

TEST_CASE("XOR triangle inequality", "[xor]") {
    // d(a,c) <= d(a,b) XOR d(b,c) is always true for XOR metric
    // But more importantly, XOR is a proper ultrametric:
    // d(a,c) <= max(d(a,b), d(b,c))
    auto kp1 = Keypair::generate();
    auto kp2 = Keypair::generate();
    auto kp3 = Keypair::generate();

    auto dab = xor_distance(kp1.node_id(), kp2.node_id());
    auto dbc = xor_distance(kp2.node_id(), kp3.node_id());
    auto dac = xor_distance(kp1.node_id(), kp3.node_id());

    // In XOR metric, d(a,c) <= d(a,b) + d(b,c) is trivially satisfied
    // since XOR never "adds up" — it's actually an ultrametric
    auto max_dist = (dab > dbc) ? dab : dbc;
    CHECK(dac <= max_dist);
}

// ═══════════════════════════════════════════════════════════════════
//  Bucket index
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Bucket index for equal IDs is -1", "[xor]") {
    auto kp = Keypair::generate();
    CHECK(kp.node_id().bucket_index(kp.node_id()) == -1);
}

TEST_CASE("Bucket index range is 0..255", "[xor]") {
    // Generate many pairs and check bucket_index is in [0, 255]
    for (int i = 0; i < 100; ++i) {
        auto kp1 = Keypair::generate();
        auto kp2 = Keypair::generate();
        auto idx = kp1.node_id().bucket_index(kp2.node_id());
        CHECK(idx >= 0);
        CHECK(idx <= 255);
    }
}

TEST_CASE("Bucket index for IDs differing only in last bit", "[xor]") {
    NodeID a{};
    a.data.fill(0);

    NodeID b = a;
    b.data[31] = 0x01; // differ in last bit

    CHECK(a.bucket_index(b) == 0);
}

TEST_CASE("Bucket index for IDs differing in first bit", "[xor]") {
    NodeID a{};
    a.data.fill(0);

    NodeID b = a;
    b.data[0] = 0x80; // differ in first bit

    CHECK(a.bucket_index(b) == 255);
}

// ═══════════════════════════════════════════════════════════════════
//  Sort by distance
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("sort_by_distance orders peers correctly", "[xor]") {
    auto target_kp = Keypair::generate();
    auto target = target_kp.node_id();

    std::vector<PeerInfo> peers;
    for (int i = 0; i < 20; ++i) {
        auto kp = Keypair::generate();
        peers.push_back({kp.node_id(), {"127.0.0.1", static_cast<uint16_t>(9000 + i)}});
    }

    sort_by_distance(peers, target);

    // Verify ordering
    for (std::size_t i = 1; i < peers.size(); ++i) {
        auto dist_prev = xor_distance(target, peers[i - 1].node_id);
        auto dist_curr = xor_distance(target, peers[i].node_id);
        CHECK(dist_prev <= dist_curr);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  NodeID hex conversion
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("NodeID to/from hex round-trip", "[identity]") {
    auto kp = Keypair::generate();
    auto id = kp.node_id();

    auto hex = id.to_hex();
    CHECK(hex.size() == 64);

    NodeID parsed;
    REQUIRE(NodeID::from_hex(hex, parsed));
    CHECK(parsed == id);
}

TEST_CASE("NodeID from_hex rejects invalid input", "[identity]") {
    NodeID out;
    CHECK_FALSE(NodeID::from_hex("", out));
    CHECK_FALSE(NodeID::from_hex("abcdef", out));
    CHECK_FALSE(NodeID::from_hex(std::string(64, 'g'), out)); // invalid hex char
}

TEST_CASE("NodeID short_hex is prefix of full hex", "[identity]") {
    auto kp = Keypair::generate();
    auto id = kp.node_id();

    auto full = id.to_hex();
    auto short_hex = id.to_short_hex();

    CHECK(short_hex.size() == 8);
    CHECK(full.substr(0, 8) == short_hex);
}

// ═══════════════════════════════════════════════════════════════════
//  DHT key derivation
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Record key is deterministic", "[dht_key]") {
    auto kp = Keypair::generate();
    auto key1 = compute_record_key(kp.node_id());
    auto key2 = compute_record_key(kp.node_id());
    CHECK(key1 == key2);
}

TEST_CASE("Alias key is case-insensitive", "[dht_key]") {
    auto key1 = compute_alias_key("Alice");
    auto key2 = compute_alias_key("alice");
    auto key3 = compute_alias_key("ALICE");
    CHECK(key1 == key2);
    CHECK(key2 == key3);
}

TEST_CASE("Alias key trims whitespace", "[dht_key]") {
    auto key1 = compute_alias_key("  bob  ");
    auto key2 = compute_alias_key("bob");
    CHECK(key1 == key2);
}

TEST_CASE("Different aliases produce different keys", "[dht_key]") {
    auto key1 = compute_alias_key("alice");
    auto key2 = compute_alias_key("bob");
    CHECK(key1 != key2);
}

// ═══════════════════════════════════════════════════════════════════
//  Keypair sign/verify
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Sign and verify message", "[identity]") {
    auto kp = Keypair::generate();
    Bytes message = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto sig = kp.sign(message);
    CHECK(Keypair::verify(sig, message.data(), message.size(), kp.public_key()));
}

TEST_CASE("Verify rejects tampered message", "[identity]") {
    auto kp = Keypair::generate();
    Bytes message = {0x01, 0x02, 0x03};

    auto sig = kp.sign(message);

    Bytes tampered = {0x01, 0x02, 0x04}; // changed last byte
    CHECK_FALSE(Keypair::verify(sig, tampered.data(), tampered.size(), kp.public_key()));
}

TEST_CASE("Verify rejects wrong public key", "[identity]") {
    auto kp1 = Keypair::generate();
    auto kp2 = Keypair::generate();
    Bytes message = {0x01, 0x02, 0x03};

    auto sig = kp1.sign(message);
    CHECK_FALSE(Keypair::verify(sig, message.data(), message.size(), kp2.public_key()));
}

// ═══════════════════════════════════════════════════════════════════
//  Keypair persistence
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Keypair save and load round-trip", "[identity]") {
    auto temp_dir = std::filesystem::temp_directory_path() / "p2p_test_keys";
    std::filesystem::remove_all(temp_dir);

    auto kp1 = Keypair::generate();
    auto id1 = kp1.node_id();

    kp1.save(temp_dir);

    auto kp2 = Keypair::load(temp_dir);
    REQUIRE(kp2.has_value());
    CHECK(kp2->node_id() == id1);

    // Sign with loaded key, verify with original public key
    Bytes msg = {0xAA, 0xBB};
    auto sig = kp2->sign(msg);
    CHECK(Keypair::verify(sig, msg.data(), msg.size(), kp1.public_key()));

    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("load_or_generate creates new on first call", "[identity]") {
    auto temp_dir = std::filesystem::temp_directory_path() / "p2p_test_keys_gen";
    std::filesystem::remove_all(temp_dir);

    auto kp1 = Keypair::load_or_generate(temp_dir);
    auto kp2 = Keypair::load_or_generate(temp_dir);

    CHECK(kp1.node_id() == kp2.node_id());

    std::filesystem::remove_all(temp_dir);
}
