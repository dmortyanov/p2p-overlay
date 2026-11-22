/// @file test_onion_packet.cpp
/// @brief Unit tests for multi-layer Onion encryption, wrapping, and peeling (Stage 5).

#include "tunnel/onion_packet.hpp"
#include "security/crypto_utils.hpp"
#include <catch2/catch_test_macros.hpp>
#include <string>

using namespace p2p;
using namespace p2p::tunnel;

TEST_CASE("OnionPacket: Wrap and peel 3-hop circuit", "[unit][tunnel]") {
    // Generate 3 hops: R1, R2, R3
    std::vector<TunnelHop> hops(3);
    for (std::size_t i = 0; i < 3; ++i) {
        hops[i].node_id = NodeID::random();
        hops[i].address = {"192.168.1." + std::to_string(10 + i), static_cast<uint16_t>(9000 + i)};
        for (auto& b : hops[i].layer_key) b = static_cast<uint8_t>(0x10 * (i + 1));
    }

    NodeID destination = NodeID::random();
    std::string secret_msg = "Hello secure onion world via 3 hops!";
    Bytes msg_bytes(secret_msg.begin(), secret_msg.end());

    // Initiator wraps message in 3 layers
    uint64_t seq = 42;
    Bytes onion = OnionPacket::wrap(msg_bytes, hops, destination, seq);
    REQUIRE(onion.size() > msg_bytes.size());

    // ─── Relay 1 (R1) peels layer 1 ───
    auto peel1 = OnionPacket::peel(onion, hops[0].layer_key, seq);
    REQUIRE(peel1.has_value());
    CHECK_FALSE(peel1->is_terminal);
    CHECK(peel1->next_hop_node_id == hops[1].node_id);
    CHECK(peel1->next_hop_address.host == hops[1].address.host);
    CHECK(peel1->next_hop_address.port == hops[1].address.port);

    // ─── Relay 2 (R2) peels layer 2 ───
    auto peel2 = OnionPacket::peel(peel1->payload, hops[1].layer_key, seq);
    REQUIRE(peel2.has_value());
    CHECK_FALSE(peel2->is_terminal);
    CHECK(peel2->next_hop_node_id == hops[2].node_id);
    CHECK(peel2->next_hop_address.host == hops[2].address.host);

    // ─── Relay 3 (R3, Exit) peels layer 3 ───
    auto peel3 = OnionPacket::peel(peel2->payload, hops[2].layer_key, seq);
    REQUIRE(peel3.has_value());
    CHECK(peel3->is_terminal);
    CHECK(peel3->next_hop_node_id == destination);

    // Plaintext at destination matches original message
    std::string recovered(peel3->payload.begin(), peel3->payload.end());
    CHECK(recovered == secret_msg);
}

TEST_CASE("OnionPacket: Wrap and peel 5-hop circuit", "[unit][tunnel]") {
    std::vector<TunnelHop> hops(5);
    for (std::size_t i = 0; i < 5; ++i) {
        hops[i].node_id = NodeID::random();
        hops[i].address = {"10.0." + std::to_string(i) + ".1", static_cast<uint16_t>(8000 + i)};
        for (auto& b : hops[i].layer_key) b = static_cast<uint8_t>(0xA0 + i);
    }

    NodeID destination = NodeID::random();
    std::string secret = "Long 5-hop onion tunnel verified!";
    Bytes msg_bytes(secret.begin(), secret.end());

    uint64_t seq = 100;
    Bytes payload = OnionPacket::wrap(msg_bytes, hops, destination, seq);

    // Iteratively peel 4 intermediate relays
    for (std::size_t i = 0; i < 4; ++i) {
        auto peel = OnionPacket::peel(payload, hops[i].layer_key, seq);
        REQUIRE(peel.has_value());
        CHECK_FALSE(peel->is_terminal);
        CHECK(peel->next_hop_node_id == hops[i + 1].node_id);
        payload = peel->payload;
    }

    // 5th relay (exit)
    auto peel_exit = OnionPacket::peel(payload, hops[4].layer_key, seq);
    REQUIRE(peel_exit.has_value());
    CHECK(peel_exit->is_terminal);
    CHECK(peel_exit->next_hop_node_id == destination);
    CHECK(std::string(peel_exit->payload.begin(), peel_exit->payload.end()) == secret);
}

TEST_CASE("OnionPacket: Tampered layer MAC tag fails decryption", "[unit][tunnel]") {
    std::vector<TunnelHop> hops(3);
    for (std::size_t i = 0; i < 3; ++i) {
        hops[i].node_id = NodeID::random();
        hops[i].address = {"192.168.1." + std::to_string(i), 9000};
        hops[i].layer_key.fill(static_cast<uint8_t>(i + 1));
    }

    Bytes onion = OnionPacket::wrap(Bytes{1, 2, 3, 4}, hops, NodeID::random(), 1);

    // Tamper with the outermost ciphertext (bit flip)
    onion[onion.size() / 2] ^= 0xFF;

    // Peeling should fail due to Poly1305 authentication tag mismatch
    auto peel_fail = OnionPacket::peel(onion, hops[0].layer_key, 1);
    CHECK_FALSE(peel_fail.has_value());
}

TEST_CASE("OnionPacket: 1-hop circuit wrap and peel", "[unit][tunnel]") {
    std::vector<TunnelHop> hops(1);
    hops[0].node_id = NodeID::random();
    hops[0].address = {"127.0.0.1", 9001};
    hops[0].layer_key.fill(0x33);

    NodeID destination = NodeID::random();
    std::string test_msg = "Single hop message";
    Bytes msg_bytes(test_msg.begin(), test_msg.end());

    uint64_t seq = 1;
    Bytes onion = OnionPacket::wrap(msg_bytes, hops, destination, seq);
    REQUIRE(onion.size() > msg_bytes.size());

    auto peel = OnionPacket::peel(onion, hops[0].layer_key, seq);
    REQUIRE(peel.has_value());
    CHECK(peel->is_terminal);
    CHECK(peel->next_hop_node_id == destination);
    CHECK(std::string(peel->payload.begin(), peel->payload.end()) == test_msg);
}

TEST_CASE("OnionPacket: Sequence number mismatch fails decryption", "[unit][tunnel]") {
    std::vector<TunnelHop> hops(1);
    hops[0].node_id = NodeID::random();
    hops[0].address = {"127.0.0.1", 9002};
    hops[0].layer_key.fill(0x77);

    NodeID destination = NodeID::random();
    Bytes msg = {0x01, 0x02, 0x03};

    uint64_t encrypt_seq = 10;
    uint64_t wrong_seq = 11; // Mismatched sequence number
    Bytes onion = OnionPacket::wrap(msg, hops, destination, encrypt_seq);

    auto peel = OnionPacket::peel(onion, hops[0].layer_key, wrong_seq);
    CHECK_FALSE(peel.has_value());
}

TEST_CASE("OnionPacket: Peeling corrupted short buffer fails safely", "[unit][tunnel]") {
    std::array<uint8_t, 32> key{};
    key.fill(0x55);

    Bytes short_buffer = {0x01, 0x02};
    auto peel = OnionPacket::peel(short_buffer, key, 1);
    CHECK_FALSE(peel.has_value());
}


