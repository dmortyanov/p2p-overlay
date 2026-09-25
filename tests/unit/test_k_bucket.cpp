/// @file test_k_bucket.cpp
/// @brief Unit tests for KBucket (capacity, LRU ordering, replacement cache).

#include "dht/k_bucket.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace p2p;
using namespace p2p::dht;

namespace {

NodeID make_test_node_id(uint8_t first_byte) {
    NodeID id;
    id.data.fill(0);
    id.data[0] = first_byte;
    return id;
}

PeerInfo make_test_peer(uint8_t byte, uint16_t port = 9000) {
    return PeerInfo{
        .node_id = make_test_node_id(byte),
        .address = PeerAddress{.host = "127.0.0.1", .port = port}
    };
}

} // namespace

TEST_CASE("KBucket: capacity limit and additions", "[dht][k_bucket]") {
    KBucket bucket(/*capacity=*/4, /*max_replacements=*/4);
    REQUIRE(bucket.size() == 0);
    REQUIRE_FALSE(bucket.is_full());
    REQUIRE(bucket.capacity() == 4);

    // Add 4 peers
    for (uint8_t i = 1; i <= 4; ++i) {
        REQUIRE(bucket.add_or_update(make_test_peer(i)));
        REQUIRE(bucket.size() == i);
    }

    REQUIRE(bucket.is_full());

    // 5th peer should not enter main bucket, but goes to replacement cache
    auto peer5 = make_test_peer(5);
    REQUIRE_FALSE(bucket.add_or_update(peer5));
    REQUIRE(bucket.size() == 4);
    REQUIRE(bucket.replacement_count() == 1);
}

TEST_CASE("KBucket: LRU ordering and touch", "[dht][k_bucket]") {
    KBucket bucket(4, 4);

    auto p1 = make_test_peer(1);
    auto p2 = make_test_peer(2);
    auto p3 = make_test_peer(3);

    bucket.add_or_update(p1);
    bucket.add_or_update(p2);
    bucket.add_or_update(p3);

    // Initial order: p1 (oldest), p2, p3 (newest)
    REQUIRE(bucket.least_recently_seen()->node_id == p1.node_id);

    // Re-adding or updating p1 should move it to the tail (newest)
    bucket.add_or_update(p1);
    auto peers = bucket.get_peers();
    REQUIRE(peers.size() == 3);
    REQUIRE(peers[0].node_id == p2.node_id);
    REQUIRE(peers[1].node_id == p3.node_id);
    REQUIRE(peers[2].node_id == p1.node_id);

    // Now p2 should be the least recently seen
    REQUIRE(bucket.least_recently_seen()->node_id == p2.node_id);
}

TEST_CASE("KBucket: removal and replacement promotion", "[dht][k_bucket]") {
    KBucket bucket(3, 4);

    auto p1 = make_test_peer(1);
    auto p2 = make_test_peer(2);
    auto p3 = make_test_peer(3);
    auto p4 = make_test_peer(4); // replacement candidate

    bucket.add_or_update(p1);
    bucket.add_or_update(p2);
    bucket.add_or_update(p3);
    bucket.add_or_update(p4); // goes to replacement

    REQUIRE(bucket.size() == 3);
    REQUIRE(bucket.replacement_count() == 1);

    // Remove p2: p4 should be promoted from replacement cache
    REQUIRE(bucket.remove(p2.node_id));
    REQUIRE(bucket.size() == 3);
    REQUIRE(bucket.replacement_count() == 0);
    REQUIRE_FALSE(bucket.contains(p2.node_id));
    REQUIRE(bucket.contains(p4.node_id));

    // Remove remaining peers
    REQUIRE(bucket.remove(p1.node_id));
    REQUIRE(bucket.size() == 2);
    REQUIRE(bucket.remove(p3.node_id));
    REQUIRE(bucket.size() == 1);
    REQUIRE(bucket.remove(p4.node_id));
    REQUIRE(bucket.size() == 0);
}
