/// @file test_lru_scenarios.cpp
/// @brief Automated tests for E2-4: LRU replacement scenarios (live vs dead contact).

#include "dht/k_bucket.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace p2p;
using namespace p2p::dht;

namespace {

NodeID make_id(uint8_t b) {
    NodeID id;
    id.data.fill(0);
    id.data[0] = b;
    return id;
}

PeerInfo make_peer(uint8_t b, uint16_t port = 9000) {
    return PeerInfo{
        .node_id = make_id(b),
        .address = PeerAddress{.host = "127.0.0.1", .port = port}
    };
}

} // namespace

TEST_CASE("E2-4 Scenario 1: Live LRU contact is preserved after PING", "[dht][lru]") {
    KBucket bucket(/*capacity=*/4, /*max_replacements=*/4);

    // Populate bucket to capacity K=4
    auto c1 = make_peer(1);
    auto c2 = make_peer(2);
    auto c3 = make_peer(3);
    auto c4 = make_peer(4);

    bucket.add_or_update(c1);
    bucket.add_or_update(c2);
    bucket.add_or_update(c3);
    bucket.add_or_update(c4);

    REQUIRE(bucket.is_full());
    REQUIRE(bucket.size() == 4);

    // The oldest contact is c1
    auto lru = bucket.least_recently_seen();
    REQUIRE(lru.has_value());
    REQUIRE(lru->node_id == c1.node_id);

    // New peer c_new arrives
    auto c_new = make_peer(5);
    bool added = bucket.add_or_update(c_new);
    REQUIRE_FALSE(added); // Cannot add directly to full bucket
    REQUIRE(bucket.replacement_count() == 1);

    // PING probe to c1 simulates a successful PONG response:
    // Contact c1 proves it is still alive -> touch(c1)
    bucket.touch(c1.node_id);

    // c1 is preserved and moved to the most recently used position
    REQUIRE(bucket.contains(c1.node_id));
    REQUIRE(bucket.size() == 4);

    // Now c2 becomes the new least recently seen contact
    auto new_lru = bucket.least_recently_seen();
    REQUIRE(new_lru.has_value());
    REQUIRE(new_lru->node_id == c2.node_id);

    // c_new was NOT promoted because c1 is alive
    REQUIRE_FALSE(bucket.contains(c_new.node_id));
    REQUIRE(bucket.replacement_count() == 1);
}

TEST_CASE("E2-4 Scenario 2: Unresponsive LRU contact is replaced by new contact", "[dht][lru]") {
    KBucket bucket(/*capacity=*/4, /*max_replacements=*/4);

    // Populate bucket to capacity K=4
    auto c1 = make_peer(1);
    auto c2 = make_peer(2);
    auto c3 = make_peer(3);
    auto c4 = make_peer(4);

    bucket.add_or_update(c1);
    bucket.add_or_update(c2);
    bucket.add_or_update(c3);
    bucket.add_or_update(c4);

    REQUIRE(bucket.is_full());

    // The oldest contact is c1
    auto lru = bucket.least_recently_seen();
    REQUIRE(lru.has_value());
    REQUIRE(lru->node_id == c1.node_id);

    // New peer c_new arrives
    auto c_new = make_peer(5);
    REQUIRE_FALSE(bucket.add_or_update(c_new));
    REQUIRE(bucket.replacement_count() == 1);

    // PING probe to c1 times out / fails -> mark_failed(c1) and evict c1
    bucket.mark_failed(c1.node_id);
    bool removed = bucket.remove(c1.node_id);
    REQUIRE(removed);

    // c1 is removed, and c_new is automatically promoted from the replacement cache
    REQUIRE_FALSE(bucket.contains(c1.node_id));
    REQUIRE(bucket.contains(c_new.node_id));
    REQUIRE(bucket.size() == 4);
    REQUIRE(bucket.replacement_count() == 0);

    // The peers are now [c2, c3, c4, c_new]
    auto peers = bucket.get_peers();
    REQUIRE(peers.size() == 4);
    REQUIRE(peers[0].node_id == c2.node_id);
    REQUIRE(peers[1].node_id == c3.node_id);
    REQUIRE(peers[2].node_id == c4.node_id);
    REQUIRE(peers[3].node_id == c_new.node_id);
}
