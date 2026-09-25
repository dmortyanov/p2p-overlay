/// @file test_routing_table.cpp
/// @brief Unit tests for RoutingTable (256 buckets, bucket indexing, find_closest with XOR metric).

#include "dht/routing_table.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace p2p;
using namespace p2p::dht;

namespace {

NodeID make_id(uint8_t byte0, uint8_t byte1 = 0) {
    NodeID id;
    id.data.fill(0);
    id.data[0] = byte0;
    id.data[1] = byte1;
    return id;
}

PeerInfo make_peer(uint8_t byte0, uint8_t byte1 = 0, uint16_t port = 9000) {
    return PeerInfo{
        .node_id = make_id(byte0, byte1),
        .address = PeerAddress{.host = "127.0.0.1", .port = port}
    };
}

} // namespace

TEST_CASE("RoutingTable: bucket index mapping", "[dht][routing_table]") {
    NodeID local = make_id(0x00);
    RoutingTable rt(local, 4);

    REQUIRE(rt.local_id() == local);
    REQUIRE(rt.total_contacts() == 0);

    // Difference in bit 7 of byte 0: index 255
    NodeID id_255 = make_id(0x80);
    REQUIRE(rt.get_bucket_index(id_255) == 255);

    // Difference in bit 0 of byte 0: index 248
    NodeID id_248 = make_id(0x01);
    REQUIRE(rt.get_bucket_index(id_248) == 248);

    // Difference in byte 1 (bit 7): index 247
    NodeID id_247 = make_id(0x00, 0x80);
    REQUIRE(rt.get_bucket_index(id_247) == 247);

    // Same ID as local -> -1
    REQUIRE(rt.get_bucket_index(local) == -1);
}

TEST_CASE("RoutingTable: self cannot be added", "[dht][routing_table]") {
    NodeID local = make_id(0xAA);
    RoutingTable rt(local, 4);

    PeerInfo self_peer{.node_id = local, .address = {.host = "127.0.0.1", .port = 9000}};
    REQUIRE_FALSE(rt.add_or_update(self_peer));
    REQUIRE(rt.total_contacts() == 0);
}

TEST_CASE("RoutingTable: find_closest ordering by XOR distance", "[dht][routing_table]") {
    NodeID local = make_id(0x00);
    RoutingTable rt(local, 4);

    // Add several peers at different distances
    auto p10 = make_peer(0x10);
    auto p20 = make_peer(0x20);
    auto p30 = make_peer(0x30);
    auto p40 = make_peer(0x40);
    auto p50 = make_peer(0x50);

    rt.add_or_update(p10);
    rt.add_or_update(p20);
    rt.add_or_update(p30);
    rt.add_or_update(p40);
    rt.add_or_update(p50);

    REQUIRE(rt.total_contacts() == 5);

    // Target is close to 0x22
    NodeID target = make_id(0x22);
    // XOR distances from target 0x22:
    // p20 (0x20 ^ 0x22 = 0x02) - closest!
    // p30 (0x30 ^ 0x22 = 0x12)
    // p10 (0x10 ^ 0x22 = 0x32)
    // p40 (0x40 ^ 0x22 = 0x62)
    // p50 (0x50 ^ 0x22 = 0x72)

    auto closest = rt.find_closest(target, 3);
    REQUIRE(closest.size() == 3);
    REQUIRE(closest[0].node_id == p20.node_id);
    REQUIRE(closest[1].node_id == p30.node_id);
    REQUIRE(closest[2].node_id == p10.node_id);
}

TEST_CASE("RoutingTable: bucket distribution", "[dht][routing_table]") {
    NodeID local = make_id(0x00);
    RoutingTable rt(local, 4);

    rt.add_or_update(make_peer(0x80)); // bucket 255
    rt.add_or_update(make_peer(0x40)); // bucket 254

    auto dist = rt.bucket_distribution();
    REQUIRE(dist.size() == 256);
    REQUIRE(dist[255] == 1);
    REQUIRE(dist[254] == 1);
    REQUIRE(dist[0] == 0);
}
