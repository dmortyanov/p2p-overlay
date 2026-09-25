/// @file test_lookup.cpp
/// @brief Unit tests for LookupSession and DHT CBOR message serialization.

#include "dht/lookup_engine.hpp"
#include "dht/dht_messages.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace p2p;
using namespace p2p::dht;

namespace {

NodeID make_id(uint8_t b0, uint8_t b1 = 0) {
    NodeID id;
    id.data.fill(0);
    id.data[0] = b0;
    id.data[1] = b1;
    return id;
}

PeerInfo make_peer(uint8_t b0, uint8_t b1 = 0, uint16_t port = 9000) {
    return PeerInfo{
        .node_id = make_id(b0, b1),
        .address = PeerAddress{.host = "127.0.0.1", .port = port}
    };
}

} // namespace

TEST_CASE("DHT Messages: FindNodeRequest serialization roundtrip", "[dht][messages]") {
    FindNodeRequest req{
        .target = make_id(0xDE, 0xAD),
        .sender = make_peer(0xBE, 0xEF, 9005)
    };

    auto bytes = serialize_find_node_request(req);
    REQUIRE(!bytes.empty());

    FindNodeRequest parsed;
    REQUIRE(deserialize_find_node_request(bytes, parsed));
    REQUIRE(parsed.target == req.target);
    REQUIRE(parsed.sender.node_id == req.sender.node_id);
    REQUIRE(parsed.sender.address.host == "127.0.0.1");
    REQUIRE(parsed.sender.address.port == 9005);
}

TEST_CASE("DHT Messages: FindNodeResponse serialization roundtrip", "[dht][messages]") {
    FindNodeResponse resp;
    resp.closest_nodes.push_back(make_peer(1, 0, 9001));
    resp.closest_nodes.push_back(make_peer(2, 0, 9002));
    resp.closest_nodes.push_back(make_peer(3, 0, 9003));

    auto bytes = serialize_find_node_response(resp);
    REQUIRE(!bytes.empty());

    FindNodeResponse parsed;
    REQUIRE(deserialize_find_node_response(bytes, parsed));
    REQUIRE(parsed.closest_nodes.size() == 3);
    REQUIRE(parsed.closest_nodes[0].node_id == resp.closest_nodes[0].node_id);
    REQUIRE(parsed.closest_nodes[1].address.port == 9002);
}

TEST_CASE("LookupSession: iterative convergence with alpha=3", "[dht][lookup]") {
    NodeID local_id = make_id(0x00);
    NodeID target_id = make_id(0xFF);

    LookupSession session(target_id, local_id, /*alpha=*/3, /*k=*/4);

    // Initial candidates from local routing table
    auto seed1 = make_peer(0x10);
    auto seed2 = make_peer(0x20);
    auto seed3 = make_peer(0x30);
    auto seed4 = make_peer(0x40);

    session.add_candidates({seed1, seed2, seed3, seed4});

    // Iteration 1: picks alpha=3 candidates closest to target
    // Distances to 0xFF:
    // seed4 (0x40 ^ 0xFF = 0xBF)
    // seed3 (0x30 ^ 0xFF = 0xCF)
    // seed2 (0x20 ^ 0xFF = 0xDF)
    // seed1 (0x10 ^ 0xFF = 0xEF)
    auto queries_1 = session.pick_next_queries();
    REQUIRE(queries_1.size() == 3);
    REQUIRE(queries_1[0].node_id == seed4.node_id);
    REQUIRE(queries_1[1].node_id == seed3.node_id);
    REQUIRE(queries_1[2].node_id == seed2.node_id);

    REQUIRE_FALSE(session.is_complete());
    REQUIRE(session.in_flight_count() == 3);

    // seed4 responds with node 0x80 (closer to 0xFF!)
    auto node_80 = make_peer(0x80);
    session.on_response(seed4.node_id, {node_80});

    // seed3 responds with node 0x90
    auto node_90 = make_peer(0x90);
    session.on_response(seed3.node_id, {node_90});

    // seed2 times out / fails
    session.on_failure(seed2.node_id);

    REQUIRE(session.in_flight_count() == 0);
    REQUIRE_FALSE(session.is_complete());

    // Iteration 2: pick next unqueried candidates (0x80, 0x90, 0x10)
    auto queries_2 = session.pick_next_queries();
    REQUIRE(queries_2.size() == 3);

    // 0x90 responds with target itself (0xFF)
    auto target_peer = make_peer(0xFF);
    session.on_response(node_90.node_id, {target_peer});
    session.on_response(node_80.node_id, {});
    session.on_response(seed1.node_id, {});

    // Target responds directly
    auto queries_3 = session.pick_next_queries();
    REQUIRE(queries_3.size() == 1);
    REQUIRE(queries_3[0].node_id == target_id);
    session.on_response(target_id, {});

    // Convergence
    REQUIRE(session.is_complete());

    auto closest = session.get_closest(4);
    REQUIRE(!closest.empty());
    REQUIRE(closest[0].node_id == target_id); // Target found at rank 1!

    const auto& m = session.metrics();
    REQUIRE(m.total_rpcs == 7);
    REQUIRE(m.iterations >= 3);
    REQUIRE(m.success);
}
