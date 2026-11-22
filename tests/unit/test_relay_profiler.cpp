/// @file test_relay_profiler.cpp
/// @brief Unit tests for RelayProfiler EMA calculations, subnet diversity, and hop selection (Stage 5).

#include "tunnel/relay_profiler.hpp"
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

using namespace p2p;
using namespace p2p::tunnel;

TEST_CASE("RelayProfiler: EMA Latency and Success Rate tracking", "[unit][tunnel]") {
    RelayProfiler profiler(0.2, 0.3);
    NodeID node_a = NodeID::random();
    profiler.register_relay(node_a, {"192.168.1.10", 9000});

    // Record latency updates
    // Initial latency is 50.0 ms.
    // 1st update: (1 - 0.2)*50 + 0.2*100 = 40 + 20 = 60.0
    profiler.record_latency(node_a, 100.0);
    auto p1 = profiler.get_profile(node_a);
    REQUIRE(p1.has_value());
    CHECK(p1->ema_latency_ms == Catch::Approx(60.0));

    // 2nd update: (1 - 0.2)*60 + 0.2*20 = 48 + 4 = 52.0
    profiler.record_latency(node_a, 20.0);
    auto p2 = profiler.get_profile(node_a);
    CHECK(p2->ema_latency_ms == Catch::Approx(52.0));

    // Record success / failure results
    // Initial success rate is 1.0.
    // Failure (0.0): (1 - 0.3)*1.0 + 0.3*0.0 = 0.7
    profiler.record_result(node_a, false);
    auto p3 = profiler.get_profile(node_a);
    CHECK(p3->ema_success_rate == Catch::Approx(0.7));
    CHECK(p3->consecutive_failures == 1);

    // Success (1.0): (1 - 0.3)*0.7 + 0.3*1.0 = 0.49 + 0.3 = 0.79
    profiler.record_result(node_a, true);
    auto p4 = profiler.get_profile(node_a);
    CHECK(p4->ema_success_rate == Catch::Approx(0.79));
    CHECK(p4->consecutive_failures == 0);
}

TEST_CASE("RelayProfiler: IPv4 /24 Subnet diversity filtering", "[unit][tunnel]") {
    CHECK(RelayProfiler::extract_subnet_24("192.168.1.50") == "192.168.1");
    CHECK(RelayProfiler::extract_subnet_24("10.20.30.40") == "10.20.30");

    std::vector<PeerAddress> existing = {
        {"192.168.1.10", 9000},
        {"10.0.1.5", 9001}
    };

    // Same subnet 192.168.1.x -> should be rejected for non-loopback
    CHECK_FALSE(RelayProfiler::is_subnet_diverse({"192.168.1.99", 9002}, existing));

    // Different subnet 192.168.2.x -> should be accepted
    CHECK(RelayProfiler::is_subnet_diverse({"192.168.2.10", 9000}, existing));

    // Different class A / B subnet -> should be accepted
    CHECK(RelayProfiler::is_subnet_diverse({"172.16.0.1", 9000}, existing));
}

TEST_CASE("RelayProfiler: Hop selection with exclusion and scoring", "[unit][tunnel]") {
    RelayProfiler profiler(0.2, 0.3);

    std::vector<PeerInfo> candidates;
    for (int i = 0; i < 5; ++i) {
        PeerInfo p;
        p.node_id = NodeID::random();
        p.address = {"10.0." + std::to_string(i) + ".1", static_cast<uint16_t>(9000 + i)};
        profiler.register_relay(p.node_id, p.address);
        candidates.push_back(p);
    }

    // Give node 0 low latency and high reliability
    profiler.record_latency(candidates[0].node_id, 10.0);
    profiler.record_result(candidates[0].node_id, true);

    // Give node 1 3 consecutive failures -> should be skipped
    profiler.record_result(candidates[1].node_id, false);
    profiler.record_result(candidates[1].node_id, false);
    profiler.record_result(candidates[1].node_id, false);

    // Exclude node 4
    std::vector<NodeID> excluded = {candidates[4].node_id};

    auto selected = profiler.select_hops(candidates, 3, excluded);
    REQUIRE(selected.size() == 3);

    // Best node (candidates[0]) must be selected first
    CHECK(selected[0].node_id == candidates[0].node_id);

    // Failed node (candidates[1]) and excluded node (candidates[4]) must NOT be in selected
    for (const auto& s : selected) {
        CHECK(s.node_id != candidates[1].node_id);
        CHECK(s.node_id != candidates[4].node_id);
    }
}

TEST_CASE("RelayProfiler: Unregistered node returns nullopt profile", "[unit][tunnel]") {
    RelayProfiler profiler;
    NodeID unknown = NodeID::random();
    CHECK_FALSE(profiler.get_profile(unknown).has_value());
}

TEST_CASE("RelayProfiler: Empty candidates list returns empty selection", "[unit][tunnel]") {
    RelayProfiler profiler;
    std::vector<PeerInfo> empty_candidates;
    auto selected = profiler.select_hops(empty_candidates, 3, {});
    CHECK(selected.empty());
}


