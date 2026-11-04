/// @file test_negative_tunnel.cpp
/// @brief Negative tests for Tunnel and Onion routing: invalid payload, circuit failure, cycles (Stage 5).

#include "tunnel/onion_packet.hpp"
#include "tunnel/tunnel_pool.hpp"
#include "tunnel/relay_profiler.hpp"
#include "tunnel/tunnel_manager.hpp"
#include "identity/keypair.hpp"

#include <catch2/catch_test_macros.hpp>
#include <chrono>

using namespace p2p;
using namespace p2p::tunnel;

TEST_CASE("Negative Tunnel: Insufficient hops (< 3) rejected", "[negative][tunnel]") {
    auto kp = identity::Keypair::generate();
    TunnelManager tm(kp.node_id(), kp);

    std::vector<PeerInfo> two_hops = {
        {NodeID::random(), {"10.0.1.1", 9001}},
        {NodeID::random(), {"10.0.2.1", 9002}}
    };

    bool callback_invoked = false;
    bool build_success = true;

    tm.async_build_tunnel(
        two_hops,
        NodeID::random(),
        nullptr,
        [&](bool success, std::shared_ptr<Tunnel> t) {
            callback_invoked = true;
            build_success = success;
        });

    CHECK(callback_invoked);
    CHECK_FALSE(build_success);
}

TEST_CASE("Negative Tunnel: Truncated or empty onion payload fails peel", "[negative][tunnel]") {
    std::array<uint8_t, security::AEAD_KEY_SIZE> key;
    key.fill(0x55);

    // Completely empty
    CHECK_FALSE(OnionPacket::peel(Bytes{}, key, 0).has_value());

    // Truncated (less than tag + header)
    Bytes tiny(10, 0xAA);
    CHECK_FALSE(OnionPacket::peel(tiny, key, 0).has_value());
}

TEST_CASE("Negative Tunnel: TunnelPool prunes expired circuits and circuits with excessive failures", "[negative][tunnel]") {
    TunnelPool pool(3);

    std::vector<TunnelHop> hops = {
        {NodeID::random(), {"10.0.1.1", 9001}, {}},
        {NodeID::random(), {"10.0.2.1", 9002}, {}},
        {NodeID::random(), {"10.0.3.1", 9003}, {}}
    };

    // Circuit with 0 second TTL (immediately expired)
    auto t_expired = std::make_shared<Tunnel>(
        RequestID::generate(), hops, NodeID::random(), std::chrono::seconds(0));
    t_expired->set_state(TunnelState::ACTIVE);
    pool.add_tunnel(t_expired);

    // Circuit with failure count >= 3
    auto t_failed = std::make_shared<Tunnel>(
        RequestID::generate(), hops, NodeID::random(), std::chrono::seconds(300));
    t_failed->set_state(TunnelState::ACTIVE);
    t_failed->increment_failures();
    t_failed->increment_failures();
    t_failed->increment_failures();
    pool.add_tunnel(t_failed);

    // Healthy circuit
    auto t_healthy = std::make_shared<Tunnel>(
        RequestID::generate(), hops, NodeID::random(), std::chrono::seconds(300));
    t_healthy->set_state(TunnelState::ACTIVE);
    pool.add_tunnel(t_healthy);

    CHECK(pool.all_tunnels().size() == 3);

    auto pruned = pool.prune_stale_tunnels();
    CHECK(pruned.size() == 2);
    CHECK(pool.active_count() == 1);
    CHECK(pool.get_tunnel(t_healthy->circuit_id()) != nullptr);
    CHECK(pool.get_tunnel(t_expired->circuit_id()) == nullptr);
    CHECK(pool.get_tunnel(t_failed->circuit_id()) == nullptr);
}

