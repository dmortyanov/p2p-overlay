/// @file test_tunnel_integration.cpp
/// @brief Multi-node integration test for 3-hop Onion circuit construction and data forwarding (Stage 5).

#include "node.hpp"
#include "config/config.hpp"
#include <catch2/catch_test_macros.hpp>
#include <thread>
#include <chrono>
#include <filesystem>
#include <atomic>

using namespace p2p;
using namespace std::chrono_literals;

namespace {

config::Config make_tunnel_node_cfg(uint16_t port, const std::string& dir, const std::vector<std::string>& bootstrap = {}) {
    config::Config cfg;
    cfg.node.listen_address = "127.0.0.1";
    cfg.node.listen_port = port;
    cfg.node.data_dir = dir;
    cfg.dht.k_bucket_size = 4;
    cfg.dht.alpha = 3;
    cfg.dht.replication = 3;
    cfg.transport.connect_timeout_ms = 1000;
    cfg.transport.io_timeout_ms = 1000;
    cfg.bootstrap.peers = bootstrap;
    return cfg;
}

void clean_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

} // namespace

TEST_CASE("Stage 5 Integration: 3-hop Onion Circuit establishment and forwarding", "[integration][tunnel]") {
    // We launch 5 nodes:
    // Initiator (A) -> R1 -> R2 -> R3 -> Destination (Bob)
    clean_dir("./test_t_node_a");
    clean_dir("./test_t_node_r1");
    clean_dir("./test_t_node_r2");
    clean_dir("./test_t_node_r3");
    clean_dir("./test_t_node_b");

    auto cfg_r1 = make_tunnel_node_cfg(25001, "./test_t_node_r1");
    auto cfg_r2 = make_tunnel_node_cfg(25002, "./test_t_node_r2");
    auto cfg_r3 = make_tunnel_node_cfg(25003, "./test_t_node_r3");
    auto cfg_b  = make_tunnel_node_cfg(25004, "./test_t_node_b");
    auto cfg_a  = make_tunnel_node_cfg(25000, "./test_t_node_a", {"127.0.0.1:25001"});

    Node r1(cfg_r1);
    Node r2(cfg_r2);
    Node r3(cfg_r3);
    Node node_b(cfg_b);
    Node node_a(cfg_a);

    r1.start();
    r2.start();
    r3.start();
    node_b.start();
    node_a.start();

    std::thread tr1([&]() { r1.run(); });
    std::thread tr2([&]() { r2.run(); });
    std::thread tr3([&]() { r3.run(); });
    std::thread tb([&]() { node_b.run(); });
    std::thread ta([&]() { node_a.run(); });

    std::this_thread::sleep_for(300ms);

    // Register contacts in A's routing table: R1, R2, R3
    PeerInfo p_r1{r1.node_id(), {"127.0.0.1", 25001}};
    PeerInfo p_r2{r2.node_id(), {"127.0.0.1", 25002}};
    PeerInfo p_r3{r3.node_id(), {"127.0.0.1", 25003}};
    PeerInfo p_b{node_b.node_id(), {"127.0.0.1", 25004}};

    node_a.add_contact(p_r1);
    node_a.add_contact(p_r2);
    node_a.add_contact(p_r3);
    node_a.add_contact(p_b);

    // Simulate 3-hop circuit establishment directly via TunnelManager
    std::vector<PeerInfo> hops = {p_r1, p_r2, p_r3};

    std::atomic<bool> build_done{false};
    std::atomic<bool> build_ok{false};
    std::shared_ptr<tunnel::Tunnel> active_circuit = nullptr;

    node_a.tunnel_manager().async_build_tunnel(
        hops,
        node_b.node_id(),
        [&](const PeerAddress& target, const tunnel::TunnelBuildMsg& msg) {
            // Deliver msg to R1 directly
            auto resp1 = r1.tunnel_manager().handle_tunnel_build(node_a.node_id(), msg);
            if (std::holds_alternative<tunnel::TunnelBuildOkMsg>(resp1)) {
                node_a.tunnel_manager().handle_tunnel_build_ok(r1.node_id(), std::get<tunnel::TunnelBuildOkMsg>(resp1));

                // Hop 1 (R2)
                tunnel::TunnelBuildMsg msg2 = msg;
                msg2.hop_index = 1;
                auto eph2 = node_a.tunnel_manager().get_build_eph_pub(msg.circuit_id, 1);
                REQUIRE(eph2.has_value());
                msg2.eph_public_key = *eph2;
                auto resp2 = r2.tunnel_manager().handle_tunnel_build(r1.node_id(), msg2);
                if (std::holds_alternative<tunnel::TunnelBuildOkMsg>(resp2)) {
                    node_a.tunnel_manager().handle_tunnel_build_ok(r2.node_id(), std::get<tunnel::TunnelBuildOkMsg>(resp2));

                    // Hop 2 (R3)
                    tunnel::TunnelBuildMsg msg3 = msg;
                    msg3.hop_index = 2;
                    auto eph3 = node_a.tunnel_manager().get_build_eph_pub(msg.circuit_id, 2);
                    REQUIRE(eph3.has_value());
                    msg3.eph_public_key = *eph3;
                    auto resp3 = r3.tunnel_manager().handle_tunnel_build(r2.node_id(), msg3);
                    if (std::holds_alternative<tunnel::TunnelBuildOkMsg>(resp3)) {
                        node_a.tunnel_manager().handle_tunnel_build_ok(r3.node_id(), std::get<tunnel::TunnelBuildOkMsg>(resp3));
                    }
                }
            }
        },
        [&](bool success, std::shared_ptr<tunnel::Tunnel> t) {
            build_ok = success;
            active_circuit = t;
            build_done = true;
        });

    for (int i = 0; i < 30 && !build_done; ++i) {
        std::this_thread::sleep_for(50ms);
    }

    REQUIRE(build_done);
    REQUIRE(build_ok);
    REQUIRE(active_circuit != nullptr);
    CHECK(active_circuit->state() == tunnel::TunnelState::ACTIVE);
    CHECK(active_circuit->hop_count() == 3);

    // Verify TunnelPool has the active circuit
    CHECK(node_a.tunnel_manager().pool()->active_count() == 1);
    CHECK(node_a.tunnel_manager().pool()->pick_tunnel(node_b.node_id()) != nullptr);

    // ─── Test Data Forwarding through all 3 layers ───
    std::string secret_payload = "E5: Onion delivery across 3 independent hops confirmed!";
    Bytes payload_bytes(secret_payload.begin(), secret_payload.end());
    Bytes onion = active_circuit->wrap_payload(payload_bytes);

    // Peel layer 1 at R1
    tunnel::TunnelDataMsg dmsg1;
    dmsg1.circuit_id = active_circuit->circuit_id();
    dmsg1.sequence_number = 1;
    dmsg1.onion_payload = onion;
    auto p1 = r1.tunnel_manager().handle_tunnel_data(node_a.node_id(), dmsg1);
    REQUIRE(p1.has_value());
    CHECK_FALSE(p1->is_terminal);
    CHECK(p1->next_hop_node_id == r2.node_id());

    // Peel layer 2 at R2
    tunnel::TunnelDataMsg dmsg2;
    dmsg2.circuit_id = active_circuit->circuit_id();
    dmsg2.sequence_number = 1;
    dmsg2.onion_payload = p1->payload;
    auto p2 = r2.tunnel_manager().handle_tunnel_data(r1.node_id(), dmsg2);
    REQUIRE(p2.has_value());
    CHECK_FALSE(p2->is_terminal);
    CHECK(p2->next_hop_node_id == r3.node_id());

    // Peel layer 3 at R3 (Exit)
    std::atomic<bool> delivered{false};
    std::string received_text;
    r3.tunnel_manager().set_data_handler([&](const tunnel::CircuitID& cid, ByteSpan data) {
        received_text = std::string(data.begin(), data.end());
        delivered = true;
    });

    tunnel::TunnelDataMsg dmsg3;
    dmsg3.circuit_id = active_circuit->circuit_id();
    dmsg3.sequence_number = 1;
    dmsg3.onion_payload = p2->payload;
    auto p3 = r3.tunnel_manager().handle_tunnel_data(r2.node_id(), dmsg3);
    REQUIRE(p3.has_value());
    CHECK(p3->is_terminal);
    CHECK(delivered);
    CHECK(received_text == secret_payload);

    // Teardown
    node_a.tunnel_manager().close_tunnel(active_circuit->circuit_id());
    CHECK(active_circuit->state() == tunnel::TunnelState::CLOSED);
    CHECK(node_a.tunnel_manager().pool()->active_count() == 0);

    node_a.stop();
    node_b.stop();
    r3.stop();
    r2.stop();
    r1.stop();

    if (ta.joinable()) ta.join();
    if (tb.joinable()) tb.join();
    if (tr3.joinable()) tr3.join();
    if (tr2.joinable()) tr2.join();
    if (tr1.joinable()) tr1.join();

    clean_dir("./test_t_node_a");
    clean_dir("./test_t_node_r1");
    clean_dir("./test_t_node_r2");
    clean_dir("./test_t_node_r3");
    clean_dir("./test_t_node_b");
}

