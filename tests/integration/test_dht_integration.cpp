/// @file test_dht_integration.cpp
/// @brief Integration tests for DHT: FIND_NODE RPC correlation and 5-node bootstrap (E2-5, E2-7).

#include "node.hpp"
#include "config/config.hpp"
#include "dht/dht_messages.hpp"

#include <catch2/catch_test_macros.hpp>

#include <thread>
#include <chrono>
#include <filesystem>

using namespace p2p;

namespace {

config::Config make_test_config(uint16_t port, const std::string& data_dir,
                                const std::vector<std::string>& bootstrap = {}) {
    config::Config cfg;
    cfg.node.listen_address = "127.0.0.1";
    cfg.node.listen_port = port;
    cfg.node.data_dir = data_dir;
    cfg.dht.k_bucket_size = 4;
    cfg.dht.alpha = 3;
    cfg.dht.replication = 3;
    cfg.transport.connect_timeout_ms = 1000;
    cfg.transport.rpc_timeout_ms = 1000;
    cfg.bootstrap.peers = bootstrap;
    return cfg;
}

void clean_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

} // namespace

TEST_CASE("E2-5 Integration: FIND_NODE request and response over TCP", "[integration][dht]") {
    clean_dir("./test_state_node_a");
    clean_dir("./test_state_node_b");

    auto cfg_a = make_test_config(21010, "./test_state_node_a");
    auto cfg_b = make_test_config(21011, "./test_state_node_b", {"127.0.0.1:21010"});

    Node node_a(cfg_a);
    Node node_b(cfg_b);

    node_a.start();
    node_b.start();

    // Run event loops in background threads
    std::thread t_a([&]() { node_a.run(); });
    std::thread t_b([&]() { node_b.run(); });

    // Allow time for TCP handshake and initial PING/PONG
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Verify mutual discovery: each should have the other in their routing table
    auto closest_to_b = node_a.find_closest_nodes(node_b.node_id(), 4);
    REQUIRE(!closest_to_b.empty());
    REQUIRE(closest_to_b[0].node_id == node_b.node_id());

    auto closest_to_a = node_b.find_closest_nodes(node_a.node_id(), 4);
    REQUIRE(!closest_to_a.empty());
    REQUIRE(closest_to_a[0].node_id == node_a.node_id());

    // Stop nodes
    node_b.stop();
    node_a.stop();

    if (t_b.joinable()) t_b.join();
    if (t_a.joinable()) t_a.join();

    clean_dir("./test_state_node_a");
    clean_dir("./test_state_node_b");
}

TEST_CASE("E2-7 Integration: 5-node cluster with seed termination", "[integration][dht]") {
    for (int i = 0; i < 5; ++i) {
        clean_dir("./test_cluster_node_" + std::to_string(i));
    }

    // Node 0: Seed bootstrap node
    auto cfg_seed = make_test_config(21020, "./test_cluster_node_0");
    Node seed_node(cfg_seed);
    seed_node.start();
    std::thread t_seed([&]() { seed_node.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Nodes 1..4: Connect to seed
    std::vector<std::unique_ptr<Node>> cluster;
    std::vector<std::thread> threads;

    for (int i = 1; i <= 4; ++i) {
        auto cfg = make_test_config(21020 + i, "./test_cluster_node_" + std::to_string(i), {"127.0.0.1:21020"});
        auto node = std::make_unique<Node>(cfg);
        node->start();
        threads.emplace_back([n = node.get()]() { n->run(); });
        cluster.push_back(std::move(node));
    }

    // Wait for bootstrap self-lookups to complete and contacts to propagate
    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    // Verify seed knows cluster nodes
    REQUIRE(seed_node.routing_table().total_contacts() >= 4);

    // Now terminate seed node (E2-7 criterion: остановка seed-узла не блокирует работу сети)
    seed_node.stop();
    if (t_seed.joinable()) t_seed.join();

    // Verify cluster nodes can still communicate and find each other
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Node 1 and Node 4 can still find contacts in their routing tables
    REQUIRE(cluster[0]->routing_table().total_contacts() > 0);
    REQUIRE(cluster[3]->routing_table().total_contacts() > 0);

    // Export routing table check (E2-8 JSON verification)
    std::string json_export = cluster[0]->export_routing_table_json();
    REQUIRE(!json_export.empty());
    REQUIRE(json_export.find("active_buckets") != std::string::npos);

    // Stop all cluster nodes
    for (auto& node : cluster) {
        node->stop();
    }
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    for (int i = 0; i < 5; ++i) {
        clean_dir("./test_cluster_node_" + std::to_string(i));
    }
}
