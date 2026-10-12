/// @file test_dht_storage.cpp
/// @brief Integration tests for DHT Storage: STORE, FIND_VALUE, replication (R=3, Quorum>=2),
/// keeper failure recovery, and alias resolution (E3-3, E3-4, E3-5, E3-8).

#include "node.hpp"
#include "config/config.hpp"
#include "dht/dht_messages.hpp"
#include "dht/node_record.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <thread>
#include <vector>

using namespace p2p;
using namespace p2p::dht;

namespace {

config::Config make_storage_test_config(uint16_t port, const std::string& data_dir,
                                       const std::vector<std::string>& bootstrap = {}) {
    config::Config cfg;
    cfg.node.listen_address = "127.0.0.1";
    cfg.node.listen_port = port;
    cfg.node.data_dir = data_dir;
    cfg.dht.k_bucket_size = 4;
    cfg.dht.alpha = 3;
    cfg.dht.replication = 3;
    cfg.dht.record_ttl_sec = 180;
    cfg.dht.republish_interval_sec = 80;
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

TEST_CASE("E3-3 Integration: Direct STORE and FIND_VALUE RPC between 2 nodes", "[integration][dht][storage]") {
    clean_dir("./test_storage_node_a");
    clean_dir("./test_storage_node_b");

    auto cfg_a = make_storage_test_config(22010, "./test_storage_node_a");
    auto cfg_b = make_storage_test_config(22011, "./test_storage_node_b", {"127.0.0.1:22010"});

    Node node_a(cfg_a);
    Node node_b(cfg_b);

    node_a.start();
    node_b.start();

    std::thread t_a([&]() { node_a.run(); });
    std::thread t_b([&]() { node_b.run(); });

    struct CleanupGuard {
        Node& na;
        Node& nb;
        std::thread& ta;
        std::thread& tb;
        ~CleanupGuard() {
            nb.stop();
            na.stop();
            if (tb.joinable()) tb.join();
            if (ta.joinable()) ta.join();
            clean_dir("./test_storage_node_a");
            clean_dir("./test_storage_node_b");
        }
    } guard{node_a, node_b, t_a, t_b};

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 1. Node A creates a signed record
    auto rec = node_a.create_self_record("test-service");
    auto key = node_record_key(rec.node_id);

    // 2. Node A publishes record to Node B
    std::atomic<bool> store_done = false;
    std::atomic<bool> store_success = false;
    std::atomic<std::size_t> store_acks = 0;

    node_a.publish_record(key, rec, [&](bool ok, std::size_t acks) {
        store_success = ok;
        store_acks = acks;
        store_done = true;
    });

    for (int i = 0; i < 20 && !store_done; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    REQUIRE(store_done);
    REQUIRE(store_success);
    REQUIRE(store_acks >= 2); // local store + Node B store

    // Verify Node B holds the record in its local RecordStore
    uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    auto b_rec = node_b.record_store().get(key, now);
    REQUIRE(b_rec.has_value());
    REQUIRE(b_rec->node_id == node_a.node_id());
    REQUIRE(b_rec->alias == "test-service");

    // 3. Node B performs FIND_VALUE for Node A's record
    std::atomic<bool> find_done = false;
    std::optional<NodeRecord> found_val;

    node_b.async_find_value(key, [&](std::optional<NodeRecord> r, const LookupMetrics& m) {
        found_val = std::move(r);
        find_done = true;
    });

    for (int i = 0; i < 20 && !find_done; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    REQUIRE(find_done);
    REQUIRE(found_val.has_value());
    REQUIRE(found_val->node_id == node_a.node_id());
    REQUIRE(found_val->alias == "test-service");

    // Stop nodes
    node_b.stop();
    node_a.stop();

    if (t_b.joinable()) t_b.join();
    if (t_a.joinable()) t_a.join();

    clean_dir("./test_storage_node_a");
    clean_dir("./test_storage_node_b");
}

TEST_CASE("E3-4 & E3-5 & E3-8 Integration: 5-node cluster replication, keeper failure, and alias resolution",
          "[integration][dht][storage][cluster]") {
    for (int i = 0; i < 5; ++i) {
        clean_dir("./test_storage_cluster_" + std::to_string(i));
    }

    // Node 0: Seed node
    auto cfg_seed = make_storage_test_config(22020, "./test_storage_cluster_0");
    auto seed_node = std::make_unique<Node>(cfg_seed);
    seed_node->start();
    std::thread t_seed([&]() { seed_node->run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Nodes 1..4: Connect to seed
    std::vector<std::unique_ptr<Node>> cluster;
    std::vector<std::thread> threads;

    for (int i = 1; i <= 4; ++i) {
        auto cfg = make_storage_test_config(22020 + i,
                                            "./test_storage_cluster_" + std::to_string(i),
                                            {"127.0.0.1:22020"});
        auto node = std::make_unique<Node>(cfg);
        node->start();
        threads.emplace_back([n = node.get()]() { n->run(); });
        cluster.push_back(std::move(node));
    }

    struct ClusterGuard {
        std::unique_ptr<Node>& seed;
        std::thread& t_seed;
        std::vector<std::unique_ptr<Node>>& nodes;
        std::vector<std::thread>& thrs;
        ~ClusterGuard() {
            for (auto& n : nodes) {
                if (n) n->stop();
            }
            for (auto& t : thrs) {
                if (t.joinable()) t.join();
            }
            if (seed) seed->stop();
            if (t_seed.joinable()) t_seed.join();
            for (int i = 0; i < 5; ++i) {
                clean_dir("./test_storage_cluster_" + std::to_string(i));
            }
        }
    } cluster_guard{seed_node, t_seed, cluster, threads};

    // Wait for bootstrap lookups and routing table convergence
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // 1. Node 1 publishes self record with alias "alpha-service" (E3-4, E3-8)
    std::atomic<bool> pub_done = false;
    std::atomic<bool> pub_success = false;
    std::atomic<std::size_t> pub_acks = 0;

    cluster[0]->publish_self_record("alpha-service", [&](bool ok, std::size_t acks) {
        pub_success = ok;
        pub_acks = acks;
        pub_done = true;
    });

    for (int i = 0; i < 40 && !pub_done; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    REQUIRE(pub_done);
    REQUIRE(pub_success);
    REQUIRE(pub_acks >= 2); // Quorum satisfied (Q >= 2)

    auto alias_key = alias_record_key("alpha-service");
    auto node_key = node_record_key(cluster[0]->node_id());

    // Count how many nodes in the entire network hold the record (replication R=3)
    uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    std::vector<Node*> keepers;
    if (seed_node->record_store().get(node_key, now).has_value()) {
        keepers.push_back(seed_node.get());
    }
    for (auto& n : cluster) {
        if (n->record_store().get(node_key, now).has_value()) {
            keepers.push_back(n.get());
        }
    }

    REQUIRE(keepers.size() >= 3); // R = 3 replication achieved!

    // 2. Node 4 resolves alias "alpha-service" via async_resolve_alias (E3-8)
    std::atomic<bool> resolve_done = false;
    std::optional<NodeRecord> resolved_rec;

    cluster[3]->async_resolve_alias("alpha-service", [&](std::optional<NodeRecord> r, const LookupMetrics& m) {
        resolved_rec = std::move(r);
        resolve_done = true;
    });

    for (int i = 0; i < 40 && !resolve_done; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    REQUIRE(resolve_done);
    REQUIRE(resolved_rec.has_value());
    REQUIRE(resolved_rec->node_id == cluster[0]->node_id());
    REQUIRE(resolved_rec->alias == "alpha-service");

    // 3. E3-5 KEEPER FAILURE SCENARIO:
    // Identify 1 keeper node that is NEITHER the publisher (cluster[0]) NOR the retriever (cluster[3]).
    Node* keeper_to_kill = nullptr;
    std::size_t killed_index = 999;

    for (std::size_t i = 1; i <= 2; ++i) {
        for (auto* k : keepers) {
            if (k == cluster[i].get()) {
                keeper_to_kill = k;
                killed_index = i;
                break;
            }
        }
        if (keeper_to_kill) break;
    }

    if (!keeper_to_kill && seed_node.get() != cluster[0].get() && seed_node.get() != cluster[3].get()) {
        keeper_to_kill = seed_node.get();
        killed_index = 0; // seed
    }

    REQUIRE(keeper_to_kill != nullptr);

    // Stop and shut down this keeper node!
    if (keeper_to_kill == seed_node.get()) {
        seed_node->stop();
        if (t_seed.joinable()) t_seed.join();
    } else {
        cluster[killed_index]->stop();
        if (threads[killed_index].joinable()) threads[killed_index].join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Clear local cache on retriever (Node 4 / cluster[3]) to force network lookup
    cluster[3]->record_store().clear();

    // Node 4 performs FIND_VALUE for node_key.
    // E3-5 CRITERION: Even after 1 keeper was stopped, FIND_VALUE returns valid record from surviving keepers!
    std::atomic<bool> find_after_kill_done = false;
    std::optional<NodeRecord> found_after_kill;

    cluster[3]->async_find_value(node_key, [&](std::optional<NodeRecord> r, const LookupMetrics& m) {
        found_after_kill = std::move(r);
        find_after_kill_done = true;
    });

    for (int i = 0; i < 40 && !find_after_kill_done; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    REQUIRE(find_after_kill_done);
    REQUIRE(found_after_kill.has_value());
    REQUIRE(found_after_kill->node_id == cluster[0]->node_id());
    REQUIRE(found_after_kill->alias == "alpha-service");

    // Clean up automatically handled by cluster_guard
}
