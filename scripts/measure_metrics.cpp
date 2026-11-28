/// @file measure_metrics.cpp
/// @brief Real empirical measurements for E1-8 (CBOR vs JSON), E2-8 (Star/Ring routing dumps),
/// and E2-9 (10 live iterative DHT lookups).

#include "node.hpp"
#include "config/config.hpp"
#include "dht/dht_messages.hpp"
#include "dht/node_record.hpp"
#include "transport/frame.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <thread>
#include <vector>

using namespace p2p;
using namespace std::chrono_literals;

namespace {

void clean_dir(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
}

config::Config make_node_cfg(uint16_t port, const std::string& data_dir,
                             const std::vector<std::string>& bootstrap = {}) {
    config::Config cfg;
    cfg.node.listen_address = "127.0.0.1";
    cfg.node.advertise_address = "127.0.0.1";
    cfg.node.listen_port = port;
    cfg.node.data_dir = data_dir;
    cfg.dht.k_bucket_size = 4;
    cfg.dht.alpha = 3;
    cfg.dht.replication = 3;
    cfg.transport.connect_timeout_ms = 2000;
    cfg.transport.io_timeout_ms = 3000;
    cfg.bootstrap.peers = bootstrap;
    return cfg;
}

void run_serialization_benchmark(const std::filesystem::path& out_csv) {
    constexpr int ITERS = 10000;

    nlohmann::json ping_j = {
        {"node_id", NodeID::random().to_hex()},
        {"public_key", nlohmann::json::binary_t(std::vector<uint8_t>(32, 0xAA))},
        {"listen_port", 9001}
    };

    dht::FindNodeRequest fn_req{
        .target = NodeID::random(),
        .sender = PeerInfo{NodeID::random(), PeerAddress{"127.0.0.1", 9001}}
    };

    dht::NodeRecord rec;
    auto kp = identity::Keypair::generate();
    rec.addresses = {PeerAddress{"127.0.0.1", 9001}};
    rec.sequence_number = 42;
    rec.issued_at = 1791800000;
    rec.expires_at = 1791800180;
    rec.alias = "alice";
    rec.sign(kp);

    std::ofstream csv(out_csv, std::ios::trunc);
    csv << "message_type,json_bytes,cbor_bytes,size_saving_pct,json_encode_us,cbor_encode_us\n";

    auto measure_msg = [&](const std::string& name, const nlohmann::json& j_obj, const Bytes& cbor_sample) {
        std::string json_str;
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < ITERS; ++i) {
            json_str = j_obj.dump();
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double json_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / ITERS;

        std::vector<uint8_t> cbor_buf;
        auto t2 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < ITERS; ++i) {
            cbor_buf = nlohmann::json::to_cbor(j_obj);
        }
        auto t3 = std::chrono::high_resolution_clock::now();
        double cbor_us = std::chrono::duration<double, std::micro>(t3 - t2).count() / ITERS;

        std::size_t jsz = json_str.size();
        std::size_t csz = cbor_sample.empty() ? cbor_buf.size() : cbor_sample.size();
        double saving = 100.0 * (static_cast<double>(jsz) - static_cast<double>(csz)) / static_cast<double>(jsz);

        csv << name << "," << jsz << "," << csz << ","
            << std::fixed << std::setprecision(1) << saving << ","
            << std::setprecision(2) << json_us << "," << cbor_us << "\n";
    };

    // Convert binary fields to hex for JSON baseline comparison
    nlohmann::json ping_json_baseline = {
        {"node_id", ping_j["node_id"]},
        {"public_key", std::string(64, 'a')},
        {"listen_port", 9001}
    };
    measure_msg("PING", ping_json_baseline, nlohmann::json::to_cbor(ping_j));

    nlohmann::json fn_json_baseline = {
        {"target", fn_req.target.to_hex()},
        {"sender_id", fn_req.sender.node_id.to_hex()},
        {"host", fn_req.sender.address.host},
        {"port", fn_req.sender.address.port}
    };
    measure_msg("FIND_NODE_REQUEST", fn_json_baseline, dht::serialize_find_node_request(fn_req));

    nlohmann::json rec_json_baseline = {
        {"node_id", rec.node_id.to_hex()},
        {"public_key", std::string(64, 'b')},
        {"addresses", {"127.0.0.1:9001"}},
        {"sequence_number", rec.sequence_number},
        {"issued_at", rec.issued_at},
        {"expires_at", rec.expires_at},
        {"alias", rec.alias},
        {"signature", std::string(128, 'c')}
    };
    measure_msg("NodeRecord", rec_json_baseline, rec.to_cbor());
    std::cout << "[E1-8] Real C++ serialization benchmark written to " << out_csv << "\n";
}

std::vector<NodeID> run_topology_and_dump(const std::string& name, uint16_t base_port, const std::filesystem::path& out_dir) {
    std::filesystem::create_directories(out_dir);
    clean_dir("./tmp_measure_" + name);

    std::vector<std::unique_ptr<Node>> nodes;
    std::vector<std::thread> threads;

    for (int i = 0; i < 5; ++i) {
        std::vector<std::string> bs;
        if (i > 0) {
            if (name == "star") {
                bs.push_back("127.0.0.1:" + std::to_string(base_port));
            } else {
                bs.push_back("127.0.0.1:" + std::to_string(base_port + i - 1));
            }
        }
        auto cfg = make_node_cfg(static_cast<uint16_t>(base_port + i),
                                 "./tmp_measure_" + name + "/n" + std::to_string(i), bs);
        nodes.push_back(std::make_unique<Node>(cfg));
    }

    for (int i = 0; i < 5; ++i) {
        nodes[i]->start();
        threads.emplace_back([&nodes, i]() { nodes[i]->run(); });
        std::this_thread::sleep_for(150ms);
    }

    // Wait for bootstrap self-lookup convergence
    std::this_thread::sleep_for(1200ms);

    std::vector<NodeID> ids;
    for (int i = 0; i < 5; ++i) {
        ids.push_back(nodes[i]->node_id());
        std::ofstream ofs(out_dir / ("node" + std::to_string(i) + ".json"), std::ios::trunc);
        ofs << nodes[i]->export_routing_table_json();
        std::cout << "[E2-8] " << name << " node" << i << " contacts="
                  << nodes[i]->routing_table().total_contacts() << "\n";
    }

    // If star, also run 10 real iterative lookups from node4 (E2-9)
    if (name == "star") {
        std::ofstream csv("results/pilot_lookups.csv", std::ios::trunc);
        csv << "lookup_id,target_node_id,iterations,total_rpcs,duration_ms,status,closest_nodes_count\n";

        for (int q = 0; q < 10; ++q) {
            NodeID target = (q < 5) ? ids[q] : NodeID::random();
            std::atomic<bool> done{false};
            dht::LookupMetrics metrics{};
            std::size_t found_cnt = 0;

            nodes[4]->async_lookup(target, [&](const std::vector<PeerInfo>& closest, const dht::LookupMetrics& m) {
                found_cnt = closest.size();
                metrics = m;
                done = true;
            });

            for (int w = 0; w < 50 && !done; ++w) {
                std::this_thread::sleep_for(20ms);
            }

            double ms = static_cast<double>(metrics.duration.count());
            csv << (q + 1) << "," << target.to_short_hex() << "...,"
                << metrics.iterations << "," << metrics.total_rpcs << ","
                << std::fixed << std::setprecision(2) << ms << ","
                << (done ? "CONVERGED" : "TIMEOUT") << "," << found_cnt << "\n";
        }
        std::cout << "[E2-9] 10 real iterative lookups recorded to results/pilot_lookups.csv\n";
    }

    for (int i = 4; i >= 0; --i) nodes[i]->stop();
    for (auto& t : threads) if (t.joinable()) t.join();
    clean_dir("./tmp_measure_" + name);
    return ids;
}

} // namespace

int main() {
    spdlog::set_level(spdlog::level::warn);
    if (sodium_init() < 0) return 1;

    std::filesystem::create_directories("results");
    run_serialization_benchmark("results/serialization_benchmark.csv");
    run_topology_and_dump("star", 24100, "results/star");
    run_topology_and_dump("ring", 24200, "results/ring");
    return 0;
}
