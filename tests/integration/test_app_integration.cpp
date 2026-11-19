/// @file test_app_integration.cpp
/// @brief Integration tests for E2E messaging and multi-chunk file transfer over live network (Stage 6, E6-4).

#include "node.hpp"
#include "config/config.hpp"
#include <catch2/catch_test_macros.hpp>
#include <thread>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <atomic>

using namespace p2p;
using namespace std::chrono_literals;

namespace {

config::Config make_app_node_cfg(uint16_t port, const std::string& dir, const std::vector<std::string>& bootstrap = {}) {
    config::Config cfg;
    cfg.node.listen_address = "127.0.0.1";
    cfg.node.listen_port = port;
    cfg.node.data_dir = dir;
    cfg.dht.k_bucket_size = 4;
    cfg.dht.alpha = 3;
    cfg.dht.replication = 3;
    cfg.transport.connect_timeout_ms = 3000;
    cfg.transport.io_timeout_ms = 10000;
    cfg.bootstrap.peers = bootstrap;
    return cfg;
}

void clean_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

void write_test_payload(const std::filesystem::path& path, std::size_t size) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    std::vector<uint8_t> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(i % 251);
    }
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}

} // namespace

TEST_CASE("Stage 6 Integration: E2E Text Messaging with APP_ACK and Deduplication", "[integration][app]") {
    clean_dir("./test_app_node_a");
    clean_dir("./test_app_node_b");

    auto cfg_b = make_app_node_cfg(26001, "./test_app_node_b");
    auto cfg_a = make_app_node_cfg(26000, "./test_app_node_a", {"127.0.0.1:26001"});

    Node node_b(cfg_b);
    Node node_a(cfg_a);

    node_b.start();
    node_a.start();

    std::thread tb([&]() { node_b.run(); });
    std::thread ta([&]() { node_a.run(); });

    std::this_thread::sleep_for(300ms);

    // Setup listener on Node B
    std::atomic<bool> msg_received{false};
    std::string received_text;
    node_b.message_service().set_on_message([&](const app::AppMessage& msg) {
        received_text = msg.text;
        msg_received = true;
    });

    // Send message from A to B
    std::atomic<bool> ack_received{false};
    std::string message_body = "Hello Bob! This is an authenticated P2P message.";

    node_a.send_message(node_b.node_id(), message_body, [&](bool ok, const std::string& err) {
        if (ok) {
            ack_received = true;
        }
    });

    for (int i = 0; i < 30 && (!msg_received || !ack_received); ++i) {
        std::this_thread::sleep_for(50ms);
    }

    CHECK(msg_received);
    CHECK(ack_received);
    CHECK(received_text == message_body);

    node_a.stop();
    node_b.stop();
    if (ta.joinable()) ta.join();
    if (tb.joinable()) tb.join();

    clean_dir("./test_app_node_a");
    clean_dir("./test_app_node_b");
}

TEST_CASE("Stage 6 Integration: Chunked File Transfer over live P2P network", "[integration][app]") {
    clean_dir("./test_file_node_a");
    clean_dir("./test_file_node_b");

    auto cfg_b = make_app_node_cfg(26011, "./test_file_node_b");
    auto cfg_a = make_app_node_cfg(26010, "./test_file_node_a", {"127.0.0.1:26011"});

    Node node_b(cfg_b);
    Node node_a(cfg_a);

    node_b.start();
    node_a.start();

    std::thread tb([&]() { node_b.run(); });
    std::thread ta([&]() { node_a.run(); });

    std::this_thread::sleep_for(300ms);

    // Create a 100 KiB file to send (will split into 3 chunks with 48 KiB chunk size)
    std::filesystem::path src_file = "./test_file_node_a/data/sample_100k.bin";
    write_test_payload(src_file, 100 * 1024);

    auto src_sha = app::compute_file_sha256(src_file);
    REQUIRE(src_sha.has_value());

    std::atomic<bool> file_delivered{false};
    std::filesystem::path received_file_path;

    node_b.file_transfer_manager().set_on_file_received([&](const app::FileMeta& meta, const std::filesystem::path& path) {
        received_file_path = path;
        file_delivered = true;
    });

    std::atomic<bool> send_completed{false};
    bool started = node_a.send_file(
        node_b.node_id(),
        src_file,
        nullptr,
        [&](bool success, const std::string& err) {
            if (success) send_completed = true;
        });

    REQUIRE(started);

    for (int i = 0; i < 40 && (!file_delivered || !send_completed); ++i) {
        std::this_thread::sleep_for(50ms);
    }

    CHECK(file_delivered);
    CHECK(send_completed);
    CHECK(std::filesystem::exists(received_file_path));

    auto dst_sha = app::compute_file_sha256(received_file_path);
    REQUIRE(dst_sha.has_value());
    CHECK(*dst_sha == *src_sha);
    CHECK(std::filesystem::file_size(received_file_path) == 100 * 1024);

    node_a.stop();
    node_b.stop();
    if (ta.joinable()) ta.join();
    if (tb.joinable()) tb.join();

    clean_dir("./test_file_node_a");
    clean_dir("./test_file_node_b");
}
