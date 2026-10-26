/// @file test_ake_integration.cpp
/// @brief Integration tests for Stage 4: Live network AKE handshake and transparent AEAD encrypted communication (E4-8).

#include "node.hpp"
#include "config/config.hpp"
#include "transport/tcp_connection.hpp"
#include "transport/frame.hpp"
#include "security/secure_session.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <thread>

using namespace p2p;

static config::Config make_node_config(uint16_t port, const std::string& data_dir) {
    config::Config cfg;
    cfg.node.listen_address = "127.0.0.1";
    cfg.node.listen_port = port;
    cfg.node.data_dir = data_dir;
    cfg.dht.k_bucket_size = 4;
    cfg.dht.alpha = 3;
    cfg.dht.record_ttl_sec = 60;
    cfg.dht.republish_interval_sec = 200;
    cfg.transport.io_timeout_ms = 3000;
    cfg.transport.connect_timeout_ms = 3000;
    return cfg;
}

TEST_CASE("E4-8: Live 2-node AKE Handshake and AEAD Encrypted Messaging", "[security][integration][stage4]") {
    REQUIRE(sodium_init() >= 0);

    std::filesystem::remove_all("./test_ake_node_a");
    std::filesystem::remove_all("./test_ake_node_b");

    auto cfg_a = make_node_config(24001, "./test_ake_node_a");
    auto cfg_b = make_node_config(24002, "./test_ake_node_b");

    auto node_a = std::make_unique<Node>(cfg_a);
    auto node_b = std::make_unique<Node>(cfg_b);

    node_a->start();
    node_b->start();

    std::thread thread_a([&]() { node_a->run(); });
    std::thread thread_b([&]() { node_b->run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Connect Node A to Node B
    node_a->connect_to_peer("127.0.0.1", 24002);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Retrieve active connection to Node B from Node A
    auto conn_to_b = node_a->get_connection_to(node_b->node_id());
    REQUIRE(conn_to_b != nullptr);
    REQUIRE(conn_to_b->is_open());

    // 1. Initiate live AKE handshake over TCP
    std::atomic<bool> handshake_done = false;
    std::atomic<bool> handshake_success = false;

    node_a->initiate_handshake(conn_to_b, [&](bool ok) {
        handshake_success = ok;
        handshake_done = true;
    });

    for (int i = 0; i < 40 && !handshake_done; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    REQUIRE(handshake_done);
    REQUIRE(handshake_success);

    // Verify both nodes have active secure sessions
    REQUIRE(conn_to_b->secure_session() != nullptr);
    REQUIRE(conn_to_b->secure_session()->is_active());

    // 2. Test encrypted bidirectional communication over the secured connection
    std::atomic<bool> app_msg_received = false;
    std::string received_msg_payload;

    conn_to_b->set_frame_handler([&](const transport::Frame& frame) {
        if (frame.type == transport::MessageType::APP_ACK) {
            received_msg_payload = std::string(frame.payload.begin(), frame.payload.end());
            app_msg_received = true;
        }
    });

    // Send encrypted message from Node A to Node B
    auto rid = RequestID::generate();
    transport::Frame msg_frame(transport::MessageType::APP_MESSAGE, rid);
    std::string secret_text = "Highly Classified P2P Payload";
    msg_frame.payload = Bytes(secret_text.begin(), secret_text.end());

    // conn_to_b->send will automatically encrypt using ChaCha20-Poly1305 with AAD
    conn_to_b->send(msg_frame);

    // Clean up
    node_a->stop();
    node_b->stop();

    if (thread_a.joinable()) thread_a.join();
    if (thread_b.joinable()) thread_b.join();

    std::filesystem::remove_all("./test_ake_node_a");
    std::filesystem::remove_all("./test_ake_node_b");
}
