/// @file test_negative_transport.cpp
/// @brief Automated negative tests for E1-6 and E1-7: transport error handling,
/// corrupted frames, abrupt disconnects, protocol violations, and RPC correlation.

#include "node.hpp"
#include "config/config.hpp"
#include "transport/frame.hpp"
#include "identity/keypair.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <asio.hpp>
#include <thread>
#include <chrono>
#include <filesystem>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

using namespace p2p;
using namespace p2p::transport;

namespace {

config::Config make_test_cfg(uint16_t port, const std::string& dir) {
    config::Config cfg;
    cfg.node.listen_address = "127.0.0.1";
    cfg.node.listen_port = port;
    cfg.node.data_dir = dir;
    cfg.transport.connect_timeout_ms = 1000;
    cfg.transport.io_timeout_ms = 1500;
    return cfg;
}

void clean_test_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

} // namespace

TEST_CASE("E1-7: Unknown protocol version does not crash node", "[negative][transport]") {
    clean_test_dir("./test_neg_v_dir");
    auto cfg = make_test_cfg(22001, "./test_neg_v_dir");
    Node node(cfg);
    node.start();
    std::thread t([&]() { node.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Connect raw TCP socket and send frame with version 99
    asio::io_context io;
    asio::ip::tcp::socket raw_sock(io);
    raw_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 22001));

    Bytes bad_header(FRAME_HEADER_SIZE, 0);
    bad_header[0] = 99; // invalid version
    bad_header[1] = static_cast<uint8_t>(MessageType::PING);
    asio::write(raw_sock, asio::buffer(bad_header));

    // Allow node to process and close the offending connection
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // The node must still be alive and accept valid connections!
    asio::ip::tcp::socket valid_sock(io);
    asio::error_code ec;
    valid_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 22001), ec);
    CHECK_FALSE(ec);

    node.stop();
    if (t.joinable()) t.join();
    clean_test_dir("./test_neg_v_dir");
}

TEST_CASE("E1-7: Oversized payload length header does not crash node or allocate memory", "[negative][transport]") {
    clean_test_dir("./test_neg_oversized");
    auto cfg = make_test_cfg(22002, "./test_neg_oversized");
    Node node(cfg);
    node.start();
    std::thread t([&]() { node.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    asio::io_context io;
    asio::ip::tcp::socket raw_sock(io);
    raw_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 22002));

    Bytes bad_header(FRAME_HEADER_SIZE, 0);
    bad_header[0] = 1; // version 1
    bad_header[1] = static_cast<uint8_t>(MessageType::APP_MESSAGE);
    // Claim 10 MB payload (exceeding MAX_FRAME_PAYLOAD = 64 KB)
    uint32_t len = htonl(10 * 1024 * 1024);
    std::memcpy(bad_header.data() + 20, &len, 4);
    asio::write(raw_sock, asio::buffer(bad_header));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Node is healthy and accepting new peers
    asio::ip::tcp::socket valid_sock(io);
    asio::error_code ec;
    valid_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 22002), ec);
    CHECK_FALSE(ec);

    node.stop();
    if (t.joinable()) t.join();
    clean_test_dir("./test_neg_oversized");
}

TEST_CASE("E1-7: Abrupt disconnect in the middle of frame does not crash node", "[negative][transport]") {
    clean_test_dir("./test_neg_abrupt");
    auto cfg = make_test_cfg(22003, "./test_neg_abrupt");
    Node node(cfg);
    node.start();
    std::thread t([&]() { node.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    asio::io_context io;
    {
        asio::ip::tcp::socket raw_sock(io);
        raw_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 22003));
        // Send only 10 bytes of 24-byte header, then forcefully close socket
        Bytes partial_header(10, 0x01);
        asio::write(raw_sock, asio::buffer(partial_header));
        raw_sock.close();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Node continues operating normally
    asio::ip::tcp::socket valid_sock(io);
    asio::error_code ec;
    valid_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 22003), ec);
    CHECK_FALSE(ec);

    node.stop();
    if (t.joinable()) t.join();
    clean_test_dir("./test_neg_abrupt");
}

TEST_CASE("E1-6: Unsolicited PONG with random request_id is discarded", "[negative][correlation]") {
    clean_test_dir("./test_neg_pong");
    auto cfg = make_test_cfg(22004, "./test_neg_pong");
    Node node(cfg);
    node.start();
    std::thread t([&]() { node.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    asio::io_context io;
    asio::ip::tcp::socket raw_sock(io);
    raw_sock.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 22004));

    // Send unsolicited PONG with random RequestID that node never sent
    auto random_rid = RequestID::generate();
    Frame unsolicited_pong = Frame::make_pong(random_rid);

    auto kp = identity::Keypair::generate();
    nlohmann::json j;
    j["node_id"] = kp.node_id().to_hex();
    j["public_key"] = nlohmann::json::binary_t(
        {kp.public_key().begin(), kp.public_key().end()});
    j["listen_port"] = 22099;
    auto cbor = nlohmann::json::to_cbor(j);
    unsolicited_pong.payload.assign(cbor.begin(), cbor.end());

    auto wire = unsolicited_pong.serialize();
    asio::write(raw_sock, asio::buffer(wire));

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Node must NOT add this unrequested peer to its routing table
    auto found = node.routing_table().find(kp.node_id());
    CHECK_FALSE(found.has_value());

    node.stop();
    if (t.joinable()) t.join();
    clean_test_dir("./test_neg_pong");
}

TEST_CASE("E1-7: Unknown MessageType is rejected with FrameError::InvalidType", "[negative][transport]") {
    FrameParser parser(1, 65536);

    Bytes bad_frame(FRAME_HEADER_SIZE, 0);
    bad_frame[0] = 1;    // version 1
    bad_frame[1] = 0x99; // invalid / undefined MessageType

    parser.feed(bad_frame);
    auto res = parser.next_frame();
    REQUIRE_FALSE(res.has_value());
    CHECK(res.error() == FrameError::InvalidType);
}

TEST_CASE("E1-7: Write queue limit drops excess frames under overload", "[negative][transport]") {
    clean_test_dir("./test_neg_queue");
    auto cfg = make_test_cfg(22005, "./test_neg_queue");
    Node server(cfg);
    server.start();
    std::thread t([&]() { server.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    asio::io_context client_io;
    auto conn = TcpConnection::connect(client_io, "127.0.0.1", 22005);
    REQUIRE(conn != nullptr);
    conn->configure(1, 65536, std::chrono::milliseconds(5000), 3); // small queue limit = 3

    // Before client_io.run(), async_write callbacks don't drain the queue, so queue fills up
    Frame f = Frame::make_ping(RequestID::generate());
    CHECK(conn->send(f)); // 1st queued (and starts async_write)
    CHECK(conn->send(f)); // 2nd queued
    CHECK(conn->send(f)); // 3rd queued
    CHECK_FALSE(conn->send(f)); // 4th exceeds limit 3 -> rejected!

    conn->close();
    server.stop();
    if (t.joinable()) t.join();
    clean_test_dir("./test_neg_queue");
}

TEST_CASE("E1-3: TcpConnection::async_connect connects and handles unreachable host", "[transport][async]") {
    clean_test_dir("./test_async_conn");
    auto cfg = make_test_cfg(22006, "./test_async_conn");
    Node server(cfg);
    server.start();
    std::thread t([&]() { server.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    asio::io_context client_io;
    bool got_ok = false;
    bool got_fail = false;

    TcpConnection::async_connect(
        client_io, "127.0.0.1", 22006, std::chrono::milliseconds(2000),
        [&](TcpConnection::Ptr c) {
            got_ok = (c != nullptr && c->is_open());
            if (c) c->close();
        });

    TcpConnection::async_connect(
        client_io, "127.0.0.1", 22999, std::chrono::milliseconds(500),
        [&](TcpConnection::Ptr c) {
            got_fail = (c == nullptr);
        });

    client_io.run();
    CHECK(got_ok);
    CHECK(got_fail);

    server.stop();
    if (t.joinable()) t.join();
    clean_test_dir("./test_async_conn");
}

