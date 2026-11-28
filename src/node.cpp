/// @file node.cpp
/// @brief Top-level P2P node implementation.

#include "node.hpp"
#include "dht/dht_messages.hpp"
#include "identity/node_id.hpp"
#include "security/secure_session.hpp"
#include "security/ake_messages.hpp"

#include <sodium.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>

namespace p2p {

// ─── Construction ───────────────────────────────────────────────────

Node::Node(config::Config cfg)
    : config_(std::move(cfg))
{
}

// ─── Start ──────────────────────────────────────────────────────────

void Node::start() {
    // 1. Initialize libsodium
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    // 2. Load or generate identity
    auto data_dir = std::filesystem::path(config_.node.data_dir);
    keypair_ = std::make_unique<identity::Keypair>(
        identity::Keypair::load_or_generate(data_dir));

    // Initialize Kademlia routing table
    routing_table_ = std::make_unique<dht::RoutingTable>(
        node_id(), config_.dht.k_bucket_size);

    // Initialize DHT local record store (Stage 3: E3-2, E3-6)
    record_store_ = std::make_unique<dht::RecordStore>();

    // Initialize Tunnel Manager (Stage 5)
    auto profiler = std::make_shared<tunnel::RelayProfiler>(
        config_.tunnel.profiling.ema_alpha_latency,
        config_.tunnel.profiling.ema_alpha_success);
    auto pool = std::make_shared<tunnel::TunnelPool>(config_.tunnel.pool_size);
    tunnel_manager_ = std::make_unique<tunnel::TunnelManager>(
        node_id(), *keypair_, pool, profiler);

    // Initialize Application Services (Stage 6)
    auto download_dir = data_dir / "downloads";
    file_transfer_manager_ = std::make_unique<app::FileTransferManager>(download_dir);
    message_service_ = std::make_unique<app::MessageService>(node_id());

    spdlog::info("═══════════════════════════════════════════════");
    spdlog::info("  P2P Overlay Node starting");
    spdlog::info("  NodeID:  {}", node_id().to_hex());
    spdlog::info("  Listen:  {}:{}", config_.node.listen_address,
                 config_.node.listen_port);
    spdlog::info("  K:       {}", config_.dht.k_bucket_size);
    spdlog::info("  Alpha:   {}", config_.dht.alpha);
    spdlog::info("  R:       {}", config_.dht.replication);
    spdlog::info("═══════════════════════════════════════════════");

    // 3. Start TCP listener
    listener_ = transport::TcpListener::create(
        io_, config_.node.listen_address, config_.node.listen_port);

    listener_->start([this](transport::TcpConnection::Ptr conn) {
        on_accept(std::move(conn));
    });

    // 4. Connect to bootstrap peers
    for (const auto& peer_str : config_.bootstrap.peers) {
        auto colon = peer_str.rfind(':');
        if (colon == std::string::npos) {
            spdlog::warn("Invalid bootstrap peer format: {} (expected host:port)",
                         peer_str);
            continue;
        }
        auto host = peer_str.substr(0, colon);
        auto port = static_cast<uint16_t>(std::stoi(peer_str.substr(colon + 1)));
        connect_to_peer(host, port);
    }

    // 5. Trigger bootstrap self-lookup (E2-7) to discover neighbors and populate k-buckets
    if (!config_.bootstrap.peers.empty()) {
        auto timer = std::make_shared<asio::steady_timer>(io_, std::chrono::milliseconds(300));
        timer->async_wait([this, timer](const std::error_code& ec) {
            if (!ec) {
                spdlog::info("Triggering bootstrap self-lookup for NodeID {}", node_id().to_short_hex());
                async_lookup(node_id(), [](const std::vector<PeerInfo>& closest, const dht::LookupMetrics& m) {
                    spdlog::info("Bootstrap self-lookup finished: {} peers discovered (RPCs: {}, iterations: {})",
                                 closest.size(), m.total_rpcs, m.iterations);
                });
            }
        });
    }

    // 6. Schedule periodic record maintenance timers (E3-7)
    schedule_purge();
    schedule_republish();
}

// ─── Stop ───────────────────────────────────────────────────────────

void Node::stop() {
    spdlog::info("Node {} shutting down...", node_id().to_short_hex());

    if (purge_timer_) {
        purge_timer_->cancel();
    }
    if (republish_timer_) {
        republish_timer_->cancel();
    }

    if (listener_) {
        listener_->stop();
    }

    std::vector<transport::TcpConnection::Ptr> to_close;
    {
        std::lock_guard lock(conns_mutex_);
        to_close = std::move(connections_);
    }

    for (auto& conn : to_close) {
        conn->close("Node shutting down");
    }

    io_.stop();
    spdlog::info("Node {} stopped", node_id().to_short_hex());
}

// ─── Run ────────────────────────────────────────────────────────────

void Node::run() {
    spdlog::info("Node {} entering event loop", node_id().to_short_hex());
    io_.run();
}

// ─── Listen port ────────────────────────────────────────────────────

uint16_t Node::listen_port() const {
    return listener_ ? listener_->local_port() : 0;
}

// ─── Helpers (E1-2, E2-5) ───────────────────────────────────────────

std::string Node::advertised_host() const {
    if (!config_.node.advertise_address.empty()) {
        return config_.node.advertise_address;
    }
    if (config_.node.listen_address == "0.0.0.0" || config_.node.listen_address == "::") {
        return "127.0.0.1";
    }
    return config_.node.listen_address;
}

transport::Frame Node::make_frame(transport::MessageType type, const RequestID& rid) const {
    transport::Frame f(type, rid);
    f.version = static_cast<uint8_t>(config_.transport.protocol_version);
    return f;
}

// ─── Connect to peer (Async E1-3) ───────────────────────────────────

void Node::connect_to_peer(const std::string& host, uint16_t port) {
    spdlog::info("Connecting asynchronously to peer {}:{}...", host, port);

    transport::TcpConnection::async_connect(
        io_, host, port,
        std::chrono::milliseconds(config_.transport.connect_timeout_ms),
        [this, host, port](transport::TcpConnection::Ptr conn) {
            if (!conn) {
                spdlog::error("Failed to connect to {}:{}", host, port);
                return;
            }
            register_connection(conn);
            send_ping(conn);
        });
}

// ─── Ping with correlation & Ed25519 proof-of-possession (E1-6, E2-2, E2-5) ─

namespace {

Bytes build_ping_pong_sign_input(std::string_view tag,
                                 const NodeID& nid,
                                 const RequestID& rid,
                                 uint16_t port) {
    Bytes out;
    out.reserve(tag.size() + NodeID::SIZE + RequestID::SIZE + 2);
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), nid.data.begin(), nid.data.end());
    out.insert(out.end(), rid.data.begin(), rid.data.end());
    out.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(port & 0xFF));
    return out;
}

} // namespace

void Node::send_ping(transport::TcpConnection::Ptr conn,
                     std::optional<NodeID> expected_peer_id,
                     std::function<void(bool success)> on_result) {
    if (!conn || !conn->is_open()) {
        if (on_result) on_result(false);
        return;
    }

    auto rid = RequestID::generate();
    auto ping = transport::Frame::make_ping(rid);
    ping.version = static_cast<uint8_t>(config_.transport.protocol_version);

    auto sign_input = build_ping_pong_sign_input("PING:", node_id(), rid, config_.node.listen_port);
    auto sig = keypair_->sign(sign_input);

    nlohmann::json j;
    j["node_id"] = node_id().to_hex();
    j["public_key"] = nlohmann::json::binary_t(
        {keypair_->public_key().begin(), keypair_->public_key().end()});
    j["listen_port"] = config_.node.listen_port;
    j["signature"] = nlohmann::json::binary_t({sig.begin(), sig.end()});
    auto cbor = nlohmann::json::to_cbor(j);
    ping.payload.assign(cbor.begin(), cbor.end());

    auto timer = std::make_shared<asio::steady_timer>(
        io_, std::chrono::milliseconds(config_.transport.io_timeout_ms));

    {
        std::lock_guard lock(pending_pings_mutex_);
        pending_pings_[rid] = PendingPing{
            .rid = rid,
            .expected_peer_id = expected_peer_id,
            .callback = [timer, on_result](bool success) {
                timer->cancel();
                if (on_result) on_result(success);
            }
        };
    }

    timer->async_wait([this, rid, timer](const std::error_code& ec) {
        if (!ec) {
            std::function<void(bool)> cb;
            {
                std::lock_guard lock(pending_pings_mutex_);
                auto it = pending_pings_.find(rid);
                if (it != pending_pings_.end()) {
                    cb = std::move(it->second.callback);
                    pending_pings_.erase(it);
                }
            }
            if (cb) cb(false);
        }
    });

    conn->send(ping);
    spdlog::debug("Sent PING to {} (rid={})", conn->remote_endpoint_str(),
                  rid.to_hex().substr(0, 8));
}

// ─── Ping all ───────────────────────────────────────────────────────

void Node::ping_all() {
    std::vector<transport::TcpConnection::Ptr> active_conns;
    {
        std::lock_guard lock(conns_mutex_);
        active_conns = connections_;
    }
    for (auto& conn : active_conns) {
        send_ping(conn);
    }
}

// ─── Connection count ───────────────────────────────────────────────

std::size_t Node::connection_count() const {
    std::lock_guard lock(conns_mutex_);
    return connections_.size();
}

// ─── Connection handlers ────────────────────────────────────────────

void Node::on_accept(transport::TcpConnection::Ptr conn) {
    spdlog::info("Accepted connection from {}", conn->remote_endpoint_str());
    register_connection(conn);
}

void Node::register_connection(transport::TcpConnection::Ptr conn) {
    // Configure protocol version, max payload, I/O timeout, and write queue limit (E1-2, E1-3, E1-7)
    conn->configure(static_cast<uint8_t>(config_.transport.protocol_version),
                    config_.transport.max_frame_payload,
                    std::chrono::milliseconds(config_.transport.io_timeout_ms),
                    config_.transport.max_write_queue_size);

    // Set up frame handler
    auto weak_conn = std::weak_ptr<transport::TcpConnection>(conn);
    conn->set_frame_handler([this, weak_conn](const transport::Frame& frame) {
        if (auto c = weak_conn.lock()) {
            on_frame(c, frame);
        }
    });

    // Set up disconnect handler
    conn->set_disconnect_handler([this, weak_conn](const std::string& reason) {
        if (auto c = weak_conn.lock()) {
            on_disconnect(c, reason);
        }
    });

    // Start reading
    conn->start_reading();

    // Store the connection
    {
        std::lock_guard lock(conns_mutex_);
        connections_.push_back(conn);
    }
}

void Node::on_frame(transport::TcpConnection::Ptr conn,
                     const transport::Frame& frame) {
    using namespace transport;

    spdlog::debug("Frame from {}: type={}, payload={} bytes",
                  conn->remote_endpoint_str(),
                  message_type_name(frame.type),
                  frame.payload.size());

    // Correlate pending request by request_id (satisfies E2-5)
    std::function<void(const transport::Frame&)> pending_cb;
    if (frame.flags & FrameFlags::IS_RESPONSE) {
        std::lock_guard lock(pending_mutex_);
        auto it = pending_requests_.find(frame.request_id);
        if (it != pending_requests_.end()) {
            pending_cb = std::move(it->second);
            pending_requests_.erase(it);
        }
    }

    switch (frame.type) {
        case MessageType::PING: {
            // E2-2: Strict validation of claimed NodeID against public key
            // ONLY accept and answer PING if identity is fully verified!
            if (frame.payload.empty()) {
                spdlog::warn("Rejected PING with empty payload from {}", conn->remote_endpoint_str());
                conn->close("Empty PING payload");
                break;
            }

            try {
                auto j = nlohmann::json::from_cbor(frame.payload);
                if (!j.contains("node_id") || !j.contains("public_key")) {
                    spdlog::warn("Rejected PING missing identity fields from {}", conn->remote_endpoint_str());
                    conn->close("Missing identity in PING");
                    break;
                }

                NodeID peer_id;
                if (!NodeID::from_hex(j["node_id"].get<std::string>(), peer_id)) {
                    spdlog::warn("Malformed NodeID from {}", conn->remote_endpoint_str());
                    conn->close("Malformed NodeID");
                    break;
                }

                auto pk_bytes = j["public_key"].get<nlohmann::json::binary_t>();
                if (pk_bytes.size() != 32) {
                    spdlog::warn("Invalid public key size in PING from {}", conn->remote_endpoint_str());
                    conn->close("Invalid public key size");
                    break;
                }

                std::array<uint8_t, 32> pk;
                std::copy(pk_bytes.begin(), pk_bytes.end(), pk.begin());
                if (!identity::verify_node_id(peer_id, pk)) {
                    spdlog::warn("E2-2 REJECT: Claimed NodeID {} does NOT match public key from {}",
                                 peer_id.to_short_hex(), conn->remote_endpoint_str());
                    conn->close("NodeID mismatch with public key");
                    break;
                }

                // E2-2: Verify proof-of-possession signature in PING
                if (!j.contains("signature")) {
                    spdlog::warn("E2-2 REJECT: PING missing signature from {}", conn->remote_endpoint_str());
                    conn->close("Missing PING signature");
                    break;
                }
                auto sig_bytes = j["signature"].get<nlohmann::json::binary_t>();
                if (sig_bytes.size() != 64) {
                    spdlog::warn("E2-2 REJECT: Invalid signature size in PING from {}", conn->remote_endpoint_str());
                    conn->close("Invalid PING signature size");
                    break;
                }
                std::array<uint8_t, 64> sig{};
                std::copy(sig_bytes.begin(), sig_bytes.end(), sig.begin());
                uint16_t peer_port = j.value("listen_port", conn->remote_port());
                auto ping_sign_input = build_ping_pong_sign_input("PING:", peer_id, frame.request_id, peer_port);
                if (!identity::Keypair::verify(sig, ping_sign_input.data(), ping_sign_input.size(), pk)) {
                    spdlog::warn("E2-2 REJECT: Invalid Ed25519 signature in PING from {}", conn->remote_endpoint_str());
                    conn->close("Invalid PING signature");
                    break;
                }

                // VALIDATION PASSED: Now and only now set peer_id, add contact, send PONG
                conn->set_peer_id(peer_id);
                spdlog::info("PING from verified NodeID={}", peer_id.to_short_hex());

                PeerInfo peer{
                    .node_id = peer_id,
                    .address = PeerAddress{
                        .host = conn->remote_ip(),
                        .port = peer_port
                    }
                };
                add_contact(peer);

                // Send signed PONG
                auto pong = Frame::make_pong(frame.request_id);
                pong.version = static_cast<uint8_t>(config_.transport.protocol_version);

                auto pong_sign_input = build_ping_pong_sign_input(
                    "PONG:", node_id(), frame.request_id, config_.node.listen_port);
                auto pong_sig = keypair_->sign(pong_sign_input);

                nlohmann::json resp_j;
                resp_j["node_id"] = node_id().to_hex();
                resp_j["public_key"] = nlohmann::json::binary_t(
                    {keypair_->public_key().begin(), keypair_->public_key().end()});
                resp_j["listen_port"] = config_.node.listen_port;
                resp_j["signature"] = nlohmann::json::binary_t({pong_sig.begin(), pong_sig.end()});
                auto cbor = nlohmann::json::to_cbor(resp_j);
                pong.payload.assign(cbor.begin(), cbor.end());

                conn->send(pong);
            } catch (const std::exception& e) {
                spdlog::warn("Failed to parse PING payload from {}: {}", conn->remote_endpoint_str(), e.what());
                conn->close("Invalid CBOR in PING");
            }
            break;
        }

        case MessageType::PONG: {
            // E1-6, E2-5: Correlate PONG by request_id. Unsolicited PONGs must be rejected!
            PendingPing ping_info;
            bool found_pending = false;
            {
                std::lock_guard lock(pending_pings_mutex_);
                auto it = pending_pings_.find(frame.request_id);
                if (it != pending_pings_.end()) {
                    ping_info = it->second;
                    pending_pings_.erase(it);
                    found_pending = true;
                }
            }

            if (!found_pending) {
                spdlog::warn("E1-6 REJECT: Unsolicited or mismatched PONG (request_id={}) from {}",
                             frame.request_id.to_hex().substr(0, 8), conn->remote_endpoint_str());
                break;
            }

            // Strict validation of PONG payload
            if (frame.payload.empty()) {
                spdlog::warn("Rejected PONG with empty payload from {}", conn->remote_endpoint_str());
                if (ping_info.callback) ping_info.callback(false);
                break;
            }

            try {
                auto j = nlohmann::json::from_cbor(frame.payload);
                if (!j.contains("node_id") || !j.contains("public_key")) {
                    spdlog::warn("Rejected PONG missing identity fields from {}", conn->remote_endpoint_str());
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }

                NodeID peer_id;
                if (!NodeID::from_hex(j["node_id"].get<std::string>(), peer_id)) {
                    spdlog::warn("Malformed NodeID in PONG from {}", conn->remote_endpoint_str());
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }

                auto pk_bytes = j["public_key"].get<nlohmann::json::binary_t>();
                if (pk_bytes.size() != 32) {
                    spdlog::warn("Invalid public key size in PONG from {}", conn->remote_endpoint_str());
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }

                std::array<uint8_t, 32> pk;
                std::copy(pk_bytes.begin(), pk_bytes.end(), pk.begin());
                if (!identity::verify_node_id(peer_id, pk)) {
                    spdlog::warn("E2-2 REJECT: Claimed NodeID {} does NOT match public key in PONG from {}",
                                 peer_id.to_short_hex(), conn->remote_endpoint_str());
                    conn->close("NodeID mismatch with public key");
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }

                // E2-2: Verify proof-of-possession signature in PONG
                if (!j.contains("signature")) {
                    spdlog::warn("E2-2 REJECT: PONG missing signature from {}", conn->remote_endpoint_str());
                    conn->close("Missing PONG signature");
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }
                auto sig_bytes = j["signature"].get<nlohmann::json::binary_t>();
                if (sig_bytes.size() != 64) {
                    spdlog::warn("E2-2 REJECT: Invalid signature size in PONG from {}", conn->remote_endpoint_str());
                    conn->close("Invalid PONG signature size");
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }
                std::array<uint8_t, 64> sig{};
                std::copy(sig_bytes.begin(), sig_bytes.end(), sig.begin());
                uint16_t peer_port = j.value("listen_port", conn->remote_port());
                auto pong_sign_input = build_ping_pong_sign_input("PONG:", peer_id, frame.request_id, peer_port);
                if (!identity::Keypair::verify(sig, pong_sign_input.data(), pong_sign_input.size(), pk)) {
                    spdlog::warn("E2-2 REJECT: Invalid Ed25519 signature in PONG from {}", conn->remote_endpoint_str());
                    conn->close("Invalid PONG signature");
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }

                // Check expected NodeID if this PING targeted a specific node (E1-6)
                if (ping_info.expected_peer_id && peer_id != *ping_info.expected_peer_id) {
                    spdlog::warn("E1-6 REJECT: Responder NodeID {} does NOT match expected NodeID {}",
                                 peer_id.to_short_hex(), ping_info.expected_peer_id->to_short_hex());
                    conn->close("Unexpected responder NodeID");
                    if (ping_info.callback) ping_info.callback(false);
                    break;
                }

                // VALIDATION PASSED
                conn->set_peer_id(peer_id);
                spdlog::info("PONG from verified NodeID={}", peer_id.to_short_hex());

                PeerInfo peer{
                    .node_id = peer_id,
                    .address = PeerAddress{
                        .host = conn->remote_ip(),
                        .port = peer_port
                    }
                };
                add_contact(peer);

                if (ping_info.callback) {
                    ping_info.callback(true);
                }
            } catch (const std::exception& e) {
                spdlog::warn("Failed to parse PONG payload from {}: {}", conn->remote_endpoint_str(), e.what());
                if (ping_info.callback) ping_info.callback(false);
            }
            break;
        }

        case MessageType::FIND_NODE_REQUEST: {
            dht::FindNodeRequest req;
            if (dht::deserialize_find_node_request(frame.payload, req)) {
                spdlog::debug("FIND_NODE_REQUEST for target {} from {}",
                              req.target.to_short_hex(),
                              req.sender.node_id.to_short_hex());
                // E2-2 & E2-5: Only update routing table if connection identity is verified,
                // and derive IP from TCP socket instead of trusting req.sender.address.host
                if (conn->peer_id() && *conn->peer_id() == req.sender.node_id) {
                    PeerInfo verified_peer{
                        .node_id = *conn->peer_id(),
                        .address = PeerAddress{
                            .host = conn->remote_ip(),
                            .port = req.sender.address.port > 0 ? req.sender.address.port : conn->remote_port()
                        }
                    };
                    add_contact(verified_peer);
                }

                auto closest = routing_table_->find_closest(req.target, config_.dht.k_bucket_size);

                dht::FindNodeResponse resp{.closest_nodes = std::move(closest)};
                auto cbor_payload = dht::serialize_find_node_response(resp);

                auto resp_frame = make_frame(MessageType::FIND_NODE_RESPONSE, frame.request_id);
                resp_frame.flags |= FrameFlags::IS_RESPONSE;
                resp_frame.payload = std::move(cbor_payload);
                conn->send(resp_frame);
            } else {
                spdlog::warn("Malformed FIND_NODE_REQUEST from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::FIND_NODE_RESPONSE: {
            dht::FindNodeResponse resp;
            if (dht::deserialize_find_node_response(frame.payload, resp)) {
                spdlog::debug("FIND_NODE_RESPONSE from {} with {} contacts (candidates only, verified on direct contact)",
                              conn->remote_endpoint_str(),
                              resp.closest_nodes.size());
            } else {
                spdlog::warn("Malformed FIND_NODE_RESPONSE from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::STORE_REQUEST: {
            dht::StoreRequest req;
            if (dht::deserialize_store_request(frame.payload, req)) {
                spdlog::info("STORE_REQUEST for key {} from {}",
                             req.key.to_short_hex(),
                             req.sender.node_id.to_short_hex());
                if (conn->peer_id() && *conn->peer_id() == req.sender.node_id) {
                    PeerInfo verified_peer{
                        .node_id = *conn->peer_id(),
                        .address = PeerAddress{
                            .host = conn->remote_ip(),
                            .port = req.sender.address.port > 0 ? req.sender.address.port : conn->remote_port()
                        }
                    };
                    add_contact(verified_peer);
                }

                uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                auto err = record_store_->put(
                    req.key, req.record, now,
                    static_cast<std::size_t>(config_.dht.max_record_size));
                bool ok = (err == dht::RecordValidationError::None);
                if (!ok) {
                    spdlog::warn("STORE_REQUEST rejected: {}", dht::record_validation_error_name(err));
                }

                dht::StoreResponse resp{
                    .key = req.key,
                    .success = ok,
                    .message = ok ? "Stored successfully" : dht::record_validation_error_name(err)
                };
                auto cbor_payload = dht::serialize_store_response(resp);

                auto resp_frame = make_frame(MessageType::STORE_RESPONSE, frame.request_id);
                resp_frame.flags |= FrameFlags::IS_RESPONSE;
                resp_frame.payload = std::move(cbor_payload);
                conn->send(resp_frame);
            } else {
                spdlog::warn("Malformed STORE_REQUEST from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::STORE_RESPONSE: {
            spdlog::debug("STORE_RESPONSE received from {}", conn->remote_endpoint_str());
            break;
        }

        case MessageType::FIND_VALUE_REQUEST: {
            dht::FindValueRequest req;
            if (dht::deserialize_find_value_request(frame.payload, req)) {
                spdlog::info("FIND_VALUE_REQUEST for key {} from {}",
                             req.key.to_short_hex(),
                             req.sender.node_id.to_short_hex());
                if (conn->peer_id() && *conn->peer_id() == req.sender.node_id) {
                    PeerInfo verified_peer{
                        .node_id = *conn->peer_id(),
                        .address = PeerAddress{
                            .host = conn->remote_ip(),
                            .port = req.sender.address.port > 0 ? req.sender.address.port : conn->remote_port()
                        }
                    };
                    add_contact(verified_peer);
                }

                uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                auto rec_opt = record_store_->get(req.key, now);

                dht::FindValueResponse resp;
                resp.key = req.key;
                if (rec_opt.has_value()) {
                    resp.has_value = true;
                    resp.record = rec_opt;
                    spdlog::info("FIND_VALUE_REQUEST for key {}: value found and returned",
                                 req.key.to_short_hex());
                } else {
                    resp.has_value = false;
                    resp.closest_nodes = routing_table_->find_closest(req.key, config_.dht.k_bucket_size);
                    spdlog::info("FIND_VALUE_REQUEST for key {}: value not found, returning {} closest nodes",
                                 req.key.to_short_hex(), resp.closest_nodes.size());
                }

                auto cbor_payload = dht::serialize_find_value_response(resp);
                auto resp_frame = make_frame(MessageType::FIND_VALUE_RESPONSE, frame.request_id);
                resp_frame.flags |= FrameFlags::IS_RESPONSE;
                resp_frame.payload = std::move(cbor_payload);
                conn->send(resp_frame);
            } else {
                spdlog::warn("Malformed FIND_VALUE_REQUEST from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::FIND_VALUE_RESPONSE: {
            spdlog::debug("FIND_VALUE_RESPONSE received from {}", conn->remote_endpoint_str());
            break;
        }

        case MessageType::HANDSHAKE_INIT: {
            security::HandshakeInit init;
            if (security::deserialize_handshake_init(frame.payload, init)) {
                spdlog::info("Received HANDSHAKE_INIT from claimed NodeID={}", init.node_id.to_short_hex());
                auto session = std::make_shared<security::SecureSession>();
                auto resp = session->process_handshake_init(init, *keypair_);
                if (resp) {
                    conn->set_secure_session(session);
                    auto resp_payload = security::serialize_handshake_response(*resp);
                    auto resp_frame = make_frame(MessageType::HANDSHAKE_RESPONSE, frame.request_id);
                    resp_frame.flags |= FrameFlags::IS_RESPONSE;
                    resp_frame.payload = std::move(resp_payload);
                    conn->send(resp_frame);
                    spdlog::info("Sent HANDSHAKE_RESPONSE for session {}", resp->session_id.to_short_hex());
                } else {
                    spdlog::warn("Rejected HANDSHAKE_INIT from {}", conn->remote_endpoint_str());
                    conn->close("HANDSHAKE_INIT validation failed");
                }
            } else {
                spdlog::warn("Malformed HANDSHAKE_INIT from {}", conn->remote_endpoint_str());
                conn->close("Malformed HANDSHAKE_INIT");
            }
            break;
        }

        case MessageType::HANDSHAKE_RESPONSE: {
            spdlog::debug("HANDSHAKE_RESPONSE received from {}", conn->remote_endpoint_str());
            break;
        }

        case MessageType::HANDSHAKE_COMPLETE: {
            security::HandshakeComplete comp;
            if (security::deserialize_handshake_complete(frame.payload, comp)) {
                auto session = conn->secure_session();
                if (session && session->process_handshake_complete(comp)) {
                    conn->set_peer_id(session->peer_node_id());
                    spdlog::info("HANDSHAKE_COMPLETE verified: Secure session {} ACTIVE with peer {}",
                                 session->session_id().to_short_hex(),
                                 session->peer_node_id().to_short_hex());
                } else {
                    spdlog::warn("Invalid HANDSHAKE_COMPLETE from {}", conn->remote_endpoint_str());
                    conn->close("HANDSHAKE_COMPLETE validation failed");
                }
            } else {
                spdlog::warn("Malformed HANDSHAKE_COMPLETE from {}", conn->remote_endpoint_str());
                conn->close("Malformed HANDSHAKE_COMPLETE");
            }
            break;
        }

        // ─── Tunnel Management (Stage 5) ───────────────────────────
        case MessageType::TUNNEL_BUILD: {
            tunnel::TunnelBuildMsg build_msg;
            if (tunnel::deserialize_tunnel_build(frame.payload, build_msg)) {
                NodeID sender_id = conn->peer_id().value_or(NodeID{});
                auto res = tunnel_manager_->handle_tunnel_build(sender_id, build_msg);
                if (std::holds_alternative<tunnel::TunnelBuildOkMsg>(res)) {
                    auto ok_payload = tunnel::serialize_tunnel_build_ok(std::get<tunnel::TunnelBuildOkMsg>(res));
                    auto ok_frame = make_frame(MessageType::TUNNEL_BUILD_OK, frame.request_id);
                    ok_frame.flags |= FrameFlags::IS_RESPONSE;
                    ok_frame.payload = std::move(ok_payload);
                    conn->send(ok_frame);
                } else {
                    auto fail_payload = tunnel::serialize_tunnel_build_fail(std::get<tunnel::TunnelBuildFailMsg>(res));
                    auto fail_frame = make_frame(MessageType::TUNNEL_BUILD_FAIL, frame.request_id);
                    fail_frame.flags |= FrameFlags::IS_RESPONSE;
                    fail_frame.payload = std::move(fail_payload);
                    conn->send(fail_frame);
                }
            } else {
                spdlog::warn("Malformed TUNNEL_BUILD from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::TUNNEL_BUILD_OK: {
            tunnel::TunnelBuildOkMsg ok_msg;
            if (tunnel::deserialize_tunnel_build_ok(frame.payload, ok_msg)) {
                NodeID sender_id = conn->peer_id().value_or(NodeID{});
                tunnel_manager_->handle_tunnel_build_ok(sender_id, ok_msg);
            }
            break;
        }

        case MessageType::TUNNEL_BUILD_FAIL: {
            tunnel::TunnelBuildFailMsg fail_msg;
            if (tunnel::deserialize_tunnel_build_fail(frame.payload, fail_msg)) {
                NodeID sender_id = conn->peer_id().value_or(NodeID{});
                tunnel_manager_->handle_tunnel_build_fail(sender_id, fail_msg);
            }
            break;
        }

        case MessageType::TUNNEL_DATA: {
            tunnel::TunnelDataMsg data_msg;
            if (tunnel::deserialize_tunnel_data(frame.payload, data_msg)) {
                NodeID sender_id = conn->peer_id().value_or(NodeID{});
                auto peeled = tunnel_manager_->handle_tunnel_data(sender_id, data_msg);
                if (peeled) {
                    if (!peeled->is_terminal) {
                        // Forward to next relay
                        connect_to_peer(peeled->next_hop_address.host, peeled->next_hop_address.port);
                        auto next_conn = get_connection_to(peeled->next_hop_node_id);
                        if (!next_conn) {
                            // Find connection by address
                            std::lock_guard<std::mutex> lock(conns_mutex_);
                            for (auto& c : connections_) {
                                if (c->remote_endpoint_str().find(peeled->next_hop_address.host) != std::string::npos) {
                                    next_conn = c;
                                    break;
                                }
                            }
                        }
                        if (next_conn) {
                            tunnel::TunnelDataMsg fwd_msg;
                            fwd_msg.circuit_id = data_msg.circuit_id;
                            fwd_msg.sequence_number = data_msg.sequence_number;
                            fwd_msg.onion_payload = std::move(peeled->payload);
                            auto fwd_frame = make_frame(MessageType::TUNNEL_DATA, RequestID::generate());
                            fwd_frame.payload = tunnel::serialize_tunnel_data(fwd_msg);
                            next_conn->send(fwd_frame);
                        } else {
                            spdlog::warn("Cannot forward TUNNEL_DATA: next hop {} unreachable",
                                         peeled->next_hop_node_id.to_short_hex());
                        }
                    } else {
                        // Terminal hop: send ACK back to previous hop
                        tunnel::TunnelAckMsg ack;
                        ack.circuit_id = data_msg.circuit_id;
                        ack.sequence_number = data_msg.sequence_number;
                        ack.success = true;
                        auto ack_frame = make_frame(MessageType::TUNNEL_ACK, frame.request_id);
                        ack_frame.payload = tunnel::serialize_tunnel_ack(ack);
                        conn->send(ack_frame);
                    }
                }
            } else {
                spdlog::warn("Malformed TUNNEL_DATA from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::TUNNEL_ACK: {
            spdlog::debug("TUNNEL_ACK received from {}", conn->remote_endpoint_str());
            break;
        }

        case MessageType::TUNNEL_CLOSE: {
            tunnel::TunnelCloseMsg close_msg;
            if (tunnel::deserialize_tunnel_close(frame.payload, close_msg)) {
                tunnel_manager_->close_tunnel(close_msg.circuit_id);
            }
            break;
        }

        // ─── Application Services (Stage 6) ────────────────────────
        case MessageType::APP_MESSAGE: {
            app::AppMessage msg;
            if (app::deserialize_app_message(frame.payload, msg)) {
                spdlog::info("APP_MESSAGE from {}: {} bytes", msg.sender_id.to_short_hex(), msg.text.size());
                auto ack = message_service_->handle_app_message(msg);
                auto ack_bytes = app::serialize_app_ack(ack);
                auto ack_frame = make_frame(MessageType::APP_ACK, frame.request_id);
                ack_frame.flags |= FrameFlags::IS_RESPONSE;
                ack_frame.payload = std::move(ack_bytes);
                conn->send(ack_frame);
            } else {
                spdlog::warn("Malformed APP_MESSAGE from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::APP_ACK: {
            app::AppAck ack;
            if (app::deserialize_app_ack(frame.payload, ack)) {
                spdlog::debug("APP_ACK from {}: ok={}", ack.sender_id.to_short_hex(), ack.ok);
                message_service_->handle_app_ack(ack);
            } else {
                spdlog::warn("Malformed APP_ACK from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::APP_FILE_META: {
            app::FileMeta meta;
            if (app::deserialize_file_meta(frame.payload, meta)) {
                spdlog::info("APP_FILE_META from {}: file='{}', size={} B, chunks={}",
                             meta.sender_id.to_short_hex(), meta.filename, meta.file_size, meta.total_chunks);
                file_transfer_manager_->handle_file_meta(meta);
            } else {
                spdlog::warn("Malformed APP_FILE_META from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::APP_FILE_BLOCK: {
            app::FileBlock block;
            if (app::deserialize_file_block(frame.payload, block)) {
                auto ack_opt = file_transfer_manager_->handle_file_block(
                    block,
                    [this, conn](const NodeID& target, const app::FileComplete& comp) {
                        auto comp_bytes = app::serialize_file_complete(comp);
                        auto comp_frame = make_frame(MessageType::APP_FILE_COMPLETE, RequestID::generate());
                        comp_frame.payload = std::move(comp_bytes);
                        conn->send(comp_frame);
                    });

                if (ack_opt) {
                    auto ack_bytes = app::serialize_file_ack(*ack_opt);
                    auto ack_frame = make_frame(MessageType::APP_FILE_ACK, frame.request_id);
                    ack_frame.flags |= FrameFlags::IS_RESPONSE;
                    ack_frame.payload = std::move(ack_bytes);
                    conn->send(ack_frame);
                }
            } else {
                spdlog::warn("Malformed APP_FILE_BLOCK from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::APP_FILE_ACK: {
            app::FileAck ack;
            if (app::deserialize_file_ack(frame.payload, ack)) {
                file_transfer_manager_->handle_file_ack(
                    ack,
                    [this, conn](const NodeID& target, const app::FileBlock& blk) {
                        auto blk_bytes = app::serialize_file_block(blk);
                        auto blk_frame = make_frame(MessageType::APP_FILE_BLOCK, RequestID::generate());
                        blk_frame.payload = std::move(blk_bytes);
                        conn->send(blk_frame);
                    });
            } else {
                spdlog::warn("Malformed APP_FILE_ACK from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::APP_FILE_COMPLETE: {
            app::FileComplete comp;
            if (app::deserialize_file_complete(frame.payload, comp)) {
                file_transfer_manager_->handle_file_complete(comp);
            } else {
                spdlog::warn("Malformed APP_FILE_COMPLETE from {}", conn->remote_endpoint_str());
            }
            break;
        }

        case MessageType::ERROR: {
            if (!frame.payload.empty()) {
                try {
                    auto j = nlohmann::json::from_cbor(frame.payload);
                    spdlog::warn("ERROR from {}: {}",
                                 conn->remote_endpoint_str(),
                                 j.value("error", "unknown"));
                } catch (...) {
                    spdlog::warn("ERROR from {} (unparseable payload)",
                                 conn->remote_endpoint_str());
                }
            }
            break;
        }

        default:
            spdlog::debug("Unhandled message type {} from {}",
                          message_type_name(frame.type),
                          conn->remote_endpoint_str());
            break;
    }

    if (pending_cb) {
        pending_cb(frame);
    }
}

void Node::on_disconnect(transport::TcpConnection::Ptr conn,
                          const std::string& reason) {
    auto peer_str = conn->peer_id()
        ? conn->peer_id()->to_short_hex()
        : conn->remote_endpoint_str();

    spdlog::info("Disconnected from {}: {}", peer_str, reason);

    // Remove from connections list
    std::lock_guard lock(conns_mutex_);
    connections_.erase(
        std::remove(connections_.begin(), connections_.end(), conn),
        connections_.end());
}

std::vector<PeerInfo> Node::find_closest_nodes(const NodeID& target, std::size_t count) const {
    if (!routing_table_) return {};
    return routing_table_->find_closest(target, count);
}

void Node::send_find_node(transport::TcpConnection::Ptr conn, const NodeID& target) {
    if (!conn) return;

    dht::FindNodeRequest req{
        .target = target,
        .sender = PeerInfo{
            .node_id = node_id(),
            .address = PeerAddress{
                .host = advertised_host(),
                .port = config_.node.listen_port
            }
        }
    };

    auto cbor_payload = dht::serialize_find_node_request(req);
    auto rid = RequestID::generate();
    auto frame = make_frame(transport::MessageType::FIND_NODE_REQUEST, rid);
    frame.payload = std::move(cbor_payload);
    conn->send(frame);
    spdlog::debug("Sent FIND_NODE_REQUEST to {} for target {}",
                  conn->remote_endpoint_str(),
                  target.to_short_hex());
}

transport::TcpConnection::Ptr Node::get_connection_to(const NodeID& id) {
    std::lock_guard lock(conns_mutex_);
    for (const auto& conn : connections_) {
        if (conn->peer_id() && *conn->peer_id() == id && conn->is_open()) {
            return conn;
        }
    }
    return nullptr;
}

void Node::async_lookup(const NodeID& target,
                        std::function<void(const std::vector<PeerInfo>&, const dht::LookupMetrics&)> callback) {
    auto session = std::make_shared<dht::LookupSession>(
        target, node_id(), config_.dht.alpha, config_.dht.k_bucket_size);

    // Initial candidates from local routing table
    auto initial_candidates = routing_table_->find_closest(target, config_.dht.alpha * 2);
    session->add_candidates(initial_candidates);

    // Recursive step function
    auto step_func = std::make_shared<std::function<void()>>();
    *step_func = [this, session, callback, step_func]() {
        if (session->is_complete()) {
            if (callback) {
                callback(session->get_closest(config_.dht.k_bucket_size), session->metrics());
            }
            return;
        }

        auto queries = session->pick_next_queries();
        if (queries.empty()) {
            if (session->in_flight_count() == 0 && callback) {
                callback(session->get_closest(config_.dht.k_bucket_size), session->metrics());
            }
            return;
        }

        for (const auto& peer : queries) {
            auto send_lookup_query = [this, session, step_func](const PeerInfo& target_peer,
                                                                 transport::TcpConnection::Ptr c) {
                dht::FindNodeRequest req{
                    .target = session->target(),
                    .sender = PeerInfo{
                        .node_id = node_id(),
                        .address = PeerAddress{
                            .host = advertised_host(),
                            .port = config_.node.listen_port
                        }
                    }
                };

                auto payload = dht::serialize_find_node_request(req);
                auto rid = RequestID::generate();
                auto req_frame = make_frame(transport::MessageType::FIND_NODE_REQUEST, rid);
                req_frame.payload = std::move(payload);

                auto timer = std::make_shared<asio::steady_timer>(
                    io_, std::chrono::milliseconds(config_.transport.io_timeout_ms));
                auto peer_id = target_peer.node_id;

                {
                    std::lock_guard lock(pending_mutex_);
                    pending_requests_[rid] = [session, peer_id, this, timer = timer, step_func](const transport::Frame& resp_frame) {
                        timer->cancel();
                        dht::FindNodeResponse resp;
                        if (dht::deserialize_find_node_response(resp_frame.payload, resp)) {
                            // E2-2: Pass candidates to lookup session; contacts are added to
                            // routing_table_ only after direct PING/PONG key-ownership verification
                            session->on_response(peer_id, resp.closest_nodes);
                        } else {
                            session->on_failure(peer_id);
                        }
                        (*step_func)();
                    };
                }

                timer->async_wait([session, peer_id, rid, this, step_func](const std::error_code& ec) {
                    if (!ec) {
                        {
                            std::lock_guard lock(pending_mutex_);
                            pending_requests_.erase(rid);
                        }
                        session->on_failure(peer_id);
                        (*step_func)();
                    }
                });

                c->send(req_frame);
            };

            auto conn = get_connection_to(peer.node_id);
            if (conn) {
                send_lookup_query(peer, conn);
            } else {
                // E1-3 & E2-2: Async connect, then verify key ownership via signed PING/PONG before querying
                transport::TcpConnection::async_connect(
                    io_, peer.address.host, peer.address.port,
                    std::chrono::milliseconds(config_.transport.connect_timeout_ms),
                    [this, peer, session, step_func, send_lookup_query](transport::TcpConnection::Ptr new_conn) {
                        if (!new_conn) {
                            session->on_failure(peer.node_id);
                            (*step_func)();
                            return;
                        }
                        register_connection(new_conn);
                        send_ping(new_conn, peer.node_id, [this, peer, new_conn, session, step_func, send_lookup_query](bool ping_ok) {
                            if (!ping_ok) {
                                session->on_failure(peer.node_id);
                                (*step_func)();
                                return;
                            }
                            send_lookup_query(peer, new_conn);
                        });
                    });
            }
        }
    };

    // Kick off first lookup step
    (*step_func)();
}

std::string Node::export_routing_table_json() const {
    if (!routing_table_) return "{}";
    return routing_table_->to_json();
}

void Node::add_contact(const PeerInfo& peer) {
    if (!routing_table_) return;
    bool added = routing_table_->add_or_update(peer);
    if (!added) {
        // Bucket is full! (E2-4)
        // Probe the least recently seen contact in this bucket
        auto lru = routing_table_->least_recently_seen_in_bucket(peer.node_id);
        if (lru && lru->node_id != peer.node_id) {
            probe_lru_contact(*lru);
        }
    }
}

void Node::probe_lru_contact(const PeerInfo& lru) {
    spdlog::debug("Probing LRU contact {} in full bucket", lru.node_id.to_short_hex());
    auto do_probe = [this, lru_id = lru.node_id](transport::TcpConnection::Ptr c) {
        if (!c) {
            spdlog::info("LRU contact {} unreachable, evicting from bucket", lru_id.to_short_hex());
            routing_table_->remove(lru_id);
            return;
        }
        send_ping(c, lru_id, [this, lru_id](bool success) {
            if (success) {
                spdlog::debug("LRU contact {} responded to probe, keeping as MRU", lru_id.to_short_hex());
                routing_table_->touch(lru_id);
            } else {
                spdlog::info("LRU contact {} failed probe, evicting from bucket", lru_id.to_short_hex());
                routing_table_->remove(lru_id);
            }
        });
    };

    auto conn = get_connection_to(lru.node_id);
    if (conn) {
        do_probe(conn);
    } else {
        transport::TcpConnection::async_connect(
            io_, lru.address.host, lru.address.port,
            std::chrono::milliseconds(config_.transport.connect_timeout_ms),
            [this, do_probe](transport::TcpConnection::Ptr new_conn) {
                if (new_conn) {
                    register_connection(new_conn);
                }
                do_probe(new_conn);
            });
    }
}

dht::NodeRecord Node::create_self_record(const std::string& alias) {
    if (!keypair_) {
        throw std::runtime_error("Cannot create record before node start (no keypair)");
    }
    uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    dht::NodeRecord rec;
    rec.node_id = node_id();
    rec.identity_public_key = keypair_->public_key();
    rec.addresses = {
        PeerAddress{
            .host = advertised_host(),
            .port = config_.node.listen_port
        }
    };
    rec.sequence_number = ++record_seq_;
    rec.issued_at = now;
    rec.expires_at = now + config_.dht.record_ttl_sec;
    rec.alias = alias;
    rec.sign(*keypair_);

    if (!alias.empty()) {
        node_alias_ = alias;
    }

    return rec;
}

void Node::publish_record(const NodeID& key,
                          const dht::NodeRecord& record,
                          std::function<void(bool success, std::size_t acks)> callback) {
    uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    auto v_err = record.validate(now);
    if (v_err != dht::RecordValidationError::None) {
        spdlog::warn("Refusing to publish invalid record: {}",
                     dht::record_validation_error_name(v_err));
        if (callback) callback(false, 0);
        return;
    }

    spdlog::info("E3-7: PUBLISH start key={}, seq={}, ttl={}s",
                 key.to_short_hex(), record.sequence_number,
                 record.expires_at > now ? (record.expires_at - now) : 0);

    // Find R closest nodes across the DHT (E3-4)
    async_lookup(key, [this, key, record, callback, now](const std::vector<PeerInfo>& closest,
                                                         const dht::LookupMetrics&) {
        std::size_t R = static_cast<std::size_t>(std::max(1, config_.dht.replication));

        // Build candidate set = closest from DHT + self, sorted strictly by XOR distance to key
        std::vector<PeerInfo> candidates = closest;
        bool has_self = false;
        for (const auto& p : candidates) {
            if (p.node_id == node_id()) {
                has_self = true;
                break;
            }
        }
        if (!has_self) {
            candidates.push_back(PeerInfo{
                .node_id = node_id(),
                .address = PeerAddress{advertised_host(), config_.node.listen_port}
            });
        }

        std::sort(candidates.begin(), candidates.end(), [&key](const PeerInfo& a, const PeerInfo& b) {
            return a.node_id.xor_distance(key) < b.node_id.xor_distance(key);
        });
        if (candidates.size() > R) {
            candidates.resize(R);
        }

        bool local_is_keeper = false;
        std::vector<PeerInfo> remote_keepers;
        for (const auto& p : candidates) {
            if (p.node_id == node_id()) {
                local_is_keeper = true;
            } else {
                remote_keepers.push_back(p);
            }
        }

        auto acks = std::make_shared<std::size_t>(0);
        if (local_is_keeper) {
            auto put_err = record_store_->put(
                key, record, now, static_cast<std::size_t>(config_.dht.max_record_size));
            if (put_err == dht::RecordValidationError::None) {
                (*acks)++;
            }
        }

        std::size_t total_keepers = candidates.size();
        auto remaining = std::make_shared<std::size_t>(remote_keepers.size());
        auto finished = std::make_shared<bool>(false);
        std::size_t required_quorum = std::min<std::size_t>(2, total_keepers);

        spdlog::info("Publishing record for key {} to {} closest keepers (local_keeper={}, total={}, quorum={})",
                     key.to_short_hex(), remote_keepers.size(), local_is_keeper, total_keepers, required_quorum);

        if (remote_keepers.empty()) {
            if (callback) callback(*acks >= required_quorum, *acks);
            return;
        }

        auto send_store_to_keeper = [this, key, record, acks, remaining, finished, required_quorum, callback]
            (const PeerInfo& target, transport::TcpConnection::Ptr conn) {
            dht::StoreRequest req{
                .key = key,
                .record = record,
                .sender = PeerInfo{
                    .node_id = node_id(),
                    .address = PeerAddress{
                        .host = advertised_host(),
                        .port = config_.node.listen_port
                    }
                }
            };

            auto payload = dht::serialize_store_request(req);
            auto rid = RequestID::generate();
            auto req_frame = make_frame(transport::MessageType::STORE_REQUEST, rid);
            req_frame.payload = std::move(payload);

            auto timer = std::make_shared<asio::steady_timer>(
                io_, std::chrono::milliseconds(config_.transport.io_timeout_ms));
            auto peer_id = target.node_id;

            {
                std::lock_guard lock(pending_mutex_);
                pending_requests_[rid] = [this, timer, acks, remaining, finished, required_quorum, callback, peer_id]
                    (const transport::Frame& resp_frame) {
                    timer->cancel();
                    dht::StoreResponse resp;
                    if (dht::deserialize_store_response(resp_frame.payload, resp) && resp.success) {
                        (*acks)++;
                        spdlog::info("Keeper {} confirmed STORE", peer_id.to_short_hex());
                    } else {
                        spdlog::warn("Keeper {} failed STORE: {}", peer_id.to_short_hex(), resp.message);
                    }

                    (*remaining)--;
                    if (*remaining == 0 && !*finished) {
                        *finished = true;
                        bool ok = (*acks >= required_quorum);
                        if (callback) callback(ok, *acks);
                    }
                };
            }

            timer->async_wait([this, rid, remaining, finished, acks, required_quorum, callback, peer_id]
                (const std::error_code& ec) {
                if (!ec) {
                    {
                        std::lock_guard lock(pending_mutex_);
                        pending_requests_.erase(rid);
                    }
                    spdlog::warn("Keeper {} timed out on STORE", peer_id.to_short_hex());
                    (*remaining)--;
                    if (*remaining == 0 && !*finished) {
                        *finished = true;
                        bool ok = (*acks >= required_quorum);
                        if (callback) callback(ok, *acks);
                    }
                }
            });

            conn->send(req_frame);
        };

        for (const auto& target : remote_keepers) {
            auto conn = get_connection_to(target.node_id);
            if (conn) {
                send_store_to_keeper(target, conn);
            } else {
                transport::TcpConnection::async_connect(
                    io_, target.address.host, target.address.port,
                    std::chrono::milliseconds(config_.transport.connect_timeout_ms),
                    [this, target, remaining, finished, acks, required_quorum, callback, send_store_to_keeper]
                    (transport::TcpConnection::Ptr new_conn) {
                        if (!new_conn) {
                            spdlog::warn("Failed to connect to keeper candidate {}", target.node_id.to_short_hex());
                            (*remaining)--;
                            if (*remaining == 0 && !*finished) {
                                *finished = true;
                                bool ok = (*acks >= required_quorum);
                                if (callback) callback(ok, *acks);
                            }
                            return;
                        }
                        register_connection(new_conn);
                        send_ping(new_conn, target.node_id, [target, new_conn, remaining, finished, acks, required_quorum, callback, send_store_to_keeper](bool ping_ok) {
                            if (!ping_ok) {
                                spdlog::warn("Keeper {} failed PING verification", target.node_id.to_short_hex());
                                (*remaining)--;
                                if (*remaining == 0 && !*finished) {
                                    *finished = true;
                                    bool ok = (*acks >= required_quorum);
                                    if (callback) callback(ok, *acks);
                                }
                                return;
                            }
                            send_store_to_keeper(target, new_conn);
                        });
                    });
            }
        }
    });
}

void Node::publish_self_record(const std::string& alias,
                               std::function<void(bool success, std::size_t acks)> callback) {
    has_published_self_ = true;
    auto rec = create_self_record(alias);
    auto node_key = dht::node_record_key(rec.node_id);

    publish_record(node_key, rec, [this, alias, rec, callback](bool ok1, std::size_t acks1) {
        if (!ok1 || alias.empty()) {
            if (callback) callback(ok1, acks1);
            return;
        }

        auto alias_key = dht::alias_record_key(alias);
        publish_record(alias_key, rec, [callback, acks1](bool ok2, std::size_t acks2) {
            if (callback) callback(ok2, std::min(acks1, acks2));
        });
    });
}

void Node::async_find_value(const NodeID& key,
                            std::function<void(std::optional<dht::NodeRecord>, const dht::LookupMetrics&)> callback) {
    uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    // 1. Check local storage
    auto local_rec = record_store_->get(key, now);
    if (local_rec) {
        spdlog::info("FIND_VALUE for key {} resolved from local storage", key.to_short_hex());
        if (callback) {
            dht::LookupMetrics m;
            m.target = key;
            m.success = true;
            callback(local_rec, m);
        }
        return;
    }

    // 2. Perform iterative FIND_VALUE across the network
    auto session = std::make_shared<dht::LookupSession>(
        key, node_id(), config_.dht.alpha, config_.dht.k_bucket_size);

    auto initial = routing_table_->find_closest(key, config_.dht.alpha * 2);
    session->add_candidates(initial);

    auto found_record = std::make_shared<std::optional<dht::NodeRecord>>(std::nullopt);
    auto finished = std::make_shared<bool>(false);

    auto step_func = std::make_shared<std::function<void()>>();
    *step_func = [this, session, key, found_record, finished, callback, step_func]() {
        if (*finished) return;

        if (found_record->has_value()) {
            *finished = true;
            session->metrics().success = true;
            if (callback) {
                callback(*found_record, session->metrics());
            }
            return;
        }

        if (session->is_complete()) {
            *finished = true;
            if (callback) {
                callback(std::nullopt, session->metrics());
            }
            return;
        }

        auto queries = session->pick_next_queries();
        if (queries.empty()) {
            if (session->in_flight_count() == 0 && !*finished) {
                *finished = true;
                if (callback) {
                    callback(std::nullopt, session->metrics());
                }
            }
            return;
        }

        for (const auto& peer : queries) {
            auto send_fv_query = [this, key, session, found_record, finished, callback, step_func]
                (const PeerInfo& target_peer, transport::TcpConnection::Ptr c) {
                dht::FindValueRequest req{
                    .key = key,
                    .sender = PeerInfo{
                        .node_id = node_id(),
                        .address = PeerAddress{
                            .host = advertised_host(),
                            .port = config_.node.listen_port
                        }
                    }
                };

                auto payload = dht::serialize_find_value_request(req);
                auto rid = RequestID::generate();
                auto req_frame = make_frame(transport::MessageType::FIND_VALUE_REQUEST, rid);
                req_frame.payload = std::move(payload);

                auto timer = std::make_shared<asio::steady_timer>(
                    io_, std::chrono::milliseconds(config_.transport.io_timeout_ms));
                auto peer_id = target_peer.node_id;

                {
                    std::lock_guard lock(pending_mutex_);
                    pending_requests_[rid] = [this, timer, session, key, peer_id, found_record, finished, callback, step_func]
                        (const transport::Frame& resp_frame) {
                        timer->cancel();
                        dht::FindValueResponse resp;
                        if (dht::deserialize_find_value_response(resp_frame.payload, resp)) {
                            if (resp.has_value && resp.record.has_value()) {
                                uint64_t cur_time = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count());
                                auto v_err = resp.record->validate(cur_time);
                                if (v_err == dht::RecordValidationError::None) {
                                    spdlog::info("FIND_VALUE: Valid record returned by keeper {}",
                                                 peer_id.to_short_hex());
                                    (void)record_store_->put(
                                        key, *resp.record, cur_time,
                                        static_cast<std::size_t>(config_.dht.max_record_size)); // Cache locally
                                    *found_record = resp.record;
                                    (*step_func)();
                                    return;
                                } else {
                                    spdlog::warn("FIND_VALUE: Invalid record from {}: {}",
                                                 peer_id.to_short_hex(),
                                                 dht::record_validation_error_name(v_err));
                                    session->on_failure(peer_id);
                                }
                            } else {
                                // Value not found at this node; process closer contacts as lookup candidates (E2-2)
                                session->on_response(peer_id, resp.closest_nodes);
                            }
                        } else {
                            session->on_failure(peer_id);
                        }
                        (*step_func)();
                    };
                }

                timer->async_wait([this, session, peer_id, rid, step_func](const std::error_code& ec) {
                    if (!ec) {
                        {
                            std::lock_guard lock(pending_mutex_);
                            pending_requests_.erase(rid);
                        }
                        session->on_failure(peer_id);
                        (*step_func)();
                    }
                });

                c->send(req_frame);
            };

            auto conn = get_connection_to(peer.node_id);
            if (conn) {
                send_fv_query(peer, conn);
            } else {
                transport::TcpConnection::async_connect(
                    io_, peer.address.host, peer.address.port,
                    std::chrono::milliseconds(config_.transport.connect_timeout_ms),
                    [this, peer, session, step_func, send_fv_query](transport::TcpConnection::Ptr new_conn) {
                        if (!new_conn) {
                            session->on_failure(peer.node_id);
                            (*step_func)();
                            return;
                        }
                        register_connection(new_conn);
                        send_ping(new_conn, peer.node_id, [peer, new_conn, session, step_func, send_fv_query](bool ping_ok) {
                            if (!ping_ok) {
                                session->on_failure(peer.node_id);
                                (*step_func)();
                                return;
                            }
                            send_fv_query(peer, new_conn);
                        });
                    });
            }
        }
    };

    (*step_func)();
}

void Node::async_resolve_alias(std::string_view alias,
                               std::function<void(std::optional<dht::NodeRecord>, const dht::LookupMetrics&)> callback) {
    auto key = dht::alias_record_key(alias);
    async_find_value(key, std::move(callback));
}

void Node::schedule_purge() {
    purge_timer_ = std::make_shared<asio::steady_timer>(io_, std::chrono::seconds(15));
    purge_timer_->async_wait([this](const std::error_code& ec) {
        if (!ec && record_store_) {
            uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            auto purged = record_store_->purge_expired(now);
            if (purged > 0) {
                spdlog::info("E3-7: Purged {} expired record(s) from DHT storage", purged);
            }
            schedule_purge();
        }
    });
}

void Node::schedule_republish() {
    int interval = config_.dht.republish_interval_sec > 0 ? config_.dht.republish_interval_sec : 80;
    republish_timer_ = std::make_shared<asio::steady_timer>(io_, std::chrono::seconds(interval));
    republish_timer_->async_wait([this](const std::error_code& ec) {
        if (!ec && keypair_) {
            if (has_published_self_) {
                spdlog::info("E3-7: Routine republish of self-record (alias='{}')", node_alias_);
                publish_self_record(node_alias_, [](bool ok, std::size_t acks) {
                    spdlog::info("E3-7: Self-record republish complete: success={}, acks={}", ok, acks);
                });
            }
            schedule_republish();
        }
    });
}

void Node::initiate_handshake(transport::TcpConnection::Ptr conn,
                              std::function<void(bool success)> callback) {
    if (!conn || !conn->is_open()) {
        if (callback) callback(false);
        return;
    }

    auto session = std::make_shared<security::SecureSession>();
    conn->set_secure_session(session);

    auto init = session->initiate_handshake(*keypair_);
    auto payload = security::serialize_handshake_init(init);

    auto rid = RequestID::generate();
    auto req_frame = make_frame(transport::MessageType::HANDSHAKE_INIT, rid);
    req_frame.payload = std::move(payload);

    auto timer = std::make_shared<asio::steady_timer>(
        io_, std::chrono::milliseconds(config_.transport.io_timeout_ms));

    {
        std::lock_guard lock(pending_mutex_);
        pending_requests_[rid] = [this, conn, session, timer, callback]
            (const transport::Frame& resp_frame) {
            timer->cancel();
            if (resp_frame.type != transport::MessageType::HANDSHAKE_RESPONSE) {
                if (callback) callback(false);
                return;
            }

            security::HandshakeResponse resp;
            if (!security::deserialize_handshake_response(resp_frame.payload, resp)) {
                spdlog::warn("Failed to deserialize HANDSHAKE_RESPONSE from {}", conn->remote_endpoint_str());
                if (callback) callback(false);
                return;
            }

            auto comp = session->process_handshake_response(resp, *keypair_);
            if (!comp) {
                spdlog::warn("Failed to process HANDSHAKE_RESPONSE from {}", conn->remote_endpoint_str());
                if (callback) callback(false);
                return;
            }

            conn->set_peer_id(session->peer_node_id());

            // Send HANDSHAKE_COMPLETE
            auto comp_frame = make_frame(transport::MessageType::HANDSHAKE_COMPLETE, RequestID::generate());
            comp_frame.payload = security::serialize_handshake_complete(*comp);
            conn->send(comp_frame);

            spdlog::info("AKE handshake successfully completed with peer {}", session->peer_node_id().to_short_hex());
            if (callback) callback(true);
        };
    }

    timer->async_wait([this, rid, callback](const std::error_code& ec) {
        if (!ec) {
            {
                std::lock_guard lock(pending_mutex_);
                pending_requests_.erase(rid);
            }
            if (callback) callback(false);
        }
    });

    conn->send(req_frame);
}

void Node::build_tunnel(const NodeID& destination,
                        std::size_t hop_count,
                        tunnel::TunnelBuildCallback callback)
{
    // Find candidate relays from routing table
    auto candidates = routing_table_->find_closest(destination, 20);

    // Select hops using RelayProfiler (enforcing subnet diversity and excluding self + destination)
    std::vector<NodeID> excluded = {node_id(), destination};
    auto selected_hops = tunnel_manager_->profiler()->select_hops(candidates, hop_count, excluded);

    if (selected_hops.size() < hop_count) {
        spdlog::warn("Insufficient diverse hops available (found {}, needed {}) for tunnel to {}",
                     selected_hops.size(), hop_count, destination.to_short_hex());
        if (callback) callback(false, nullptr);
        return;
    }

    tunnel_manager_->async_build_tunnel(
        selected_hops,
        destination,
        [this](const PeerAddress& target, const tunnel::TunnelBuildMsg& msg) {
            connect_to_peer(target.host, target.port);
            transport::TcpConnection::Ptr conn = nullptr;
            {
                std::lock_guard<std::mutex> lock(conns_mutex_);
                for (auto& c : connections_) {
                    if (c->remote_endpoint_str().find(target.host) != std::string::npos) {
                        conn = c;
                        break;
                    }
                }
            }
            if (conn) {
                auto frame = make_frame(transport::MessageType::TUNNEL_BUILD, RequestID::generate());
                frame.payload = tunnel::serialize_tunnel_build(msg);
                conn->send(frame);
            }
        },
        std::move(callback));
}

bool Node::send_tunnel_data(const tunnel::CircuitID& circuit_id, ByteSpan payload) {
    auto t = tunnel_manager_->pool()->get_tunnel(circuit_id);
    if (!t || t->state() != tunnel::TunnelState::ACTIVE) {
        return false;
    }

    auto onion = t->wrap_payload(payload);
    tunnel::TunnelDataMsg data_msg;
    data_msg.circuit_id = circuit_id;
    data_msg.sequence_number = t->next_sequence();
    data_msg.onion_payload = std::move(onion);

    auto entry_hop = t->entry_hop();
    auto conn = get_connection_to(entry_hop.node_id);
    if (!conn) {
        std::lock_guard<std::mutex> lock(conns_mutex_);
        for (auto& c : connections_) {
            if (c->remote_endpoint_str().find(entry_hop.address.host) != std::string::npos) {
                conn = c;
                break;
            }
        }
    }

    if (conn) {
        auto frame = make_frame(transport::MessageType::TUNNEL_DATA, RequestID::generate());
        frame.payload = tunnel::serialize_tunnel_data(data_msg);
        conn->send(frame);
        return true;
    }
    return false;
}

// ─── Application Layer Methods (Stage 6) ────────────────────────────────────

RequestID Node::send_message(const NodeID& recipient,
                             const std::string& text,
                             app::DeliveryCallback cb) {
    auto send_fn = [this](const NodeID& target, const app::AppMessage& msg) {
        auto conn = get_connection_to(target);
        if (conn) {
            auto frame = make_frame(transport::MessageType::APP_MESSAGE, msg.msg_id);
            frame.payload = app::serialize_app_message(msg);
            conn->send(frame);
        } else {
            spdlog::warn("Cannot send APP_MESSAGE: no connection to {}", target.to_short_hex());
        }
    };

    return message_service_->send_message(recipient, text, send_fn, std::move(cb));
}

bool Node::send_file(const NodeID& recipient,
                     const std::filesystem::path& filepath,
                     app::FileSenderSession::ProgressFunc progress_cb,
                     app::FileSenderSession::CompletionFunc completion_cb) {
    auto conn = get_connection_to(recipient);
    if (!conn) {
        spdlog::warn("Cannot send file: no connection to {}", recipient.to_short_hex());
        return false;
    }

    auto send_meta = [this, conn](const NodeID& target, const app::FileMeta& meta) {
        auto frame = make_frame(transport::MessageType::APP_FILE_META, meta.file_id);
        frame.payload = app::serialize_file_meta(meta);
        conn->send(frame);
    };

    auto send_block = [this, conn](const NodeID& target, const app::FileBlock& block) {
        auto frame = make_frame(transport::MessageType::APP_FILE_BLOCK, RequestID::generate());
        frame.payload = app::serialize_file_block(block);
        conn->send(frame);
    };

    return file_transfer_manager_->start_send_file(
        filepath, node_id(), recipient, send_meta, send_block,
        std::move(progress_cb), std::move(completion_cb));
}

} // namespace p2p
