/// @file node.cpp
/// @brief Top-level P2P node implementation.

#include "node.hpp"
#include "dht/dht_messages.hpp"
#include "identity/node_id.hpp"

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

// ─── Connect to peer ────────────────────────────────────────────────

void Node::connect_to_peer(const std::string& host, uint16_t port) {
    spdlog::info("Connecting to peer {}:{}...", host, port);

    auto conn = transport::TcpConnection::connect(
        io_, host, port,
        std::chrono::milliseconds(config_.transport.connect_timeout_ms));

    if (!conn) {
        spdlog::error("Failed to connect to {}:{}", host, port);
        return;
    }

    register_connection(conn);
    send_ping(conn);
}

// ─── Ping with correlation (E1-6, E2-5) ──────────────────────────────

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

    nlohmann::json j;
    j["node_id"] = node_id().to_hex();
    j["public_key"] = nlohmann::json::binary_t(
        {keypair_->public_key().begin(), keypair_->public_key().end()});
    j["listen_port"] = config_.node.listen_port;
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
    // Configure protocol version, max payload, and I/O timeout (E1-2, E1-3)
    conn->configure(static_cast<uint8_t>(config_.transport.protocol_version),
                    config_.transport.max_frame_payload,
                    std::chrono::milliseconds(config_.transport.io_timeout_ms));

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

                // VALIDATION PASSED: Now and only now set peer_id, add contact, send PONG
                conn->set_peer_id(peer_id);
                spdlog::info("PING from verified NodeID={}", peer_id.to_short_hex());

                uint16_t peer_port = j.value("listen_port", conn->remote_port());
                PeerInfo peer{
                    .node_id = peer_id,
                    .address = PeerAddress{
                        .host = conn->remote_ip(),
                        .port = peer_port
                    }
                };
                add_contact(peer);

                // Send PONG
                auto pong = Frame::make_pong(frame.request_id);
                pong.version = static_cast<uint8_t>(config_.transport.protocol_version);

                nlohmann::json resp_j;
                resp_j["node_id"] = node_id().to_hex();
                resp_j["public_key"] = nlohmann::json::binary_t(
                    {keypair_->public_key().begin(), keypair_->public_key().end()});
                resp_j["listen_port"] = config_.node.listen_port;
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

                uint16_t peer_port = j.value("listen_port", conn->remote_port());
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
                add_contact(req.sender);

                auto closest = routing_table_->find_closest(req.target, config_.dht.k_bucket_size);

                dht::FindNodeResponse resp{.closest_nodes = std::move(closest)};
                auto cbor_payload = dht::serialize_find_node_response(resp);

                Frame resp_frame(MessageType::FIND_NODE_RESPONSE, frame.request_id);
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
                spdlog::debug("FIND_NODE_RESPONSE from {} with {} contacts",
                              conn->remote_endpoint_str(),
                              resp.closest_nodes.size());
                for (const auto& peer : resp.closest_nodes) {
                    add_contact(peer);
                }
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
                add_contact(req.sender);

                uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                auto err = record_store_->put(req.key, req.record, now);
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

                Frame resp_frame(MessageType::STORE_RESPONSE, frame.request_id);
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
                add_contact(req.sender);

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
                Frame resp_frame(MessageType::FIND_VALUE_RESPONSE, frame.request_id);
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
                .host = config_.node.listen_address,
                .port = config_.node.listen_port
            }
        }
    };

    auto cbor_payload = dht::serialize_find_node_request(req);
    auto rid = RequestID::generate();
    transport::Frame frame(transport::MessageType::FIND_NODE_REQUEST, rid);
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
            auto conn = get_connection_to(peer.node_id);
            if (!conn) {
                conn = transport::TcpConnection::connect(
                    io_, peer.address.host, peer.address.port,
                    std::chrono::milliseconds(config_.transport.connect_timeout_ms));
                if (conn) {
                    conn->set_peer_id(peer.node_id);
                    register_connection(conn);
                }
            }

            if (!conn) {
                session->on_failure(peer.node_id);
                (*step_func)();
                continue;
            }

            dht::FindNodeRequest req{
                .target = session->target(),
                .sender = PeerInfo{
                    .node_id = node_id(),
                    .address = PeerAddress{
                        .host = config_.node.listen_address,
                        .port = config_.node.listen_port
                    }
                }
            };

            auto payload = dht::serialize_find_node_request(req);
            auto rid = RequestID::generate();
            transport::Frame req_frame(transport::MessageType::FIND_NODE_REQUEST, rid);
            req_frame.payload = std::move(payload);

            auto timer = std::make_shared<asio::steady_timer>(
                io_, std::chrono::milliseconds(config_.transport.io_timeout_ms));
            auto peer_id = peer.node_id;

            {
                std::lock_guard lock(pending_mutex_);
                pending_requests_[rid] = [session, peer_id, this, timer = timer, step_func](const transport::Frame& resp_frame) {
                    timer->cancel();
                    dht::FindNodeResponse resp;
                    if (dht::deserialize_find_node_response(resp_frame.payload, resp)) {
                        session->on_response(peer_id, resp.closest_nodes);
                        for (const auto& contact : resp.closest_nodes) {
                            add_contact(contact);
                        }
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

            conn->send(req_frame);
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
    auto conn = get_connection_to(lru.node_id);
    if (!conn) {
        conn = transport::TcpConnection::connect(
            io_, lru.address.host, lru.address.port,
            std::chrono::milliseconds(config_.transport.connect_timeout_ms));
        if (conn) {
            conn->set_peer_id(lru.node_id);
            register_connection(conn);
        }
    }

    if (!conn) {
        // Unreachable contact -> evict immediately to promote replacement candidate (E2-4)
        spdlog::info("LRU contact {} unreachable, evicting from bucket", lru.node_id.to_short_hex());
        routing_table_->remove(lru.node_id);
        return;
    }

    send_ping(conn, lru.node_id, [this, lru_id = lru.node_id](bool success) {
        if (success) {
            spdlog::debug("LRU contact {} responded to probe, keeping as MRU", lru_id.to_short_hex());
            routing_table_->touch(lru_id);
        } else {
            spdlog::info("LRU contact {} failed probe, evicting from bucket", lru_id.to_short_hex());
            routing_table_->remove(lru_id);
        }
    });
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
            .host = config_.node.listen_address,
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

    // Always store in local store as well
    (void)record_store_->put(key, record, now);

    // Find R closest nodes across the DHT (E3-4)
    async_lookup(key, [this, key, record, callback](const std::vector<PeerInfo>& closest,
                                                    const dht::LookupMetrics&) {
        std::vector<PeerInfo> remote_keepers;
        for (const auto& peer : closest) {
            if (peer.node_id != node_id()) {
                remote_keepers.push_back(peer);
            }
            if (remote_keepers.size() + 1 >= static_cast<std::size_t>(config_.dht.replication)) {
                break;
            }
        }

        std::size_t total_keepers = remote_keepers.size() + 1; // 1 local + remote
        auto acks = std::make_shared<std::size_t>(1); // local node already stored
        auto remaining = std::make_shared<std::size_t>(remote_keepers.size());
        auto finished = std::make_shared<bool>(false);
        std::size_t required_quorum = std::min<std::size_t>(2, total_keepers);

        spdlog::info("Publishing record for key {} to {} remote keepers (total: {}, quorum: {})",
                     key.to_short_hex(), remote_keepers.size(), total_keepers, required_quorum);

        if (remote_keepers.empty()) {
            if (callback) callback(*acks >= required_quorum, *acks);
            return;
        }

        for (const auto& target : remote_keepers) {
            auto conn = get_connection_to(target.node_id);
            if (!conn) {
                conn = transport::TcpConnection::connect(
                    io_, target.address.host, target.address.port,
                    std::chrono::milliseconds(config_.transport.connect_timeout_ms));
                if (conn) {
                    conn->set_peer_id(target.node_id);
                    register_connection(conn);
                }
            }

            if (!conn) {
                spdlog::warn("Failed to connect to keeper candidate {}", target.node_id.to_short_hex());
                (*remaining)--;
                if (*remaining == 0 && !*finished) {
                    *finished = true;
                    bool ok = (*acks >= required_quorum);
                    if (callback) callback(ok, *acks);
                }
                continue;
            }

            dht::StoreRequest req{
                .key = key,
                .record = record,
                .sender = PeerInfo{
                    .node_id = node_id(),
                    .address = PeerAddress{
                        .host = config_.node.listen_address,
                        .port = config_.node.listen_port
                    }
                }
            };

            auto payload = dht::serialize_store_request(req);
            auto rid = RequestID::generate();
            transport::Frame req_frame(transport::MessageType::STORE_REQUEST, rid);
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
        }
    });
}

void Node::publish_self_record(const std::string& alias,
                               std::function<void(bool success, std::size_t acks)> callback) {
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
            auto conn = get_connection_to(peer.node_id);
            if (!conn) {
                conn = transport::TcpConnection::connect(
                    io_, peer.address.host, peer.address.port,
                    std::chrono::milliseconds(config_.transport.connect_timeout_ms));
                if (conn) {
                    conn->set_peer_id(peer.node_id);
                    register_connection(conn);
                }
            }

            if (!conn) {
                session->on_failure(peer.node_id);
                (*step_func)();
                continue;
            }

            dht::FindValueRequest req{
                .key = key,
                .sender = PeerInfo{
                    .node_id = node_id(),
                    .address = PeerAddress{
                        .host = config_.node.listen_address,
                        .port = config_.node.listen_port
                    }
                }
            };

            auto payload = dht::serialize_find_value_request(req);
            auto rid = RequestID::generate();
            transport::Frame req_frame(transport::MessageType::FIND_VALUE_REQUEST, rid);
            req_frame.payload = std::move(payload);

            auto timer = std::make_shared<asio::steady_timer>(
                io_, std::chrono::milliseconds(config_.transport.io_timeout_ms));
            auto peer_id = peer.node_id;

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
                                (void)record_store_->put(key, *resp.record, cur_time); // Cache locally
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
                            // Value not found at this node; process closer contacts returned
                            session->on_response(peer_id, resp.closest_nodes);
                            for (const auto& contact : resp.closest_nodes) {
                                add_contact(contact);
                            }
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

            conn->send(req_frame);
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
            spdlog::info("E3-7: Routine republish of self-record");
            publish_self_record(node_alias_, [](bool ok, std::size_t acks) {
                spdlog::debug("E3-7: Self-record republish result: success={}, acks={}", ok, acks);
            });
            schedule_republish();
        }
    });
}

} // namespace p2p
