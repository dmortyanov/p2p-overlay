/// @file node.cpp
/// @brief Top-level P2P node implementation.

#include "node.hpp"
#include "dht/dht_messages.hpp"

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
}

// ─── Stop ───────────────────────────────────────────────────────────

void Node::stop() {
    spdlog::info("Node {} shutting down...", node_id().to_short_hex());

    if (listener_) {
        listener_->stop();
    }

    {
        std::lock_guard lock(conns_mutex_);
        for (auto& conn : connections_) {
            conn->close("node shutdown");
        }
        connections_.clear();
    }

    io_.stop();
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

    // Send a PING to introduce ourselves
    auto rid = RequestID::generate();
    auto ping = transport::Frame::make_ping(rid);

    // Include our NodeID and public key in the PING payload
    nlohmann::json j;
    j["node_id"] = node_id().to_hex();
    j["public_key"] = nlohmann::json::binary_t(
        {keypair_->public_key().begin(), keypair_->public_key().end()});
    auto cbor = nlohmann::json::to_cbor(j);
    ping.payload.assign(cbor.begin(), cbor.end());

    conn->send(ping);
    spdlog::debug("Sent PING to {}:{} (rid={})", host, port,
                  rid.to_hex().substr(0, 8));
}

// ─── Ping all ───────────────────────────────────────────────────────

void Node::ping_all() {
    std::lock_guard lock(conns_mutex_);
    for (auto& conn : connections_) {
        auto rid = RequestID::generate();
        conn->send(transport::Frame::make_ping(rid));
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

    switch (frame.type) {
        case MessageType::PING: {
            // Parse sender info from PING payload
            if (!frame.payload.empty()) {
                try {
                    auto j = nlohmann::json::from_cbor(frame.payload);
                    if (j.contains("node_id")) {
                        NodeID peer_id;
                        NodeID::from_hex(j["node_id"].get<std::string>(), peer_id);
                        conn->set_peer_id(peer_id);
                        spdlog::info("PING from NodeID={}", peer_id.to_short_hex());

                        // Update routing table
                        auto endpoint = conn->remote_endpoint();
                        PeerInfo peer{
                            .node_id = peer_id,
                            .address = PeerAddress{
                                .host = endpoint.address().to_string(),
                                .port = endpoint.port()
                            }
                        };
                        routing_table_->add_or_update(peer);
                    }
                } catch (const std::exception& e) {
                    spdlog::warn("Failed to parse PING payload: {}", e.what());
                }
            }

            // Send PONG
            auto pong = Frame::make_pong(frame.request_id);

            // Include our identity in PONG too
            nlohmann::json j;
            j["node_id"] = node_id().to_hex();
            j["public_key"] = nlohmann::json::binary_t(
                {keypair_->public_key().begin(), keypair_->public_key().end()});
            auto cbor = nlohmann::json::to_cbor(j);
            pong.payload.assign(cbor.begin(), cbor.end());

            conn->send(pong);
            break;
        }

        case MessageType::PONG: {
            if (!frame.payload.empty()) {
                try {
                    auto j = nlohmann::json::from_cbor(frame.payload);
                    if (j.contains("node_id")) {
                        NodeID peer_id;
                        NodeID::from_hex(j["node_id"].get<std::string>(), peer_id);
                        conn->set_peer_id(peer_id);
                        spdlog::info("PONG from NodeID={}", peer_id.to_short_hex());

                        // Update routing table
                        auto endpoint = conn->remote_endpoint();
                        PeerInfo peer{
                            .node_id = peer_id,
                            .address = PeerAddress{
                                .host = endpoint.address().to_string(),
                                .port = endpoint.port()
                            }
                        };
                        routing_table_->add_or_update(peer);
                    }
                } catch (const std::exception& e) {
                    spdlog::warn("Failed to parse PONG payload: {}", e.what());
                }
            }
            break;
        }

        case MessageType::FIND_NODE_REQUEST: {
            dht::FindNodeRequest req;
            if (dht::deserialize_find_node_request(frame.payload, req)) {
                spdlog::debug("FIND_NODE_REQUEST for target {} from {}",
                              req.target.to_short_hex(),
                              req.sender.node_id.to_short_hex());
                routing_table_->add_or_update(req.sender);

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
                    routing_table_->add_or_update(peer);
                }
            } else {
                spdlog::warn("Malformed FIND_NODE_RESPONSE from {}", conn->remote_endpoint_str());
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

} // namespace p2p
