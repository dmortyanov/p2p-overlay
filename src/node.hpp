#pragma once
/// @file node.hpp
/// @brief Top-level P2P node orchestrating all subsystems.
///
/// The Node class ties together:
///   - Identity (keypair, NodeID)
///   - Transport (TCP listener, connections)
///   - Configuration
///
/// Later stages will add:
///   - DHT (k-bucket, routing table, lookup)
///   - Tunnel management
///   - Application services
///   - Metrics

#include "config/config.hpp"
#include "identity/keypair.hpp"
#include "transport/tcp_connection.hpp"
#include "transport/tcp_listener.hpp"

#include <asio.hpp>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace p2p {

/// Top-level P2P overlay node.
class Node {
public:
    /// Construct a node with the given configuration.
    explicit Node(config::Config cfg);

    /// Initialize identity, start listener, connect to bootstrap peers.
    void start();

    /// Graceful shutdown.
    void stop();

    /// Run the event loop (blocks until stop() is called).
    void run();

    /// Get this node's identity.
    [[nodiscard]] const identity::Keypair& keypair() const { return *keypair_; }
    [[nodiscard]] NodeID node_id() const { return keypair_->node_id(); }

    /// Get the listen port.
    [[nodiscard]] uint16_t listen_port() const;

    /// Connect to a peer by address.
    void connect_to_peer(const std::string& host, uint16_t port);

    /// Send a PING to all connected peers.
    void ping_all();

    /// Get number of active connections.
    [[nodiscard]] std::size_t connection_count() const;

private:
    /// Handle a new incoming connection.
    void on_accept(transport::TcpConnection::Ptr conn);

    /// Handle a frame from any connection.
    void on_frame(transport::TcpConnection::Ptr conn, const transport::Frame& frame);

    /// Handle disconnection.
    void on_disconnect(transport::TcpConnection::Ptr conn, const std::string& reason);

    /// Register a connection and set up handlers.
    void register_connection(transport::TcpConnection::Ptr conn);

    config::Config                 config_;
    asio::io_context               io_;
    std::unique_ptr<identity::Keypair> keypair_;
    transport::TcpListener::Ptr    listener_;

    // Active connections indexed by remote endpoint string
    mutable std::mutex             conns_mutex_;
    std::vector<transport::TcpConnection::Ptr> connections_;
};

} // namespace p2p
