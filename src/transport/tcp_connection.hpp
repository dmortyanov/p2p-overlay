#pragma once
/// @file tcp_connection.hpp
/// @brief Manages a single TCP connection with frame-based communication.
///
/// Handles:
///   - Async reading/writing of frames over TCP
///   - Connection lifecycle (connect, send, receive, close)
///   - Timeouts
///   - Integration with FrameParser for stream reassembly

#include "transport/frame.hpp"
#include "common/types.hpp"

#include <asio.hpp>
#include <spdlog/spdlog.h>

#include <functional>
#include <memory>
#include <optional>
#include <queue>
#include <string>

namespace p2p::transport {

/// Callback for received frames.
using FrameHandler = std::function<void(const Frame&)>;

/// Callback for connection events.
using DisconnectHandler = std::function<void(const std::string& reason)>;

/// A single TCP connection with frame-level send/receive.
///
/// Each connection maintains:
///   - An asio::tcp::socket
///   - A FrameParser for incoming data reassembly
///   - A write queue for outgoing frames
///   - Optional peer identification (NodeID set after handshake)
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
    using Ptr = std::shared_ptr<TcpConnection>;

    /// Create from an already-connected socket (accepted by listener).
    static Ptr create(asio::ip::tcp::socket socket) {
        return Ptr(new TcpConnection(std::move(socket)));
    }

    /// Connect to a remote peer.
    /// @param io      The io_context to use
    /// @param host    Remote hostname or IP
    /// @param port    Remote port
    /// @param timeout Connection timeout
    static Ptr connect(asio::io_context& io,
                       const std::string& host,
                       uint16_t port,
                       std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    ~TcpConnection();

    // Non-copyable, non-movable (shared_ptr managed)
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;

    /// Start async read loop. Must be called after creation.
    void start_reading();

    /// Send a frame asynchronously.
    void send(const Frame& frame);

    /// Close the connection gracefully.
    void close(const std::string& reason = "closed");

    /// Set handler for incoming frames.
    void set_frame_handler(FrameHandler handler) { frame_handler_ = std::move(handler); }

    /// Set handler for disconnect events.
    void set_disconnect_handler(DisconnectHandler handler) { disconnect_handler_ = std::move(handler); }

    /// Set the peer's NodeID (after identity verification).
    void set_peer_id(const NodeID& id) { peer_id_ = id; }

    /// Get the peer's NodeID (if known).
    [[nodiscard]] std::optional<NodeID> peer_id() const { return peer_id_; }

    /// Get remote endpoint as string.
    [[nodiscard]] std::string remote_endpoint_str() const;

    /// Check if the connection is open.
    [[nodiscard]] bool is_open() const { return socket_.is_open(); }

private:
    explicit TcpConnection(asio::ip::tcp::socket socket);

    /// Async read loop implementation.
    void do_read();

    /// Process buffered data through the frame parser.
    void process_incoming();

    /// Write the next queued frame.
    void do_write();

    asio::ip::tcp::socket socket_;
    FrameParser           parser_;
    FrameHandler          frame_handler_;
    DisconnectHandler     disconnect_handler_;
    std::optional<NodeID> peer_id_;

    // Read buffer
    static constexpr std::size_t READ_BUF_SIZE = 8192;
    std::array<uint8_t, READ_BUF_SIZE> read_buf_{};

    // Write queue
    std::queue<Bytes> write_queue_;
    bool              writing_ = false;
};

} // namespace p2p::transport
