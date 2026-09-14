#pragma once
/// @file tcp_listener.hpp
/// @brief TCP server that accepts incoming connections.

#include "transport/tcp_connection.hpp"

#include <asio.hpp>
#include <spdlog/spdlog.h>

#include <functional>
#include <memory>
#include <string>

namespace p2p::transport {

/// Callback invoked when a new connection is accepted.
using AcceptHandler = std::function<void(TcpConnection::Ptr)>;

/// TCP listener that accepts incoming peer connections.
class TcpListener : public std::enable_shared_from_this<TcpListener> {
public:
    using Ptr = std::shared_ptr<TcpListener>;

    /// Create a listener bound to the specified address and port.
    static Ptr create(asio::io_context& io,
                      const std::string& address,
                      uint16_t port) {
        return Ptr(new TcpListener(io, address, port));
    }

    /// Start accepting connections.
    void start(AcceptHandler handler);

    /// Stop accepting new connections.
    void stop();

    /// Get the actual port (useful if bound to port 0).
    [[nodiscard]] uint16_t local_port() const;

private:
    TcpListener(asio::io_context& io,
                const std::string& address,
                uint16_t port);

    void do_accept();

    asio::ip::tcp::acceptor acceptor_;
    AcceptHandler           accept_handler_;
    bool                    running_ = false;
};

} // namespace p2p::transport
