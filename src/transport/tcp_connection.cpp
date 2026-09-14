/// @file tcp_connection.cpp
/// @brief TCP connection implementation with async frame I/O.

#include "transport/tcp_connection.hpp"

#include <spdlog/spdlog.h>

namespace p2p::transport {

// ─── Construction ───────────────────────────────────────────────────

TcpConnection::TcpConnection(asio::ip::tcp::socket socket)
    : socket_(std::move(socket))
{
}

TcpConnection::~TcpConnection() {
    if (socket_.is_open()) {
        asio::error_code ec;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }
}

// ─── Connect ────────────────────────────────────────────────────────

TcpConnection::Ptr TcpConnection::connect(
    asio::io_context& io,
    const std::string& host,
    uint16_t port,
    std::chrono::milliseconds timeout)
{
    asio::ip::tcp::resolver resolver(io);
    auto endpoints = resolver.resolve(host, std::to_string(port));

    asio::ip::tcp::socket socket(io);

    // Synchronous connect with error handling
    asio::error_code ec;
    asio::connect(socket, endpoints, ec);

    if (ec) {
        spdlog::error("Failed to connect to {}:{} — {}", host, port, ec.message());
        return nullptr;
    }

    // Disable Nagle's algorithm for lower latency
    socket.set_option(asio::ip::tcp::no_delay(true), ec);

    spdlog::debug("Connected to {}:{}", host, port);
    return Ptr(new TcpConnection(std::move(socket)));
}

// ─── Remote endpoint ────────────────────────────────────────────────

std::string TcpConnection::remote_endpoint_str() const {
    try {
        auto ep = socket_.remote_endpoint();
        return ep.address().to_string() + ":" + std::to_string(ep.port());
    } catch (...) {
        return "<unknown>";
    }
}

// ─── Read loop ──────────────────────────────────────────────────────

void TcpConnection::start_reading() {
    do_read();
}

void TcpConnection::do_read() {
    auto self = shared_from_this();
    socket_.async_read_some(
        asio::buffer(read_buf_),
        [this, self](asio::error_code ec, std::size_t bytes_read) {
            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    std::string reason = (ec == asio::error::eof)
                        ? "peer closed connection"
                        : ec.message();
                    spdlog::debug("Connection {} read error: {}",
                                  remote_endpoint_str(), reason);
                    if (disconnect_handler_) {
                        disconnect_handler_(reason);
                    }
                }
                return;
            }

            // Feed raw bytes into the frame parser
            parser_.feed(read_buf_.data(), bytes_read);

            // Extract all complete frames
            process_incoming();

            // Continue reading
            do_read();
        }
    );
}

void TcpConnection::process_incoming() {
    while (true) {
        auto result = parser_.next_frame();
        if (result.has_value()) {
            // Complete frame received
            auto& frame = result.value();
            spdlog::trace("Received frame: type={}, payload={} bytes, from={}",
                          message_type_name(frame.type),
                          frame.payload.size(),
                          remote_endpoint_str());
            if (frame_handler_) {
                frame_handler_(frame);
            }
        } else {
            auto err = result.error();
            if (err == FrameError::IncompleteHeader ||
                err == FrameError::IncompletePayload) {
                // Need more data, stop processing
                break;
            }
            // Protocol error — log and continue
            spdlog::warn("Frame error from {}: {}",
                         remote_endpoint_str(),
                         frame_error_name(err));
            // For serious errors (bad version, oversized), we could
            // close the connection. For now, skip and try next frame.
        }
    }
}

// ─── Write ──────────────────────────────────────────────────────────

void TcpConnection::send(const Frame& frame) {
    if (!socket_.is_open()) {
        spdlog::warn("Attempted to send on closed connection");
        return;
    }

    auto data = frame.serialize();
    spdlog::trace("Sending frame: type={}, payload={} bytes, to={}",
                  message_type_name(frame.type),
                  frame.payload.size(),
                  remote_endpoint_str());

    bool was_writing = writing_;
    write_queue_.push(std::move(data));

    if (!was_writing) {
        do_write();
    }
}

void TcpConnection::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }

    writing_ = true;
    auto self = shared_from_this();
    const auto& data = write_queue_.front();

    asio::async_write(
        socket_,
        asio::buffer(data),
        [this, self](asio::error_code ec, std::size_t /*bytes_written*/) {
            if (ec) {
                spdlog::error("Write error to {}: {}",
                              remote_endpoint_str(), ec.message());
                if (disconnect_handler_) {
                    disconnect_handler_(ec.message());
                }
                return;
            }

            write_queue_.pop();
            do_write();
        }
    );
}

// ─── Close ──────────────────────────────────────────────────────────

void TcpConnection::close(const std::string& reason) {
    if (!socket_.is_open()) return;

    spdlog::debug("Closing connection to {} — {}",
                  remote_endpoint_str(), reason);

    asio::error_code ec;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);

    if (disconnect_handler_) {
        disconnect_handler_(reason);
    }
}

} // namespace p2p::transport
