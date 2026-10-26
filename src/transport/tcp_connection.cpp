/// @file tcp_connection.cpp
/// @brief TCP connection implementation with async frame I/O.

#include "transport/tcp_connection.hpp"
#include "security/secure_session.hpp"

#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#include <sys/socket.h>
#endif

namespace p2p::transport {

// ─── Construction ───────────────────────────────────────────────────

TcpConnection::TcpConnection(asio::ip::tcp::socket socket)
    : socket_(std::move(socket))
    , io_timer_(socket_.get_executor())
{
}

TcpConnection::~TcpConnection() {
    io_timer_.cancel();
    asio::error_code ec;
    if (socket_.is_open()) {
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }
}

// ─── Configuration & Watchdog ────────────────────────────────────────

void TcpConnection::configure(uint8_t version, uint32_t max_payload, std::chrono::milliseconds io_timeout) {
    parser_.set_expected_version(version);
    parser_.set_max_payload(max_payload);
    io_timeout_ = io_timeout;
    reset_io_timer();
}

void TcpConnection::reset_io_timer() {
    if (io_timeout_.count() <= 0 || !socket_.is_open()) return;
    io_timer_.cancel();
    io_timer_.expires_after(io_timeout_);
    auto self = shared_from_this();
    io_timer_.async_wait([this, self](const asio::error_code& ec) {
        if (!ec && socket_.is_open()) {
            spdlog::debug("Connection {} closed due to inactivity timeout ({} ms)",
                          remote_endpoint_str(), io_timeout_.count());
            close("I/O inactivity timeout");
        }
    });
}

// ─── Connect ────────────────────────────────────────────────────────

TcpConnection::Ptr TcpConnection::connect(
    asio::io_context& io,
    const std::string& host,
    uint16_t port,
    std::chrono::milliseconds timeout)
{
    asio::ip::tcp::resolver resolver(io);
    asio::error_code ec;
    auto endpoints = resolver.resolve(host, std::to_string(port), ec);

    if (ec) {
        spdlog::error("Failed to resolve {}:{} — {}", host, port, ec.message());
        return nullptr;
    }

    asio::ip::tcp::socket socket(io);
    bool connected = false;

    // Connect with timeout to the resolved endpoints (E1-3)
    for (const auto& entry : endpoints) {
        ec.clear();
        socket.open(entry.endpoint().protocol(), ec);
        if (ec) continue;

        socket.non_blocking(true, ec);
        socket.connect(entry.endpoint(), ec);

        if (ec == asio::error::in_progress || ec == asio::error::would_block) {
#ifdef _WIN32
            WSAPOLLFD fdArray;
            fdArray.fd = socket.native_handle();
            fdArray.events = POLLOUT;
            fdArray.revents = 0;
            int ret = WSAPoll(&fdArray, 1, static_cast<int>(timeout.count()));
#else
            struct pollfd pfd;
            pfd.fd = socket.native_handle();
            pfd.events = POLLOUT;
            pfd.revents = 0;
            int ret = poll(&pfd, 1, static_cast<int>(timeout.count()));
#endif
            if (ret > 0) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                getsockopt(socket.native_handle(), SOL_SOCKET, SO_ERROR,
                           reinterpret_cast<char*>(&so_error), &len);
                if (so_error == 0) {
                    connected = true;
                    ec.clear();
                    break;
                } else {
                    ec = asio::error_code(so_error, asio::error::get_system_category());
                }
            } else if (ret == 0) {
                ec = asio::error::timed_out;
            } else {
                ec = asio::error::try_again;
            }
        } else if (!ec) {
            connected = true;
            break;
        }

        socket.close();
    }

    if (!connected) {
        spdlog::error("Failed to connect to {}:{} — {}", host, port,
                      ec ? ec.message() : "connection timed out");
        return nullptr;
    }

    socket.non_blocking(false, ec);
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

std::string TcpConnection::remote_ip() const {
    try {
        return socket_.remote_endpoint().address().to_string();
    } catch (...) {
        return "127.0.0.1";
    }
}

uint16_t TcpConnection::remote_port() const {
    try {
        return socket_.remote_endpoint().port();
    } catch (...) {
        return 0;
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

            reset_io_timer();

            // Feed raw bytes into the frame parser
            parser_.feed(read_buf_.data(), bytes_read);

            // Extract all complete frames
            process_incoming();

            // Continue reading
            do_read();
        }
    );
}

void TcpConnection::set_secure_session(std::shared_ptr<security::SecureSession> session) {
    secure_session_ = std::move(session);
}

std::shared_ptr<security::SecureSession> TcpConnection::secure_session() const {
    return secure_session_;
}

void TcpConnection::process_incoming() {
    while (true) {
        auto result = parser_.next_frame();
        if (result.has_value()) {
            // Complete frame received
            auto& frame = result.value();

            if (static_cast<uint16_t>(frame.flags) & static_cast<uint16_t>(FrameFlags::IS_ENCRYPTED)) {
                if (secure_session_ && secure_session_->is_active()) {
                    if (!secure_session_->decrypt_frame(frame)) {
                        spdlog::warn("Decryption or replay check failed from {}, closing connection",
                                     remote_endpoint_str());
                        close("Decryption or replay check failed");
                        return;
                    }
                } else {
                    spdlog::warn("Received encrypted frame without active secure session from {}, closing",
                                 remote_endpoint_str());
                    close("Encrypted frame without active secure session");
                    return;
                }
            }

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
            // Protocol error — log and handle
            spdlog::warn("Frame error from {}: {}",
                         remote_endpoint_str(),
                         frame_error_name(err));
            if (err == FrameError::UnsupportedVersion || err == FrameError::PayloadTooLarge) {
                close(std::string("Protocol error: ") + std::string(frame_error_name(err)));
                break;
            }
        }
    }
}

// ─── Write ──────────────────────────────────────────────────────────

void TcpConnection::send(const Frame& frame) {
    if (!socket_.is_open()) {
        spdlog::warn("Attempted to send on closed connection");
        return;
    }

    reset_io_timer();

    Frame to_send = frame;
    if (secure_session_ && secure_session_->is_active()) {
        if (!(static_cast<uint16_t>(to_send.flags) & static_cast<uint16_t>(FrameFlags::IS_ENCRYPTED)) &&
            to_send.type != MessageType::HANDSHAKE_INIT &&
            to_send.type != MessageType::HANDSHAKE_RESPONSE &&
            to_send.type != MessageType::HANDSHAKE_COMPLETE) {
            if (!secure_session_->encrypt_frame(to_send)) {
                spdlog::warn("Failed to encrypt frame for peer {}", remote_endpoint_str());
                return;
            }
        }
    }

    auto data = to_send.serialize();
    spdlog::trace("Sending frame: type={}, payload={} bytes, to={}",
                  message_type_name(to_send.type),
                  to_send.payload.size(),
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
