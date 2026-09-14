/// @file tcp_listener.cpp
/// @brief TCP listener implementation.

#include "transport/tcp_listener.hpp"

namespace p2p::transport {

TcpListener::TcpListener(asio::io_context& io,
                         const std::string& address,
                         uint16_t port)
    : acceptor_(io)
{
    auto endpoint = asio::ip::tcp::endpoint(
        asio::ip::make_address(address), port);

    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen(asio::socket_base::max_listen_connections);

    spdlog::info("TCP listener bound to {}:{}", address, local_port());
}

void TcpListener::start(AcceptHandler handler) {
    accept_handler_ = std::move(handler);
    running_ = true;
    do_accept();
}

void TcpListener::stop() {
    running_ = false;
    asio::error_code ec;
    acceptor_.close(ec);
}

uint16_t TcpListener::local_port() const {
    return acceptor_.local_endpoint().port();
}

void TcpListener::do_accept() {
    if (!running_) return;

    auto self = shared_from_this();
    acceptor_.async_accept(
        [this, self](asio::error_code ec, asio::ip::tcp::socket socket) {
            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    spdlog::error("Accept error: {}", ec.message());
                }
                return;
            }

            // Disable Nagle for low latency
            socket.set_option(asio::ip::tcp::no_delay(true), ec);

            auto conn = TcpConnection::create(std::move(socket));
            spdlog::debug("Accepted connection from {}",
                          conn->remote_endpoint_str());

            if (accept_handler_) {
                accept_handler_(std::move(conn));
            }

            // Continue accepting
            do_accept();
        }
    );
}

} // namespace p2p::transport
