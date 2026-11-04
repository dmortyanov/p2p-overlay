/// @file tunnel.cpp
/// @brief Tunnel (Circuit) class implementation.

#include "tunnel/tunnel.hpp"

namespace p2p::tunnel {

Tunnel::Tunnel(CircuitID circuit_id,
               std::vector<TunnelHop> hops,
               NodeID destination_id,
               std::chrono::seconds ttl)
    : circuit_id_(circuit_id)
    , hops_(std::move(hops))
    , destination_id_(destination_id)
    , ttl_(ttl)
    , created_at_(std::chrono::steady_clock::now())
    , last_active_(created_at_)
{
}

bool Tunnel::is_expired() const {
    auto now = std::chrono::steady_clock::now();
    return (now - created_at_) > ttl_;
}

uint64_t Tunnel::next_sequence() {
    return sequence_.fetch_add(1);
}

Bytes Tunnel::wrap_payload(ByteSpan payload) {
    uint64_t seq = next_sequence();
    touch();
    return OnionPacket::wrap(payload, hops_, destination_id_, seq);
}

void Tunnel::touch() {
    last_active_ = std::chrono::steady_clock::now();
}

} // namespace p2p::tunnel

