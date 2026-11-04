/// @file tunnel_manager.cpp
/// @brief Tunnel Manager implementation.

#include "tunnel/tunnel_manager.hpp"
#include <spdlog/spdlog.h>

namespace p2p::tunnel {

TunnelManager::TunnelManager(NodeID local_node_id,
                             const identity::Keypair& keypair,
                             std::shared_ptr<TunnelPool> pool,
                             std::shared_ptr<RelayProfiler> profiler)
    : local_node_id_(local_node_id)
    , keypair_(keypair)
    , pool_(pool ? pool : std::make_shared<TunnelPool>(3))
    , profiler_(profiler ? profiler : std::make_shared<RelayProfiler>())
{
}

void TunnelManager::async_build_tunnel(
    const std::vector<PeerInfo>& hops,
    const NodeID& destination,
    std::function<void(const PeerAddress& target, const TunnelBuildMsg& msg)> send_build_fn,
    TunnelBuildCallback callback)
{
    if (hops.size() < 3) {
        spdlog::warn("Cannot build tunnel: requested {} hops, minimum is 3", hops.size());
        if (callback) callback(false, nullptr);
        return;
    }

    CircuitID cid = RequestID::generate();
    PendingBuild pb;
    pb.circuit_id = cid;
    pb.destination = destination;
    pb.callback = std::move(callback);
    pb.start_time = std::chrono::steady_clock::now();

    // Prepare ephemeral keys and hop records
    for (std::size_t i = 0; i < hops.size(); ++i) {
        TunnelHop hop;
        hop.node_id = hops[i].node_id;
        hop.address = hops[i].address;
        pb.hops.push_back(hop);
        pb.ephemeral_keys.push_back(security::X25519Keypair::generate());
    }

    // Build the outermost TUNNEL_BUILD message for hop 0 (R1)
    TunnelBuildMsg build_msg;
    build_msg.circuit_id = cid;
    build_msg.hop_index = 0;
    build_msg.total_hops = static_cast<uint8_t>(hops.size());
    build_msg.eph_public_key = pb.ephemeral_keys[0].public_key;

    if (hops.size() > 1) {
        build_msg.next_hop_node_id = hops[1].node_id;
        build_msg.next_hop_address = hops[1].address;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_builds_[cid] = std::move(pb);
    }

    spdlog::info("Initiating tunnel build {}: {} hops -> {}",
                 cid.to_short_hex(), hops.size(), destination.to_short_hex());

    if (send_build_fn) {
        send_build_fn(hops[0].address, build_msg);
    }
}

std::optional<std::array<uint8_t, 32>> TunnelManager::get_build_eph_pub(const CircuitID& cid, uint8_t hop_idx) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pending_builds_.find(cid);
    if (it != pending_builds_.end()) {
        if (hop_idx < it->second.ephemeral_keys.size()) {
            return it->second.ephemeral_keys[hop_idx].public_key;
        }
    }
    return std::nullopt;
}

std::variant<TunnelBuildOkMsg, TunnelBuildFailMsg> TunnelManager::handle_tunnel_build(
    const NodeID& from_peer,
    const TunnelBuildMsg& msg)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Generate ephemeral keypair for this relay hop
    auto relay_eph = security::X25519Keypair::generate();

    // Compute Diffie-Hellman shared secret with initiator's ephemeral pubkey
    auto ss_opt = security::x25519_diffie_hellman(relay_eph.secret_key, msg.eph_public_key);
    if (!ss_opt) {
        TunnelBuildFailMsg fail;
        fail.circuit_id = msg.circuit_id;
        fail.hop_index = msg.hop_index;
        fail.reason = "ECDH scalar multiplication failed";
        return fail;
    }

    // Derive symmetric layer key via HKDF
    auto prk = security::hkdf_extract(nullptr, 0, ss_opt->data(), ss_opt->size());
    auto okm = security::hkdf_expand(prk, "p2p-tunnel-layer-v1", security::AEAD_KEY_SIZE);

    RelayCircuitState rstate;
    rstate.circuit_id = msg.circuit_id;
    rstate.hop_index = msg.hop_index;
    std::copy_n(okm.begin(), security::AEAD_KEY_SIZE, rstate.layer_key.begin());
    rstate.prev_hop_node_id = from_peer;
    rstate.next_hop_node_id = msg.next_hop_node_id;
    rstate.next_hop_address = msg.next_hop_address;
    rstate.is_exit = (msg.hop_index + 1 >= msg.total_hops);
    rstate.last_active = std::chrono::steady_clock::now();

    relay_circuits_[msg.circuit_id] = rstate;

    spdlog::info("Relay node joined circuit {}: hop {}/{} (exit: {})",
                 msg.circuit_id.to_short_hex(), msg.hop_index + 1, msg.total_hops, rstate.is_exit);

    TunnelBuildOkMsg ok;
    ok.circuit_id = msg.circuit_id;
    ok.hop_index = msg.hop_index;
    ok.eph_public_key = relay_eph.public_key;
    return ok;
}

void TunnelManager::handle_tunnel_build_ok(const NodeID& from_peer, const TunnelBuildOkMsg& msg) {
    TunnelBuildCallback cb = nullptr;
    std::shared_ptr<Tunnel> completed_tunnel = nullptr;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_builds_.find(msg.circuit_id);
        if (it == pending_builds_.end()) return;

        auto& pb = it->second;
        uint8_t idx = msg.hop_index;
        if (idx >= pb.hops.size()) return;

        // Compute shared secret using our secret key for this hop and relay's ephemeral pubkey
        auto ss_opt = security::x25519_diffie_hellman(pb.ephemeral_keys[idx].secret_key, msg.eph_public_key);
        if (ss_opt) {
            auto prk = security::hkdf_extract(nullptr, 0, ss_opt->data(), ss_opt->size());
            auto okm = security::hkdf_expand(prk, "p2p-tunnel-layer-v1", security::AEAD_KEY_SIZE);
            std::copy_n(okm.begin(), security::AEAD_KEY_SIZE, pb.hops[idx].layer_key.begin());
            pb.acks_received++;
        }

        // Check if all hops established (or for multi-hop handshake, if completed)
        if (pb.acks_received >= pb.hops.size()) {
            completed_tunnel = std::make_shared<Tunnel>(
                pb.circuit_id, pb.hops, pb.destination);
            completed_tunnel->set_state(TunnelState::ACTIVE);
            pool_->add_tunnel(completed_tunnel);

            // Record success for all hops in profiler
            for (const auto& hop : pb.hops) {
                profiler_->record_result(hop.node_id, true);
            }

            cb = std::move(pb.callback);
            pending_builds_.erase(it);
        }
    }

    if (completed_tunnel && cb) {
        spdlog::info("Circuit {} successfully built and active in pool!", completed_tunnel->circuit_id().to_short_hex());
        cb(true, completed_tunnel);
    }
}

void TunnelManager::handle_tunnel_build_fail(const NodeID& from_peer, const TunnelBuildFailMsg& msg) {
    TunnelBuildCallback cb = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_builds_.find(msg.circuit_id);
        if (it != pending_builds_.end()) {
            profiler_->record_result(from_peer, false);
            cb = std::move(it->second.callback);
            pending_builds_.erase(it);
        }
    }

    spdlog::warn("Circuit {} build failed at hop {}: {}",
                 msg.circuit_id.to_short_hex(), msg.hop_index, msg.reason);

    if (cb) {
        cb(false, nullptr);
    }
}

std::optional<PeeledLayer> TunnelManager::handle_tunnel_data(
    const NodeID& from_peer,
    const TunnelDataMsg& msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = relay_circuits_.find(msg.circuit_id);
    if (it == relay_circuits_.end()) {
        spdlog::warn("Received TUNNEL_DATA for unknown circuit {}", msg.circuit_id.to_short_hex());
        return std::nullopt;
    }

    it->second.last_active = std::chrono::steady_clock::now();

    // Peel layer using this relay's layer key
    auto peeled = OnionPacket::peel(msg.onion_payload, it->second.layer_key, msg.sequence_number);
    if (!peeled) {
        spdlog::warn("Failed to peel onion layer for circuit {}", msg.circuit_id.to_short_hex());
        return std::nullopt;
    }

    if (peeled->is_terminal && data_handler_) {
        // Delivered to destination endpoint
        data_handler_(msg.circuit_id, peeled->payload);
    }

    return peeled;
}

void TunnelManager::close_tunnel(
    const CircuitID& circuit_id,
    std::function<void(const PeerAddress& target, const TunnelCloseMsg& msg)> send_close_fn)
{
    std::shared_ptr<Tunnel> tunnel = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tunnel = pool_->get_tunnel(circuit_id);
        pool_->remove_tunnel(circuit_id);
        relay_circuits_.erase(circuit_id);
    }

    if (tunnel) {
        tunnel->set_state(TunnelState::CLOSED);
        if (send_close_fn && !tunnel->hops().empty()) {
            TunnelCloseMsg close_msg;
            close_msg.circuit_id = circuit_id;
            close_msg.reason = "Normal circuit teardown";
            send_close_fn(tunnel->entry_hop().address, close_msg);
        }
    }
}

} // namespace p2p::tunnel

