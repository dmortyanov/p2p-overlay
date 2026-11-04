#pragma once
/// @file tunnel_manager.hpp
/// @brief Tunnel Manager orchestrating circuit creation, hop forwarding, and teardown (Stage 5).

#include "common/types.hpp"
#include "tunnel/tunnel_types.hpp"
#include "tunnel/tunnel.hpp"
#include "tunnel/tunnel_pool.hpp"
#include "tunnel/relay_profiler.hpp"
#include "security/crypto_utils.hpp"
#include "identity/keypair.hpp"

#include <memory>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace p2p::tunnel {

/// Callback definitions
using TunnelBuildCallback = std::function<void(bool success, std::shared_ptr<Tunnel> tunnel)>;
using TunnelDataCallback  = std::function<void(const CircuitID& cid, ByteSpan payload)>;

/// Intermediate relay state for a circuit passing through this node.
struct RelayCircuitState {
    CircuitID circuit_id{};
    uint8_t hop_index{0};
    std::array<uint8_t, security::AEAD_KEY_SIZE> layer_key{};
    NodeID prev_hop_node_id{};
    NodeID next_hop_node_id{};
    PeerAddress next_hop_address{};
    bool is_exit{false};
    std::chrono::steady_clock::time_point last_active{};
};

class TunnelManager {
public:
    TunnelManager(NodeID local_node_id,
                  const identity::Keypair& keypair,
                  std::shared_ptr<TunnelPool> pool = nullptr,
                  std::shared_ptr<RelayProfiler> profiler = nullptr);

    [[nodiscard]] std::shared_ptr<TunnelPool> pool() const { return pool_; }
    [[nodiscard]] std::shared_ptr<RelayProfiler> profiler() const { return profiler_; }

    /// Initiate asynchronous construction of a multi-hop onion circuit.
    /// @param hops Ordered relay hops chosen by RelayProfiler.
    /// @param destination Final destination NodeID.
    /// @param send_build_fn Transport function to send TUNNEL_BUILD frame to first hop.
    /// @param callback Invoked upon success or timeout.
    void async_build_tunnel(
        const std::vector<PeerInfo>& hops,
        const NodeID& destination,
        std::function<void(const PeerAddress& target, const TunnelBuildMsg& msg)> send_build_fn,
        TunnelBuildCallback callback);

    /// Get ephemeral public key for a hop in a pending circuit build.
    [[nodiscard]] std::optional<std::array<uint8_t, 32>> get_build_eph_pub(const CircuitID& cid, uint8_t hop_idx) const;

    /// Process incoming TUNNEL_BUILD at intermediate or exit relay.
    /// @return Response message (TUNNEL_BUILD_OK or TUNNEL_BUILD_FAIL).
    [[nodiscard]] std::variant<TunnelBuildOkMsg, TunnelBuildFailMsg> handle_tunnel_build(
        const NodeID& from_peer,
        const TunnelBuildMsg& msg);

    /// Process incoming TUNNEL_BUILD_OK at initiator.
    void handle_tunnel_build_ok(const NodeID& from_peer, const TunnelBuildOkMsg& msg);

    /// Process incoming TUNNEL_BUILD_FAIL at initiator.
    void handle_tunnel_build_fail(const NodeID& from_peer, const TunnelBuildFailMsg& msg);

    /// Process incoming TUNNEL_DATA at relay or endpoint.
    /// If intermediate relay: peels one layer, returns forwarded next hop and peeled payload.
    /// If exit / endpoint: returns plaintext payload.
    [[nodiscard]] std::optional<PeeledLayer> handle_tunnel_data(
        const NodeID& from_peer,
        const TunnelDataMsg& msg);

    /// Close circuit.
    void close_tunnel(const CircuitID& circuit_id,
                      std::function<void(const PeerAddress& target, const TunnelCloseMsg& msg)> send_close_fn = nullptr);

    /// Register data handler for messages exiting a tunnel locally.
    void set_data_handler(TunnelDataCallback handler) {
        data_handler_ = std::move(handler);
    }

private:
    NodeID local_node_id_;
    const identity::Keypair& keypair_;
    std::shared_ptr<TunnelPool> pool_;
    std::shared_ptr<RelayProfiler> profiler_;

    mutable std::mutex mutex_;

    // Pending circuit builds initiated locally
    struct PendingBuild {
        CircuitID circuit_id;
        std::vector<TunnelHop> hops;
        NodeID destination;
        std::vector<security::X25519Keypair> ephemeral_keys; // Keypair per hop
        std::size_t acks_received{0};
        TunnelBuildCallback callback;
        std::chrono::steady_clock::time_point start_time;
    };
    std::unordered_map<CircuitID, PendingBuild> pending_builds_;

    // Circuits forwarded through this node as a relay
    std::unordered_map<CircuitID, RelayCircuitState> relay_circuits_;

    TunnelDataCallback data_handler_;
};

} // namespace p2p::tunnel

