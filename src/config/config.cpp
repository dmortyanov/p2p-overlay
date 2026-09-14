/// @file config.cpp
/// @brief TOML configuration loader using toml++.

#include "config/config.hpp"

#include <spdlog/spdlog.h>
#include <toml++/toml.hpp>

#include <stdexcept>

namespace p2p::config {

Config load_config(const std::filesystem::path& path) {
    Config cfg;

    if (!std::filesystem::exists(path)) {
        spdlog::warn("Config file {} not found, using defaults", path.string());
        return cfg;
    }

    try {
        auto tbl = toml::parse_file(path.string());

        // ─── Node ────────────────────────────────────────────
        if (auto node = tbl["node"]) {
            cfg.node.listen_address = node["listen_address"].value_or(cfg.node.listen_address);
            cfg.node.listen_port    = static_cast<uint16_t>(
                node["listen_port"].value_or(static_cast<int64_t>(cfg.node.listen_port)));
            cfg.node.data_dir       = node["data_dir"].value_or(cfg.node.data_dir);
        }

        // ─── Identity ───────────────────────────────────────
        if (auto id = tbl["identity"]) {
            cfg.identity.algorithm = id["algorithm"].value_or(cfg.identity.algorithm);
        }

        // ─── DHT ─────────────────────────────────────────────
        if (auto dht = tbl["dht"]) {
            cfg.dht.node_id_bits          = static_cast<int>(dht["node_id_bits"].value_or(static_cast<int64_t>(cfg.dht.node_id_bits)));
            cfg.dht.k_bucket_size         = static_cast<int>(dht["k_bucket_size"].value_or(static_cast<int64_t>(cfg.dht.k_bucket_size)));
            cfg.dht.alpha                 = static_cast<int>(dht["alpha"].value_or(static_cast<int64_t>(cfg.dht.alpha)));
            cfg.dht.replication           = static_cast<int>(dht["replication"].value_or(static_cast<int64_t>(cfg.dht.replication)));
            cfg.dht.record_ttl_sec        = static_cast<int>(dht["record_ttl_sec"].value_or(static_cast<int64_t>(cfg.dht.record_ttl_sec)));
            cfg.dht.republish_interval_sec = static_cast<int>(dht["republish_interval_sec"].value_or(static_cast<int64_t>(cfg.dht.republish_interval_sec)));
            cfg.dht.refresh_interval_sec  = static_cast<int>(dht["refresh_interval_sec"].value_or(static_cast<int64_t>(cfg.dht.refresh_interval_sec)));
            cfg.dht.max_record_size       = static_cast<int>(dht["max_record_size"].value_or(static_cast<int64_t>(cfg.dht.max_record_size)));
        }

        // ─── Transport ───────────────────────────────────────
        if (auto tr = tbl["transport"]) {
            cfg.transport.protocol_version     = static_cast<int>(tr["protocol_version"].value_or(static_cast<int64_t>(cfg.transport.protocol_version)));
            cfg.transport.max_frame_payload    = static_cast<uint32_t>(tr["max_frame_payload"].value_or(static_cast<int64_t>(cfg.transport.max_frame_payload)));
            cfg.transport.connect_timeout_ms   = static_cast<int>(tr["connect_timeout_ms"].value_or(static_cast<int64_t>(cfg.transport.connect_timeout_ms)));
            cfg.transport.io_timeout_ms        = static_cast<int>(tr["io_timeout_ms"].value_or(static_cast<int64_t>(cfg.transport.io_timeout_ms)));
            cfg.transport.keepalive_interval_ms = static_cast<int>(tr["keepalive_interval_ms"].value_or(static_cast<int64_t>(cfg.transport.keepalive_interval_ms)));
        }

        // ─── Tunnel ──────────────────────────────────────────
        if (auto tn = tbl["tunnel"]) {
            cfg.tunnel.min_relay_hops        = static_cast<int>(tn["min_relay_hops"].value_or(static_cast<int64_t>(cfg.tunnel.min_relay_hops)));
            cfg.tunnel.max_relay_hops        = static_cast<int>(tn["max_relay_hops"].value_or(static_cast<int64_t>(cfg.tunnel.max_relay_hops)));
            cfg.tunnel.tunnel_ttl_sec        = static_cast<int>(tn["tunnel_ttl_sec"].value_or(static_cast<int64_t>(cfg.tunnel.tunnel_ttl_sec)));
            cfg.tunnel.pool_size             = static_cast<int>(tn["pool_size"].value_or(static_cast<int64_t>(cfg.tunnel.pool_size)));
            cfg.tunnel.heartbeat_interval_ms = static_cast<int>(tn["heartbeat_interval_ms"].value_or(static_cast<int64_t>(cfg.tunnel.heartbeat_interval_ms)));
            cfg.tunnel.max_consecutive_failures = static_cast<int>(tn["max_consecutive_failures"].value_or(static_cast<int64_t>(cfg.tunnel.max_consecutive_failures)));

            if (auto prof = tn["profiling"]) {
                cfg.tunnel.profiling.ema_alpha_success = prof["ema_alpha_success"].value_or(cfg.tunnel.profiling.ema_alpha_success);
                cfg.tunnel.profiling.ema_alpha_latency = prof["ema_alpha_latency"].value_or(cfg.tunnel.profiling.ema_alpha_latency);
            }
        }

        // ─── App ─────────────────────────────────────────────
        if (auto app = tbl["app"]) {
            cfg.app.max_message_size          = static_cast<int>(app["max_message_size"].value_or(static_cast<int64_t>(cfg.app.max_message_size)));
            cfg.app.file_block_size           = static_cast<int>(app["file_block_size"].value_or(static_cast<int64_t>(cfg.app.file_block_size)));
            cfg.app.max_file_size             = app["max_file_size"].value_or(cfg.app.max_file_size);
            cfg.app.incomplete_file_timeout_sec = static_cast<int>(app["incomplete_file_timeout_sec"].value_or(static_cast<int64_t>(cfg.app.incomplete_file_timeout_sec)));
            cfg.app.download_dir              = app["download_dir"].value_or(cfg.app.download_dir);
        }

        // ─── Logging ─────────────────────────────────────────
        if (auto log = tbl["logging"]) {
            cfg.logging.level = log["level"].value_or(cfg.logging.level);
            cfg.logging.file  = log["file"].value_or(cfg.logging.file);
        }

        // ─── Metrics ─────────────────────────────────────────
        if (auto met = tbl["metrics"]) {
            cfg.metrics.enabled       = met["enabled"].value_or(cfg.metrics.enabled);
            cfg.metrics.export_format = met["export_format"].value_or(cfg.metrics.export_format);
            cfg.metrics.export_dir    = met["export_dir"].value_or(cfg.metrics.export_dir);
        }

        // ─── Bootstrap ───────────────────────────────────────
        if (auto bs = tbl["bootstrap"]) {
            cfg.bootstrap.scheme = bs["scheme"].value_or(cfg.bootstrap.scheme);

            if (auto peers = bs["peers"].as_array()) {
                cfg.bootstrap.peers.clear();
                for (const auto& peer : *peers) {
                    if (auto s = peer.value<std::string>()) {
                        cfg.bootstrap.peers.push_back(*s);
                    }
                }
            }
        }

        spdlog::info("Loaded config from {}", path.string());

    } catch (const toml::parse_error& err) {
        throw std::runtime_error(
            "Failed to parse config " + path.string() + ": " + std::string(err.description()));
    }

    return cfg;
}

Config load_config(const std::filesystem::path& path,
                   const std::string& listen_address,
                   uint16_t listen_port,
                   const std::string& data_dir,
                   const std::vector<std::string>& bootstrap_peers) {
    auto cfg = load_config(path);

    // Apply command-line overrides
    if (!listen_address.empty()) cfg.node.listen_address = listen_address;
    if (listen_port != 0)        cfg.node.listen_port    = listen_port;
    if (!data_dir.empty())       cfg.node.data_dir       = data_dir;
    if (!bootstrap_peers.empty()) cfg.bootstrap.peers    = bootstrap_peers;

    return cfg;
}

} // namespace p2p::config
