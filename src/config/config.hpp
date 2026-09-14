#pragma once
/// @file config.hpp
/// @brief Configuration loading from TOML files.

#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>

namespace p2p::config {

/// All configuration parameters for a P2P node.
/// Corresponds to config/default.toml structure.
struct Config {
    // ─── Node ────────────────────────────────────────────────
    struct {
        std::string listen_address = "0.0.0.0";
        uint16_t    listen_port    = 9000;
        std::string data_dir       = "./node_state";
    } node;

    // ─── Identity ────────────────────────────────────────────
    struct {
        std::string algorithm = "ed25519";
    } identity;

    // ─── DHT ─────────────────────────────────────────────────
    struct {
        int      node_id_bits          = 256;
        int      k_bucket_size         = 4;
        int      alpha                 = 3;
        int      replication           = 3;
        int      record_ttl_sec        = 180;
        int      republish_interval_sec = 80;
        int      refresh_interval_sec  = 60;
        int      max_record_size       = 4096;
    } dht;

    // ─── Transport ───────────────────────────────────────────
    struct {
        int      protocol_version     = 1;
        uint32_t max_frame_payload    = 65536;
        int      connect_timeout_ms   = 5000;
        int      io_timeout_ms        = 10000;
        int      keepalive_interval_ms = 30000;
    } transport;

    // ─── Tunnel ──────────────────────────────────────────────
    struct {
        int min_relay_hops        = 3;
        int max_relay_hops        = 5;
        int tunnel_ttl_sec        = 300;
        int pool_size             = 3;
        int heartbeat_interval_ms = 10000;
        int max_consecutive_failures = 3;

        struct {
            double ema_alpha_success = 0.3;
            double ema_alpha_latency = 0.2;
        } profiling;
    } tunnel;

    // ─── Application ─────────────────────────────────────────
    struct {
        int         max_message_size          = 65536;
        int         file_block_size           = 49152;
        int64_t     max_file_size             = 104857600;
        int         incomplete_file_timeout_sec = 120;
        std::string download_dir              = "./downloads";
    } app;

    // ─── Logging ─────────────────────────────────────────────
    struct {
        std::string level = "info";
        std::string file;
    } logging;

    // ─── Metrics ─────────────────────────────────────────────
    struct {
        bool        enabled       = true;
        std::string export_format = "csv";
        std::string export_dir    = "./results";
    } metrics;

    // ─── Bootstrap ───────────────────────────────────────────
    struct {
        std::string              scheme = "star";
        std::vector<std::string> peers;
    } bootstrap;
};

/// Load configuration from a TOML file.
/// Missing fields use defaults from the struct above.
[[nodiscard]] Config load_config(const std::filesystem::path& path);

/// Load with override: base config + command-line overrides.
[[nodiscard]] Config load_config(const std::filesystem::path& path,
                                 const std::string& listen_address,
                                 uint16_t listen_port,
                                 const std::string& data_dir,
                                 const std::vector<std::string>& bootstrap_peers);

} // namespace p2p::config
