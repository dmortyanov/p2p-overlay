/// @file main.cpp
/// @brief P2P overlay node entry point.
///
/// Usage:
///   p2p_node [options]
///
/// Options:
///   --config <path>      Path to TOML config (default: config/default.toml)
///   --port <port>        Listen port override
///   --data-dir <dir>     Data directory override
///   --bootstrap <peers>  Comma-separated bootstrap peers (host:port,...)
///   --log-level <level>  Log level: trace,debug,info,warn,error
///
/// Examples:
///   p2p_node --port 9001 --bootstrap "127.0.0.1:9000"
///   p2p_node --config my_config.toml --log-level debug

#include "node.hpp"
#include "config/config.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <sodium.h>

#include <csignal>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace {

// Global node pointer for signal handling
p2p::Node* g_node = nullptr;

void signal_handler(int sig) {
    spdlog::info("Received signal {}, shutting down...", sig);
    if (g_node) {
        g_node->stop();
    }
}

/// Parse comma-separated peer list.
std::vector<std::string> parse_peers(const std::string& peers_str) {
    std::vector<std::string> peers;
    std::string current;
    for (char c : peers_str) {
        if (c == ',') {
            if (!current.empty()) {
                peers.push_back(current);
                current.clear();
            }
        } else if (c != ' ') {
            current += c;
        }
    }
    if (!current.empty()) {
        peers.push_back(current);
    }
    return peers;
}

void setup_logging(const std::string& level) {
    auto console = spdlog::get("console");
    if (!console) {
        console = spdlog::stdout_color_mt("console");
        spdlog::set_default_logger(console);
    }

    if      (level == "trace")    spdlog::set_level(spdlog::level::trace);
    else if (level == "debug")    spdlog::set_level(spdlog::level::debug);
    else if (level == "info")     spdlog::set_level(spdlog::level::info);
    else if (level == "warn")     spdlog::set_level(spdlog::level::warn);
    else if (level == "error")    spdlog::set_level(spdlog::level::err);
    else if (level == "critical") spdlog::set_level(spdlog::level::critical);
    else                          spdlog::set_level(spdlog::level::info);

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    // ─── Parse command-line arguments ────────────────────────────
    std::string config_path    = "config/default.toml";
    std::string listen_address;
    uint16_t    listen_port    = 0;
    std::string data_dir;
    std::string bootstrap_str;
    std::string log_level      = "info";
    std::string dump_routing_path;
    int duration_sec           = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
            config_path = argv[++i];
        } else if ((arg == "--port" || arg == "-p") && i + 1 < argc) {
            listen_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "--address" || arg == "-a") && i + 1 < argc) {
            listen_address = argv[++i];
        } else if ((arg == "--data-dir" || arg == "-d") && i + 1 < argc) {
            data_dir = argv[++i];
        } else if ((arg == "--bootstrap" || arg == "-b") && i + 1 < argc) {
            bootstrap_str = argv[++i];
        } else if ((arg == "--log-level" || arg == "-l") && i + 1 < argc) {
            log_level = argv[++i];
        } else if (arg == "--dump-routing" && i + 1 < argc) {
            dump_routing_path = argv[++i];
        } else if (arg == "--duration" && i + 1 < argc) {
            duration_sec = std::stoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "P2P Overlay Node v0.1.0\n"
                      << "Usage: p2p_node [options]\n"
                      << "  --config, -c <path>      Config file (default: config/default.toml)\n"
                      << "  --port, -p <port>        Listen port\n"
                      << "  --address, -a <addr>     Listen address\n"
                      << "  --data-dir, -d <dir>     Data directory\n"
                      << "  --bootstrap, -b <peers>  Bootstrap peers (host:port,...)\n"
                      << "  --log-level, -l <level>  Log level (trace/debug/info/warn/error)\n"
                      << "  --dump-routing <path>    Dump routing table JSON to path on exit\n"
                      << "  --duration <seconds>     Auto-terminate after duration\n"
                      << "  --help, -h               Show this help\n";
            return 0;
        }
    }

    // ─── Setup ───────────────────────────────────────────────────
    setup_logging(log_level);

    if (sodium_init() < 0) {
        spdlog::critical("Failed to initialize libsodium");
        return 1;
    }

    // ─── Load config ─────────────────────────────────────────────
    auto bootstrap_peers = bootstrap_str.empty()
        ? std::vector<std::string>{}
        : parse_peers(bootstrap_str);

    auto config = p2p::config::load_config(
        config_path, listen_address, listen_port, data_dir, bootstrap_peers);

    // Apply log level from config if not overridden
    if (log_level == "info" && !config.logging.level.empty()) {
        setup_logging(config.logging.level);
    }

    // ─── Create and run node ─────────────────────────────────────
    try {
        p2p::Node node(std::move(config));
        g_node = &node;

        // Install signal handlers for graceful shutdown
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        node.start();

        std::thread killer;
        if (duration_sec > 0) {
            killer = std::thread([&node, duration_sec]() {
                std::this_thread::sleep_for(std::chrono::seconds(duration_sec));
                spdlog::info("Duration timer expired ({} s), stopping node...", duration_sec);
                node.stop();
            });
        }

        node.run();

        if (killer.joinable()) {
            killer.join();
        }

        if (!dump_routing_path.empty()) {
            if (dump_routing_path == "-") {
                std::cout << "\n--- ROUTING_TABLE_JSON_START ---\n"
                          << node.export_routing_table_json()
                          << "\n--- ROUTING_TABLE_JSON_END ---\n" << std::flush;
            } else {
                try {
                    auto p = std::filesystem::path(dump_routing_path);
                    if (p.has_parent_path()) {
                        std::filesystem::create_directories(p.parent_path());
                    }
                    std::ofstream f(dump_routing_path);
                    if (f.is_open()) {
                        f << node.export_routing_table_json();
                        spdlog::info("Exported routing table to {}", dump_routing_path);
                    }
                } catch (const std::exception& e) {
                    spdlog::error("Failed to dump routing table to {}: {}", dump_routing_path, e.what());
                }
            }
        }

        g_node = nullptr;
        spdlog::info("Node shut down cleanly");
        return 0;

    } catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        return 1;
    }
}
