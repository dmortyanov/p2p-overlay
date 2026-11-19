#pragma once
/// @file app_messages.hpp
/// @brief Wire message structures and CBOR serialization for Application Layer (Stage 6).
///
/// Implements E2E messaging (APP_MESSAGE, APP_ACK) and chunked file transfer
/// (APP_FILE_META, APP_FILE_BLOCK, APP_FILE_ACK, APP_FILE_COMPLETE).

#include "common/types.hpp"
#include "transport/message_types.hpp"
#include "identity/node_id.hpp"

#include <cstdint>
#include <array>
#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace p2p::app {

/// Default chunk size: 48 KiB = 49 152 bytes (fits easily in MAX_FRAME_PAYLOAD = 65 536).
inline constexpr uint32_t DEFAULT_CHUNK_SIZE = 48 * 1024;

/// Maximum permissible chunk size: 60 KiB = 61 440 bytes.
inline constexpr uint32_t MAX_CHUNK_SIZE = 60 * 1024;

/// Upper limit for file transfers (1 GiB).
inline constexpr uint64_t MAX_FILE_SIZE = 1024ULL * 1024ULL * 1024ULL;

/// ─── Message Structures ────────────────────────────────────────────────────

/// Payload for APP_MESSAGE (0x40).
struct AppMessage {
    RequestID msg_id{RequestID::generate()};
    NodeID sender_id{};
    NodeID recipient_id{};
    uint64_t timestamp{0};
    std::string text{};
    bool is_e2e_encrypted{false};
};

/// Payload for APP_ACK (0x41).
struct AppAck {
    RequestID msg_id{};
    NodeID sender_id{};
    bool ok{true};
    std::string error_msg{};
};

/// Payload for APP_FILE_META (0x42).
struct FileMeta {
    RequestID file_id{RequestID::generate()};
    std::string filename{};
    uint64_t file_size{0};
    uint32_t chunk_size{DEFAULT_CHUNK_SIZE};
    uint32_t total_chunks{0};
    std::array<uint8_t, 32> file_sha256{};
    NodeID sender_id{};
};

/// Payload for APP_FILE_BLOCK (0x43).
struct FileBlock {
    RequestID file_id{};
    uint32_t chunk_index{0};
    Bytes data{};
    std::array<uint8_t, 32> chunk_sha256{};
};

/// Payload for APP_FILE_ACK (0x44).
struct FileAck {
    RequestID file_id{};
    uint32_t chunk_index{0};
    bool ok{true};
    std::string error_msg{};
};

/// Payload for APP_FILE_COMPLETE (0x45).
struct FileComplete {
    RequestID file_id{};
    bool ok{true};
    std::array<uint8_t, 32> file_sha256{};
};

/// ─── Path Sanitization & Security Helpers ─────────────────────────────────

/// Check if a filename is safe (no directory separators '/', '\', no '..', not empty).
[[nodiscard]] bool is_safe_filename(std::string_view name);

/// Sanitize filename: extracts base name, strips traversal characters, returns safe filename.
/// Returns fallback "download.dat" if input is completely empty or malicious.
[[nodiscard]] std::string sanitize_filename(std::string_view name);

/// ─── CBOR Serialization / Deserialization ──────────────────────────────────

[[nodiscard]] Bytes serialize_app_message(const AppMessage& msg);
[[nodiscard]] bool deserialize_app_message(ByteSpan payload, AppMessage& out_msg);

[[nodiscard]] Bytes serialize_app_ack(const AppAck& msg);
[[nodiscard]] bool deserialize_app_ack(ByteSpan payload, AppAck& out_msg);

[[nodiscard]] Bytes serialize_file_meta(const FileMeta& msg);
[[nodiscard]] bool deserialize_file_meta(ByteSpan payload, FileMeta& out_msg);

[[nodiscard]] Bytes serialize_file_block(const FileBlock& msg);
[[nodiscard]] bool deserialize_file_block(ByteSpan payload, FileBlock& out_msg);

[[nodiscard]] Bytes serialize_file_ack(const FileAck& msg);
[[nodiscard]] bool deserialize_file_ack(ByteSpan payload, FileAck& out_msg);

[[nodiscard]] Bytes serialize_file_complete(const FileComplete& msg);
[[nodiscard]] bool deserialize_file_complete(ByteSpan payload, FileComplete& out_msg);

} // namespace p2p::app

