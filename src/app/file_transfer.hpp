#pragma once
/// @file file_transfer.hpp
/// @brief Chunked file transfer engine with SHA-256 integrity and sliding window (Stage 6).

#include "common/types.hpp"
#include "app/app_messages.hpp"
#include "identity/node_id.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <filesystem>
#include <fstream>

namespace p2p::app {

/// ─── File Utilities ────────────────────────────────────────────────────────

/// Compute SHA-256 of a memory buffer.
[[nodiscard]] std::array<uint8_t, 32> compute_sha256(ByteSpan data);

/// Compute SHA-256 of a file on disk.
[[nodiscard]] std::optional<std::array<uint8_t, 32>> compute_file_sha256(const std::filesystem::path& path);

/// Chunk metadata holding precomputed chunk bytes and hash.
struct ChunkData {
    uint32_t index{0};
    Bytes data{};
    std::array<uint8_t, 32> sha256{};
};

/// ─── File Chunker ──────────────────────────────────────────────────────────

/// Splits local file into chunks of size chunk_size and computes hashes.
class FileChunker {
public:
    static std::optional<FileChunker> from_file(
        const std::filesystem::path& path,
        const NodeID& sender_id,
        uint32_t chunk_size = DEFAULT_CHUNK_SIZE);

    [[nodiscard]] const FileMeta& meta() const noexcept { return meta_; }
    [[nodiscard]] const std::vector<ChunkData>& chunks() const noexcept { return chunks_; }
    [[nodiscard]] std::optional<ChunkData> get_chunk(uint32_t index) const;

private:
    FileMeta meta_{};
    std::vector<ChunkData> chunks_{};
};

/// ─── File Sender Session ───────────────────────────────────────────────────

class FileSenderSession {
public:
    using SendBlockFunc = std::function<void(const FileBlock&)>;
    using ProgressFunc = std::function<void(uint64_t sent_bytes, uint64_t total_bytes)>;
    using CompletionFunc = std::function<void(bool success, const std::string& err)>;

    FileSenderSession(FileChunker chunker,
                      NodeID recipient,
                      uint32_t window_size = 4);

    [[nodiscard]] const FileMeta& meta() const noexcept { return chunker_.meta(); }
    [[nodiscard]] const NodeID& recipient() const noexcept { return recipient_; }
    [[nodiscard]] bool is_complete() const;

    /// Begin or advance transmission: sends blocks within sliding window.
    void advance_window(const SendBlockFunc& send_block);

    /// Process received FileAck for a chunk.
    /// Returns true if all chunks are now acknowledged.
    bool handle_ack(const FileAck& ack, const SendBlockFunc& send_block);

    void set_progress_callback(ProgressFunc cb) { progress_cb_ = std::move(cb); }
    void set_completion_callback(CompletionFunc cb) { completion_cb_ = std::move(cb); }
    void mark_completed(bool success, const std::string& err);

private:
    FileChunker chunker_;
    NodeID recipient_{};
    uint32_t window_size_{4};
    uint32_t window_start_{0};
    uint32_t next_to_send_{0};
    std::vector<bool> acked_{};
    ProgressFunc progress_cb_{};
    CompletionFunc completion_cb_{};
    mutable std::mutex mutex_{};
};

/// ─── File Receiver Session ─────────────────────────────────────────────────

class FileReceiverSession {
public:
    FileReceiverSession(FileMeta meta, std::filesystem::path download_dir);
    ~FileReceiverSession();

    [[nodiscard]] const FileMeta& meta() const noexcept { return meta_; }
    [[nodiscard]] bool is_complete() const noexcept { return is_complete_; }
    [[nodiscard]] const std::filesystem::path& target_path() const noexcept { return target_path_; }

    /// Receive and validate incoming FileBlock.
    /// Returns FileAck to send back.
    FileAck handle_block(const FileBlock& block);

    /// Verify full file SHA-256 and finalize download.
    bool finalize();

private:
    FileMeta meta_{};
    std::filesystem::path download_dir_{};
    std::filesystem::path temp_path_{};
    std::filesystem::path target_path_{};
    std::vector<bool> received_chunks_{};
    uint32_t received_count_{0};
    bool is_complete_{false};
    mutable std::mutex mutex_{};
};

/// ─── High-Level File Transfer Manager ──────────────────────────────────────

class FileTransferManager {
public:
    using SendMetaFunc = std::function<void(const NodeID& target, const FileMeta&)>;
    using SendBlockFunc = std::function<void(const NodeID& target, const FileBlock&)>;
    using SendAckFunc = std::function<void(const NodeID& target, const FileAck&)>;
    using SendCompleteFunc = std::function<void(const NodeID& target, const FileComplete&)>;

    using OnFileReceivedCallback = std::function<void(const FileMeta& meta, const std::filesystem::path& local_path)>;

    explicit FileTransferManager(std::filesystem::path download_dir);

    [[nodiscard]] const std::filesystem::path& download_dir() const noexcept { return download_dir_; }

    /// Start sending a local file to target recipient.
    bool start_send_file(
        const std::filesystem::path& filepath,
        const NodeID& sender_id,
        const NodeID& recipient_id,
        const SendMetaFunc& send_meta,
        const SendBlockFunc& send_block,
        FileSenderSession::ProgressFunc progress_cb = nullptr,
        FileSenderSession::CompletionFunc completion_cb = nullptr);

    /// Handle incoming APP_FILE_META (0x42)
    bool handle_file_meta(const FileMeta& meta);

    /// Handle incoming APP_FILE_BLOCK (0x43)
    std::optional<FileAck> handle_file_block(
        const FileBlock& block,
        const SendCompleteFunc& send_complete = nullptr);

    /// Handle incoming APP_FILE_ACK (0x44)
    bool handle_file_ack(const FileAck& ack, const SendBlockFunc& send_block);

    /// Handle incoming APP_FILE_COMPLETE (0x45)
    bool handle_file_complete(const FileComplete& complete);

    void set_on_file_received(OnFileReceivedCallback cb) { on_received_cb_ = std::move(cb); }

    [[nodiscard]] std::size_t active_senders_count() const;
    [[nodiscard]] std::size_t active_receivers_count() const;

private:
    std::filesystem::path download_dir_{};
    std::map<RequestID, std::shared_ptr<FileSenderSession>> senders_{};
    std::map<RequestID, std::shared_ptr<FileReceiverSession>> receivers_{};
    OnFileReceivedCallback on_received_cb_{};
    mutable std::mutex mutex_{};
};

} // namespace p2p::app
