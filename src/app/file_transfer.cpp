/// @file file_transfer.cpp
/// @brief Implementation of chunked file transfer engine.

#include "app/file_transfer.hpp"
#include <sodium.h>
#include <fstream>
#include <iostream>

namespace p2p::app {

std::array<uint8_t, 32> compute_sha256(ByteSpan data) {
    std::array<uint8_t, 32> hash{};
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
}

std::optional<std::array<uint8_t, 32>> compute_file_sha256(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return std::nullopt;

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    std::vector<char> buffer(64 * 1024);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char*>(buffer.data()), file.gcount());
    }

    std::array<uint8_t, 32> hash{};
    crypto_hash_sha256_final(&state, hash.data());
    return hash;
}

// ─── FileChunker ────────────────────────────────────────────────────────────

std::optional<FileChunker> FileChunker::from_file(
    const std::filesystem::path& path,
    const NodeID& sender_id,
    uint32_t chunk_size) {

    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        return std::nullopt;
    }

    uint64_t file_size = std::filesystem::file_size(path, ec);
    if (ec || file_size > MAX_FILE_SIZE) {
        return std::nullopt;
    }

    if (chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE) {
        chunk_size = DEFAULT_CHUNK_SIZE;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return std::nullopt;

    FileChunker chunker;
    chunker.meta_.file_id = RequestID::generate();
    chunker.meta_.filename = sanitize_filename(path.filename().string());
    chunker.meta_.file_size = file_size;
    chunker.meta_.chunk_size = chunk_size;
    chunker.meta_.sender_id = sender_id;

    if (file_size == 0) {
        chunker.meta_.total_chunks = 0;
        chunker.meta_.file_sha256 = compute_sha256({});
        return chunker;
    }

    uint32_t total_chunks = static_cast<uint32_t>((file_size + chunk_size - 1) / chunk_size);
    chunker.meta_.total_chunks = total_chunks;

    crypto_hash_sha256_state file_hash_state;
    crypto_hash_sha256_init(&file_hash_state);

    for (uint32_t i = 0; i < total_chunks; ++i) {
        uint32_t current_chunk_len = static_cast<uint32_t>(
            std::min<uint64_t>(chunk_size, file_size - static_cast<uint64_t>(i) * chunk_size));

        Bytes chunk_bytes(current_chunk_len);
        file.read(reinterpret_cast<char*>(chunk_bytes.data()), current_chunk_len);
        if (static_cast<uint32_t>(file.gcount()) != current_chunk_len) {
            return std::nullopt;
        }

        crypto_hash_sha256_update(&file_hash_state, chunk_bytes.data(), chunk_bytes.size());

        ChunkData cd;
        cd.index = i;
        cd.data = std::move(chunk_bytes);
        cd.sha256 = compute_sha256(cd.data);

        chunker.chunks_.push_back(std::move(cd));
    }

    crypto_hash_sha256_final(&file_hash_state, chunker.meta_.file_sha256.data());
    return chunker;
}

std::optional<ChunkData> FileChunker::get_chunk(uint32_t index) const {
    if (index >= chunks_.size()) return std::nullopt;
    return chunks_[index];
}

// ─── FileSenderSession ──────────────────────────────────────────────────────

FileSenderSession::FileSenderSession(FileChunker chunker,
                                     NodeID recipient,
                                     uint32_t window_size)
    : chunker_(std::move(chunker)),
      recipient_(recipient),
      window_size_(std::max<uint32_t>(1, window_size)),
      acked_(chunker_.meta().total_chunks, false) {}

bool FileSenderSession::is_complete() const {
    std::lock_guard lock(mutex_);
    if (chunker_.meta().total_chunks == 0) return true;
    return window_start_ >= chunker_.meta().total_chunks;
}

void FileSenderSession::advance_window(const SendBlockFunc& send_block) {
    std::lock_guard lock(mutex_);
    if (!send_block) return;

    uint32_t total = chunker_.meta().total_chunks;
    uint32_t window_end = std::min(window_start_ + window_size_, total);

    while (next_to_send_ < window_end) {
        auto chunk = chunker_.get_chunk(next_to_send_);
        if (chunk) {
            FileBlock block;
            block.file_id = chunker_.meta().file_id;
            block.chunk_index = chunk->index;
            block.data = chunk->data;
            block.chunk_sha256 = chunk->sha256;
            send_block(block);
        }
        ++next_to_send_;
    }
}

bool FileSenderSession::handle_ack(const FileAck& ack, const SendBlockFunc& send_block) {
    std::lock_guard lock(mutex_);
    if (ack.file_id != chunker_.meta().file_id) return false;
    if (ack.chunk_index >= acked_.size()) return false;

    if (!ack.ok) {
        // Retransmit failed chunk
        auto chunk = chunker_.get_chunk(ack.chunk_index);
        if (chunk && send_block) {
            FileBlock block;
            block.file_id = chunker_.meta().file_id;
            block.chunk_index = chunk->index;
            block.data = chunk->data;
            block.chunk_sha256 = chunk->sha256;
            send_block(block);
        }
        return false;
    }

    acked_[ack.chunk_index] = true;

    // Advance window start
    while (window_start_ < acked_.size() && acked_[window_start_]) {
        ++window_start_;
    }

    if (progress_cb_) {
        uint64_t sent_bytes = std::min<uint64_t>(
            static_cast<uint64_t>(window_start_) * chunker_.meta().chunk_size,
            chunker_.meta().file_size);
        progress_cb_(sent_bytes, chunker_.meta().file_size);
    }

    // Send more blocks within sliding window
    if (send_block) {
        uint32_t total = chunker_.meta().total_chunks;
        uint32_t window_end = std::min(window_start_ + window_size_, total);
        while (next_to_send_ < window_end) {
            auto chunk = chunker_.get_chunk(next_to_send_);
            if (chunk) {
                FileBlock block;
                block.file_id = chunker_.meta().file_id;
                block.chunk_index = chunk->index;
                block.data = chunk->data;
                block.chunk_sha256 = chunk->sha256;
                send_block(block);
            }
            ++next_to_send_;
        }
    }

    bool all_done = (window_start_ >= acked_.size());
    if (all_done && completion_cb_) {
        completion_cb_(true, "");
        completion_cb_ = nullptr;
    }
    return all_done;
}

void FileSenderSession::mark_completed(bool success, const std::string& err) {
    std::lock_guard lock(mutex_);
    if (completion_cb_) {
        completion_cb_(success, err);
        completion_cb_ = nullptr;
    }
}

// ─── FileReceiverSession ────────────────────────────────────────────────────

FileReceiverSession::FileReceiverSession(FileMeta meta, std::filesystem::path download_dir)
    : meta_(std::move(meta)),
      download_dir_(std::move(download_dir)),
      received_chunks_(meta_.total_chunks, false) {

    // Strictly sanitize filename to prevent path traversal
    meta_.filename = sanitize_filename(meta_.filename);

    std::error_code ec;
    std::filesystem::create_directories(download_dir_, ec);

    // Target sanitized path
    target_path_ = download_dir_ / meta_.filename;
    temp_path_ = download_dir_ / (meta_.filename + "." + meta_.file_id.to_hex().substr(0, 8) + ".part");

    // Initialize/truncate temporary file and pre-allocate size
    std::ofstream ofs(temp_path_, std::ios::binary | std::ios::trunc);
    ofs.close();
    if (meta_.file_size > 0) {
        std::filesystem::resize_file(temp_path_, meta_.file_size, ec);
    }
}

FileReceiverSession::~FileReceiverSession() {
    if (!is_complete_) {
        std::error_code ec;
        std::filesystem::remove(temp_path_, ec);
    }
}

FileAck FileReceiverSession::handle_block(const FileBlock& block) {
    std::lock_guard lock(mutex_);
    FileAck ack;
    ack.file_id = meta_.file_id;
    ack.chunk_index = block.chunk_index;

    if (block.file_id != meta_.file_id) {
        ack.ok = false;
        ack.error_msg = "File ID mismatch";
        return ack;
    }

    if (block.chunk_index >= meta_.total_chunks) {
        ack.ok = false;
        ack.error_msg = "Chunk index out of bounds";
        return ack;
    }

    if (block.data.size() > meta_.chunk_size) {
        ack.ok = false;
        ack.error_msg = "Chunk size exceeds session limit";
        return ack;
    }

    // Verify chunk SHA-256 hash
    auto computed_chunk_sha = compute_sha256(block.data);
    if (computed_chunk_sha != block.chunk_sha256) {
        ack.ok = false;
        ack.error_msg = "Corrupted chunk: SHA-256 mismatch";
        return ack;
    }

    // Write chunk into temp file at offset
    std::fstream ofs(temp_path_, std::ios::in | std::ios::out | std::ios::binary);
    if (!ofs.is_open()) {
        ack.ok = false;
        ack.error_msg = "Failed to open temporary file for write";
        return ack;
    }

    uint64_t offset = static_cast<uint64_t>(block.chunk_index) * meta_.chunk_size;
    ofs.seekp(static_cast<std::streamoff>(offset));
    ofs.write(reinterpret_cast<const char*>(block.data.data()), block.data.size());
    ofs.flush();

    if (!received_chunks_[block.chunk_index]) {
        received_chunks_[block.chunk_index] = true;
        ++received_count_;
    }

    ack.ok = true;
    return ack;
}

bool FileReceiverSession::finalize() {
    std::lock_guard lock(mutex_);
    if (meta_.total_chunks > 0 && received_count_ < meta_.total_chunks) {
        return false;
    }

    // Verify whole file SHA-256
    auto computed_file_sha = compute_file_sha256(temp_path_);
    if (!computed_file_sha || *computed_file_sha != meta_.file_sha256) {
        std::error_code ec;
        std::filesystem::remove(temp_path_, ec);
        return false;
    }

    // Atomic rename into target path
    std::error_code ec;
    std::filesystem::rename(temp_path_, target_path_, ec);
    if (ec) {
        // Fallback: copy and remove
        std::filesystem::copy_file(temp_path_, target_path_, std::filesystem::copy_options::overwrite_existing, ec);
        std::filesystem::remove(temp_path_, ec);
    }

    is_complete_ = true;
    return true;
}

// ─── FileTransferManager ────────────────────────────────────────────────────

FileTransferManager::FileTransferManager(std::filesystem::path download_dir)
    : download_dir_(std::move(download_dir)) {
    std::error_code ec;
    std::filesystem::create_directories(download_dir_, ec);
}

bool FileTransferManager::start_send_file(
    const std::filesystem::path& filepath,
    const NodeID& sender_id,
    const NodeID& recipient_id,
    const SendMetaFunc& send_meta,
    const SendBlockFunc& send_block,
    FileSenderSession::ProgressFunc progress_cb,
    FileSenderSession::CompletionFunc completion_cb) {

    auto chunker = FileChunker::from_file(filepath, sender_id);
    if (!chunker) return false;

    auto session = std::make_shared<FileSenderSession>(std::move(*chunker), recipient_id);
    session->set_progress_callback(std::move(progress_cb));
    session->set_completion_callback(std::move(completion_cb));

    RequestID fid = session->meta().file_id;

    {
        std::lock_guard lock(mutex_);
        senders_[fid] = session;
    }

    if (send_meta) {
        send_meta(recipient_id, session->meta());
    }

    if (send_block) {
        session->advance_window([&](const FileBlock& block) {
            send_block(recipient_id, block);
        });
    }

    return true;
}

bool FileTransferManager::handle_file_meta(const FileMeta& meta) {
    std::lock_guard lock(mutex_);
    if (meta.total_chunks == 0 || meta.chunk_size == 0) {
        return false; // Zero-chunk or invalid chunk size
    }
    if (receivers_.contains(meta.file_id)) {
        return false; // Already exists
    }

    auto session = std::make_shared<FileReceiverSession>(meta, download_dir_);
    receivers_[meta.file_id] = session;
    return true;
}

std::optional<FileAck> FileTransferManager::handle_file_block(
    const FileBlock& block,
    const SendCompleteFunc& send_complete) {

    std::shared_ptr<FileReceiverSession> session;
    {
        std::lock_guard lock(mutex_);
        auto it = receivers_.find(block.file_id);
        if (it == receivers_.end()) {
            FileAck bad_ack;
            bad_ack.file_id = block.file_id;
            bad_ack.chunk_index = block.chunk_index;
            bad_ack.ok = false;
            bad_ack.error_msg = "Unknown or expired file transfer session";
            return bad_ack;
        }
        session = it->second;
    }

    auto ack = session->handle_block(block);

    // Check if fully received
    if (ack.ok) {
        std::lock_guard lock(mutex_);
        if (session->finalize()) {
            if (send_complete) {
                FileComplete complete;
                complete.file_id = session->meta().file_id;
                complete.ok = true;
                complete.file_sha256 = session->meta().file_sha256;
                send_complete(session->meta().sender_id, complete);
            }
            if (on_received_cb_) {
                on_received_cb_(session->meta(), session->target_path());
            }
        }
    }

    return ack;
}

bool FileTransferManager::handle_file_ack(const FileAck& ack, const SendBlockFunc& send_block) {
    std::shared_ptr<FileSenderSession> session;
    {
        std::lock_guard lock(mutex_);
        auto it = senders_.find(ack.file_id);
        if (it == senders_.end()) return false;
        session = it->second;
    }

    bool done = session->handle_ack(ack, [&](const FileBlock& block) {
        if (send_block) {
            send_block(session->recipient(), block);
        }
    });

    if (done) {
        std::lock_guard lock(mutex_);
        senders_.erase(ack.file_id);
    }
    return true;
}

bool FileTransferManager::handle_file_complete(const FileComplete& complete) {
    std::shared_ptr<FileSenderSession> session;
    {
        std::lock_guard lock(mutex_);
        auto it = senders_.find(complete.file_id);
        if (it != senders_.end()) {
            session = it->second;
            senders_.erase(it);
        }
    }
    if (session) {
        session->mark_completed(complete.ok, complete.ok ? "" : "File transfer rejected by receiver");
        return true;
    }
    return false;
}

std::size_t FileTransferManager::active_senders_count() const {
    std::lock_guard lock(mutex_);
    return senders_.size();
}

std::size_t FileTransferManager::active_receivers_count() const {
    std::lock_guard lock(mutex_);
    return receivers_.size();
}

} // namespace p2p::app
