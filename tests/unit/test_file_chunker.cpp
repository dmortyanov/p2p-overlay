/// @file test_file_chunker.cpp
/// @brief Unit tests for file chunking, hashing and sliding window (Stage 6, E6-2).

#include "app/file_transfer.hpp"
#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <filesystem>

using namespace p2p;
using namespace p2p::app;

namespace {

void create_dummy_file(const std::filesystem::path& path, std::size_t size, uint8_t fill_byte = 0xAA) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    std::vector<uint8_t> buf(size, fill_byte);
    ofs.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}

} // namespace

TEST_CASE("Stage 6: FileChunker splits file into 48 KiB chunks with SHA-256 hashes", "[app][unit]") {
    std::filesystem::path test_dir = "./test_chunker_dir";
    std::filesystem::remove_all(test_dir);

    // 1. Small file (1000 bytes) -> 1 chunk
    auto small_path = test_dir / "small.bin";
    create_dummy_file(small_path, 1000, 0x11);

    auto sender_id = NodeID::random();
    auto chunker_opt = FileChunker::from_file(small_path, sender_id, 48 * 1024);
    REQUIRE(chunker_opt.has_value());
    CHECK(chunker_opt->meta().total_chunks == 1);
    CHECK(chunker_opt->meta().file_size == 1000);
    CHECK(chunker_opt->chunks().size() == 1);
    CHECK(chunker_opt->chunks()[0].data.size() == 1000);

    // 2. Multi-chunk file: 120 KiB (48 KiB + 48 KiB + 24 KiB = 3 chunks)
    auto multi_path = test_dir / "multi.bin";
    std::size_t total_bytes = 48 * 1024 * 2 + 24 * 1024;
    create_dummy_file(multi_path, total_bytes, 0x42);

    auto chunker_multi = FileChunker::from_file(multi_path, sender_id, 48 * 1024);
    REQUIRE(chunker_multi.has_value());
    CHECK(chunker_multi->meta().total_chunks == 3);
    CHECK(chunker_multi->meta().file_size == total_bytes);
    CHECK(chunker_multi->chunks().size() == 3);

    CHECK(chunker_multi->chunks()[0].data.size() == 48 * 1024);
    CHECK(chunker_multi->chunks()[1].data.size() == 48 * 1024);
    CHECK(chunker_multi->chunks()[2].data.size() == 24 * 1024);

    // Verify chunk hashes match individual compute_sha256
    for (const auto& c : chunker_multi->chunks()) {
        auto expected = compute_sha256(c.data);
        CHECK(c.sha256 == expected);
    }

    std::filesystem::remove_all(test_dir);
}

TEST_CASE("Stage 6: FileSenderSession sliding window advancement and ACK handling", "[app][unit]") {
    std::filesystem::path test_dir = "./test_window_dir";
    std::filesystem::remove_all(test_dir);

    auto file_path = test_dir / "window_test.bin";
    create_dummy_file(file_path, 48 * 1024 * 5, 0x77); // 5 chunks

    auto sender_id = NodeID::random();
    auto recipient_id = NodeID::random();
    auto chunker = FileChunker::from_file(file_path, sender_id, 48 * 1024);
    REQUIRE(chunker.has_value());

    // Window size = 2 chunks
    FileSenderSession session(std::move(*chunker), recipient_id, 2);
    REQUIRE_FALSE(session.is_complete());

    std::vector<uint32_t> sent_indices;
    auto send_block = [&](const FileBlock& b) {
        sent_indices.push_back(b.chunk_index);
    };

    // First advance: sends chunks 0 and 1
    session.advance_window(send_block);
    REQUIRE(sent_indices.size() == 2);
    CHECK(sent_indices[0] == 0);
    CHECK(sent_indices[1] == 1);

    // Ack chunk 0: window moves, sends chunk 2
    FileAck ack0;
    ack0.file_id = session.meta().file_id;
    ack0.chunk_index = 0;
    ack0.ok = true;

    session.handle_ack(ack0, send_block);
    REQUIRE(sent_indices.size() == 3);
    CHECK(sent_indices[2] == 2);

    // Ack remaining chunks 1, 2, 3, 4
    for (uint32_t i = 1; i < 5; ++i) {
        FileAck ack;
        ack.file_id = session.meta().file_id;
        ack.chunk_index = i;
        ack.ok = true;
        session.handle_ack(ack, send_block);
    }

    CHECK(session.is_complete());
    std::filesystem::remove_all(test_dir);
}

