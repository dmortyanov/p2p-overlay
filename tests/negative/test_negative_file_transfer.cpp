/// @file test_negative_file_transfer.cpp
/// @brief Negative and attack-resilience tests for file transfer (Stage 6, E6-3).

#include "app/file_transfer.hpp"
#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>

using namespace p2p;
using namespace p2p::app;

namespace {

void clean_dir(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
}

} // namespace

TEST_CASE("Stage 6 Negative: Path Traversal Attack is safely neutralized", "[app][negative]") {
    std::filesystem::path download_dir = "./test_negative_downloads";
    clean_dir(download_dir);

    FileTransferManager mgr(download_dir);

    // Malicious metadata attempting to write outside download directory
    FileMeta malicious_meta;
    malicious_meta.file_id = RequestID::generate();
    malicious_meta.filename = "../../etc/shadow";
    malicious_meta.file_size = 64;
    malicious_meta.chunk_size = 48 * 1024;
    malicious_meta.total_chunks = 1;
    malicious_meta.sender_id = NodeID::random();

    // Block to transfer
    FileBlock block;
    block.file_id = malicious_meta.file_id;
    block.chunk_index = 0;
    block.data.assign(64, 0x41);
    block.chunk_sha256 = compute_sha256(block.data);
    malicious_meta.file_sha256 = block.chunk_sha256;

    // The manager and deserializer must sanitize the path
    REQUIRE(mgr.handle_file_meta(malicious_meta));

    // Verify file is saved ONLY inside download_dir with filename "shadow"
    std::filesystem::path saved_path;
    mgr.set_on_file_received([&](const FileMeta& m, const std::filesystem::path& path) {
        saved_path = path;
    });

    auto ack = mgr.handle_file_block(block);
    REQUIRE(ack.has_value());
    CHECK(ack->ok);

    // Path traversal check: must be saved strictly inside download_dir with filename "shadow"
    CHECK(saved_path == download_dir / "shadow");
    CHECK(std::filesystem::exists(download_dir / "shadow"));
    CHECK_FALSE(std::filesystem::exists("./test_negative_downloads/../../test_traversal_escape.txt"));

    clean_dir(download_dir);
}

TEST_CASE("Stage 6 Negative: Corrupted Chunk Hash is strictly rejected by receiver", "[app][negative]") {
    std::filesystem::path download_dir = "./test_negative_chunk_dir";
    clean_dir(download_dir);

    FileMeta meta;
    meta.file_id = RequestID::generate();
    meta.filename = "test_corrupt.bin";
    meta.file_size = 100;
    meta.chunk_size = 48 * 1024;
    meta.total_chunks = 1;
    meta.sender_id = NodeID::random();

    FileReceiverSession receiver(meta, download_dir);

    // Block with tampered data (byte-flip attack)
    FileBlock corrupt_block;
    corrupt_block.file_id = meta.file_id;
    corrupt_block.chunk_index = 0;
    corrupt_block.data.assign(100, 0x55);
    corrupt_block.chunk_sha256.fill(0x00); // Invalid / mismatched hash

    auto ack = receiver.handle_block(corrupt_block);
    CHECK_FALSE(ack.ok);
    CHECK(ack.error_msg.find("mismatch") != std::string::npos);
    CHECK_FALSE(receiver.is_complete());

    clean_dir(download_dir);
}

TEST_CASE("Stage 6 Negative: Out-of-bounds Chunk Index is rejected", "[app][negative]") {
    std::filesystem::path download_dir = "./test_negative_bounds_dir";
    clean_dir(download_dir);

    FileMeta meta;
    meta.file_id = RequestID::generate();
    meta.filename = "bounds_test.bin";
    meta.file_size = 200;
    meta.chunk_size = 48 * 1024;
    meta.total_chunks = 1;
    meta.sender_id = NodeID::random();

    FileReceiverSession receiver(meta, download_dir);

    FileBlock oob_block;
    oob_block.file_id = meta.file_id;
    oob_block.chunk_index = 99; // Total chunks is only 1!
    oob_block.data.assign(50, 0x33);
    oob_block.chunk_sha256 = compute_sha256(oob_block.data);

    auto ack = receiver.handle_block(oob_block);
    CHECK_FALSE(ack.ok);
    CHECK(ack.error_msg.find("out of bounds") != std::string::npos);

    clean_dir(download_dir);
}
