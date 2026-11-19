/// @file test_app_messages.cpp
/// @brief Unit tests for application message serialization and path security (Stage 6, E6-1).

#include "app/app_messages.hpp"
#include <catch2/catch_test_macros.hpp>

using namespace p2p;
using namespace p2p::app;

TEST_CASE("Stage 6: APP_MESSAGE CBOR Serialization round-trip", "[app][unit]") {
    AppMessage original;
    original.msg_id = RequestID::generate();
    original.sender_id = NodeID::random();
    original.recipient_id = NodeID::random();
    original.timestamp = 1791800000;
    original.text = "Hello P2P encrypted chat!";
    original.is_e2e_encrypted = false;

    auto bytes = serialize_app_message(original);
    REQUIRE_FALSE(bytes.empty());

    AppMessage restored;
    REQUIRE(deserialize_app_message(bytes, restored));

    CHECK(restored.msg_id == original.msg_id);
    CHECK(restored.sender_id == original.sender_id);
    CHECK(restored.recipient_id == original.recipient_id);
    CHECK(restored.timestamp == original.timestamp);
    CHECK(restored.text == original.text);
    CHECK(restored.is_e2e_encrypted == original.is_e2e_encrypted);
}

TEST_CASE("Stage 6: APP_ACK CBOR Serialization round-trip", "[app][unit]") {
    AppAck original;
    original.msg_id = RequestID::generate();
    original.sender_id = NodeID::random();
    original.ok = true;
    original.error_msg = "";

    auto bytes = serialize_app_ack(original);
    REQUIRE_FALSE(bytes.empty());

    AppAck restored;
    REQUIRE(deserialize_app_ack(bytes, restored));

    CHECK(restored.msg_id == original.msg_id);
    CHECK(restored.sender_id == original.sender_id);
    CHECK(restored.ok == true);
    CHECK(restored.error_msg.empty());
}

TEST_CASE("Stage 6: APP_FILE_META CBOR Serialization round-trip", "[app][unit]") {
    FileMeta original;
    original.file_id = RequestID::generate();
    original.filename = "report_2026.pdf";
    original.file_size = 147456;
    original.chunk_size = 49152;
    original.total_chunks = 3;
    original.file_sha256.fill(0x5a);
    original.sender_id = NodeID::random();

    auto bytes = serialize_file_meta(original);
    REQUIRE_FALSE(bytes.empty());

    FileMeta restored;
    REQUIRE(deserialize_file_meta(bytes, restored));

    CHECK(restored.file_id == original.file_id);
    CHECK(restored.filename == original.filename);
    CHECK(restored.file_size == original.file_size);
    CHECK(restored.chunk_size == original.chunk_size);
    CHECK(restored.total_chunks == original.total_chunks);
    CHECK(restored.file_sha256 == original.file_sha256);
    CHECK(restored.sender_id == original.sender_id);
}

TEST_CASE("Stage 6: APP_FILE_BLOCK and ACK CBOR Serialization", "[app][unit]") {
    FileBlock block;
    block.file_id = RequestID::generate();
    block.chunk_index = 1;
    block.data = {0x01, 0x02, 0x03, 0x04, 0x05, 0xAA, 0xBB, 0xCC};
    block.chunk_sha256.fill(0x3c);

    auto block_bytes = serialize_file_block(block);
    REQUIRE_FALSE(block_bytes.empty());

    FileBlock restored_block;
    REQUIRE(deserialize_file_block(block_bytes, restored_block));
    CHECK(restored_block.file_id == block.file_id);
    CHECK(restored_block.chunk_index == 1);
    CHECK(restored_block.data == block.data);
    CHECK(restored_block.chunk_sha256 == block.chunk_sha256);

    FileAck ack;
    ack.file_id = block.file_id;
    ack.chunk_index = 1;
    ack.ok = true;

    auto ack_bytes = serialize_file_ack(ack);
    REQUIRE_FALSE(ack_bytes.empty());

    FileAck restored_ack;
    REQUIRE(deserialize_file_ack(ack_bytes, restored_ack));
    CHECK(restored_ack.file_id == ack.file_id);
    CHECK(restored_ack.chunk_index == 1);
    CHECK(restored_ack.ok == true);
}

TEST_CASE("Stage 6: APP_FILE_COMPLETE CBOR Serialization", "[app][unit]") {
    FileComplete original;
    original.file_id = RequestID::generate();
    original.ok = true;
    original.file_sha256.fill(0x7e);

    auto bytes = serialize_file_complete(original);
    REQUIRE_FALSE(bytes.empty());

    FileComplete restored;
    REQUIRE(deserialize_file_complete(bytes, restored));
    CHECK(restored.file_id == original.file_id);
    CHECK(restored.ok == true);
    CHECK(restored.file_sha256 == original.file_sha256);
}

TEST_CASE("Stage 6: Path Traversal Protection and Filename Sanitization", "[app][unit]") {
    CHECK(is_safe_filename("document.pdf"));
    CHECK(is_safe_filename("archive_v1.2.tar.gz"));
    CHECK_FALSE(is_safe_filename("../etc/passwd"));
    CHECK_FALSE(is_safe_filename("..\\windows\\system32"));
    CHECK_FALSE(is_safe_filename("/root/.ssh/id_rsa"));
    CHECK_FALSE(is_safe_filename("."));
    CHECK_FALSE(is_safe_filename(".."));
    CHECK_FALSE(is_safe_filename(""));

    // Sanitization must strip directory paths and escape malicious traversals
    CHECK(sanitize_filename("../../etc/passwd") == "passwd");
    CHECK(sanitize_filename("..\\..\\windows\\cmd.exe") == "cmd.exe");
    CHECK(sanitize_filename("/var/log/syslog") == "syslog");
    CHECK(sanitize_filename("..") == "download.dat");
    CHECK(sanitize_filename("") == "download.dat");
    CHECK(sanitize_filename("safe_file.txt") == "safe_file.txt");
}

