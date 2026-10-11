/// @file test_frame.cpp
/// @brief Unit tests for the frame protocol: serialization, parsing, edge cases.
///
/// Tests cover (per TZ section 16: "100 кадров переменной длины"):
///   - Basic serialize/deserialize round-trip
///   - Variable payload sizes (0, 1, 100, MAX_FRAME_PAYLOAD)
///   - Multiple frames in one buffer (glued reads)
///   - Partial header and partial payload
///   - Oversized payload rejection (before buffer allocation)
///   - Wrong protocol version rejection
///   - 100+ frames stress test

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "transport/frame.hpp"
#include "common/types.hpp"

#include <sodium.h>
#include <cstring>
#include <random>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

using namespace p2p;
using namespace p2p::transport;

// Helper: initialize libsodium once
static struct SodiumInit {
    SodiumInit() { sodium_init(); }
} sodium_init_guard;

// ═══════════════════════════════════════════════════════════════════
//  Basic round-trip
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Frame serialize/deserialize round-trip", "[frame]") {
    Frame original;
    original.version = PROTOCOL_VERSION;
    original.type = MessageType::PING;
    original.flags = FrameFlags::NONE;
    original.request_id = RequestID::generate();
    original.payload = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto wire = original.serialize();
    REQUIRE(wire.size() == FRAME_HEADER_SIZE + original.payload.size());

    FrameParser parser;
    parser.feed(wire);

    auto result = parser.next_frame();
    REQUIRE(result.has_value());

    auto& parsed = result.value();
    CHECK(parsed.version == original.version);
    CHECK(parsed.type == original.type);
    CHECK(parsed.request_id == original.request_id);
    CHECK(parsed.payload == original.payload);
}

// ═══════════════════════════════════════════════════════════════════
//  Empty payload
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Frame with empty payload", "[frame]") {
    Frame f;
    f.type = MessageType::PONG;
    f.request_id = RequestID::generate();
    // No payload

    auto wire = f.serialize();
    REQUIRE(wire.size() == FRAME_HEADER_SIZE);

    FrameParser parser;
    parser.feed(wire);

    auto result = parser.next_frame();
    REQUIRE(result.has_value());
    CHECK(result->payload.empty());
}

// ═══════════════════════════════════════════════════════════════════
//  Variable payload sizes
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Frame with variable payload sizes", "[frame]") {
    auto payload_size = GENERATE(1, 10, 100, 1000, 4096, 32768, 65536);

    Frame f;
    f.type = MessageType::APP_MESSAGE;
    f.request_id = RequestID::generate();
    f.payload.resize(payload_size);
    // Fill with pattern
    for (int i = 0; i < payload_size; ++i) {
        f.payload[i] = static_cast<uint8_t>(i & 0xFF);
    }

    auto wire = f.serialize();
    FrameParser parser;
    parser.feed(wire);

    auto result = parser.next_frame();
    REQUIRE(result.has_value());
    CHECK(result->payload.size() == static_cast<std::size_t>(payload_size));
    CHECK(result->payload == f.payload);
}

// ═══════════════════════════════════════════════════════════════════
//  Multiple frames in one buffer (glued TCP reads)
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Multiple frames in single buffer", "[frame]") {
    constexpr int NUM_FRAMES = 5;
    Bytes combined;

    std::vector<Frame> originals;
    for (int i = 0; i < NUM_FRAMES; ++i) {
        Frame f;
        f.type = static_cast<MessageType>(0x01 + i);
        f.request_id = RequestID::generate();
        f.payload = {static_cast<uint8_t>(i), static_cast<uint8_t>(i + 1)};
        originals.push_back(f);

        auto wire = f.serialize();
        combined.insert(combined.end(), wire.begin(), wire.end());
    }

    FrameParser parser;
    parser.feed(combined);

    for (int i = 0; i < NUM_FRAMES; ++i) {
        auto result = parser.next_frame();
        REQUIRE(result.has_value());
        CHECK(result->type == originals[i].type);
        CHECK(result->request_id == originals[i].request_id);
        CHECK(result->payload == originals[i].payload);
    }

    // No more frames
    auto result = parser.next_frame();
    REQUIRE(!result.has_value());
}

// ═══════════════════════════════════════════════════════════════════
//  Partial header (split TCP read)
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Partial header handling", "[frame]") {
    Frame f;
    f.type = MessageType::FIND_NODE_REQUEST;
    f.request_id = RequestID::generate();
    f.payload = {0xAA, 0xBB, 0xCC};

    auto wire = f.serialize();

    // Feed 10 bytes, then the rest (split inside header)
    FrameParser parser;
    parser.feed(wire.data(), 10);

    auto result = parser.next_frame();
    REQUIRE(!result.has_value());
    CHECK(result.error() == FrameError::IncompleteHeader);

    // Feed remaining
    parser.feed(wire.data() + 10, wire.size() - 10);

    result = parser.next_frame();
    REQUIRE(result.has_value());
    CHECK(result->type == MessageType::FIND_NODE_REQUEST);
    CHECK(result->payload == f.payload);
}

// ═══════════════════════════════════════════════════════════════════
//  Partial payload (split TCP read)
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Partial payload handling", "[frame]") {
    Frame f;
    f.type = MessageType::STORE_REQUEST;
    f.request_id = RequestID::generate();
    f.payload.resize(1000);
    for (int i = 0; i < 1000; ++i) f.payload[i] = static_cast<uint8_t>(i);

    auto wire = f.serialize();

    // Feed header + 100 bytes of payload
    FrameParser parser;
    std::size_t first_chunk = FRAME_HEADER_SIZE + 100;
    parser.feed(wire.data(), first_chunk);

    auto result = parser.next_frame();
    REQUIRE(!result.has_value());
    CHECK(result.error() == FrameError::IncompletePayload);

    // Feed rest
    parser.feed(wire.data() + first_chunk, wire.size() - first_chunk);

    result = parser.next_frame();
    REQUIRE(result.has_value());
    CHECK(result->payload == f.payload);
}

// ═══════════════════════════════════════════════════════════════════
//  Oversized payload rejection
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Oversized payload is rejected before allocation", "[frame]") {
    // Manually construct a header with payload_length > MAX_FRAME_PAYLOAD
    Bytes bad_header(FRAME_HEADER_SIZE, 0);
    bad_header[0] = PROTOCOL_VERSION;  // version
    bad_header[1] = static_cast<uint8_t>(MessageType::APP_MESSAGE); // type

    // Set payload_length to MAX_FRAME_PAYLOAD + 1 in network byte order
    uint32_t oversized = MAX_FRAME_PAYLOAD + 1;
    uint32_t net_len = htonl(oversized);
    std::memcpy(bad_header.data() + 20, &net_len, 4);

    FrameParser parser;
    parser.feed(bad_header);

    auto result = parser.next_frame();
    REQUIRE(!result.has_value());
    CHECK(result.error() == FrameError::PayloadTooLarge);
}

// ═══════════════════════════════════════════════════════════════════
//  Wrong protocol version rejection
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Wrong protocol version is rejected", "[frame]") {
    Bytes bad_header(FRAME_HEADER_SIZE, 0);
    bad_header[0] = 99;  // wrong version!
    bad_header[1] = static_cast<uint8_t>(MessageType::PING);

    FrameParser parser;
    parser.feed(bad_header);

    auto result = parser.next_frame();
    REQUIRE(!result.has_value());
    CHECK(result.error() == FrameError::UnsupportedVersion);
}

// ═══════════════════════════════════════════════════════════════════
//  Flags preservation
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Frame flags are preserved", "[frame]") {
    Frame f;
    f.type = MessageType::APP_MESSAGE;
    f.flags = FrameFlags::IS_RESPONSE | FrameFlags::IS_ENCRYPTED;
    f.request_id = RequestID::generate();

    auto wire = f.serialize();
    FrameParser parser;
    parser.feed(wire);

    auto result = parser.next_frame();
    REQUIRE(result.has_value());
    CHECK((result->flags & FrameFlags::IS_RESPONSE));
    CHECK((result->flags & FrameFlags::IS_ENCRYPTED));
    CHECK(!(result->flags & FrameFlags::IS_ERROR));
}

// ═══════════════════════════════════════════════════════════════════
//  100+ frames stress test (TZ requirement)
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("100 frames of variable length with randomized stream chunking (E1-5)", "[frame][stress]") {
    std::mt19937 rng(42); // deterministic seed
    std::uniform_int_distribution<int> size_dist(0, 4096);

    FrameParser parser;
    std::vector<Frame> originals;
    Bytes combined_stream;

    for (int i = 0; i < 120; ++i) {
        Frame f;
        f.type = static_cast<MessageType>(0x01 + (i % 20));
        f.request_id = RequestID::generate();

        int payload_size = size_dist(rng);
        f.payload.resize(payload_size);
        for (int j = 0; j < payload_size; ++j) {
            f.payload[j] = static_cast<uint8_t>(rng() & 0xFF);
        }

        originals.push_back(f);
        auto wire = f.serialize();
        combined_stream.insert(combined_stream.end(), wire.begin(), wire.end());
    }

    // Feed combined stream in truly random chunks (1..256 bytes) to simulate realistic TCP fragmentation
    std::uniform_int_distribution<std::size_t> chunk_dist(1, 256);
    std::size_t offset = 0;
    std::vector<Frame> parsed_frames;

    while (offset < combined_stream.size()) {
        std::size_t chunk_len = std::min(chunk_dist(rng), combined_stream.size() - offset);
        parser.feed(combined_stream.data() + offset, chunk_len);
        offset += chunk_len;

        while (true) {
            auto result = parser.next_frame();
            if (!result.has_value()) break;
            parsed_frames.push_back(std::move(result.value()));
        }
    }

    REQUIRE(parsed_frames.size() == originals.size());
    for (std::size_t i = 0; i < originals.size(); ++i) {
        CHECK(parsed_frames[i].type == originals[i].type);
        CHECK(parsed_frames[i].request_id == originals[i].request_id);
        CHECK(parsed_frames[i].payload == originals[i].payload);
    }
}

TEST_CASE("FrameParser configurable version and payload limits (E1-2)", "[frame][config]") {
    // Configured with protocol_version = 2 and max_payload = 1024
    FrameParser custom_parser(2, 1024);
    CHECK(custom_parser.expected_version() == 2);
    CHECK(custom_parser.max_payload() == 1024);

    // Frame with version 1 is now rejected
    Frame f_v1;
    f_v1.version = 1;
    f_v1.type = MessageType::PING;
    f_v1.request_id = RequestID::generate();
    custom_parser.feed(f_v1.serialize());
    auto res1 = custom_parser.next_frame();
    REQUIRE(!res1.has_value());
    CHECK(res1.error() == FrameError::UnsupportedVersion);

    // Frame with version 2 is accepted
    Frame f_v2;
    f_v2.version = 2;
    f_v2.type = MessageType::PING;
    f_v2.request_id = RequestID::generate();
    f_v2.payload = {0x01, 0x02};
    custom_parser.feed(f_v2.serialize());
    auto res2 = custom_parser.next_frame();
    REQUIRE(res2.has_value());
    CHECK(res2->version == 2);

    // Oversized payload for custom max (2000 > 1024)
    Frame f_oversized;
    f_oversized.version = 2;
    f_oversized.type = MessageType::APP_MESSAGE;
    f_oversized.request_id = RequestID::generate();
    f_oversized.payload.resize(2000, 0xFF);
    custom_parser.feed(f_oversized.serialize());
    auto res3 = custom_parser.next_frame();
    REQUIRE(!res3.has_value());
    CHECK(res3.error() == FrameError::PayloadTooLarge);
}

// ═══════════════════════════════════════════════════════════════════
//  Byte-by-byte feeding
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Frame parsed from byte-by-byte feed", "[frame]") {
    Frame f;
    f.type = MessageType::TUNNEL_DATA;
    f.request_id = RequestID::generate();
    f.payload = {0x01, 0x02, 0x03};

    auto wire = f.serialize();

    FrameParser parser;
    // Feed one byte at a time
    for (std::size_t i = 0; i < wire.size() - 1; ++i) {
        parser.feed(wire.data() + i, 1);
        auto result = parser.next_frame();
        REQUIRE(!result.has_value());
    }

    // Feed last byte
    parser.feed(wire.data() + wire.size() - 1, 1);
    auto result = parser.next_frame();
    REQUIRE(result.has_value());
    CHECK(result->type == MessageType::TUNNEL_DATA);
    CHECK(result->payload == f.payload);
}

// ═══════════════════════════════════════════════════════════════════
//  MAX_FRAME_PAYLOAD boundary
// ═══════════════════════════════════════════════════════════════════

TEST_CASE("Frame at exact MAX_FRAME_PAYLOAD is accepted", "[frame]") {
    Frame f;
    f.type = MessageType::APP_FILE_BLOCK;
    f.request_id = RequestID::generate();
    f.payload.resize(MAX_FRAME_PAYLOAD, 0xAB);

    auto wire = f.serialize();
    FrameParser parser;
    parser.feed(wire);

    auto result = parser.next_frame();
    REQUIRE(result.has_value());
    CHECK(result->payload.size() == MAX_FRAME_PAYLOAD);
}

TEST_CASE("wire_size returns correct value", "[frame]") {
    Frame f;
    f.payload = {1, 2, 3, 4, 5};
    CHECK(f.wire_size() == FRAME_HEADER_SIZE + 5);

    Frame empty;
    CHECK(empty.wire_size() == FRAME_HEADER_SIZE);
}
