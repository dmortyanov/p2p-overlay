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

TEST_CASE("100 frames of variable length", "[frame][stress]") {
    std::mt19937 rng(42); // deterministic seed
    std::uniform_int_distribution<int> size_dist(0, 4096);

    FrameParser parser;
    std::vector<Frame> originals;

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

        // Simulate realistic TCP: sometimes feed multiple frames at once,
        // sometimes split a frame across feeds
        auto wire = f.serialize();
        if (i % 3 == 0 && !wire.empty()) {
            // Split in the middle
            std::size_t split = wire.size() / 2;
            parser.feed(wire.data(), split);
            parser.feed(wire.data() + split, wire.size() - split);
        } else {
            parser.feed(wire);
        }
    }

    // Extract all frames
    int count = 0;
    while (true) {
        auto result = parser.next_frame();
        if (!result.has_value()) break;

        REQUIRE(count < static_cast<int>(originals.size()));
        CHECK(result->type == originals[count].type);
        CHECK(result->request_id == originals[count].request_id);
        CHECK(result->payload == originals[count].payload);
        ++count;
    }

    CHECK(count == 120);
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
