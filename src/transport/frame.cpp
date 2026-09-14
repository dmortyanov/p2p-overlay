/// @file frame.cpp
/// @brief Wire frame serialization, deserialization, and incremental parsing.

#include "transport/frame.hpp"

#include <cstring>
#include <algorithm>
#include <nlohmann/json.hpp>

// For network byte order conversion
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace p2p::transport {

// ─── Serialization ──────────────────────────────────────────────────

Bytes Frame::serialize() const {
    Bytes out;
    out.reserve(FRAME_HEADER_SIZE + payload.size());

    // version (1 byte)
    out.push_back(version);

    // type (1 byte)
    out.push_back(static_cast<uint8_t>(type));

    // flags (2 bytes, network byte order)
    uint16_t net_flags = htons(static_cast<uint16_t>(flags));
    auto* fp = reinterpret_cast<const uint8_t*>(&net_flags);
    out.insert(out.end(), fp, fp + 2);

    // request_id (16 bytes)
    out.insert(out.end(), request_id.data.begin(), request_id.data.end());

    // payload_length (4 bytes, network byte order)
    uint32_t net_len = htonl(static_cast<uint32_t>(payload.size()));
    auto* lp = reinterpret_cast<const uint8_t*>(&net_len);
    out.insert(out.end(), lp, lp + 4);

    // payload
    out.insert(out.end(), payload.begin(), payload.end());

    return out;
}

// ─── Factory methods ────────────────────────────────────────────────

Frame Frame::make_ping(const RequestID& rid) {
    Frame f;
    f.type = MessageType::PING;
    f.request_id = rid;
    // PING has empty payload (or optional sender NodeID in CBOR)
    return f;
}

Frame Frame::make_pong(const RequestID& rid) {
    Frame f;
    f.type = MessageType::PONG;
    f.flags = FrameFlags::IS_RESPONSE;
    f.request_id = rid;
    return f;
}

Frame Frame::make_error(const RequestID& rid, const std::string& message) {
    Frame f;
    f.type = MessageType::ERROR;
    f.flags = FrameFlags::IS_RESPONSE | FrameFlags::IS_ERROR;
    f.request_id = rid;

    // Serialize error message as CBOR via nlohmann/json
    nlohmann::json j = {{"error", message}};
    auto cbor = nlohmann::json::to_cbor(j);
    f.payload.assign(cbor.begin(), cbor.end());
    return f;
}

// ─── Parser ─────────────────────────────────────────────────────────

void FrameParser::feed(const uint8_t* data, std::size_t len) {
    buffer_.insert(buffer_.end(), data, data + len);
}

std::expected<Frame, FrameError> FrameParser::next_frame() {
    // Need at least a full header
    if (buffer_.size() < FRAME_HEADER_SIZE) {
        return std::unexpected(FrameError::IncompleteHeader);
    }

    const uint8_t* hdr = buffer_.data();

    // Parse header fields
    uint8_t version = hdr[0];
    auto msg_type   = static_cast<MessageType>(hdr[1]);

    uint16_t net_flags;
    std::memcpy(&net_flags, hdr + 2, 2);
    auto flags = static_cast<FrameFlags>(ntohs(net_flags));

    RequestID rid;
    std::memcpy(rid.data.data(), hdr + 4, RequestID::SIZE);

    uint32_t net_payload_len;
    std::memcpy(&net_payload_len, hdr + 20, 4);
    uint32_t payload_len = ntohl(net_payload_len);

    // ── Validation (BEFORE allocating payload buffer) ─────────────

    // Check version
    if (version != PROTOCOL_VERSION) {
        // Discard the header bytes so we don't re-parse
        buffer_.erase(buffer_.begin(), buffer_.begin() + FRAME_HEADER_SIZE);
        return std::unexpected(FrameError::UnsupportedVersion);
    }

    // Check payload size BEFORE allocating
    if (payload_len > MAX_FRAME_PAYLOAD) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + FRAME_HEADER_SIZE);
        return std::unexpected(FrameError::PayloadTooLarge);
    }

    // Check if full payload has arrived
    std::size_t total_size = FRAME_HEADER_SIZE + payload_len;
    if (buffer_.size() < total_size) {
        return std::unexpected(FrameError::IncompletePayload);
    }

    // ── Build frame ───────────────────────────────────────────────

    Frame frame;
    frame.version    = version;
    frame.type       = msg_type;
    frame.flags      = flags;
    frame.request_id = rid;

    if (payload_len > 0) {
        frame.payload.assign(
            buffer_.begin() + FRAME_HEADER_SIZE,
            buffer_.begin() + total_size
        );
    }

    // Remove consumed bytes from buffer
    buffer_.erase(buffer_.begin(), buffer_.begin() + total_size);

    return frame;
}

} // namespace p2p::transport
