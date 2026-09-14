#pragma once
/// @file frame.hpp
/// @brief Wire frame protocol — serialization and deserialization.
///
/// Frame layout (24-byte header + variable payload):
///
///   Offset  Size   Field
///   ──────  ─────  ─────────────────────────────
///   0       1      version         protocol version
///   1       1      type            MessageType enum
///   2       2      flags           FrameFlags, network byte order
///   4       16     request_id      unique ID for req/resp matching
///   20      4      payload_length  payload size, network byte order
///   24      var    payload         CBOR-encoded data or ciphertext
///
/// Total header: 24 bytes. MAX_FRAME_PAYLOAD = 65536 bytes.
///
/// The frame layer handles:
///   - Serialization of header fields to network byte order
///   - Boundary-aware reading from TCP stream (partial header,
///     partial payload, multiple frames in one read)
///   - Validation: unknown version, oversized payload, etc.

#include "message_types.hpp"
#include "common/types.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace p2p::transport {

/// Current protocol version.
inline constexpr uint8_t PROTOCOL_VERSION = 1;

/// Maximum payload size (bytes).
inline constexpr uint32_t MAX_FRAME_PAYLOAD = 65536;

/// Frame header size (bytes).
inline constexpr std::size_t FRAME_HEADER_SIZE = 24;

/// Errors that can occur during frame parsing.
enum class FrameError {
    IncompleteHeader,    ///< Not enough bytes for header yet
    IncompletePayload,   ///< Header parsed, waiting for payload
    UnsupportedVersion,  ///< Unknown protocol version
    PayloadTooLarge,     ///< payload_length > MAX_FRAME_PAYLOAD
    InvalidType,         ///< Unknown message type
};

/// Human-readable error descriptions.
[[nodiscard]] constexpr std::string_view frame_error_name(FrameError e) {
    switch (e) {
        case FrameError::IncompleteHeader:   return "IncompleteHeader";
        case FrameError::IncompletePayload:  return "IncompletePayload";
        case FrameError::UnsupportedVersion: return "UnsupportedVersion";
        case FrameError::PayloadTooLarge:    return "PayloadTooLarge";
        case FrameError::InvalidType:        return "InvalidType";
        default:                             return "Unknown";
    }
}

/// A parsed or constructed frame ready for sending/processing.
struct Frame {
    uint8_t     version    = PROTOCOL_VERSION;
    MessageType type       = MessageType::ERROR;
    FrameFlags  flags      = FrameFlags::NONE;
    RequestID   request_id{};
    Bytes       payload;

    /// Convenience: total wire size.
    [[nodiscard]] std::size_t wire_size() const {
        return FRAME_HEADER_SIZE + payload.size();
    }

    /// Serialize this frame into a byte buffer (header + payload).
    /// Returns the serialized bytes ready for TCP write.
    [[nodiscard]] Bytes serialize() const;

    /// Create a PING frame.
    static Frame make_ping(const RequestID& rid);

    /// Create a PONG response to a PING.
    static Frame make_pong(const RequestID& rid);

    /// Create an ERROR frame.
    static Frame make_error(const RequestID& rid, const std::string& message);
};

/// Incremental frame parser.
///
/// Handles TCP stream reassembly:
///   - Partial header reads
///   - Partial payload reads
///   - Multiple frames in a single read
///
/// Usage:
///   FrameParser parser;
///   parser.feed(data_from_tcp_read);
///   while (auto frame = parser.next_frame()) {
///       process(*frame);
///   }
class FrameParser {
public:
    /// Feed raw bytes from TCP into the parser.
    void feed(const uint8_t* data, std::size_t len);
    void feed(const Bytes& data) { feed(data.data(), data.size()); }

    /// Try to extract the next complete frame.
    /// Returns nullopt if no complete frame is available yet.
    /// Returns FrameError if the frame is malformed.
    [[nodiscard]] std::expected<Frame, FrameError> next_frame();

    /// Check if there are remaining bytes in the buffer.
    [[nodiscard]] bool has_pending_data() const { return !buffer_.empty(); }

    /// Get number of buffered bytes (for diagnostics).
    [[nodiscard]] std::size_t buffered_bytes() const { return buffer_.size(); }

    /// Reset parser state, discarding buffered data.
    void reset() { buffer_.clear(); }

private:
    Bytes buffer_;
};

} // namespace p2p::transport
