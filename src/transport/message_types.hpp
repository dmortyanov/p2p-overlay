#pragma once
/// @file message_types.hpp
/// @brief Protocol message type enumeration.
///
/// Defines all message types used in the P2P overlay protocol.
/// Each type occupies 1 byte in the frame header.

#include <cstdint>
#include <string_view>

namespace p2p::transport {

/// Protocol message types (1 byte in frame header).
enum class MessageType : uint8_t {
    // ─── DHT RPC ─────────────────────────────────────────────
    PING                = 0x01,
    PONG                = 0x02,
    FIND_NODE_REQUEST   = 0x10,
    FIND_NODE_RESPONSE  = 0x11,
    STORE_REQUEST       = 0x12,
    STORE_RESPONSE      = 0x13,
    FIND_VALUE_REQUEST  = 0x14,
    FIND_VALUE_RESPONSE = 0x15,

    // ─── Tunnel Management ───────────────────────────────────
    TUNNEL_BUILD        = 0x20,
    TUNNEL_BUILD_OK     = 0x21,
    TUNNEL_BUILD_FAIL   = 0x22,
    TUNNEL_DATA         = 0x30,
    TUNNEL_ACK          = 0x31,
    TUNNEL_CLOSE        = 0x32,
    TUNNEL_HEARTBEAT    = 0x33,

    // ─── Application Layer ───────────────────────────────────
    APP_MESSAGE         = 0x40,
    APP_ACK             = 0x41,
    APP_FILE_META       = 0x42,
    APP_FILE_BLOCK      = 0x43,
    APP_FILE_ACK        = 0x44,
    APP_FILE_COMPLETE   = 0x45,

    // ─── Security Handshake ──────────────────────────────────
    HANDSHAKE_INIT      = 0x50,
    HANDSHAKE_RESPONSE  = 0x51,
    HANDSHAKE_COMPLETE  = 0x52,

    // ─── Error ───────────────────────────────────────────────
    ERROR               = 0xFF,
};

/// Frame header flags (2 bytes, network byte order).
enum class FrameFlags : uint16_t {
    NONE          = 0x0000,
    IS_RESPONSE   = 0x0001,   ///< This frame is a response to a request
    IS_ERROR      = 0x0002,   ///< This frame carries an error payload
    IS_ENCRYPTED  = 0x0004,   ///< Payload is AEAD-encrypted
    IS_FRAGMENT   = 0x0008,   ///< Payload is a fragment (future use)
    HAS_MORE      = 0x0010,   ///< More fragments follow (future use)
};

/// Combine flags with bitwise OR.
inline constexpr FrameFlags operator|(FrameFlags a, FrameFlags b) {
    return static_cast<FrameFlags>(
        static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}

/// Check if a flag is set.
inline constexpr bool operator&(FrameFlags a, FrameFlags b) {
    return (static_cast<uint16_t>(a) & static_cast<uint16_t>(b)) != 0;
}

/// Human-readable name for message types (for logging).
[[nodiscard]] constexpr std::string_view message_type_name(MessageType t) {
    switch (t) {
        case MessageType::PING:                return "PING";
        case MessageType::PONG:                return "PONG";
        case MessageType::FIND_NODE_REQUEST:   return "FIND_NODE_REQUEST";
        case MessageType::FIND_NODE_RESPONSE:  return "FIND_NODE_RESPONSE";
        case MessageType::STORE_REQUEST:       return "STORE_REQUEST";
        case MessageType::STORE_RESPONSE:      return "STORE_RESPONSE";
        case MessageType::FIND_VALUE_REQUEST:  return "FIND_VALUE_REQUEST";
        case MessageType::FIND_VALUE_RESPONSE: return "FIND_VALUE_RESPONSE";
        case MessageType::TUNNEL_BUILD:        return "TUNNEL_BUILD";
        case MessageType::TUNNEL_BUILD_OK:     return "TUNNEL_BUILD_OK";
        case MessageType::TUNNEL_BUILD_FAIL:   return "TUNNEL_BUILD_FAIL";
        case MessageType::TUNNEL_DATA:         return "TUNNEL_DATA";
        case MessageType::TUNNEL_ACK:          return "TUNNEL_ACK";
        case MessageType::TUNNEL_CLOSE:        return "TUNNEL_CLOSE";
        case MessageType::TUNNEL_HEARTBEAT:    return "TUNNEL_HEARTBEAT";
        case MessageType::APP_MESSAGE:         return "APP_MESSAGE";
        case MessageType::APP_ACK:             return "APP_ACK";
        case MessageType::APP_FILE_META:       return "APP_FILE_META";
        case MessageType::APP_FILE_BLOCK:      return "APP_FILE_BLOCK";
        case MessageType::APP_FILE_ACK:        return "APP_FILE_ACK";
        case MessageType::APP_FILE_COMPLETE:   return "APP_FILE_COMPLETE";
        case MessageType::HANDSHAKE_INIT:      return "HANDSHAKE_INIT";
        case MessageType::HANDSHAKE_RESPONSE:  return "HANDSHAKE_RESPONSE";
        case MessageType::HANDSHAKE_COMPLETE:  return "HANDSHAKE_COMPLETE";
        case MessageType::ERROR:               return "ERROR";
        default:                               return "UNKNOWN";
    }
}

} // namespace p2p::transport
