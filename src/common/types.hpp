#pragma once
/// @file types.hpp
/// @brief Common types used across the P2P overlay network.

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <compare>
#include <functional>
#include <span>

namespace p2p {

/// 256-bit (32-byte) identifier for nodes and DHT keys.
/// Computed as SHA-256(canonical_encode(identity_public_key)).
struct NodeID {
    static constexpr std::size_t SIZE = 32;
    std::array<uint8_t, SIZE> data{};

    bool operator==(const NodeID& other) const = default;
    auto operator<=>(const NodeID& other) const = default;

    /// XOR distance metric (Kademlia).
    [[nodiscard]] NodeID xor_distance(const NodeID& other) const {
        NodeID result;
        for (std::size_t i = 0; i < SIZE; ++i) {
            result.data[i] = data[i] ^ other.data[i];
        }
        return result;
    }

    /// Find the index of the most significant differing bit (0..255).
    /// Returns -1 if IDs are equal.
    /// Used to determine which k-bucket a contact belongs to.
    [[nodiscard]] int bucket_index(const NodeID& other) const {
        for (std::size_t i = 0; i < SIZE; ++i) {
            uint8_t diff = data[i] ^ other.data[i];
            if (diff != 0) {
                // Count leading zeros in this byte
                int leading = 0;
                for (int bit = 7; bit >= 0; --bit) {
                    if (diff & (1 << bit)) break;
                    ++leading;
                }
                return static_cast<int>(255 - (i * 8 + leading));
            }
        }
        return -1; // equal
    }

    /// Check if this XOR distance is less than another.
    [[nodiscard]] bool is_closer_than(const NodeID& dist_a, const NodeID& dist_b) {
        // Compare dist_a < dist_b lexicographically (big-endian)
        return dist_a < dist_b;
    }

    /// Hex string representation for logging.
    [[nodiscard]] std::string to_hex() const {
        static constexpr char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(SIZE * 2);
        for (auto byte : data) {
            result += hex_chars[byte >> 4];
            result += hex_chars[byte & 0x0f];
        }
        return result;
    }

    /// Short hex (first 8 chars) for display.
    [[nodiscard]] std::string to_short_hex() const {
        return to_hex().substr(0, 8);
    }

    /// Parse from hex string.
    [[nodiscard]] static bool from_hex(const std::string& hex, NodeID& out) {
        if (hex.size() != SIZE * 2) return false;
        for (std::size_t i = 0; i < SIZE; ++i) {
            auto hi = hex_char_to_nibble(hex[i * 2]);
            auto lo = hex_char_to_nibble(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            out.data[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return true;
    }

    /// Check if all zeros.
    [[nodiscard]] bool is_zero() const {
        for (auto b : data) {
            if (b != 0) return false;
        }
        return true;
    }

private:
    static int hex_char_to_nibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
};

/// Byte buffer alias.
using Bytes = std::vector<uint8_t>;

/// Span of bytes (non-owning view).
using ByteSpan = std::span<const uint8_t>;

/// 16-byte unique request identifier for request/response matching.
struct RequestID {
    static constexpr std::size_t SIZE = 16;
    std::array<uint8_t, SIZE> data{};

    bool operator==(const RequestID& other) const = default;

    /// Generate a random request ID using libsodium.
    static RequestID generate();

    [[nodiscard]] std::string to_hex() const {
        static constexpr char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(SIZE * 2);
        for (auto byte : data) {
            result += hex_chars[byte >> 4];
            result += hex_chars[byte & 0x0f];
        }
        return result;
    }
};

/// Network address of a peer.
struct PeerAddress {
    std::string host;
    uint16_t    port = 0;

    bool operator==(const PeerAddress& other) const = default;

    [[nodiscard]] std::string to_string() const {
        return host + ":" + std::to_string(port);
    }
};

/// Information about a known peer (contact in routing table).
struct PeerInfo {
    NodeID      node_id;
    PeerAddress address;

    bool operator==(const PeerInfo& other) const {
        return node_id == other.node_id;
    }
};

} // namespace p2p

/// Hash support for NodeID (for use in unordered containers).
template <>
struct std::hash<p2p::NodeID> {
    std::size_t operator()(const p2p::NodeID& id) const noexcept {
        // Use first 8 bytes as hash
        std::size_t h = 0;
        std::memcpy(&h, id.data.data(), sizeof(h));
        return h;
    }
};

/// Hash support for RequestID.
template <>
struct std::hash<p2p::RequestID> {
    std::size_t operator()(const p2p::RequestID& id) const noexcept {
        std::size_t h = 0;
        std::memcpy(&h, id.data.data(), sizeof(h));
        return h;
    }
};
