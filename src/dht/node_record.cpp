#include "dht/node_record.hpp"
#include "identity/node_id.hpp"

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace p2p::dht {

std::string record_validation_error_name(RecordValidationError err) {
    switch (err) {
        case RecordValidationError::None:              return "None";
        case RecordValidationError::InvalidSize:       return "InvalidSize";
        case RecordValidationError::IdentityMismatch:  return "IdentityMismatch";
        case RecordValidationError::InvalidSignature:  return "InvalidSignature";
        case RecordValidationError::Expired:           return "Expired";
        case RecordValidationError::NotYetValid:       return "NotYetValid";
        case RecordValidationError::EmptyAddresses:    return "EmptyAddresses";
        case RecordValidationError::InvalidAddress:    return "InvalidAddress";
        case RecordValidationError::RollbackDetected:  return "RollbackDetected";
    }
    return "Unknown";
}

NodeID node_record_key(const NodeID& node_id) {
    // SHA256("node:" || node_id)
    static const std::string prefix = "node:";
    std::vector<uint8_t> preimage;
    preimage.reserve(prefix.size() + node_id.data.size());
    preimage.insert(preimage.end(), prefix.begin(), prefix.end());
    preimage.insert(preimage.end(), node_id.data.begin(), node_id.data.end());

    NodeID out;
    crypto_hash_sha256(out.data.data(), preimage.data(), preimage.size());
    return out;
}

std::string normalize_alias(std::string_view alias) {
    // Strip leading and trailing whitespace, convert ASCII to lowercase
    auto start = alias.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) return "";
    auto end = alias.find_last_not_of(" \t\r\n");
    std::string_view trimmed = alias.substr(start, end - start + 1);

    std::string result;
    result.reserve(trimmed.size());
    for (char c : trimmed) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

NodeID alias_record_key(std::string_view alias) {
    // SHA256("alias:" || normalize(alias))
    static const std::string prefix = "alias:";
    std::string norm = normalize_alias(alias);
    std::vector<uint8_t> preimage;
    preimage.reserve(prefix.size() + norm.size());
    preimage.insert(preimage.end(), prefix.begin(), prefix.end());
    preimage.insert(preimage.end(), norm.begin(), norm.end());

    NodeID out;
    crypto_hash_sha256(out.data.data(), preimage.data(), preimage.size());
    return out;
}

Bytes NodeRecord::canonical_bytes() const {
    Bytes out;
    // 1. node_id (32 bytes)
    out.insert(out.end(), node_id.data.begin(), node_id.data.end());
    // 2. identity_public_key (32 bytes)
    out.insert(out.end(), identity_public_key.begin(), identity_public_key.end());

    // Big-endian helper
    auto append_be64 = [&out](uint64_t val) {
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
        }
    };
    auto append_be16 = [&out](uint16_t val) {
        out.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(val & 0xFF));
    };

    // 3. sequence_number, issued_at, expires_at (8 bytes each)
    append_be64(sequence_number);
    append_be64(issued_at);
    append_be64(expires_at);

    // 4. alias length + alias string
    append_be16(static_cast<uint16_t>(alias.size()));
    out.insert(out.end(), alias.begin(), alias.end());

    // 5. addresses count
    append_be16(static_cast<uint16_t>(addresses.size()));
    for (const auto& addr : addresses) {
        append_be16(static_cast<uint16_t>(addr.host.size()));
        out.insert(out.end(), addr.host.begin(), addr.host.end());
        append_be16(addr.port);
    }

    return out;
}

void NodeRecord::sign(const identity::Keypair& keypair) {
    node_id = keypair.node_id();
    identity_public_key = keypair.public_key();
    auto bytes = canonical_bytes();
    signature = keypair.sign(bytes);
}

bool NodeRecord::verify_signature() const {
    // 1. Verify node_id == SHA256(identity_public_key)
    if (!identity::verify_node_id(node_id, identity_public_key)) {
        return false;
    }
    // 2. Verify Ed25519 signature over canonical bytes
    auto bytes = canonical_bytes();
    return identity::Keypair::verify(signature, bytes.data(), bytes.size(), identity_public_key);
}

bool NodeRecord::is_time_valid(uint64_t current_time_sec) const {
    // 30 seconds clock skew tolerance for issued_at in future
    constexpr uint64_t SKEW_TOLERANCE = 30;
    if (current_time_sec + SKEW_TOLERANCE < issued_at) {
        return false;
    }
    if (current_time_sec > expires_at) {
        return false;
    }
    return true;
}

RecordValidationError NodeRecord::validate(uint64_t current_time_sec) const {
    // Check sizes
    if (alias.size() > 256 || addresses.size() > 16) {
        return RecordValidationError::InvalidSize;
    }
    if (addresses.empty()) {
        return RecordValidationError::EmptyAddresses;
    }
    for (const auto& addr : addresses) {
        if (addr.host.empty() || addr.port == 0) {
            return RecordValidationError::InvalidAddress;
        }
    }

    // Check time window
    constexpr uint64_t SKEW_TOLERANCE = 30;
    if (current_time_sec + SKEW_TOLERANCE < issued_at) {
        return RecordValidationError::NotYetValid;
    }
    if (current_time_sec > expires_at) {
        return RecordValidationError::Expired;
    }

    // Check identity & signature
    if (!identity::verify_node_id(node_id, identity_public_key)) {
        return RecordValidationError::IdentityMismatch;
    }
    if (!verify_signature()) {
        return RecordValidationError::InvalidSignature;
    }

    return RecordValidationError::None;
}

Bytes NodeRecord::to_cbor() const {
    nlohmann::json j;
    j["node_id"] = node_id.to_hex();
    j["public_key"] = nlohmann::json::binary_t({identity_public_key.begin(), identity_public_key.end()});
    j["seq"] = sequence_number;
    j["issued_at"] = issued_at;
    j["expires_at"] = expires_at;
    j["alias"] = alias;
    j["sig"] = nlohmann::json::binary_t({signature.begin(), signature.end()});

    nlohmann::json addrs = nlohmann::json::array();
    for (const auto& addr : addresses) {
        addrs.push_back({{"host", addr.host}, {"port", addr.port}});
    }
    j["addrs"] = addrs;

    auto cbor = nlohmann::json::to_cbor(j);
    return Bytes(cbor.begin(), cbor.end());
}

std::optional<NodeRecord> NodeRecord::from_cbor(ByteSpan bytes) {
    if (bytes.empty()) return std::nullopt;
    try {
        auto j = nlohmann::json::from_cbor(bytes);
        NodeRecord rec;

        if (!j.contains("node_id") || !j.contains("public_key") ||
            !j.contains("seq") || !j.contains("issued_at") ||
            !j.contains("expires_at") || !j.contains("sig") ||
            !j.contains("addrs")) {
            return std::nullopt;
        }

        if (!NodeID::from_hex(j["node_id"].get<std::string>(), rec.node_id)) {
            return std::nullopt;
        }

        auto pk = j["public_key"].get<nlohmann::json::binary_t>();
        if (pk.size() != 32) return std::nullopt;
        std::copy(pk.begin(), pk.end(), rec.identity_public_key.begin());

        rec.sequence_number = j["seq"].get<uint64_t>();
        rec.issued_at = j["issued_at"].get<uint64_t>();
        rec.expires_at = j["expires_at"].get<uint64_t>();
        rec.alias = j.value("alias", "");

        auto sig = j["sig"].get<nlohmann::json::binary_t>();
        if (sig.size() != 64) return std::nullopt;
        std::copy(sig.begin(), sig.end(), rec.signature.begin());

        for (const auto& item : j["addrs"]) {
            rec.addresses.push_back(PeerAddress{
                .host = item.value("host", ""),
                .port = item.value("port", static_cast<uint16_t>(0))
            });
        }

        return rec;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace p2p::dht
