/// @file app_messages.cpp
/// @brief CBOR serialization implementation for Application Layer protocol messages.

#include "app/app_messages.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <algorithm>

namespace p2p::app {

using json = nlohmann::json;

bool is_safe_filename(std::string_view name) {
    if (name.empty()) return false;
    if (name.find('/') != std::string_view::npos) return false;
    if (name.find('\\') != std::string_view::npos) return false;
    if (name.find('\0') != std::string_view::npos) return false;
    if (name == "." || name == "..") return false;
    if (name.starts_with("../") || name.starts_with("..\\")) return false;
    return true;
}

std::string sanitize_filename(std::string_view name) {
    if (name.empty()) return "download.dat";
    std::string normalized(name);
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    std::filesystem::path p(normalized);
    std::string base = p.filename().string();
    // Strip null or control characters
    base.erase(std::remove_if(base.begin(), base.end(), [](char c) {
        return c == '\0' || c == '/' || c == '\\' || (static_cast<unsigned char>(c) < 32);
    }), base.end());

    if (base.empty() || base == "." || base == "..") {
        return "download.dat";
    }
    return base;
}

// ─── APP_MESSAGE (0x40) ─────────────────────────────────────────────────────

Bytes serialize_app_message(const AppMessage& msg) {
    json j = json::object();
    j["mid"] = json::binary_t({msg.msg_id.data.begin(), msg.msg_id.data.end()});
    j["snd"] = json::binary_t({msg.sender_id.data.begin(), msg.sender_id.data.end()});
    j["dst"] = json::binary_t({msg.recipient_id.data.begin(), msg.recipient_id.data.end()});
    j["ts"] = msg.timestamp;
    j["txt"] = msg.text;
    j["e2e"] = msg.is_e2e_encrypted;
    return json::to_cbor(j);
}

bool deserialize_app_message(ByteSpan payload, AppMessage& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto mid_bin = j.at("mid").get_binary();
        if (mid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(mid_bin.begin(), RequestID::SIZE, out_msg.msg_id.data.begin());

        auto snd_bin = j.at("snd").get_binary();
        if (snd_bin.size() != NodeID::SIZE) return false;
        std::copy_n(snd_bin.begin(), NodeID::SIZE, out_msg.sender_id.data.begin());

        auto dst_bin = j.at("dst").get_binary();
        if (dst_bin.size() != NodeID::SIZE) return false;
        std::copy_n(dst_bin.begin(), NodeID::SIZE, out_msg.recipient_id.data.begin());

        out_msg.timestamp = j.at("ts").get<uint64_t>();
        out_msg.text = j.at("txt").get<std::string>();
        out_msg.is_e2e_encrypted = j.at("e2e").get<bool>();
        return true;
    } catch (...) {
        return false;
    }
}

// ─── APP_ACK (0x41) ─────────────────────────────────────────────────────────

Bytes serialize_app_ack(const AppAck& msg) {
    json j = json::object();
    j["mid"] = json::binary_t({msg.msg_id.data.begin(), msg.msg_id.data.end()});
    j["snd"] = json::binary_t({msg.sender_id.data.begin(), msg.sender_id.data.end()});
    j["ok"] = msg.ok;
    j["err"] = msg.error_msg;
    return json::to_cbor(j);
}

bool deserialize_app_ack(ByteSpan payload, AppAck& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto mid_bin = j.at("mid").get_binary();
        if (mid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(mid_bin.begin(), RequestID::SIZE, out_msg.msg_id.data.begin());

        auto snd_bin = j.at("snd").get_binary();
        if (snd_bin.size() != NodeID::SIZE) return false;
        std::copy_n(snd_bin.begin(), NodeID::SIZE, out_msg.sender_id.data.begin());

        out_msg.ok = j.at("ok").get<bool>();
        out_msg.error_msg = j.at("err").get<std::string>();
        return true;
    } catch (...) {
        return false;
    }
}

// ─── APP_FILE_META (0x42) ───────────────────────────────────────────────────

Bytes serialize_file_meta(const FileMeta& msg) {
    json j = json::object();
    j["fid"] = json::binary_t({msg.file_id.data.begin(), msg.file_id.data.end()});
    j["name"] = msg.filename;
    j["sz"] = msg.file_size;
    j["csz"] = msg.chunk_size;
    j["cnt"] = msg.total_chunks;
    j["sha"] = json::binary_t({msg.file_sha256.begin(), msg.file_sha256.end()});
    j["snd"] = json::binary_t({msg.sender_id.data.begin(), msg.sender_id.data.end()});
    return json::to_cbor(j);
}

bool deserialize_file_meta(ByteSpan payload, FileMeta& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto fid_bin = j.at("fid").get_binary();
        if (fid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(fid_bin.begin(), RequestID::SIZE, out_msg.file_id.data.begin());

        out_msg.filename = sanitize_filename(j.at("name").get<std::string>());
        out_msg.file_size = j.at("sz").get<uint64_t>();
        out_msg.chunk_size = j.at("csz").get<uint32_t>();
        out_msg.total_chunks = j.at("cnt").get<uint32_t>();

        if (out_msg.chunk_size == 0 || out_msg.chunk_size > MAX_CHUNK_SIZE) return false;
        if (out_msg.file_size > MAX_FILE_SIZE) return false;

        auto sha_bin = j.at("sha").get_binary();
        if (sha_bin.size() != 32) return false;
        std::copy_n(sha_bin.begin(), 32, out_msg.file_sha256.begin());

        auto snd_bin = j.at("snd").get_binary();
        if (snd_bin.size() != NodeID::SIZE) return false;
        std::copy_n(snd_bin.begin(), NodeID::SIZE, out_msg.sender_id.data.begin());

        return true;
    } catch (...) {
        return false;
    }
}

// ─── APP_FILE_BLOCK (0x43) ──────────────────────────────────────────────────

Bytes serialize_file_block(const FileBlock& msg) {
    json j = json::object();
    j["fid"] = json::binary_t({msg.file_id.data.begin(), msg.file_id.data.end()});
    j["idx"] = msg.chunk_index;
    j["dat"] = json::binary_t({msg.data.begin(), msg.data.end()});
    j["sha"] = json::binary_t({msg.chunk_sha256.begin(), msg.chunk_sha256.end()});
    return json::to_cbor(j);
}

bool deserialize_file_block(ByteSpan payload, FileBlock& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto fid_bin = j.at("fid").get_binary();
        if (fid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(fid_bin.begin(), RequestID::SIZE, out_msg.file_id.data.begin());

        out_msg.chunk_index = j.at("idx").get<uint32_t>();

        auto dat_bin = j.at("dat").get_binary();
        if (dat_bin.size() > MAX_CHUNK_SIZE) return false;
        out_msg.data.assign(dat_bin.begin(), dat_bin.end());

        auto sha_bin = j.at("sha").get_binary();
        if (sha_bin.size() != 32) return false;
        std::copy_n(sha_bin.begin(), 32, out_msg.chunk_sha256.begin());

        return true;
    } catch (...) {
        return false;
    }
}

// ─── APP_FILE_ACK (0x44) ────────────────────────────────────────────────────

Bytes serialize_file_ack(const FileAck& msg) {
    json j = json::object();
    j["fid"] = json::binary_t({msg.file_id.data.begin(), msg.file_id.data.end()});
    j["idx"] = msg.chunk_index;
    j["ok"] = msg.ok;
    j["err"] = msg.error_msg;
    return json::to_cbor(j);
}

bool deserialize_file_ack(ByteSpan payload, FileAck& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto fid_bin = j.at("fid").get_binary();
        if (fid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(fid_bin.begin(), RequestID::SIZE, out_msg.file_id.data.begin());

        out_msg.chunk_index = j.at("idx").get<uint32_t>();
        out_msg.ok = j.at("ok").get<bool>();
        out_msg.error_msg = j.at("err").get<std::string>();
        return true;
    } catch (...) {
        return false;
    }
}

// ─── APP_FILE_COMPLETE (0x45) ───────────────────────────────────────────────

Bytes serialize_file_complete(const FileComplete& msg) {
    json j = json::object();
    j["fid"] = json::binary_t({msg.file_id.data.begin(), msg.file_id.data.end()});
    j["ok"] = msg.ok;
    j["sha"] = json::binary_t({msg.file_sha256.begin(), msg.file_sha256.end()});
    return json::to_cbor(j);
}

bool deserialize_file_complete(ByteSpan payload, FileComplete& out_msg) {
    try {
        auto j = json::from_cbor(payload.begin(), payload.end());
        if (!j.is_object()) return false;

        auto fid_bin = j.at("fid").get_binary();
        if (fid_bin.size() != RequestID::SIZE) return false;
        std::copy_n(fid_bin.begin(), RequestID::SIZE, out_msg.file_id.data.begin());

        out_msg.ok = j.at("ok").get<bool>();

        auto sha_bin = j.at("sha").get_binary();
        if (sha_bin.size() != 32) return false;
        std::copy_n(sha_bin.begin(), 32, out_msg.file_sha256.begin());

        return true;
    } catch (...) {
        return false;
    }
}

} // namespace p2p::app
