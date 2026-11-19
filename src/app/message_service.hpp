#pragma once
/// @file message_service.hpp
/// @brief Application messaging service with E2E encryption, ACK delivery, and deduplication (Stage 6).

#include "common/types.hpp"
#include "app/app_messages.hpp"
#include "security/crypto_utils.hpp"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <deque>
#include <memory>
#include <mutex>
#include <functional>
#include <chrono>

namespace p2p::app {

/// Callback for received text messages.
using OnMessageReceivedCallback = std::function<void(const AppMessage& msg)>;

/// Callback for delivery confirmation.
using DeliveryCallback = std::function<void(bool success, const std::string& err)>;

class MessageService {
public:
    using SendMsgFunc = std::function<void(const NodeID& target, const AppMessage&)>;
    using SendAckFunc = std::function<void(const NodeID& target, const AppAck&)>;

    explicit MessageService(NodeID self_id, std::size_t max_dedup_history = 1000);

    [[nodiscard]] const NodeID& self_id() const noexcept { return self_id_; }

    /// Send a message to recipient.
    RequestID send_message(
        const NodeID& recipient,
        const std::string& text,
        const SendMsgFunc& send_func,
        DeliveryCallback delivery_cb = nullptr,
        const std::optional<std::array<uint8_t, security::AEAD_KEY_SIZE>>& e2e_key = std::nullopt);

    /// Handle incoming APP_MESSAGE (0x40).
    /// Returns AppAck to send back.
    AppAck handle_app_message(
        const AppMessage& msg,
        const std::optional<std::array<uint8_t, security::AEAD_KEY_SIZE>>& e2e_key = std::nullopt);

    /// Handle incoming APP_ACK (0x41).
    bool handle_app_ack(const AppAck& ack);

    /// Set handler for incoming messages.
    void set_on_message(OnMessageReceivedCallback cb) { on_message_cb_ = std::move(cb); }

    [[nodiscard]] std::size_t pending_messages_count() const;
    [[nodiscard]] bool has_seen_message(const RequestID& mid) const;

private:
    struct PendingMessage {
        AppMessage message{};
        DeliveryCallback callback{};
        std::chrono::steady_clock::time_point sent_at{};
    };

    NodeID self_id_{};
    std::size_t max_dedup_history_{1000};

    std::map<RequestID, PendingMessage> pending_{};
    std::set<RequestID> seen_messages_{};
    std::deque<RequestID> seen_order_{};

    OnMessageReceivedCallback on_message_cb_{};
    mutable std::mutex mutex_{};
};

} // namespace p2p::app

