/// @file message_service.cpp
/// @brief Implementation of application messaging service.

#include "app/message_service.hpp"
#include <chrono>

namespace p2p::app {

namespace {

uint64_t current_unix_timestamp() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace

MessageService::MessageService(NodeID self_id, std::size_t max_dedup_history)
    : self_id_(self_id),
      max_dedup_history_(std::max<std::size_t>(100, max_dedup_history)) {}

RequestID MessageService::send_message(
    const NodeID& recipient,
    const std::string& text,
    const SendMsgFunc& send_func,
    DeliveryCallback delivery_cb,
    const std::optional<std::array<uint8_t, security::AEAD_KEY_SIZE>>& e2e_key) {

    AppMessage msg;
    msg.msg_id = RequestID::generate();
    msg.sender_id = self_id_;
    msg.recipient_id = recipient;
    msg.timestamp = current_unix_timestamp();

    if (e2e_key) {
        auto nonce = security::construct_aead_nonce(1);
        auto ct = security::chacha20_poly1305_encrypt(
            reinterpret_cast<const uint8_t*>(text.data()), text.size(),
            nullptr, 0,
            nonce, *e2e_key);
        msg.text = std::string(ct.begin(), ct.end());
        msg.is_e2e_encrypted = true;
    } else {
        msg.text = text;
        msg.is_e2e_encrypted = false;
    }

    {
        std::lock_guard lock(mutex_);
        PendingMessage pending;
        pending.message = msg;
        pending.callback = std::move(delivery_cb);
        pending.sent_at = std::chrono::steady_clock::now();
        pending_[msg.msg_id] = std::move(pending);
    }

    if (send_func) {
        send_func(recipient, msg);
    }

    return msg.msg_id;
}

AppAck MessageService::handle_app_message(
    const AppMessage& msg,
    const std::optional<std::array<uint8_t, security::AEAD_KEY_SIZE>>& e2e_key) {

    AppAck ack;
    ack.msg_id = msg.msg_id;
    ack.sender_id = self_id_;

    AppMessage dispatched = msg;

    {
        std::lock_guard lock(mutex_);
        if (seen_messages_.contains(msg.msg_id)) {
            // Already seen — deduplicate, return ACK without re-notifying listener
            ack.ok = true;
            return ack;
        }

        seen_messages_.insert(msg.msg_id);
        seen_order_.push_back(msg.msg_id);

        if (seen_order_.size() > max_dedup_history_) {
            auto oldest = seen_order_.front();
            seen_order_.pop_front();
            seen_messages_.erase(oldest);
        }
    }

    // Handle E2E decryption if needed
    if (msg.is_e2e_encrypted) {
        if (!e2e_key) {
            ack.ok = false;
            ack.error_msg = "Missing E2E decryption key";
            return ack;
        }
        auto nonce = security::construct_aead_nonce(1);
        auto pt = security::chacha20_poly1305_decrypt(
            reinterpret_cast<const uint8_t*>(msg.text.data()), msg.text.size(),
            nullptr, 0,
            nonce, *e2e_key);
        if (!pt) {
            ack.ok = false;
            ack.error_msg = "E2E decryption failed (corrupted or MAC mismatch)";
            return ack;
        }
        dispatched.text = std::string(pt->begin(), pt->end());
        dispatched.is_e2e_encrypted = false;
    }

    if (on_message_cb_) {
        on_message_cb_(dispatched);
    }

    ack.ok = true;
    return ack;
}

bool MessageService::handle_app_ack(const AppAck& ack) {
    DeliveryCallback cb = nullptr;
    {
        std::lock_guard lock(mutex_);
        auto it = pending_.find(ack.msg_id);
        if (it == pending_.end()) return false;
        cb = std::move(it->second.callback);
        pending_.erase(it);
    }

    if (cb) {
        cb(ack.ok, ack.error_msg);
    }
    return true;
}

std::size_t MessageService::pending_messages_count() const {
    std::lock_guard lock(mutex_);
    return pending_.size();
}

bool MessageService::has_seen_message(const RequestID& mid) const {
    std::lock_guard lock(mutex_);
    return seen_messages_.contains(mid);
}

} // namespace p2p::app

