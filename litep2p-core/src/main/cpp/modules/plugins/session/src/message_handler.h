#pragma once

#include "session_events.h"
#include "session_manager.h"

#include <chrono>
#include <unordered_map>

namespace detail {
    class MessageHandler {
    public:
        explicit MessageHandler(SessionManager::Impl* sm);
        void handleDataReceived(const DataReceivedEvent& event);
        void handleSendMessage(const SendMessageEvent& event);
    private:
        SessionManager::Impl* m_sm;

        // Per-peer count of consecutive *real* decryption failures (not replays).
        // A single corrupt/reordered UDP frame is normal during bursts and must
        // not destroy the session; only reaching the threshold (>=3 in a row)
        // triggers the stale-keys recovery path. Reset on a successful decrypt.
        std::unordered_map<std::string, int> m_consecutive_decrypt_fail;
    };
}
