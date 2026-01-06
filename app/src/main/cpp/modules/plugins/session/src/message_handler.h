#pragma once

#include "session_events.h"
#include "session_manager.h"

namespace detail {
    class MessageHandler {
    public:
        explicit MessageHandler(SessionManager::Impl* sm);
        void handleDataReceived(const DataReceivedEvent& event);
        void handleSendMessage(const SendMessageEvent& event);
    private:
        SessionManager::Impl* m_sm;
    };
}
