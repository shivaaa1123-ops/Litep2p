#pragma once

#include "session_events.h"
#include "session_manager.h"

namespace detail {
    class PeerLifecycleManager {
    public:
        explicit PeerLifecycleManager(SessionManager::Impl* sm);
        void handlePeerDiscovered(const PeerDiscoveredEvent& event);
        void handlePeerDisconnect(const PeerDisconnectEvent& event);
        void handleConnectToPeer(const ConnectToPeerEvent& event);
    private:
        SessionManager::Impl* m_sm;
    };
}
