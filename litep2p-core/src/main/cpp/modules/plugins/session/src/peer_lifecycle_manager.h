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
        
        // Handle LAN discovery result - updates peer with discovered local endpoint
        // This enables local IP connections when peers are on the same network
        void handleLanDiscoveryResult(const LanDiscoveryResultEvent& event);
        
    private:
        SessionManager::Impl* m_sm;
        
        // Helper to check if an IP is a private/LAN address (RFC1918)
        static bool isPrivateLanIp(const std::string& ip);
    };
}
