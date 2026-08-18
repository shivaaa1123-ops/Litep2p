#pragma once

#include "session_events.h"
#include "session_manager.h"
#include <chrono>
#include <atomic>
#include <unordered_map>

namespace detail {
    class MaintenanceManager {
    public:
        explicit MaintenanceManager(SessionManager::Impl* sm);
        void handleTimerTick(const TimerTickEvent& event);
    private:
        SessionManager::Impl* m_sm;
        std::chrono::steady_clock::time_point m_last_heartbeat;
        std::chrono::steady_clock::time_point m_last_discovery_broadcast;
        // Throttled kick to reconnect/re-register signaling after transient network flaps.
        // (A single reconnect attempt can fail with ENETUNREACH while cellular/Wi-Fi is coming up.)
        std::chrono::steady_clock::time_point m_last_signaling_reconnect_kick;
        // Periodic scan to retry non-connected peers even when at least one peer is connected.
        std::chrono::steady_clock::time_point m_last_peer_retry_scan;
        // Periodic LAN endpoint re-discovery when on WiFi
        std::chrono::steady_clock::time_point m_last_lan_discovery_scan;
        // Periodic endpoint fallback check - switch to alternate endpoint if current fails
        std::chrono::steady_clock::time_point m_last_endpoint_fallback_check;
        // Moved to ConfigManager: getHeartbeatIntervalSec(), getPeerExpirationTimeoutMs()
        
        // Helper to trigger LAN re-discovery for peers with stale LAN endpoints
        void performLanRediscovery();
        // Helper to check and fallback endpoints for failing connections
        void checkEndpointFallback();
        // Field diagnostics: report peers stuck in CONNECTING/HANDSHAKING beyond
        // the anomaly_reporter.stall_threshold_ms (once per stall episode).
        void detectStalledPeers();
        // Tracks which stalled (peer, state) episodes have already been reported.
        std::unordered_map<std::string, int> m_reported_stall_state;
    };
}
