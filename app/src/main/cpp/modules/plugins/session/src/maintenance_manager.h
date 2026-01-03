#pragma once

#include "session_events.h"
#include "session_manager.h"
#include <chrono>
#include <atomic>

namespace detail {
    class MaintenanceManager {
    public:
        explicit MaintenanceManager(SessionManager::Impl* sm);
        void handleTimerTick(const TimerTickEvent& event);
    private:
        SessionManager::Impl* m_sm;
        std::chrono::steady_clock::time_point m_last_heartbeat;
        std::chrono::steady_clock::time_point m_last_discovery_broadcast;
        // Moved to ConfigManager: getHeartbeatIntervalSec(), getPeerExpirationTimeoutMs()
    };
}
