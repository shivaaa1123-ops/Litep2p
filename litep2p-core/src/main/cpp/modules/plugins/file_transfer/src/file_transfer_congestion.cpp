#include "file_transfer_manager.h"
#include "logger.h"

#include <algorithm>

// ============================================================================
// CONGESTION HANDLING
// ============================================================================

void FileTransferManager::report_congestion(const std::string& path_id,
                                            const CongestionMetrics& metrics) {
    {
        std::lock_guard<std::mutex> lock(m_congestion_mutex);
        m_congestion_history.push_back(metrics);

        // Keep last 100 samples
        if (m_congestion_history.size() > 100) {
            m_congestion_history.pop_front();
        }
    }

    // Update path metrics based on congestion
    {
        std::lock_guard<std::mutex> path_lock(m_paths_mutex);
        auto it = m_path_map.find(path_id);
        if (it != m_path_map.end()) {
            // Reduce bandwidth estimate based on loss
            if (metrics.packet_loss_percent > 0) {
                int reduced_bw = static_cast<int>(it->second->bandwidth_kbps *
                                                  (1.0f - metrics.packet_loss_percent / 100.0f));
                it->second->bandwidth_kbps = std::max(reduced_bw, static_cast<int>(MIN_RATE_LIMIT_KBPS));
            }
        }
    }

    // Estimate new congestion level
    CongestionLevel new_level = estimate_congestion();
    if (new_level != m_current_congestion_level) {
        m_current_congestion_level = new_level;
        adjust_rate_limit(new_level);

        if (m_congestion_callback) {
            m_congestion_callback(new_level, metrics);
        }
    }
}

CongestionMetrics FileTransferManager::get_congestion_metrics() {
    std::lock_guard<std::mutex> lock(m_congestion_mutex);

    if (m_congestion_history.empty()) {
        return CongestionMetrics{CongestionLevel::LOW, 0.0f, 0.0f, 0.0f, 0};
    }

    return m_congestion_history.back();
}

uint32_t FileTransferManager::get_adaptive_rate_limit() {
    return m_current_rate_limit_kbps.load();
}

void FileTransferManager::set_rate_limit(uint32_t rate_kbps) {
    uint32_t limited = std::max(MIN_RATE_LIMIT_KBPS, std::min(rate_kbps, MAX_RATE_LIMIT_KBPS));
    m_current_rate_limit_kbps.store(limited);
    LOG_INFO("FT: Rate limit set to " + std::to_string(limited) + " Kbps");
}

void FileTransferManager::adjust_rate_limit(CongestionLevel level) {
    uint32_t new_limit = m_current_rate_limit_kbps.load();

    switch (level) {
        case CongestionLevel::LOW:
            new_limit = std::min(new_limit + 100, MAX_RATE_LIMIT_KBPS);
            LOG_DEBUG("FT: Congestion LOW - increasing rate limit to " +
                      std::to_string(new_limit) + " Kbps");
            break;

        case CongestionLevel::MODERATE:
            new_limit = std::max(new_limit - 50, MIN_RATE_LIMIT_KBPS);
            LOG_DEBUG("FT: Congestion MODERATE - reducing rate limit to " +
                      std::to_string(new_limit) + " Kbps");
            break;

        case CongestionLevel::HIGH:
            new_limit = std::max(new_limit - 200, MIN_RATE_LIMIT_KBPS);
            LOG_DEBUG("FT: Congestion HIGH - significantly reducing rate limit to " +
                      std::to_string(new_limit) + " Kbps");
            break;

        case CongestionLevel::SEVERE:
            new_limit = MIN_RATE_LIMIT_KBPS;
            LOG_WARN("FT: Congestion SEVERE - limiting rate to minimum " +
                     std::to_string(new_limit) + " Kbps");
            break;
    }

    m_current_rate_limit_kbps.store(new_limit);
}

CongestionLevel FileTransferManager::estimate_congestion() {
    std::lock_guard<std::mutex> lock(m_congestion_mutex);

    if (m_congestion_history.empty()) {
        return CongestionLevel::LOW;
    }

    // Average recent samples (last 10)
    float avg_loss = 0.0f;
    float avg_rtt = 0.0f;
    float avg_util = 0.0f;

    size_t samples = std::min(size_t(10), m_congestion_history.size());
    for (size_t i = m_congestion_history.size() - samples; i < m_congestion_history.size(); i++) {
        avg_loss += m_congestion_history[i].packet_loss_percent;
        avg_rtt += m_congestion_history[i].rtt_ms;
        avg_util += m_congestion_history[i].bandwidth_utilization_percent;
    }

    avg_loss /= samples;
    avg_rtt /= samples;
    avg_util /= samples;

    // Estimate congestion level
    if (avg_loss > 10.0f || avg_util > 80.0f) {
        return CongestionLevel::SEVERE;
    } else if (avg_loss > 5.0f || avg_util > 60.0f) {
        return CongestionLevel::HIGH;
    } else if (avg_loss > 1.0f || avg_util > 40.0f) {
        return CongestionLevel::MODERATE;
    } else {
        return CongestionLevel::LOW;
    }
}

void FileTransferManager::congestion_monitor_loop() {
    while (m_running) {
        std::unique_lock<std::mutex> lk(m_shutdown_mutex);
        m_shutdown_cv.wait_for(lk, std::chrono::milliseconds(m_congestion_check_interval_ms),
                               [this] { return !m_running; });
        if (!m_running) break;

        // Simple AIMD (Additive Increase, Multiplicative Decrease)
        // If we haven't seen congestion for a while, slowly increase rate limit.
        
        std::lock_guard<std::mutex> lock(m_congestion_mutex);
        if (m_congestion_history.empty()) continue;

        auto last_report = m_congestion_history.back();
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              now - last_report.timestamp).count();

        // If no congestion reports for 1 second, assume things are improving
        if (elapsed_ms > 1000) {
            uint32_t current_limit = m_current_rate_limit_kbps.load();
            if (current_limit < MAX_RATE_LIMIT_KBPS) {
                // Additive Increase: +50 Kbps per second
                m_current_rate_limit_kbps.store(current_limit + 50);
                // LOG_DEBUG("FT: AIMD Increase rate limit to " + std::to_string(current_limit + 50));
            }
            
            // Reset congestion level if it was high
            if (m_current_congestion_level != CongestionLevel::LOW && elapsed_ms > 5000) {
                m_current_congestion_level = CongestionLevel::LOW;
            }
        }
    }
}
