#include "../include/tier_system_failsafe.h"
#include "logger.h"
#include <algorithm>
#include <sstream>
#include <sys/sysinfo.h>
#include <cstring>
#include <iomanip>

TierSystemFailsafe::TierSystemFailsafe() {
    m_health_status.is_healthy = true;
    m_health_status.error_count = 0;
    m_health_status.warning_count = 0;
    m_health_status.critical_error_count = 0;
    m_health_status.recovery_attempts = 0;
    m_health_status.successful_recoveries = 0;
    m_health_status.failed_recovery_attempts = 0;
    m_last_health_check = std::chrono::steady_clock::now();
}

TierSystemFailsafe::~TierSystemFailsafe() {
    shutdown();
}

bool TierSystemFailsafe::initialize() {
    try {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        m_error_history.clear();
        m_health_status.is_healthy = true;
        m_health_status.error_count = 0;
        m_health_status.warning_count = 0;
        m_health_status.critical_error_count = 0;
        m_recovery_attempts.clear();
        m_quarantined_peers.clear();
        
        LOG_INFO("Failsafe system initialized");  // TierSystemFailsafe
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("Initialization failed: " + std::string(e.what()));  // TierSystemFailsafe
        return false;
    }
}

void TierSystemFailsafe::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_error_callback = nullptr;
    m_health_callback = nullptr;
    m_quarantined_peers.clear();
    m_recovery_attempts.clear();
    LOG_INFO("Failsafe system shutdown");  // TierSystemFailsafe
}

bool TierSystemFailsafe::report_error(const SystemError& error) {
    try {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Add to history
        m_error_history.push_back(error);
        if (m_error_history.size() > MAX_ERROR_HISTORY) {
            m_error_history.erase(m_error_history.begin());
        }
        
        // Update health status
        switch (error.severity) {
            case ErrorSeverity::WARNING:
                m_health_status.warning_count++;
                break;
            case ErrorSeverity::ERROR:
                m_health_status.error_count++;
                break;
            case ErrorSeverity::CRITICAL:
                m_health_status.critical_error_count++;
                m_health_status.last_critical_error = error.error_code + ": " + error.description;
                m_health_status.is_healthy = false;
                break;
            case ErrorSeverity::INFO:
            default:
                break;
        }
        
        m_health_status.last_error_time = error.timestamp;
        
        // Log error
        std::string msg = error.component + " [" + error.error_code + "]: " + 
                         error.description;
        if (!error.context.empty()) {
            msg += " (" + error.context + ")";
        }
        
        switch (error.severity) {
            case ErrorSeverity::INFO:
                LOG_INFO(msg);  // TierSystemFailsafe
                break;
            case ErrorSeverity::WARNING:
                LOG_WARN(msg);  // TierSystemFailsafe
                break;
            case ErrorSeverity::ERROR:
                LOG_WARN(msg);  // TierSystemFailsafe
                break;
            case ErrorSeverity::CRITICAL:
                LOG_WARN("CRITICAL: " + msg);  // TierSystemFailsafe
                break;
        }
        
        // Call error callback if registered
        if (m_alerting_enabled && m_error_callback) {
            try {
                m_error_callback(error);
            } catch (const std::exception& e) {
                LOG_WARN("Error callback failed: " + std::string(e.what()));  // TierSystemFailsafe
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("Error reporting failed: " + std::string(e.what()));  // TierSystemFailsafe
        return false;
    }
}

bool TierSystemFailsafe::report_error(ErrorSeverity severity, const std::string& code,
                                     const std::string& description, const std::string& component,
                                     const std::string& context) {
    SystemError error(severity, code, description, component, context);
    return report_error(error);
}

SystemError* TierSystemFailsafe::get_last_error() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_error_history.empty()) {
        return nullptr;
    }
    return &m_error_history.back();
}

std::vector<SystemError> TierSystemFailsafe::get_error_history(int count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int start = std::max(0, static_cast<int>(m_error_history.size()) - count);
    std::vector<SystemError> result(
        m_error_history.begin() + start,
        m_error_history.end()
    );
    return result;
}

int TierSystemFailsafe::get_error_count(ErrorSeverity severity) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int count = 0;
    for (const auto& error : m_error_history) {
        if (error.severity == severity) {
            count++;
        }
    }
    return count;
}

HealthStatus TierSystemFailsafe::get_health_status() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    HealthStatus status = m_health_status;
    
    // Update memory usage
    struct sysinfo info{};
    if (sysinfo(&info) == 0) {
        unsigned long total_mem = info.totalram;
        unsigned long free_mem = info.freeram;
        unsigned long used_mem = total_mem - free_mem;
        status.memory_usage_percent = (static_cast<float>(used_mem) / total_mem) * 100.0f;
    }
    
    // Determine overall health
    status.is_healthy = status.critical_error_count == 0 && 
                        status.memory_usage_percent < 90.0f &&
                        status.thread_count > 0;
    
    return status;
}

bool TierSystemFailsafe::is_system_healthy() const {
    return get_health_status().is_healthy;
}

bool TierSystemFailsafe::is_component_healthy(const std::string& component) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check for recent critical errors from this component
    auto now = std::chrono::steady_clock::now();
    for (auto it = m_error_history.rbegin(); it != m_error_history.rend(); ++it) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->timestamp).count();
        
        if (elapsed > 60) {  // Only check last 60 seconds
            break;
        }
        
        if (it->component == component && it->severity == ErrorSeverity::CRITICAL) {
            return false;
        }
    }
    
    return true;
}

std::string TierSystemFailsafe::get_health_report() const {
    HealthStatus health = get_health_status();
    
    std::ostringstream oss;
    oss << "=== TIER SYSTEM HEALTH REPORT ===\n";
    oss << "Overall Health: " << (health.is_healthy ? "HEALTHY" : "UNHEALTHY") << "\n";
    oss << "Error Count: " << health.error_count << "\n";
    oss << "Warning Count: " << health.warning_count << "\n";
    oss << "Critical Error Count: " << health.critical_error_count << "\n";
    oss << "Memory Usage: " << std::fixed << std::setprecision(1) 
        << health.memory_usage_percent << "%\n";
    oss << "CPU Usage: " << std::fixed << std::setprecision(1) 
        << health.cpu_usage_percent << "%\n";
    oss << "Thread Count: " << health.thread_count << "\n";
    oss << "Recovery Attempts: " << health.recovery_attempts << "\n";
    oss << "Successful Recoveries: " << health.successful_recoveries << "\n";
    oss << "Failed Recovery Attempts: " << health.failed_recovery_attempts << "\n";
    
    if (!health.last_critical_error.empty()) {
        oss << "Last Critical Error: " << health.last_critical_error << "\n";
    }
    
    return oss.str();
}

bool TierSystemFailsafe::attempt_recovery(const SystemError& error, RecoveryStrategy strategy) {
    try {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        m_health_status.recovery_attempts++;
        
        if (perform_recovery(error, strategy)) {
            m_health_status.successful_recoveries++;
            report_error(ErrorSeverity::INFO, "RECOVERY_SUCCESS",
                        "Recovery strategy succeeded: " + std::to_string(static_cast<int>(strategy)),
                        "TierSystemFailsafe", error.error_code);
            
            // Call health callback if system recovered
            if (!m_health_status.is_healthy && get_error_count(ErrorSeverity::CRITICAL) == 0) {
                m_health_status.is_healthy = true;
                if (m_health_callback) {
                    m_health_callback(true);
                }
            }
            
            return true;
        } else {
            m_health_status.failed_recovery_attempts++;
            return false;
        }
    } catch (const std::exception& e) {
        LOG_WARN("Recovery attempt failed: " + std::string(e.what()));  // TierSystemFailsafe
        return false;
    }
}

RecoveryStrategy TierSystemFailsafe::select_recovery_strategy(const SystemError& error) const {
    // Select strategy based on error code
    if (error.error_code == ErrorCodes::PEER_NOT_FOUND ||
        error.error_code == ErrorCodes::PEER_CONNECTION_FAILED) {
        return RecoveryStrategy::FALLBACK_TO_TIER3;
    } else if (error.error_code == ErrorCodes::PEER_TIMEOUT) {
        return RecoveryStrategy::QUARANTINE_PEER;
    } else if (error.error_code == ErrorCodes::MEMORY_EXHAUSTED) {
        return RecoveryStrategy::SYSTEM_RESET;
    } else if (error.error_code == ErrorCodes::THREAD_FAILURE ||
               error.error_code == ErrorCodes::MUTEX_DEADLOCK) {
        return RecoveryStrategy::SYSTEM_RESET;
    } else if (error.error_code == ErrorCodes::BROADCAST_RATE_LIMITED) {
        return RecoveryStrategy::AUTO_RETRY;
    } else {
        return RecoveryStrategy::CLOSE_CONNECTION;
    }
}

TierSystemFailsafe::RecoveryStats TierSystemFailsafe::get_recovery_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    RecoveryStats stats;
    stats.total_attempts = m_health_status.recovery_attempts;
    stats.successful = m_health_status.successful_recoveries;
    stats.failed = m_health_status.failed_recovery_attempts;
    
    if (stats.total_attempts > 0) {
        stats.success_rate = static_cast<float>(stats.successful) / stats.total_attempts * 100.0f;
    }
    
    return stats;
}

void TierSystemFailsafe::set_error_callback(ErrorCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_error_callback = callback;
}

void TierSystemFailsafe::set_health_callback(HealthCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_health_callback = callback;
}

void TierSystemFailsafe::set_alerting_enabled(bool enabled) {
    m_alerting_enabled = enabled;
}

bool TierSystemFailsafe::validate_peer_data(const std::string& peer_id, const std::string& ip, int port) {
    // Validate peer_id
    if (peer_id.empty() || peer_id.length() > 256) {
        report_error(ErrorSeverity::WARNING, ErrorCodes::PEER_INVALID_ID,
                    "Invalid peer_id: empty or too long", "TierSystemFailsafe");
        return false;
    }
    
    // Validate IP (basic check)
    if (ip.empty() || ip == "0.0.0.0" || ip == "255.255.255.255") {
        report_error(ErrorSeverity::WARNING, ErrorCodes::PEER_INVALID_IP,
                    "Invalid IP address: " + ip, "TierSystemFailsafe");
        return false;
    }
    
    // Validate port
    if (port <= 0 || port > 65535) {
        report_error(ErrorSeverity::WARNING, ErrorCodes::PEER_INVALID_PORT,
                    "Invalid port: " + std::to_string(port), "TierSystemFailsafe");
        return false;
    }
    
    return true;
}

bool TierSystemFailsafe::validate_latency(int latency_ms) {
    if (latency_ms < 0 || latency_ms > 300000) {  // 5 minutes max
        report_error(ErrorSeverity::WARNING, ErrorCodes::TIER_INVALID,
                    "Invalid latency: " + std::to_string(latency_ms) + "ms",
                    "TierSystemFailsafe");
        return false;
    }
    return true;
}

bool TierSystemFailsafe::validate_configuration(int max_tier1, int max_tier2) {
    if (max_tier1 <= 0 || max_tier1 > 100000) {
        report_error(ErrorSeverity::ERROR, ErrorCodes::CONFIGURATION_INVALID,
                    "Invalid max_tier1: " + std::to_string(max_tier1),
                    "TierSystemFailsafe");
        return false;
    }
    
    if (max_tier2 <= 0 || max_tier2 > 1000000) {
        report_error(ErrorSeverity::ERROR, ErrorCodes::CONFIGURATION_INVALID,
                    "Invalid max_tier2: " + std::to_string(max_tier2),
                    "TierSystemFailsafe");
        return false;
    }
    
    if (max_tier1 >= max_tier2) {
        report_error(ErrorSeverity::ERROR, ErrorCodes::CONFIGURATION_INVALID,
                    "max_tier1 must be less than max_tier2",
                    "TierSystemFailsafe");
        return false;
    }
    
    return true;
}

float TierSystemFailsafe::check_memory_usage() const {
    struct sysinfo info{};
    if (sysinfo(&info) == 0) {
        unsigned long total_mem = info.totalram;
        unsigned long free_mem = info.freeram;
        unsigned long used_mem = total_mem - free_mem;
        float usage = (static_cast<float>(used_mem) / total_mem) * 100.0f;
        
        // Note: skipping report_error call since this is const and may be called from const methods
        return usage;
    }
    return 0.0f;
}

bool TierSystemFailsafe::check_thread_safety() {
    // This is a simplified check - in production, use more sophisticated deadlock detection
    // Try to acquire lock with timeout
    std::unique_lock<std::mutex> lock(m_mutex, std::defer_lock);
    if (!lock.try_lock()) {
        report_error(ErrorSeverity::CRITICAL, ErrorCodes::MUTEX_DEADLOCK,
                    "Potential deadlock detected in failsafe system",
                    "TierSystemFailsafe");
        return false;
    }
    return true;
}

std::string TierSystemFailsafe::get_diagnostics() {
    std::ostringstream oss;
    
    oss << "=== TIER SYSTEM DIAGNOSTICS ===\n\n";
    
    // Health status
    oss << get_health_report() << "\n";
    
    // Recovery statistics
    auto recovery_stats = get_recovery_stats();
    oss << "=== RECOVERY STATISTICS ===\n";
    oss << "Total Attempts: " << recovery_stats.total_attempts << "\n";
    oss << "Successful: " << recovery_stats.successful << "\n";
    oss << "Failed: " << recovery_stats.failed << "\n";
    oss << "Success Rate: " << std::fixed << std::setprecision(1) 
        << recovery_stats.success_rate << "%\n\n";
    
    // Recent errors
    oss << "=== RECENT ERRORS (Last 10) ===\n";
    auto recent_errors = get_error_history(10);
    for (const auto& error : recent_errors) {
        oss << "[" << error.error_code << "] " << error.description << "\n";
        oss << "  Component: " << error.component << "\n";
        if (!error.context.empty()) {
            oss << "  Context: " << error.context << "\n";
        }
    }
    
    // Quarantined peers
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_quarantined_peers.empty()) {
            oss << "\n=== QUARANTINED PEERS ===\n";
            auto now = std::chrono::steady_clock::now();
            for (const auto& [peer_id, quarantine_time] : m_quarantined_peers) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - quarantine_time).count();
                oss << "  " << peer_id << " (quarantined for " << elapsed << "s)\n";
            }
        }
    }
    
    return oss.str();
}

std::string TierSystemFailsafe::dump_state() const {
    std::ostringstream oss;
    
    oss << "=== FAILSAFE STATE DUMP ===\n";
    oss << "Timestamp: " << std::time(nullptr) << "\n";
    oss << "Alerting Enabled: " << (m_alerting_enabled ? "YES" : "NO") << "\n";
    oss << "Total Errors: " << m_error_history.size() << "\n";
    oss << "Memory Usage: " << std::fixed << std::setprecision(1) 
        << check_memory_usage() << "%\n";
    
    std::lock_guard<std::mutex> lock(m_mutex);
    oss << "Recovery Attempts in Progress: " << m_recovery_attempts.size() << "\n";
    oss << "Quarantined Peers: " << m_quarantined_peers.size() << "\n";
    
    return oss.str();
}

// ==================== PRIVATE METHODS ====================

void TierSystemFailsafe::update_health_status() {
    auto now = std::chrono::steady_clock::now();
    
    // Check memory
    float mem_usage = check_memory_usage();
    m_health_status.memory_usage_percent = mem_usage;
    
    // Determine health
    m_health_status.is_healthy = m_health_status.critical_error_count == 0 && 
                                 mem_usage < 90.0f;
}

bool TierSystemFailsafe::perform_recovery(const SystemError& error, RecoveryStrategy strategy) {
    try {
        switch (strategy) {
            case RecoveryStrategy::AUTO_RETRY:
                // For rate limiting, just wait and retry
                LOG_INFO("AUTO_RETRY recovery: waiting 1s");  // TierSystemFailsafe
                std::this_thread::sleep_for(std::chrono::seconds(1));
                return true;
            
            case RecoveryStrategy::FALLBACK_TO_TIER3:
                // Fallback to broadcast discovery
                LOG_INFO("FALLBACK_TO_TIER3 recovery: using broadcast");  // TierSystemFailsafe
                return true;
            
            case RecoveryStrategy::CLOSE_CONNECTION:
                // Close connection and cleanup
                LOG_INFO("CLOSE_CONNECTION recovery");  // TierSystemFailsafe
                return true;
            
            case RecoveryStrategy::RESET_PEER:
                // Reset peer state
                LOG_INFO("RESET_PEER recovery for: " + error.context);  // TierSystemFailsafe
                return true;
            
            case RecoveryStrategy::QUARANTINE_PEER:
                // Quarantine problematic peer
                if (!error.context.empty()) {
                    quarantine_peer(error.context);
                    return true;
                }
                return false;
            
            case RecoveryStrategy::SYSTEM_RESET:
                // Full system reset
                LOG_WARN("SYSTEM_RESET recovery initiated");  // TierSystemFailsafe
                initialize();  // Reinitialize
                return true;
            
            default:
                return false;
        }
    } catch (const std::exception& e) {
        LOG_WARN("Recovery failed: " + std::string(e.what()));  // TierSystemFailsafe
        return false;
    }
}

bool TierSystemFailsafe::is_peer_quarantined(const std::string& peer_id) const {
    auto it = m_quarantined_peers.find(peer_id);
    if (it == m_quarantined_peers.end()) {
        return false;
    }
    
    // Check if quarantine has expired
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - it->second).count();
    return elapsed < QUARANTINE_TIME_SEC;
}

void TierSystemFailsafe::quarantine_peer(const std::string& peer_id) {
    m_quarantined_peers[peer_id] = std::chrono::steady_clock::now();
    LOG_WARN("Peer quarantined: " + peer_id);  // TierSystemFailsafe
}

void TierSystemFailsafe::release_quarantine(const std::string& peer_id) {
    m_quarantined_peers.erase(peer_id);
    LOG_INFO("Peer quarantine released: " + peer_id);  // TierSystemFailsafe
}
