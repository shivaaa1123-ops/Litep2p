#ifndef TIER_SYSTEM_FAILSAFE_H
#define TIER_SYSTEM_FAILSAFE_H

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <memory>
#include <unordered_map>

/**
 * FAILSAFE & ERROR HANDLING SYSTEM
 * 
 * Comprehensive error detection, recovery, and monitoring
 * Ensures the tier system remains robust under all conditions
 */

enum class ErrorSeverity {
    INFO,       // Informational, not a problem
    WARNING,    // Potential issue, should monitor
    ERROR,      // Operational problem, needs attention
    CRITICAL    // System failure, immediate action required
};

struct SystemError {
    ErrorSeverity severity;
    std::string error_code;
    std::string description;
    std::string component;      // Which component (TierManager, BroadcastDiscovery, etc)
    std::chrono::steady_clock::time_point timestamp;
    std::string context;        // Additional context (peer_id, etc)
    
    SystemError(ErrorSeverity sev, const std::string& code, const std::string& desc,
               const std::string& comp, const std::string& ctx = "")
        : severity(sev), error_code(code), description(desc), component(comp),
          timestamp(std::chrono::steady_clock::now()), context(ctx) {}
};

/**
 * Health monitoring system
 */
struct HealthStatus {
    bool is_healthy = true;
    int error_count = 0;
    int warning_count = 0;
    int critical_error_count = 0;
    
    std::chrono::steady_clock::time_point last_error_time;
    std::string last_critical_error;
    
    float memory_usage_percent = 0.0f;
    float cpu_usage_percent = 0.0f;
    int thread_count = 0;
    
    // Recovery metrics
    int recovery_attempts = 0;
    int successful_recoveries = 0;
    int failed_recovery_attempts = 0;
};

/**
 * Recovery strategy
 */
enum class RecoveryStrategy {
    AUTO_RETRY,              // Automatically retry operation
    FALLBACK_TO_TIER3,      // Drop to Tier 3 (discovery)
    CLOSE_CONNECTION,        // Close and cleanup connection
    RESET_PEER,             // Reset peer state completely
    QUARANTINE_PEER,        // Stop trying this peer temporarily
    SYSTEM_RESET            // Full system restart
};

/**
 * FAILSAFE MANAGER
 * 
 * Monitors system health, detects errors, and triggers recoveries
 */
class TierSystemFailsafe {
public:
    explicit TierSystemFailsafe();
    ~TierSystemFailsafe();
    
    // ==================== INITIALIZATION ====================
    
    /**
     * Initialize failsafe system
     * @return true on success
     */
    bool initialize();
    
    /**
     * Shutdown failsafe system
     */
    void shutdown();
    
    // ==================== ERROR REPORTING ====================
    
    /**
     * Report an error
     * @param error System error to report
     * @return true if error was recorded
     */
    bool report_error(const SystemError& error);
    
    /**
     * Report error with convenience function
     */
    bool report_error(ErrorSeverity severity, const std::string& code,
                     const std::string& description, const std::string& component,
                     const std::string& context = "");
    
    /**
     * Get last error
     */
    SystemError* get_last_error();
    
    /**
     * Get error history (last N errors)
     */
    std::vector<SystemError> get_error_history(int count = 100) const;
    
    /**
     * Get error count by severity
     */
    int get_error_count(ErrorSeverity severity) const;
    
    // ==================== HEALTH MONITORING ====================
    
    /**
     * Get current health status
     */
    HealthStatus get_health_status() const;
    
    /**
     * Is system healthy?
     */
    bool is_system_healthy() const;
    
    /**
     * Check specific component health
     */
    bool is_component_healthy(const std::string& component) const;
    
    /**
     * Get detailed health report
     */
    std::string get_health_report() const;
    
    // ==================== RECOVERY ====================
    
    /**
     * Attempt recovery from error
     * @param error Error to recover from
     * @param strategy Recovery strategy to use
     * @return true if recovery successful
     */
    bool attempt_recovery(const SystemError& error, RecoveryStrategy strategy);
    
    /**
     * Auto-select recovery strategy based on error
     */
    RecoveryStrategy select_recovery_strategy(const SystemError& error) const;
    
    /**
     * Get recovery statistics
     */
    struct RecoveryStats {
        int total_attempts = 0;
        int successful = 0;
        int failed = 0;
        float success_rate = 0.0f;
    };
    RecoveryStats get_recovery_stats() const;
    
    // ==================== MONITORING & ALERTING ====================
    
    /**
     * Register error callback
     * Called when critical error occurs
     */
    using ErrorCallback = std::function<void(const SystemError&)>;
    void set_error_callback(ErrorCallback callback);
    
    /**
     * Register health change callback
     */
    using HealthCallback = std::function<void(bool is_healthy)>;
    void set_health_callback(HealthCallback callback);
    
    /**
     * Enable/disable alerting
     */
    void set_alerting_enabled(bool enabled);
    
    // ==================== VALIDATION & CHECKING ====================
    
    /**
     * Validate peer data
     */
    bool validate_peer_data(const std::string& peer_id, const std::string& ip, int port);
    
    /**
     * Validate latency value
     */
    bool validate_latency(int latency_ms);
    
    /**
     * Validate tier configuration
     */
    bool validate_configuration(int max_tier1, int max_tier2);
    
    /**
     * Check memory usage
     * @return percentage of available memory used
     */
    float check_memory_usage() const;
    
    /**
     * Check thread safety
     * @return true if no deadlocks detected
     */
    bool check_thread_safety();
    
    // ==================== DEBUGGING ====================
    
    /**
     * Get detailed diagnostics
     */
    std::string get_diagnostics();
    
    /**
     * Dump current state for debugging
     */
    std::string dump_state() const;

private:
    // ==================== PRIVATE MEMBERS ====================
    
    mutable std::mutex m_mutex;
    
    std::vector<SystemError> m_error_history;
    static constexpr int MAX_ERROR_HISTORY = 1000;
    
    HealthStatus m_health_status;
    std::atomic<bool> m_alerting_enabled{true};
    
    ErrorCallback m_error_callback;
    HealthCallback m_health_callback;
    
    std::chrono::steady_clock::time_point m_last_health_check;
    
    // Recovery tracking
    std::unordered_map<std::string, int> m_recovery_attempts;  // peer_id -> attempts
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_quarantined_peers;
    static constexpr int MAX_RECOVERY_ATTEMPTS = 5;
    static constexpr int QUARANTINE_TIME_SEC = 300;  // 5 minutes
    
    // ==================== PRIVATE METHODS ====================
    
    /**
     * Update health status based on errors
     */
    void update_health_status();
    
    /**
     * Perform recovery operation
     */
    bool perform_recovery(const SystemError& error, RecoveryStrategy strategy);
    
    /**
     * Check if peer is quarantined
     */
    bool is_peer_quarantined(const std::string& peer_id) const;
    
    /**
     * Quarantine a peer
     */
    void quarantine_peer(const std::string& peer_id);
    
    /**
     * Release quarantined peer
     */
    void release_quarantine(const std::string& peer_id);
};

/**
 * ERROR CODES
 * 
 * Standardized error codes for consistent error handling
 */
namespace ErrorCodes {
    // Peer-related
    const std::string PEER_NOT_FOUND = "PEER_001";
    const std::string PEER_INVALID_ID = "PEER_002";
    const std::string PEER_INVALID_IP = "PEER_003";
    const std::string PEER_INVALID_PORT = "PEER_004";
    const std::string PEER_CONNECTION_FAILED = "PEER_005";
    const std::string PEER_TIMEOUT = "PEER_006";
    
    // Tier-related
    const std::string TIER_FULL = "TIER_001";
    const std::string TIER_INVALID = "TIER_002";
    const std::string TIER_CHANGE_FAILED = "TIER_003";
    
    // Broadcast-related
    const std::string BROADCAST_RATE_LIMITED = "BCAST_001";
    const std::string BROADCAST_INVALID_MESSAGE = "BCAST_002";
    const std::string BROADCAST_DEDUP_FAIL = "BCAST_003";
    const std::string DISCOVERY_TIMEOUT = "BCAST_004";
    
    // System-related
    const std::string MEMORY_EXHAUSTED = "SYS_001";
    const std::string THREAD_FAILURE = "SYS_002";
    const std::string MUTEX_DEADLOCK = "SYS_003";
    const std::string CONFIGURATION_INVALID = "SYS_004";
    const std::string INITIALIZATION_FAILED = "SYS_005";
    
    // Network-related
    const std::string NETWORK_UNREACHABLE = "NET_001";
    const std::string NETWORK_TIMEOUT = "NET_002";
    const std::string SOCKET_ERROR = "NET_003";
}

/**
 * Assert with error reporting
 */
#define ASSERT_WITH_ERROR(condition, severity, code, description, component) \
    do { \
        if (!(condition)) { \
            SystemError err(severity, code, description, component); \
            /* Report error */ \
        } \
    } while(0)

/**
 * Safe pointer dereference
 */
#define SAFE_DEREF(ptr, default_value) \
    ((ptr) != nullptr ? *(ptr) : (default_value))

/**
 * Safe lock with timeout
 */
#define SAFE_LOCK(mutex, timeout_ms) \
    std::unique_lock<std::mutex> lock(mutex, std::defer_lock); \
    if (!lock.try_lock_for(std::chrono::milliseconds(timeout_ms))) { \
        /* Handle timeout */ \
    }

#endif // TIER_SYSTEM_FAILSAFE_H
