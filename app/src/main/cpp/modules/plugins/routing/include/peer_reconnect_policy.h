#ifndef PEER_RECONNECT_POLICY_H
#define PEER_RECONNECT_POLICY_H

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <random>

/**
 * Peer Reconnect Policy for Weak/High-Latency Networks
 * 
 * Features:
 * - Adaptive exponential backoff (respects battery optimization level)
 * - Network condition detection (latency, packet loss, signal strength)
 * - Battery-aware aggressive reconnect (without draining battery)
 * - Jitter and randomization (prevents thundering herd)
 * - Circuit breaker pattern (prevents hammering dead peers)
 * - Multi-channel failover (TCP → UDP → Relay)
 * - Keepalive with adaptive intervals
 * - Per-peer retry state tracking
 */

enum class NetworkCondition {
    EXCELLENT,      // RTT < 50ms, no packet loss
    GOOD,           // RTT 50-150ms, <1% loss
    FAIR,           // RTT 150-300ms, 1-5% loss
    POOR,           // RTT 300-1000ms, 5-20% loss
    CRITICAL,       // RTT > 1000ms, >20% loss
    OFFLINE         // No connectivity
};

enum class BatteryLevel {
    CRITICAL,       // 0-10%
    LOW,            // 10-20%
    NORMAL,         // 20-80%
    HIGH            // 80-100%
};

// High-level reconnect behavior selection.
//
// AUTO: Derive behavior from network type + battery + charging state.
// AGGRESSIVE: Prioritize fast recovery and reliability (still respects NETWORK_DOWN).
// BALANCED: Reasonable retry pacing for most environments.
// POWER_SAVER: Minimize radio/battery usage (mobile-first).
enum class ReconnectMode {
    AUTO,
    AGGRESSIVE,
    BALANCED,
    POWER_SAVER
};

struct PeerConnectionStats {
    std::string peer_id;
    
    // Connection state
    bool connected;
    bool attempting_reconnect;
    int consecutive_failures;
    int total_failures;
    int successful_connections;
    
    // Timing statistics
    uint64_t last_connection_attempt_ms;      // Monotonic ms (steady clock) of last attempt; 0 = never
    uint64_t last_successful_connection_ms;   // Monotonic ms (steady clock) of last success; 0 = never
    uint32_t average_rtt_ms;
    uint32_t max_rtt_ms;
    uint32_t min_rtt_ms;
    
    // Network quality
    float packet_loss_rate;                    // 0.0 to 1.0
    NetworkCondition current_condition;
    
    // Retry state
    int retry_count_current_cycle;
    int backoff_level;                         // 1, 2, 4, 8, 16...
    uint64_t next_retry_time_ms;               // Monotonic ms (steady clock) when next retry is allowed; 0 = now

    // Circuit breaker: when non-zero and now < circuit_breaker_until_ms, automatic reconnect should not run.
    // This prevents hammering dead peers while still allowing recovery if a peer comes back later.
    uint64_t circuit_breaker_until_ms;         // Monotonic ms (steady clock); 0 = closed
    
    // Connection method
    std::string last_used_method;              // "TCP", "UDP", "Relay"
    bool tcp_available;
    bool udp_available;
    bool relay_available;
};

class PeerReconnectPolicy {
public:
    // Singleton instance
    static PeerReconnectPolicy& getInstance();
    
    /**
     * Initialize reconnect policy
     * @param battery_level: Current battery level (0-100%)
     * @param network_wifi: True if on WiFi, false if on mobile
     */
    void initialize(int battery_level_percent, bool network_wifi);

    // Explicit mode override (optional). If not set, AUTO mode can be driven by config.json.
    void set_reconnect_mode(ReconnectMode mode);
    void set_reconnect_mode_string(const std::string& mode);
    ReconnectMode get_reconnect_mode() const;

    // Suggested reconnect pacing for global schedulers (e.g., DB-first reconnect tick).
    // This is intentionally coarse: per-peer backoff is still applied via get_retry_strategy().
    uint32_t get_reconnect_attempt_interval_ms() const;
    
    /**
     * Start tracking a peer for automatic reconnection
     */
    void track_peer(const std::string& peer_id);
    
    /**
     * Untrack a peer (stop reconnection attempts)
     */
    void untrack_peer(const std::string& peer_id);
    
    /**
     * Connection successful - reset retry counter
     */
    void on_connection_success(const std::string& peer_id,
                              const std::string& method,  // "TCP", "UDP", "Relay"
                              uint32_t rtt_ms);
    
    /**
     * Connection failed - schedule retry with backoff
     */
    void on_connection_failure(const std::string& peer_id,
                              const std::string& attempted_method,
                              float packet_loss_rate = 0.0f);
    
    /**
     * Check if should attempt reconnection now
     * Call periodically from main loop
     */
    bool should_reconnect_now(const std::string& peer_id);
    
    /**
     * Get next peer to reconnect to (prioritized)
     */
    std::string get_next_peer_to_reconnect();
    
    /**
     * Get retry strategy for peer (backoff time, method, etc)
     */
    struct RetryStrategy {
        uint32_t backoff_ms;                    // How long to wait before retry
        std::vector<std::string> methods;      // Try in order: ["TCP", "UDP", "Relay"]
        bool should_retry;
    };
    RetryStrategy get_retry_strategy(const std::string& peer_id);
    
    /**
     * Update battery level (call when battery changes)
     */
    void set_battery_level(int percent, bool is_charging);
    
    /**
     * Update network type (call when network changes)
     */
    void set_network_type(bool is_wifi, bool is_available);
    
    /**
     * Detect network condition from RTT and packet loss
     */
    NetworkCondition detect_network_condition(uint32_t rtt_ms, float packet_loss_rate);
    
    /**
     * Get statistics for a peer
     */
    PeerConnectionStats get_peer_stats(const std::string& peer_id) const;
    
    /**
     * Get all tracked peers
     */
    std::vector<std::string> get_tracked_peers() const;
    
    /**
     * Reset statistics for a peer
     */
    void reset_peer_stats(const std::string& peer_id);
    
    /**
     * Get current network condition
     */
    NetworkCondition get_network_condition() const { return current_network_condition_; }
    
    /**
     * Get current battery level
     */
    BatteryLevel get_battery_level() const { return current_battery_level_; }
    
    /**
     * Estimate battery impact of reconnection attempt
     * Returns estimated battery drain percentage
     */
    float estimate_battery_drain(const std::string& peer_id);
    
    /**
     * Check if reconnection allowed given battery state
     * Returns true if safe to reconnect
     */
    bool is_reconnect_battery_safe(const std::string& peer_id);
    
    /**
     * Get recommended keepalive interval (seconds)
     * Depends on battery level and network type
     */
    uint32_t get_keepalive_interval_seconds() const;
    
    /**
     * Get JSON status for monitoring
     */
    std::string get_status_json() const;
    
    /**
     * Shutdown and cleanup
     */
    void shutdown();

private:
    PeerReconnectPolicy();

    static ReconnectMode parse_reconnect_mode_string_(std::string mode);
    void recompute_effective_mode_flags_locked_();
    
    // Configuration based on battery level
    struct RetryConfig {
        uint32_t initial_backoff_ms;            // 500ms, 1s, 5s, 30s, 60s...
        uint32_t max_backoff_ms;                // Cap on backoff
        int max_retries;                        // Give up after N retries
        bool aggressive_mode;                   // More frequent retries on AC power
        float battery_drain_threshold;          // Don't retry if would exceed this
    };
    
    RetryConfig get_retry_config_for_battery();
    
    // Backoff calculation with jitter
    uint32_t calculate_backoff_with_jitter(int backoff_level);
    
    // Priority scoring for reconnection
    float calculate_peer_priority(const PeerConnectionStats& stats, uint64_t now_ms);
    
    // State
    std::unordered_map<std::string, PeerConnectionStats> peer_stats_;
    mutable std::mutex peers_mutex_;
    
    // Current system state
    BatteryLevel current_battery_level_;
    int battery_percent_;
    bool is_charging_;
    bool is_wifi_;
    bool is_network_available_;
    NetworkCondition current_network_condition_;
    uint32_t last_network_update_ms_;
    
    // Configuration
    bool use_aggressive_reconnect_;            // WiFi + AC power = aggressive
    bool use_battery_aware_mode_;              // Mobile data + battery = conservative

    // Mode selection
    ReconnectMode reconnect_mode_ = ReconnectMode::AUTO;
    bool reconnect_mode_overridden_ = false;

    std::mt19937 random_engine_;
};

#endif // PEER_RECONNECT_POLICY_H
