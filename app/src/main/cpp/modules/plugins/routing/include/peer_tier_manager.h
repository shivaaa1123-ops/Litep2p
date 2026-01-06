#ifndef PEER_TIER_MANAGER_H
#define PEER_TIER_MANAGER_H

#include "peer.h"
#include "peer_tier.h"
#include <unordered_map>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <memory>
#include <deque>
#include <climits>
#include <atomic>

/**
 * DYNAMIC TIER LATENCY SYSTEM
 * 
 * Core component for intelligent peer connection management
 * Automatically classifies peers into tiers based on latency,
 * discovers new peers via broadcast, and cleans up idle connections.
 * 
 * Tier 1 (HOT):   <100ms, 1,000 max, always kept
 * Tier 2 (WARM):  100-300ms, 5,000 max, kept while active
 * Tier 3 (COLD):  >300ms or unknown, broadcast-only, zero memory
 */

/**
 * Latency statistics for a peer
 * Maintains rolling window of recent measurements
 */
struct LatencyStats {
    static constexpr int HISTORY_SIZE = 20;  // Keep 20 samples
    
    std::deque<int> history_ms;      // Last 20 latency measurements
    int min_latency_ms = INT_MAX;
    int max_latency_ms = 0;
    int sum_latency_ms = 0;          // Sum for quick average calculation
    
    /**
     * Record a new latency measurement
     * @param latency_ms Latency in milliseconds
     */
    void record(int latency_ms) {
        if (latency_ms < 0) return;  // Invalid measurement
        
        history_ms.push_back(latency_ms);
        if (history_ms.size() > HISTORY_SIZE) {
            int old = history_ms.front();
            history_ms.pop_front();
            sum_latency_ms -= old;
        }
        
        sum_latency_ms += latency_ms;
        min_latency_ms = std::min(min_latency_ms, latency_ms);
        max_latency_ms = std::max(max_latency_ms, latency_ms);
    }
    
    /**
     * Get average latency from history
     * @return Average latency in ms, or -1 if no measurements
     */
    int get_average() const {
        if (history_ms.empty()) return -1;
        return sum_latency_ms / history_ms.size();
    }
    
    /**
     * Get median latency from history
     * @return Median latency in ms, or -1 if no measurements
     */
    int get_median() const;
    
    /**
     * Check if latency is stable (variance < threshold)
     * @return true if measurements are stable, false if erratic
     */
    bool is_stable() const;
    
    /**
     * Get number of measurements
     */
    int count() const { return history_ms.size(); }
};

/**
 * Peer metadata for tier management
 */
struct ManagedPeer {
    std::string peer_id;
    std::string ip;
    int port;
    
    PeerTier current_tier = PeerTier::TIER_UNKNOWN;
    PeerTier recommended_tier = PeerTier::TIER_UNKNOWN;
    
    LatencyStats latency_stats;
    
    // Activity tracking
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point last_tier_change;
    int activity_count = 0;           // Message count from this peer
    
    // Connection state
    bool is_connected = false;
    bool has_session_key = false;
    std::vector<uint8_t> session_key;
    
    // Flags
    bool is_bootstrap = false;        // Special bootstrap peer
    bool is_relay_node = false;       // Acts as relay for others
    bool promotion_pending = false;   // Candidate for promotion to T1
    
    // Constructor
    ManagedPeer(const std::string& id, const std::string& ip_addr, int port_num)
        : peer_id(id), ip(ip_addr), port(port_num),
          created_at(std::chrono::steady_clock::now()),
          last_activity(std::chrono::steady_clock::now()) {}
};

/**
 * Configuration for PeerTierManager
 */
struct PeerTierConfig {
    // Tier limits
    int max_tier1_peers = 1000;
    int max_tier2_peers = 5000;
    
    // Latency thresholds (milliseconds)
    int tier1_threshold_ms = 100;
    int tier2_threshold_ms = 300;
    int tier_change_hysteresis_ms = 20;  // Prevent flapping
    
    // Cleanup settings
    int tier2_idle_timeout_sec = 300;       // 5 minutes
    int tier2_cleanup_interval_sec = 10;    // Check every 10 sec
    int dedup_cache_timeout_sec = 3600;     // 1 hour
    
    // Discovery settings
    int broadcast_ttl_max_hops = 5;
    int broadcast_dedup_size = 10000;       // Max requests to track
    int max_broadcasts_per_peer_min = 100;  // Rate limit
    
    // Activity thresholds for promotion
    int activity_threshold_for_promotion = 10;  // >10 messages
    float activity_rate_threshold = 0.5;        // >0.5 msg/sec
    
    // Safety limits
    int max_latency_spike_threshold_ms = 1000;  // Alert if spike > 1s
    bool enable_safety_checks = true;
    bool enable_auto_cleanup = true;
    bool enable_auto_promotion = true;
};

/**
 * Metrics for monitoring
 */
struct PeerTierMetrics {
    // Tier distribution
    int tier1_count = 0;
    int tier2_count = 0;
    int tier3_count = 0;
    
    // Activity
    int total_discoveries = 0;
    int total_promotions = 0;
    int total_demotions = 0;
    int total_cleanups = 0;
    
    // Broadcast tracking
    int broadcasts_sent = 0;
    int broadcasts_relayed = 0;
    int broadcasts_dropped_dedup = 0;
    float dedup_ratio = 0.0f;
    
    // Latency tracking
    int avg_tier1_latency_ms = 0;
    int avg_tier2_latency_ms = 0;
    int latency_spikes_detected = 0;
    
    // Health
    bool is_healthy = true;
    std::string last_error;
};

/**
 * PEER TIER MANAGER - Core Component
 * 
 * Manages peer tiers, latency tracking, discovery, and cleanup
 * Thread-safe, failproof, with comprehensive error handling
 */
class PeerTierManager {
public:
    explicit PeerTierManager(const PeerTierConfig& config = PeerTierConfig());
    ~PeerTierManager();
    
    // ==================== INITIALIZATION & LIFECYCLE ====================
    
    /**
     * Initialize the manager and start background threads
     * @return true on success, false on failure
     */
    bool initialize();
    
    /**
     * Shutdown and cleanup all resources
     */
    void shutdown();
    
    /**
     * Check if manager is running
     */
    bool is_running() const;
    
    // ==================== PEER MANAGEMENT ====================
    
    /**
     * Add a new peer to the system
     * @param peer_id Unique peer identifier
     * @param ip IP address
     * @param port Port number
     * @return true on success
     */
    bool add_peer(const std::string& peer_id, const std::string& ip, int port);
    
    /**
     * Get peer by ID
     * @param peer_id Peer identifier
     * @return Pointer to ManagedPeer, or nullptr if not found
     */
    ManagedPeer* get_peer(const std::string& peer_id);
    const ManagedPeer* get_peer_const(const std::string& peer_id) const;
    
    /**
     * Remove peer from system
     * @param peer_id Peer identifier
     * @return true if removed, false if not found
     */
    bool remove_peer(const std::string& peer_id);
    
    /**
     * Check if peer exists
     */
    bool peer_exists(const std::string& peer_id) const;
    
    /**
     * Get peer count by tier
     */
    int get_tier_count(PeerTier tier) const;
    
    /**
     * Get all peers in a tier (snapshot)
     */
    std::vector<ManagedPeer> get_peers_by_tier(PeerTier tier) const;
    
    // ==================== LATENCY TRACKING ====================
    
    /**
     * Record a latency measurement for a peer
     * @param peer_id Peer identifier
     * @param latency_ms Latency in milliseconds
     * @return true on success
     */
    bool record_latency(const std::string& peer_id, int latency_ms);
    
    /**
     * Get latency for a peer
     * @param peer_id Peer identifier
     * @return Average latency in ms, or -1 if unknown
     */
    int get_latency(const std::string& peer_id) const;
    
    /**
     * Get latency statistics for a peer
     * @param peer_id Peer identifier
     * @return LatencyStats, or empty if peer not found
     */
    LatencyStats get_latency_stats(const std::string& peer_id) const;
    
    // ==================== TIER MANAGEMENT ====================
    
    /**
     * Classify a peer based on current latency
     * Automatically moves between tiers
     * @param peer_id Peer identifier
     * @return Recommended tier
     */
    PeerTier classify_peer(const std::string& peer_id);
    
    /**
     * Get current tier for a peer
     * @param peer_id Peer identifier
     * @return Current tier
     */
    PeerTier get_peer_tier(const std::string& peer_id) const;
    
    /**
     * Manually set peer tier (with validation)
     * @param peer_id Peer identifier
     * @param tier Target tier
     * @return true on success, false if invalid (e.g., T1 full)
     */
    bool set_peer_tier(const std::string& peer_id, PeerTier tier);
    
    /**
     * Record activity from a peer (increments activity count)
     * May trigger automatic promotion
     * @param peer_id Peer identifier
     * @return true on success
     */
    bool record_activity(const std::string& peer_id);
    
    /**
     * Check if peer should be promoted to higher tier
     * @param peer_id Peer identifier
     * @return true if promotion conditions met
     */
    bool should_promote(const std::string& peer_id) const;
    
    /**
     * Check if peer should be demoted to lower tier
     * @param peer_id Peer identifier
     * @return true if demotion conditions met
     */
    bool should_demote(const std::string& peer_id) const;
    
    // ==================== DISCOVERY & BROADCAST ====================
    
    /**
     * Initiate peer discovery via broadcast
     * @param target_peer_id Peer to find
     * @param request_id Unique request identifier
     * @return true on success
     */
    bool initiate_discovery(const std::string& target_peer_id, const std::string& request_id);
    
    /**
     * Process incoming broadcast message
     * @param request_id Unique request identifier
     * @param source_peer_id Who sent this broadcast
     * @param message Broadcast message data
     * @return true if should relay, false if duplicate/invalid
     */
    bool process_broadcast(const std::string& request_id, const std::string& source_peer_id, 
                          const std::string& message);
    
    /**
     * Check if broadcast should be relayed (deduplication)
     * @param request_id Unique request identifier
     * @return true if not seen before (should relay), false if duplicate
     */
    bool should_relay_broadcast(const std::string& request_id);
    
    /**
     * Get broadcast statistics
     */
    struct BroadcastStats {
        int total_broadcasts = 0;
        int successful_discoveries = 0;
        int failed_discoveries = 0;
        int broadcasts_queued = 0;
    };
    BroadcastStats get_broadcast_stats() const;
    
    // ==================== IDLE CLEANUP & LIFECYCLE ====================
    
    /**
     * Mark peer as active (updates last_activity)
     * @param peer_id Peer identifier
     * @return true on success
     */
    bool mark_active(const std::string& peer_id);
    
    /**
     * Check if peer is idle
     * @param peer_id Peer identifier
     * @param timeout_sec Idle timeout in seconds
     * @return true if idle longer than timeout
     */
    bool is_idle(const std::string& peer_id, int timeout_sec) const;
    
    /**
     * Get idle time for a peer
     * @param peer_id Peer identifier
     * @return Idle time in seconds, or -1 if peer not found
     */
    int get_idle_time(const std::string& peer_id) const;
    
    /**
     * Perform cleanup of idle Tier 2 peers
     * Called periodically by background thread
     * @return Number of peers cleaned up
     */
    int cleanup_idle_tier2();
    
    /**
     * Force cleanup of a specific peer
     * @param peer_id Peer identifier
     * @return true on success
     */
    bool force_cleanup_peer(const std::string& peer_id);
    
    // ==================== MONITORING & METRICS ====================
    
    /**
     * Get comprehensive metrics snapshot
     */
    PeerTierMetrics get_metrics() const;
    
    /**
     * Get health status
     * @return true if system is healthy
     */
    bool is_healthy() const;
    
    /**
     * Get last error message
     */
    std::string get_last_error() const;
    
    /**
     * Reset metrics (for testing)
     */
    void reset_metrics();
    
    // ==================== CONFIGURATION ====================
    
    /**
     * Update configuration
     * @param config New configuration
     * @return true on success
     */
    bool update_config(const PeerTierConfig& config);
    
    /**
     * Get current configuration
     */
    PeerTierConfig get_config() const;
    
    // ==================== DEBUGGING & LOGGING ====================
    
    /**
     * Get detailed status for all peers (JSON format)
     */
    std::string get_status_json() const;
    
    /**
     * Get detailed status for specific peer
     */
    std::string get_peer_status_json(const std::string& peer_id) const;

private:
    // ==================== PRIVATE MEMBERS ====================
    
    mutable std::mutex m_mutex;
    
    // Configuration
    PeerTierConfig m_config;
    
    // Peer storage
    std::unordered_map<std::string, std::unique_ptr<ManagedPeer>> m_peers;
    std::unordered_map<int, std::vector<std::string>> m_tier_map;  // tier -> peer_ids
    
    // Broadcast deduplication
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_seen_broadcasts;
    std::unordered_map<std::string, int> m_peer_broadcast_count;  // Rate limiting
    
    // Lifecycle
    std::atomic<bool> m_running{false};
    std::thread m_cleanup_thread;
    std::thread m_promotion_thread;
    std::chrono::steady_clock::time_point m_last_cleanup;
    
    // Thread synchronization for shutdown
    std::mutex m_thread_mutex;
    std::condition_variable m_thread_cv;
    
    // Metrics
    PeerTierMetrics m_metrics;
    std::string m_last_error;
    
    // ==================== PRIVATE METHODS ====================
    
    /**
     * Background thread: cleanup idle Tier 2 peers
     */
    void cleanup_loop();
    
    /**
     * Background thread: promote deserving peers
     */
    void promotion_loop();
    
    /**
     * Internal classification logic
     */
    PeerTier classify_by_latency(int avg_latency_ms) const;
    
    /**
     * Check if tier has capacity for new peer
     */
    bool tier_has_capacity(PeerTier tier) const;
    
    /**
     * Find best peer to evict from tier (LRU)
     */
    std::string find_lru_peer_in_tier(PeerTier tier) const;

    // ==================== LOCKED INTERNAL HELPERS ====================
    // These helpers MUST only be called while holding m_mutex.
    ManagedPeer* get_peer_locked(const std::string& peer_id);
    const ManagedPeer* get_peer_locked(const std::string& peer_id) const;
    bool tier_has_capacity_locked(PeerTier tier) const;
    std::string find_lru_peer_in_tier_locked(PeerTier tier) const;
    bool move_peer_to_tier_locked(const std::string& peer_id, PeerTier new_tier);
    bool should_promote_locked(const std::string& peer_id) const;
    int cleanup_idle_tier2_locked();
    
    /**
     * Safely move peer to new tier
     */
    bool move_peer_to_tier(const std::string& peer_id, PeerTier new_tier);
    
    /**
     * Cleanup broadcast deduplication cache
     */
    void cleanup_broadcast_cache();
    
    /**
     * Validate input parameters
     */
    bool validate_peer_id(const std::string& peer_id) const;
    bool validate_ip(const std::string& ip) const;
    bool validate_port(int port) const;
};

#endif // PEER_TIER_MANAGER_H
