#ifndef BROADCAST_DISCOVERY_MANAGER_H
#define BROADCAST_DISCOVERY_MANAGER_H

#include <string>
#include <functional>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <thread>
#include <memory>
#include <chrono>
#include <vector>
#include <atomic>

/**
 * BROADCAST DISCOVERY MANAGER
 * 
 * Handles peer discovery via controlled broadcasting.
 * Features:
 * - TTL-based propagation limiting
 * - Request deduplication (prevent relay loops)
 * - Rate limiting (prevent DoS)
 * - Automatic response handling
 * - Latency measurement
 */

/**
 * Broadcast message structure
 */
struct BroadcastMessage {
    std::string request_id;          // Unique request identifier (UUID)
    std::string source_peer_id;      // Original sender
    std::string target_peer_id;      // Who we're looking for
    int ttl;                         // Time-to-live (hops remaining)
    int hop_count;                   // Total hops taken (from source)
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point sent_at;
    
    // For validation
    std::vector<uint8_t> signature;  // Signature to prevent tampering
    bool is_valid = true;
};

/**
 * Discovery response
 */
struct DiscoveryResponse {
    std::string request_id;
    std::string source_peer_id; // Added
    std::string responder_peer_id;   // Who responded
    std::string responder_ip;
    int responder_port;
    int hop_count;                   // How many hops the response took
    std::chrono::steady_clock::time_point received_at;
    int latency_ms; // Added for direct assignment
    
    /**
     * Calculate latency from discovery broadcast to response
     */
    int calculate_latency_ms() const { // Renamed from get_latency_ms
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            received_at - created_at
        );
        return elapsed.count();
    }
    
    std::chrono::steady_clock::time_point created_at;  // When broadcast was created
};

/**
 * Configuration for broadcast discovery
 */
struct BroadcastDiscoveryConfig {
    // TTL and propagation
    int default_ttl = 5;                    // Max hops
    int relay_delay_ms = 10;                // Delay before relaying (stagger)
    
    // Deduplication and caching
    int dedup_cache_size = 10000;
    int dedup_timeout_sec = 3600;           // 1 hour
    
    // Rate limiting
    int max_broadcasts_per_peer_per_min = 100;
    int max_broadcasts_per_min_network = 10000;
    
    // Response handling
    int discovery_timeout_sec = 30;         // Wait up to 30 seconds for response
    int max_pending_discoveries = 1000;
    
    // Safety
    bool enable_signature_validation = true;
    bool enable_rate_limiting = true;
    bool enable_deduplication = true;
    int max_message_size = 4096;            // Max broadcast message size
};

/**
 * Pending discovery request
 */
struct PendingDiscovery {
    std::string request_id;
    std::string target_peer_id;
    std::chrono::steady_clock::time_point created_at;
    std::vector<DiscoveryResponse> responses;  // All responses received
    bool is_satisfied = false;  // Got at least one response
    using OnDiscoveryCompleteCallback = std::function<void(const DiscoveryResponse&)>; // Defined as a type within the struct.
    OnDiscoveryCompleteCallback on_complete_callback; // Added member
};

/**
 * BROADCAST DISCOVERY MANAGER
 * 
 * Manages discovery requests, broadcast propagation, and responses
 * Thread-safe, with comprehensive error handling
 */
class BroadcastDiscoveryManager {
public:
    // Callbacks
    using OnDiscoveryComplete = std::function<void(const DiscoveryResponse&)>;
    using OnBroadcastReceived = std::function<void(const BroadcastMessage&)>;
    using OnRelayNeeded = std::function<void(const BroadcastMessage&)>;
    
    explicit BroadcastDiscoveryManager(const BroadcastDiscoveryConfig& config = BroadcastDiscoveryConfig());
    ~BroadcastDiscoveryManager();
    
    // ==================== INITIALIZATION ====================
    
    /**
     * Initialize manager
     * @return true on success
     */
    bool initialize();
    
    /**
     * Shutdown manager
     */
    void shutdown();
    
    /**
     * Check if running
     */
    bool is_running() const;
    
    // ==================== DISCOVERY REQUESTS ====================
    
    /**
     * Initiate a discovery request for a peer
     * @param target_peer_id Peer to find
     * @param on_complete Callback when peer is found
     * @return request_id or empty string on failure
     */
    std::string discover_peer(const std::string& target_peer_id,
                             OnDiscoveryComplete on_complete = nullptr);
    
    /**
     * Cancel a pending discovery request
     * @param request_id Request to cancel
     * @return true on success
     */
    bool cancel_discovery(const std::string& request_id);
    
    /**
     * Get pending discovery by ID
     * @param request_id Request identifier
     * @return Discovery info, or nullptr if not found/completed
     */
    std::shared_ptr<PendingDiscovery> get_pending_discovery(const std::string& request_id);
    
    /**
     * Get all pending discoveries (snapshot)
     */
    std::vector<std::shared_ptr<PendingDiscovery>> get_all_pending_discoveries() const;
    
    /**
     * Get count of pending discoveries
     */
    int get_pending_discovery_count() const;
    
    // ==================== BROADCAST HANDLING ====================
    
    /**
     * Process incoming broadcast message
     * Called when we receive a broadcast from network
     * @param message Broadcast message
     * @return true if valid and should be relayed, false if duplicate/invalid
     */
    bool process_broadcast_message(const BroadcastMessage& message);
    
    /**
     * Register broadcast received callback
     * Called when we receive a broadcast (for listener to act on it)
     */
    void set_broadcast_received_callback(OnBroadcastReceived callback);
    
    /**
     * Register relay needed callback
     * Called when we should relay message to our neighbors
     */
    void set_relay_needed_callback(OnRelayNeeded callback);
    
    /**
     * Check if we should relay a broadcast (handles dedup + rate limiting)
     * @param message Message to check
     * @return true if should relay, false if duplicate or rate limited
     */
    bool should_relay_broadcast(const BroadcastMessage& message);
    
    /**
     * Create a new broadcast message (for sending)
     * @param target_peer_id Who to find
     * @param source_peer_id Our peer ID (source)
     * @param initial_ttl Time-to-live for the broadcast
     * @param signature Digital signature for validation
     * @return Broadcast message ready to send
     */
    BroadcastMessage create_broadcast_message(const std::string& target_peer_id,
                                             const std::string& source_peer_id,
                                             int initial_ttl,
                                             const std::vector<uint8_t>& signature); // Updated to match cpp definition and use vector<uint8_t>
    
    // ==================== RESPONSE HANDLING ====================
    
    /**
     * Process discovery response from a peer
     * Called when we receive a response to our broadcast
     * @param response Discovery response
     * @return true on success
     */
    bool process_discovery_response(const DiscoveryResponse& response);
    
    /**
     * Create discovery response (for responding to broadcast)
     * @param request_id Original request we're responding to
     * @param responder_peer_id Our peer ID
     * @param responder_ip Our IP address
     * @param responder_port Our port
     * @return Response message
     */
    DiscoveryResponse create_discovery_response(const std::string& request_id,
                                               const std::string& responder_peer_id,
                                               const std::string& responder_ip,
                                               int responder_port);
    
    // ==================== DEDUPLICATION & CACHING ====================
    
    /**
     * Check if broadcast is a duplicate
     * @param request_id Request identifier
     * @return true if we've seen this before
     */
    bool is_broadcast_duplicate(const std::string& request_id) const;
    
    /**
     * Mark broadcast as seen (for deduplication)
     * @param request_id Request identifier
     */
    void mark_broadcast_seen(const std::string& request_id);
    
    /**
     * Get deduplication cache stats
     */
    struct DedupStats {
        int cache_size = 0;
        int total_deduplicated = 0;
        int cache_hits = 0;
        float hit_ratio = 0.0f;
    };
    DedupStats get_dedup_stats() const;
    
    // ==================== RATE LIMITING ====================
    
    /**
     * Check if peer is rate limited
     * @param peer_id Peer to check
     * @return true if peer exceeded broadcast limit
     */
    bool is_peer_rate_limited(const std::string& peer_id) const;
    
    /**
     * Record broadcast from peer (for rate limiting)
     * @param peer_id Source peer
     * @return true if within limits, false if rate limited
     */
    bool record_peer_broadcast(const std::string& peer_id);
    
    /**
     * Get rate limiting stats
     */
    struct RateLimitStats {
        int peers_rate_limited = 0;
        int broadcasts_dropped = 0;
        int total_broadcasts = 0;
    };
    RateLimitStats get_rate_limit_stats() const;
    
    // ==================== STATISTICS & MONITORING ====================
    
    /**
     * Get comprehensive statistics
     */
    struct BroadcastStats {
        int total_broadcasts_sent = 0;
        int total_broadcasts_received = 0;
        int total_broadcasts_relayed = 0;
        int successful_discoveries = 0;
        int failed_discoveries = 0;
        int avg_discovery_latency_ms = 0;
        int max_discovery_latency_ms = 0;
        int pending_discoveries = 0;
    };
    BroadcastStats get_statistics() const;
    
    /**
     * Reset statistics (for testing)
     */
    void reset_statistics();
    
    // ==================== VALIDATION & SAFETY ====================
    
    /**
     * Validate broadcast message
     * @param message Message to validate
     * @return Error message if invalid, empty string if valid
     */
    std::string validate_broadcast_message(const BroadcastMessage& message) const;
    
    /**
     * Validate discovery response
     * @param response Response to validate
     * @return Error message if invalid, empty string if valid
     */
    std::string validate_discovery_response(const DiscoveryResponse& response) const;
    
    /**
     * Check system health
     * @return true if all systems operational
     */
    bool is_healthy() const;
    
    /**
     * Get last error message
     */
    std::string get_last_error() const;
    
    // ==================== CONFIGURATION ====================
    
    /**
     * Update configuration
     * @param config New configuration
     * @return true on success
     */
    bool update_config(const BroadcastDiscoveryConfig& config);
    
    /**
     * Get current configuration
     */
    BroadcastDiscoveryConfig get_config() const;
    
    // ==================== DEBUGGING ====================
    
    /**
     * Get detailed status as JSON
     */
    std::string get_status_json() const;
    
    /**
     * Dump all pending discoveries (for debugging)
     */
    std::string dump_pending_discoveries() const;

private:
    // ==================== PRIVATE MEMBERS ====================
    
    mutable std::mutex m_mutex;
    BroadcastDiscoveryConfig m_config;
    
    // Pending discoveries
    std::unordered_map<std::string, std::shared_ptr<PendingDiscovery>> m_pending_discoveries;
    
    // Broadcast deduplication
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_seen_broadcasts;
    
    // Rate limiting (mutable to allow updates in const methods)
    mutable std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> m_peer_broadcast_times;
    
    // Callbacks
    OnBroadcastReceived m_on_broadcast_callback;
    OnRelayNeeded m_on_relay_callback;
    
    // Lifecycle
    std::atomic<bool> m_running{false};
    std::thread m_cleanup_thread;
    std::thread m_response_timeout_thread;
    
    // Statistics tracking
    struct InternalStats {
        int broadcasts_sent = 0;
        int broadcasts_received = 0;
        int broadcasts_relayed = 0;
        int broadcasts_dropped_dedup = 0;
        int broadcasts_dropped_rate_limit = 0;
        int successful_discoveries = 0;
        int failed_discoveries = 0;
        int total_discovery_latency_ms = 0;
        int discovery_count = 0;
    } m_stats;
    
    std::string m_last_error;
    
    // ==================== PRIVATE METHODS ====================
    
    /**
     * Background thread: cleanup old deduplication entries
     */
    void cleanup_loop();
    
    /**
     * Background thread: timeout pending discoveries
     */
    void response_timeout_loop();
    
    /**
     * Generate unique request ID
     */
    std::string generate_request_id();
    
    /**
     * Check if peer broadcast is within rate limits
     */
    bool check_rate_limit(const std::string& peer_id);
    
    /**
     * Cleanup old dedup cache entries
     */
    void cleanup_dedup_cache();
    
    /**
     * Timeout pending discoveries that haven't received responses
     */
    void timeout_pending_discoveries();
    
    /**
     * Calculate average latency from responses
     */
    int calculate_avg_latency() const;
};

#endif // BROADCAST_DISCOVERY_MANAGER_H
