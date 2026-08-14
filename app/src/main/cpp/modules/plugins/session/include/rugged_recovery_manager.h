#ifndef RUGGED_RECOVERY_MANAGER_H
#define RUGGED_RECOVERY_MANAGER_H

#include <string>
#include <chrono>
#include <mutex>
#include <atomic>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <queue>

/**
 * =============================================================================
 * RUGGED RECOVERY MANAGER
 * =============================================================================
 * 
 * A self-healing recovery system designed for resilient P2P communication.
 * 
 * Design Principles:
 * 1. NEVER GIVE UP - Multiple fallback paths for every operation
 * 2. FAST DETECTION - Detect failures in <2s, not after timeouts
 * 3. AUTOMATIC RECOVERY - No manual intervention required
 * 4. GRACEFUL DEGRADATION - Fall back to slower paths when fast paths fail
 * 
 * Recovery Layers (in order of attempt):
 * 1. Direct UDP (fastest, ~10ms RTT on LAN)
 * 2. NAT Hole Punch (for WAN, ~50-200ms setup)
 * 3. Signaling Relay (guaranteed path, ~100-300ms RTT)
 * 4. TCP Fallback (if UDP completely blocked)
 * 
 * Network Change Handling:
 * - Detects WiFi<->LTE transitions in real-time
 * - Proactively restarts sockets before they become stale
 * - Invalidates stale sessions and re-handshakes
 * - Triggers parallel reconnects for all known peers
 * 
 * Message Reliability:
 * - Application-layer ACKs for critical messages
 * - Automatic retransmission with exponential backoff
 * - Path escalation on consecutive failures
 * - Reliable delivery confirmation callback
 */

namespace recovery {

// =============================================================================
// CONFIGURATION CONSTANTS (tuned for rugged recovery)
// =============================================================================

// Socket restart verification
constexpr int SOCKET_RESTART_VERIFY_TIMEOUT_MS = 3000;   // Max wait for socket restart
constexpr int SOCKET_RESTART_VERIFY_INTERVAL_MS = 100;   // Poll interval
constexpr int SOCKET_RESTART_MAX_RETRIES = 3;            // Max restart attempts

// Message delivery reliability
constexpr int MESSAGE_ACK_TIMEOUT_MS = 2000;             // Initial ACK timeout (reduced from 5s)
constexpr int MESSAGE_ACK_MAX_RETRIES = 5;               // Max retries before escalation
constexpr float MESSAGE_ACK_BACKOFF_MULTIPLIER = 1.5f;   // Exponential backoff
constexpr int MESSAGE_ACK_MAX_TIMEOUT_MS = 10000;        // Cap timeout at 10s

// Path escalation thresholds
constexpr int PATH_ESCALATION_FAILURE_THRESHOLD = 2;     // Failures before trying alternate path
constexpr int RELAY_FALLBACK_THRESHOLD = 3;              // Failures before forcing relay

// Session watchdog
constexpr int SESSION_STALE_DETECTION_MS = 5000;         // Detect stale sessions quickly
constexpr int HANDSHAKE_STUCK_DETECTION_MS = 2000;       // Escalate stuck handshakes early

// Network change recovery
constexpr int POST_NETWORK_CHANGE_SETTLE_MS = 500;       // Wait for interface to stabilize
constexpr int PARALLEL_RECONNECT_LIMIT = 5;              // Max parallel reconnects
constexpr int RECONNECT_BURST_INTERVAL_MS = 100;         // Delay between burst reconnects

// =============================================================================
// MESSAGE DELIVERY TRACKING
// =============================================================================

enum class DeliveryStatus {
    PENDING,            // Sent, waiting for ACK
    DELIVERED,          // ACK received
    FAILED_TIMEOUT,     // All retries exhausted
    FAILED_PEER_GONE,   // Peer disconnected
    RELAYED,            // Delivered via relay (fallback path)
};

enum class DeliveryPath {
    DIRECT_UDP,         // Direct UDP to peer
    HOLE_PUNCH,         // Via NAT hole punch
    SIGNALING_RELAY,    // Via signaling server relay
    TCP_FALLBACK,       // TCP connection (if UDP blocked)
};

struct MessageDeliveryRecord {
    std::string message_id;
    std::string peer_id;
    std::string message_content;
    std::chrono::steady_clock::time_point first_sent;
    std::chrono::steady_clock::time_point last_attempt;
    int attempt_count = 0;
    int current_timeout_ms = MESSAGE_ACK_TIMEOUT_MS;
    DeliveryPath current_path = DeliveryPath::DIRECT_UDP;
    DeliveryStatus status = DeliveryStatus::PENDING;
    bool requires_ack = false;
    
    // Callback when delivery is confirmed or fails
    std::function<void(DeliveryStatus, DeliveryPath)> on_complete;
};

// =============================================================================
// SOCKET HEALTH TRACKING
// =============================================================================

struct SocketHealth {
    std::atomic<bool> is_healthy{true};
    std::atomic<int64_t> last_send_success_ms{0};
    std::atomic<int64_t> last_recv_success_ms{0};
    std::atomic<int64_t> last_restart_ms{0};
    std::atomic<int> consecutive_send_failures{0};
    std::atomic<int> restart_count{0};
    
    bool needs_restart() const {
        return !is_healthy.load(std::memory_order_acquire) ||
               consecutive_send_failures.load(std::memory_order_acquire) >= 3;
    }
};

// =============================================================================
// PEER RECOVERY STATE
// =============================================================================

struct PeerRecoveryState {
    std::string peer_id;
    
    // Path statistics
    int direct_failures = 0;
    int relay_successes = 0;
    bool prefer_relay = false;
    
    // Recovery timing
    std::chrono::steady_clock::time_point last_recovery_attempt;
    std::chrono::steady_clock::time_point last_successful_send;
    std::chrono::steady_clock::time_point last_successful_recv;
    
    // Pending reliable messages
    std::vector<std::string> pending_reliable_message_ids;
    
    void record_direct_failure() {
        direct_failures++;
        if (direct_failures >= RELAY_FALLBACK_THRESHOLD) {
            prefer_relay = true;
        }
    }
    
    void record_success(bool via_relay) {
        if (via_relay) {
            relay_successes++;
        } else {
            direct_failures = 0;  // Reset on direct success
            prefer_relay = false;
        }
        last_successful_send = std::chrono::steady_clock::now();
    }
};

// =============================================================================
// RECOVERY MANAGER INTERFACE
// =============================================================================

class RuggedRecoveryManager {
public:
    using SendCallback = std::function<void(const std::string& network_id, const std::string& message)>;
    using RelayCallback = std::function<void(const std::string& peer_id, const std::string& message)>;
    using RestartSocketCallback = std::function<bool()>;
    using ReconnectPeerCallback = std::function<void(const std::string& peer_id)>;
    using GetPeerNetworkIdCallback = std::function<std::string(const std::string& peer_id)>;
    
    RuggedRecoveryManager();
    ~RuggedRecoveryManager();
    
    // Initialization
    void initialize(
        SendCallback send_direct,
        RelayCallback send_relay,
        RestartSocketCallback restart_socket,
        ReconnectPeerCallback reconnect_peer,
        GetPeerNetworkIdCallback get_network_id
    );
    
    void shutdown();
    
    // =========================================================================
    // RELIABLE MESSAGE DELIVERY
    // =========================================================================
    
    /**
     * Send a message with delivery confirmation.
     * @param peer_id Target peer
     * @param message Message content (will be wrapped with reliability header)
     * @param require_ack If true, wait for ACK and retry on failure
     * @param on_complete Callback when delivery confirmed or failed
     * @return Unique message ID for tracking
     */
    std::string send_reliable(
        const std::string& peer_id,
        const std::string& message,
        bool require_ack,
        std::function<void(DeliveryStatus, DeliveryPath)> on_complete = nullptr
    );
    
    /**
     * Process incoming ACK for a reliable message.
     * @return true if this was a valid ACK for a pending message
     */
    bool process_ack(const std::string& message_id);
    
    /**
     * Process incoming reliable message - generates ACK if needed.
     * @return The unwrapped message content, or empty if invalid
     */
    std::string process_incoming_reliable(
        const std::string& peer_id,
        const std::string& wrapped_message
    );
    
    // =========================================================================
    // SOCKET RECOVERY
    // =========================================================================
    
    /**
     * Called when network change is detected.
     * Orchestrates full recovery: socket restart, session invalidation, reconnects.
     */
    void handle_network_change(bool is_wifi, bool is_available);
    
    /**
     * Restart socket with verification.
     * @return true if socket restarted and verified working
     */
    bool restart_socket_verified();
    
    /**
     * Report socket operation result for health tracking.
     */
    void report_socket_send(bool success);
    void report_socket_recv(bool success);
    
    // =========================================================================
    // PEER RECOVERY
    // =========================================================================
    
    /**
     * Mark peer as needing recovery (will trigger reconnect on next tick).
     */
    void schedule_peer_recovery(const std::string& peer_id);
    
    /**
     * Get the best path for sending to a peer.
     */
    DeliveryPath get_best_path(const std::string& peer_id) const;
    
    /**
     * Periodic tick - process retries, escalations, and scheduled recoveries.
     * Call this from the session manager's timer loop (~100ms interval).
     */
    void tick();
    
    // =========================================================================
    // STATISTICS & DEBUGGING
    // =========================================================================
    
    struct Stats {
        int64_t messages_sent_total = 0;
        int64_t messages_delivered_total = 0;
        int64_t messages_failed_total = 0;
        int64_t messages_relayed_total = 0;
        int64_t socket_restarts_total = 0;
        int64_t socket_restart_failures = 0;
        int64_t path_escalations_total = 0;
        int64_t network_changes_handled = 0;
        int64_t peer_recoveries_triggered = 0;
    };
    
    Stats get_stats() const;
    std::string get_status_json() const;
    
private:
    // Callbacks
    SendCallback m_send_direct;
    RelayCallback m_send_relay;
    RestartSocketCallback m_restart_socket;
    ReconnectPeerCallback m_reconnect_peer;
    GetPeerNetworkIdCallback m_get_network_id;
    
    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutting_down{false};
    
    // Socket health
    SocketHealth m_socket_health;
    
    // Message tracking
    mutable std::mutex m_messages_mutex;
    std::unordered_map<std::string, MessageDeliveryRecord> m_pending_messages;
    std::unordered_set<std::string> m_seen_message_ids;  // Dedup incoming
    
    // Peer recovery state
    mutable std::mutex m_peers_mutex;
    std::unordered_map<std::string, PeerRecoveryState> m_peer_states;
    std::queue<std::string> m_recovery_queue;
    
    // Statistics
    mutable std::mutex m_stats_mutex;
    Stats m_stats;
    
    // Network change tracking
    std::atomic<int64_t> m_last_network_change_ms{0};
    std::atomic<bool> m_network_recovery_in_progress{false};
    
    // Internal helpers
    std::string generate_message_id();
    void process_pending_retries();
    void process_recovery_queue();
    void escalate_path(MessageDeliveryRecord& record);
    void send_via_path(MessageDeliveryRecord& record);
    void send_ack(const std::string& peer_id, const std::string& message_id);
    PeerRecoveryState& get_or_create_peer_state(const std::string& peer_id);
    
    int64_t steady_now_ms() const;
};

} // namespace recovery

#endif // RUGGED_RECOVERY_MANAGER_H
