#ifndef NAT_TRAVERSAL_H
#define NAT_TRAVERSAL_H

/**
 * @file nat_traversal.h
 * @brief NAT Traversal Module - Production-Ready NAT Hole Punching and STUN
 * 
 * This module provides comprehensive NAT traversal capabilities including:
 * 
 * ## Core Features
 * - **STUN-based NAT Detection**: Detects NAT type using RFC 5389 STUN protocol
 *   with CHANGE-REQUEST support for accurate classification
 * - **UDP Hole Punching**: Multi-threaded hole punching with configurable
 *   retry logic and exponential backoff
 * - **UPnP Port Mapping**: Automatic port mapping with lease management
 * - **Peer Heartbeat**: Keep-alive mechanism to maintain NAT bindings
 * 
 * ## NAT Types Detected
 * - Open (no NAT)
 * - Full Cone NAT (most permissive)
 * - Restricted Cone NAT
 * - Port-Restricted Cone NAT
 * - Symmetric NAT (most restrictive, TURN recommended)
 * 
 * ## Thread Safety
 * - All public methods are thread-safe
 * - Uses fine-grained locking for optimal concurrency
 * - Background threads for heartbeats and maintenance
 * 
 * ## Metrics & Monitoring
 * - Built-in metrics tracking (STUN probes, hole punches, heartbeats)
 * - getMetrics() for runtime statistics
 * - JSON export via toJSON() for debugging
 * 
 * ## IPv6 Support
 * - Full IPv6 support for STUN and hole punching
 * - Dual-stack operation with AF_UNSPEC
 * 
 * ## Usage Example
 * @code
 *   NATTraversal& nat = NATTraversal::getInstance();
 *   nat.setConnectionManager(&udpManager);
 *   nat.initialize(5000);
 *   
 *   // Detect NAT type
 *   NATInfo info = nat.detectNATType();
 *   std::cout << "NAT Type: " << natTypeToString(info.nat_type) << std::endl;
 *   
 *   // Register and punch through to peer
 *   PeerAddress peer{"peer-id", "net-1", "192.168.1.100", 5000, 
 *                    "203.0.113.50", 62000};
 *   nat.registerPeer(peer);
 *   nat.performHolePunching("peer-id");
 *   
 *   // Get metrics
 *   NATMetrics metrics = nat.getMetrics();
 *   std::cout << "Hole punch success rate: " 
 *             << metrics.hole_punch_success_rate << std::endl;
 * @endcode
 * 
 * @note TURN relay support is not included (planned for future release)
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "nat_stun.h"
#include "turn_client.h"
#include "../../session/include/iudp_connection_manager.h"

using json = nlohmann::json;

/**
 * @struct NATMapping
 * @brief Represents a UPnP port mapping
 */

struct NATMapping {
    std::string internal_ip;
    uint16_t internal_port{0};
    std::string external_ip;
    uint16_t external_port{0};
    std::string protocol{"UDP"};
    int64_t lease_duration_seconds{0};
    int64_t created_at_ms{0};
    std::string mapping_id;
    std::string network_id;
};

struct STUNServer {
    std::string hostname;
    uint16_t port{3478};
    std::string protocol{"UDP"};
};

struct NATInfo {
    NATType nat_type{NATType::Unknown};
    std::string external_ip;
    uint16_t external_port{0};
    std::string local_ip;
    uint16_t local_port{0};
    bool supports_upnp{false};
    bool supports_stun{false};
    int64_t detected_at_ms{0};
    std::string relay_ip;
    uint16_t relay_port{0};
};

inline std::string natTypeToString(NATType type) {
    switch (type) {
        case NATType::Open: return "Open";
        case NATType::FullCone: return "Full Cone";
        case NATType::RestrictedCone: return "Restricted Cone";
        case NATType::PortRestrictedCone: return "Port-Restricted Cone";
        case NATType::Symmetric: return "Symmetric";
        case NATType::Unknown: default: return "Unknown";
    }
}

struct PeerAddress {
    std::string peer_id;
    std::string network_id;
    std::string internal_ip;
    uint16_t internal_port{0};
    std::string external_ip;
    uint16_t external_port{0};
    std::string nat_type;
    int64_t discovered_at_ms{0};
    bool verified{false};
    int64_t last_heartbeat_ms{0};
    int missed_heartbeats{0};
    int64_t last_successful_punch_ms{0};
    
    // Connection quality metrics
    int32_t latency_ms{-1};           // RTT in ms, -1 if unknown
    int32_t avg_latency_ms{-1};       // Moving average RTT
    int32_t jitter_ms{0};             // Latency variation
    uint32_t packets_sent{0};         // Total packets sent
    uint32_t packets_received{0};     // Total packets received
    float packet_loss_rate{0.0f};     // 0.0 - 1.0
    int64_t last_validated_ms{0};     // Last successful connectivity check
};

/**
 * @struct ConnectionValidation
 * @brief Result of a peer connection validation check
 */
struct ConnectionValidation {
    bool reachable{false};            ///< Whether peer responded to probe
    int32_t latency_ms{-1};           ///< Round-trip time in ms (-1 if not measured)
    std::string error_message;        ///< Error description if not reachable
    int64_t validated_at_ms{0};       ///< Timestamp of validation
};

/**
 * @interface IUpnpController
 * @brief Interface for UPnP IGD port mapping operations
 */
class IUpnpController {
public:
    virtual ~IUpnpController() = default;
    virtual bool isAvailable() const = 0;
    virtual bool addPortMapping(uint16_t internal_port,
                                uint16_t external_port,
                                const std::string& protocol,
                                int lease_seconds,
                                std::string& mapping_id) = 0;
    virtual bool removePortMapping(const std::string& mapping_id) = 0;
};

/**
 * @struct NATMetrics
 * @brief Runtime metrics for NAT traversal monitoring
 * 
 * All counters are accumulated since last resetMetrics() call.
 * Thread-safe to read via getMetrics().
 */
struct NATMetrics {
    // STUN metrics
    uint64_t stun_requests_sent{0};       ///< Total STUN binding requests sent
    uint64_t stun_responses_received{0};  ///< Successful STUN responses;
    uint64_t stun_timeouts{0};
    uint64_t stun_errors{0};
    int32_t avg_stun_latency_ms{0};
    
    // Hole punching metrics
    uint64_t hole_punch_attempts{0};
    uint64_t hole_punch_successes{0};
    uint64_t hole_punch_failures{0};
    float hole_punch_success_rate{0.0f};
    
    // NAT detection
    NATType detected_nat_type{NATType::Unknown};
    int64_t last_detection_ms{0};
    int detection_count{0};
    
    // Peer metrics
    int active_peers{0};
    int verified_peers{0};
    int unreachable_peers{0};
    
    // UPnP metrics
    uint64_t upnp_mapping_attempts{0};
    uint64_t upnp_mapping_successes{0};
    int active_upnp_mappings{0};
    
    // Heartbeat metrics
    uint64_t heartbeats_sent{0};
    uint64_t heartbeats_received{0};
    
    // Discovery metrics
    uint64_t discovery_broadcasts_sent{0};
    uint64_t discovery_responses_received{0};
    
    // Timestamps
    int64_t last_updated_ms{0};
    int64_t uptime_ms{0};
};

class NATTraversal {
public:
    struct Options {
        bool stun_enabled{true};
        bool upnp_enabled{false};
        bool hole_punching_enabled{true};
        int stun_timeout_ms{2000};
        int heartbeat_interval_sec{15};
        int heartbeat_timeout_ms{45000};
        int cleanup_interval_sec{60};
        int hole_punch_max_attempts{5};
        int hole_punch_initial_backoff_ms{100};
        // Cooldown after a punch job exhausts retries.
        // Prevents repeated scheduling loops during reconnect races.
        int hole_punch_failure_cooldown_ms{5000};
        int punch_thread_pool_size{10};
        int punch_queue_limit{128};
        int upnp_lease_duration_sec{3600};
        int max_missed_heartbeats{3};
        bool turn_enabled{false};
        TurnConfig turn_config;
    };

    static NATTraversal& getInstance();

    bool initialize(uint16_t local_port);
    void shutdown();

    void reloadConfiguration();

    void setConnectionManager(IUdpConnectionManager* manager);
    void setUpnpController(std::shared_ptr<IUpnpController> controller);

    void registerPeer(const PeerAddress& peer);
    // Removes a peer from internal tracking and cancels any outstanding hole-punch work.
    void unregisterPeer(const std::string& peer_id);
    // Cancels queued/in-flight hole punching for a peer. The peer may remain registered.
    void cancelHolePunching(const std::string& peer_id);
    std::vector<PeerAddress> getRegisteredPeers() const;
    std::vector<PeerAddress> getNetworkPeers(const std::string& network_id) const;
    bool performHolePunching(const std::string& peer_id);
    bool performNetworkHolePunching(const std::string& peer_id, const std::string& network_id);

    // Best-effort cancellation hook used by SessionManager stop() to accelerate teardown
    // (e.g., abort in-flight STUN NAT detection promptly).
    void requestCancel();

    NATInfo detectNATType();
    NATInfo getNATInfo() const;

    bool attemptUPnPMapping(uint16_t internal_port,
                            uint16_t external_port,
                            const std::string& protocol = "UDP");
    bool removeUPnPMapping(const std::string& mapping_id);
    NATMapping getMappingForPort(uint16_t port) const;

    void addSTUNServer(const STUNServer& server);
    std::vector<STUNServer> getSTUNServers() const;
    bool testConnectivity();
    
    // Connection validation and keepalive
    bool validatePeerConnection(const std::string& peer_id);
    bool sendKeepalive(const std::string& peer_id);
    int getPeerLatencyMs(const std::string& peer_id) const;
    bool isPeerReachable(const std::string& peer_id) const;
    
    // Metrics and monitoring
    NATMetrics getMetrics() const;
    void resetMetrics();

    void handleStunPacket(const std::string& ip, int port, const std::vector<uint8_t>& data);

    json toJSON() const;

    void sendHeartbeats();
    void receiveHeartbeat(const std::string& peer_id);
    void startEngineStaged(uint16_t local_port);

private:
    struct PendingTransaction {
        std::vector<uint8_t> response;
        bool completed{false};
    };

    NATTraversal();
    ~NATTraversal();

    NATTraversal(const NATTraversal&) = delete;
    NATTraversal& operator=(const NATTraversal&) = delete;

    void ensureConfigurationLoaded();
    void loadOptionsLocked();
    void refreshStunServerListLocked();

    void startHeartbeatThread();
    void stopHeartbeatThread();
    void heartbeatLoop();

    void startMaintenanceThread();
    void stopMaintenanceThread();
    void maintenanceLoop();

    void startPunchThreadPool();
    void stopPunchThreadPool();
    void clearPunchQueue();
    void enqueuePunchTask(const PeerAddress& peer);
    void punchWorkerLoop();

    bool performHolePunchingInternal(const PeerAddress& peer);
    void markPeerPunchSuccess(const std::string& peer_id);

    void cleanupStalePeersLocked(int64_t now_ms, const Options& options_snapshot);
    void cleanupStaleMappingsLocked(int64_t now_ms);
    void renewLeasesLocked(int64_t now_ms);

    void sendDiscoveryPackets();
    void updateLocalPeersFromDiscovery();
    void sendNetworkBroadcast();

    NATType detectNatViaStunServers(std::string& external_ip, uint16_t& external_port);
    void reconcilePunchThreadPoolSize();

    static std::string transactionKey(const std::vector<uint8_t>& tx_id);

    mutable std::mutex options_mutex_;
    Options options_;

    mutable std::mutex nat_info_mutex_;
    NATInfo nat_info_;

    mutable std::mutex stun_mutex_;
    std::vector<STUNServer> stun_servers_;

    mutable std::mutex peers_mutex_;
    std::unordered_map<std::string, PeerAddress> peers_by_id_;

    mutable std::mutex mapping_mutex_;
    std::unordered_map<std::string, NATMapping> mappings_by_id_;

    mutable std::mutex pending_mutex_;
    std::unordered_map<std::string, PendingTransaction> pending_transactions_;
    std::condition_variable pending_cv_;

    mutable std::mutex punch_mutex_;
    std::queue<PeerAddress> punch_queue_;
    // De-duplication / coalescing for punch tasks.
    // We intentionally allow at most one in-flight punch job per peer_id, and
    // coalesce repeated schedule requests (common during reconnect races).
    std::unordered_set<std::string> punch_queued_peers_;
    std::unordered_set<std::string> punch_inflight_peers_;
    std::unordered_map<std::string, PeerAddress> punch_reschedule_latest_;
    // Cancellation and cooldown tracking for hole-punch jobs (guarded by punch_mutex_).
    std::unordered_set<std::string> punch_cancelled_peers_;
    std::unordered_map<std::string, int64_t> punch_last_failure_ms_;
    std::condition_variable punch_cv_;
    bool punch_shutdown_{false};
    std::vector<std::thread> punch_workers_;
    int current_punch_worker_count_{0};
    
    // On-demand punch mode: spawn threads only when needed, destroy after use
    bool on_demand_punch_mode_{false};
    std::atomic<int> active_on_demand_punches_{0};
    static constexpr int MAX_ON_DEMAND_PUNCH_THREADS = 4;

    std::thread heartbeat_thread_;
    std::thread maintenance_thread_;
    std::thread engine_thread_;

    std::mutex heartbeat_mutex_;
    std::condition_variable heartbeat_cv_;
    bool heartbeat_stop_requested_{false};

    std::mutex maintenance_mutex_;
    std::condition_variable maintenance_cv_;
    bool maintenance_stop_requested_{false};

    std::shared_ptr<IUpnpController> upnp_controller_;
    mutable std::mutex upnp_mutex_;

    std::atomic<IUdpConnectionManager*> connection_manager_{nullptr};
    std::mutex connection_mutex_;

    std::atomic_bool initialized_{false};
    std::atomic_bool shutdown_requested_{false};
    uint16_t local_port_{0};
    STUNClient stun_client_;
    std::vector<uint8_t> heartbeat_payload_;
    
    // Metrics tracking
    mutable std::mutex metrics_mutex_;
    NATMetrics metrics_;
    int64_t init_time_ms_{0};
};

#endif // NAT_TRAVERSAL_H
