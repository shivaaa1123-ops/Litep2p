#pragma once

#include "session_manager.h"
#include "session_dependencies.h"
#include "discovery.h"
#include "peer_index.h"
#include "logger.h"
#include "session_events.h"
#include "scheduled_event.h"
#include "constants.h"
#include "nat_traversal.h"
#include "peer_reconnect_policy.h"
#include "peer_tier_manager.h"
#include "tier_system_failsafe.h"
#include "broadcast_discovery_manager.h"
#include "file_transfer_manager.h"
#include "event_manager.h"
#include "itcp_connection_manager.h"
#include "iudp_connection_manager.h"
#include "message_handler.h"
#include "peer_lifecycle_manager.h"
#include "maintenance_manager.h"
#include "message_types.h"
#include "wire_codec.h"
#include "local_peer_db.h"
#include "rugged_recovery_manager.h"
#if ENABLE_PROXY_MODULE
#include "proxy_endpoint.h"
#endif
#if ENABLE_OVERLAY_MODULE
#include "overlay_router.h"
#endif
#include "../../discovery/include/signaling_client.h"
#if HAVE_NOISE_PROTOCOL
#include "secure_session.h"
#endif
#include <mutex>
#include <thread>
#include <chrono>
#include <algorithm>
#include <condition_variable>
#include <vector>
#include <queue>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <future>
#include <deque>

#include <cstdint>

// Wire encode/decode helpers are in wire_codec.h (wire::encode_message / wire::decode_message)

// Implementation class
struct MessageAckInfo {
    std::string message_id;
    std::string peer_id;
    std::string network_id;
    std::string message_content;
    std::chrono::steady_clock::time_point send_time;
    int retry_count;
    bool acknowledged;
};

struct MessageRetryInfo {
    int retry_count;
    std::chrono::steady_clock::time_point last_attempt;
    std::string message;
    std::string network_id;
    std::string peer_id;
};

class SessionManager::Impl {
public:
    Impl(std::shared_ptr<ISessionDependenciesFactory> factory);
    ~Impl();
    
    void start(int port, std::function<void(const std::vector<Peer>&)> cb, const std::string& comms_mode, const std::string& peer_id);
    void stop();
    std::future<void> stopAsync();
    void connectToPeer(const std::string& peer_id);
    void connectToPeer(const std::string& peer_id, bool bypass_reconnect_policy, const char* source);
    bool disconnectFromPeer(const std::string& peer_id);
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);
    void setMessageReceivedCallback(std::function<void(const std::string&, const std::string&)> cb);
    bool isPeerConnected(const std::string& peer_id) const;
    std::string getPeerFsmState(const std::string& peer_id) const;
    std::string getPeerConnectionType(const std::string& peer_id) const;
    void set_battery_level_public(int percent, bool is_charging);
    void set_network_info_public(bool is_wifi, bool is_available);
    void set_reconnect_mode_public(const std::string& mode);
    std::string get_reconnect_status_json_public() const;

    BatteryOptimizer* get_battery_optimizer();
    SessionCache* get_session_cache();
    MessageBatcher* get_message_batcher();
    PeerIndex* get_peer_index();
    FileTransferManager* get_file_transfer_manager();

    // File transfer (offer/accept model) — thin adapters over FileTransferManager.
    std::string send_file(const std::string& peer_id, const std::string& file_path, int priority);
    bool accept_file_transfer(const std::string& transfer_id, const std::string& save_path);
    bool decline_file_transfer(const std::string& transfer_id);
    bool pause_transfer(const std::string& transfer_id);
    bool resume_transfer(const std::string& transfer_id);
    bool cancel_transfer(const std::string& transfer_id);
    float get_transfer_progress(const std::string& transfer_id) const;
    float get_transfer_speed(const std::string& transfer_id) const;
    std::vector<std::string> get_active_transfers() const;
    void set_file_transfer_callbacks(SessionManager::FileTransferOfferCallback on_offer,
                                     SessionManager::FileTransferProgressCallback on_progress,
                                     SessionManager::FileTransferCompleteCallback on_complete);

    // Wire FileTransferManager's outbound callback into the session send path
    // and register the offer/progress/complete forwarding. Called from start().
    void wire_file_transfer_manager();

#if HAVE_NOISE_PROTOCOL
    NoiseNKManager* get_noise_nk_manager();
    NoiseKeyStore* get_noise_key_store();
#endif

    void enable_noise_nk();
    bool is_noise_nk_enabled() const;

private:
    friend class SessionManager;
    friend class detail::MessageHandler;
    friend class detail::PeerLifecycleManager;
    friend class detail::MaintenanceManager;

    // Event handlers
    void pushEvent(SessionEvent event);
    void onData(const std::string& network_id, const std::string& data);
    void onDisconnect(const std::string& network_id);
    void timerLoop();
    void processEventQueue();
    
    // Message handling
    void handleSendMessageWithRetry(const std::string& peer_id, const std::string& network_id, 
                                   const std::string& message, const std::string& message_id = "");
    void handleMessageSendComplete(const MessageSendCompleteEvent& event);
    
    void initializeTierSystemCallbacks();
    void notifyPeerUpdate();
    void set_battery_level(int percent, bool is_charging);
    void set_network_info(bool is_wifi, bool is_available);
    std::string get_reconnect_status_json() const;
    
#if HAVE_NOISE_PROTOCOL
    void initializeNoiseHandshake(const std::string& peer_id);
    std::string processNoiseHandshakeMessage(const std::string& peer_id, const std::string& message);
    void queueMessage(const std::string& peer_id, const std::string& message);
    void flushQueuedMessages(const std::string& peer_id);
    void clearQueuedMessages(const std::string& peer_id);
    bool shouldInitiateNoiseHandshake(const std::string& peer_id) const;
    void sendNoiseHandshakeMessage(const std::string& peer_id, const std::string& handshake_payload);
    
    // PROACTIVE RELAY ESCALATION: Re-send handshake via signaling relay when UDP handshake is stuck
    void proactiveHandshakeRelay(const std::string& peer_id);
#endif

    // Discovery response handling - now supports full response with local IP info
    void handleDiscoveryResponse(const std::string& discovered_peer_id);
    void handleDiscoveryResponseWithEndpoint(const std::string& discovered_peer_id, 
                                              const std::string& responder_ip, 
                                              int responder_port,
                                              int latency_ms);
    void handlePeerDiscovered(const std::string& network_id, const std::string& peer_id);
    void handlePeerLeftFromSignaling(const std::string& peer_id);
    void handleFSMEvent(const FSMEvent& event);
    void handleLanDiscoveryResult(const LanDiscoveryResultEvent& event);

    // Local peer persistence (SQLite)
    void maybe_init_peer_db_();
    void bootstrap_peers_from_db_();
    void db_first_connect_and_prune_tick_();

    // Signaling/NAT recovery helpers (used by MaintenanceManager and network callbacks).
    void setup_signaling_callbacks(SignalingClient& client);
    void ensure_signaling_connected_async(bool force = false);
    void refresh_external_address_async(bool force = false);
    
    // Broadcast updated LAN IP to all known peers via signaling (called on WiFi handoff)
    void broadcastLanIpUpdate();
    void schedule_lan_ip_broadcast_(std::chrono::milliseconds delay);
    void join_owned_recovery_workers_();

    // NATTraversal uses a raw pointer to the active IUdpConnectionManager. stop() clears it.
    // start()/network recovery MUST re-register it so STUN bound-socket probing + hole punching work.
    void ensure_nat_connection_manager_registered_();

    // Hook NAT hole-punch completion into the peer FSM so peers don't get stuck CONNECTING
    // when hole punching exhausts retries.
    void ensure_nat_punch_observer_registered_();
    void unregister_nat_punch_observer_();
    void handle_nat_punch_result_(const std::string& peer_id, bool success);

    // Remote admin/control plane (LP_ADMIN over APPLICATION_DATA)
    void load_remote_control_config();
    bool handle_admin_command_message(const std::string& from_peer_id, const std::string& payload);
    void send_admin_ack_(const std::string& to_peer_id,
                         const std::string& request_id,
                         bool ok,
                         const std::string& message,
                         const std::string& applied_settings_json);
    
    // Helper function to convert PeerState to string
    std::string state_to_string(PeerState state) const;
    
    // Helper function to get mutex for a specific peer
    std::mutex& get_peer_mutex(const std::string& peer_id) const;
    
    // =====================================================================
    // Mutex ordering (DEADLOCK AVOIDANCE)
    // =====================================================================
    // The session layer uses multiple mutexes that can be taken together.
    // When more than one of these must be held at the same time, ALWAYS
    // acquire them in the order listed below:
    //
    //   1) m_peers_mutex
    //   2) m_network_index_mutex
    //
    // Rationale:
    // - m_peers_mutex protects: m_peers, m_peer_contexts, and peer state fields.
    // - m_network_index_mutex protects: m_network_id_to_peer_id and
    //   m_ephemeral_to_advertised_port_map.
    //
    // IMPORTANT RULES:
    // - Never acquire m_peers_mutex while holding m_network_index_mutex.
    // - If you need both, use PeersThenNetworkIndexLock and call the *_locked_
    //   helpers below (they assume the appropriate mutex(es) are already held).
    struct PeersThenNetworkIndexLock {
        std::lock_guard<std::mutex> peers_lock;
        std::lock_guard<std::mutex> index_lock;
        explicit PeersThenNetworkIndexLock(Impl& sm)
            : peers_lock(sm.m_peers_mutex), index_lock(sm.m_network_index_mutex) {}
    };

    // Synchronization for async operations
    mutable std::mutex m_lifecycle_mutex;
    mutable std::mutex m_stop_mutex;
    std::condition_variable m_stop_cv;
    std::atomic<bool> m_stopped;
    std::atomic<bool> m_shutting_down{false};  // Shutdown barrier flag

    // Helper functions for fast peer lookups
    Peer* find_peer_by_id(const std::string& peer_id);
    const Peer* find_peer_by_id(const std::string& peer_id) const;
    // Peer lookup by network_id requires BOTH m_peers_mutex and m_network_index_mutex.
    // Callers should take PeersThenNetworkIndexLock first and then call these.
    std::string peer_id_by_network_id_locked_(const std::string& network_id) const;
    Peer* find_peer_by_network_id_locked_(const std::string& network_id);
    const Peer* find_peer_by_network_id_locked_(const std::string& network_id) const;
    
    // Network ID index management
    void add_peer_to_network_index(const std::string& peer_id, const std::string& network_id);
    void remove_peer_from_network_index(const std::string& network_id);

    // Variants that REQUIRE m_network_index_mutex to already be held.
    void add_peer_to_network_index_locked_(const std::string& peer_id, const std::string& network_id);
    void remove_peer_from_network_index_locked_(const std::string& network_id);

    // Ephemeral mapping helpers that REQUIRE m_network_index_mutex to already be held.
    void prune_ephemeral_mappings_for_advertised_locked_(const std::string& advertised_network_id);
    void upsert_ephemeral_mapping_locked_(const std::string& ephemeral_network_id,
                                         const std::string& advertised_network_id);
    void update_peer_network_index(const std::string& old_network_id, const std::string& peer_id, const std::string& new_network_id);
    void update_peer_indexes();
    void remove_peer_from_indexes(size_t index);
    
    // Safely remove a peer by ID, updating indexes
    void remove_peer_by_id(const std::string& peer_id);

    // Unified communication interface to reduce code duplication
    void send_message_to_peer(const std::string& network_id, const std::string& message);

    // ---------------------------------------------------------------
    // Homogeneous / heterogeneous communication modes
    // ---------------------------------------------------------------
    // Records which transport (UDP/TCP) a peer used on inbound, so heterogeneous
    // mode can route outbound traffic back on the same transport.
    void note_inbound_transport(const std::string& network_id, const std::string& transport);
    // Returns the transport to use for outbound traffic to `peer_id`:
    //  - homogeneous mode: the configured single protocol (UDP/TCP/QUIC)
    //  - heterogeneous mode: the peer's inbound transport if known, else the default UDP
    std::string outbound_transport_for_peer(const std::string& peer_id) const;

    // Member variables
    std::atomic<bool> m_running;
    std::unique_ptr<ITcpConnectionManager> m_tcpConnectionManager;
    std::unique_ptr<IUdpConnectionManager> m_udpConnectionManager;
    std::unordered_map<std::string, Peer> m_peers; // Key: peer.id
    std::function<void(const std::vector<Peer>&)> m_peer_update_cb;
    std::function<void(const std::string&, const std::string&)> m_message_received_cb;  // peer_id, message
    std::string m_localPeerId;
    // Process-lifetime identifier used to detect restarts across CONTROL_CONNECT.
    // (Noise sessions cannot survive process restarts even if static keys persist.)
    uint64_t m_local_boot_id{0};
    std::string m_comms_mode;
    // True when the engine runs in heterogeneous mode (accepts both UDP and TCP
    // connections). Dictated by `communication.mode` in config / `--mode` on the
    // desktop CLI. Homogeneous (false) is the historic single-protocol behavior.
    bool m_comms_heterogeneous{false};
    
    std::shared_ptr<ISessionDependenciesFactory> m_factory;
    std::unique_ptr<PeerIndex> m_peer_index;
    std::mutex m_keepalive_mutex;
    
    // Network ID to Peer ID mapping for O(1) lookups
    std::unordered_map<std::string, std::string> m_network_id_to_peer_id;
    mutable std::mutex m_network_index_mutex;
    
    // Ephemeral port to advertised network_id mapping
    // Maps incoming ephemeral ports to the advertised network_id for data routing
    // Example: "192.168.3.5:46392" (ephemeral) -> "192.168.3.5:30001" (advertised)
    std::unordered_map<std::string, std::string> m_ephemeral_to_advertised_port_map;
    
    std::unique_ptr<TierSystemFailsafe> m_failsafe;
    std::unique_ptr<PeerTierManager> m_peer_tier_manager;
    std::unique_ptr<BroadcastDiscoveryManager> m_broadcast_discovery;
    std::unique_ptr<FileTransferManager> m_file_transfer_manager;
    std::unique_ptr<EventManager> m_event_manager;

    // File transfer event callbacks (guarded by m_file_transfer_cb_mutex).
    SessionManager::FileTransferOfferCallback m_ft_offer_cb;
    SessionManager::FileTransferProgressCallback m_ft_progress_cb;
    SessionManager::FileTransferCompleteCallback m_ft_complete_cb;
    mutable std::mutex m_file_transfer_cb_mutex;
    
    std::unique_ptr<detail::MessageHandler> m_message_handler;
    std::unique_ptr<detail::PeerLifecycleManager> m_peer_lifecycle_manager;
    std::unique_ptr<detail::MaintenanceManager> m_maintenance_manager;
    
    // Rugged Recovery Manager - handles automatic recovery from network failures
    std::unique_ptr<recovery::RuggedRecoveryManager> m_recovery_manager;

    // Optional persistence: local peer database (SQLite).
    std::unique_ptr<LocalPeerDb> m_local_peer_db;
    bool m_peer_db_bootstrapped{false};

#if ENABLE_PROXY_MODULE
    std::unique_ptr<proxy::ProxyEndpoint> m_proxy_endpoint;
#endif

#if ENABLE_OVERLAY_MODULE
    // Multi-hop overlay router (LPX2). Relay role is opt-in (config/runtime);
    // the origin/destination roles are always available once a peer key is
    // registered for the counterpart.
    std::unique_ptr<overlay::OverlayRouter> m_overlay_router;
#endif

    // Remote control configuration (safe-by-default: disabled unless config enables it)
    bool m_remote_control_enabled{false};
    std::unordered_set<std::string> m_remote_control_allowed_senders;

    // Peer State Machine
    PeerStateMachine m_peer_fsm;
    std::unordered_map<std::string, PeerContext> m_peer_contexts; // Key: peer.id

    // Peers explicitly disconnected by the user via disconnectFromPeer().
    // Automatic reconnect scans (maintenance + DB-first) skip these peers until
    // the user calls connectToPeer() again or the peer connects inbound.
    // Guarded by m_peers_mutex.
    std::unordered_set<std::string> m_user_disconnected_peers;
    
    std::queue<SessionEvent> m_eventQueue;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCv;
    mutable std::mutex m_peers_mutex;
    
    // Granular mutexes for individual peers
    mutable std::unordered_map<std::string, std::unique_ptr<std::mutex>> m_peer_mutexes;
    mutable std::mutex m_peer_mutexes_mutex; // Mutex to protect the mutex container

    bool m_use_noise_protocol;
    bool m_noise_nk_enabled;
#if HAVE_NOISE_PROTOCOL
    std::unique_ptr<SecureSessionManager> m_secure_session_manager;
    std::unique_ptr<NoiseNKManager> m_noise_nk_manager;
    std::unique_ptr<NoiseKeyStore> m_noise_key_store;
#endif
    std::mutex m_secure_session_mutex;
    
    std::unique_ptr<BatteryOptimizer> m_battery_optimizer;
    std::unique_ptr<SessionCache> m_session_cache;
    std::unique_ptr<MessageBatcher> m_message_batcher;

    // ---------------------------------------------------------------------
    // Peer latency measurement (PING/PONG)
    // ---------------------------------------------------------------------
    // IMPORTANT:
    // Never embed steady_clock timestamps into the wire payload.
    // steady_clock epochs are process/device-specific, so subtracting a
    // remote timestamp produces nonsense. Instead, we send a small token
    // and compute RTT using the *local* steady_clock timestamp recorded
    // when we sent the PING.
    std::atomic<uint64_t> m_ping_seq{0};
    mutable std::mutex m_ping_mutex;
    // peer_id -> (last_ping_token, last_ping_sent_time)
    std::unordered_map<std::string, std::pair<uint64_t, std::chrono::steady_clock::time_point>> m_last_ping_by_peer;
    
    // LAN_IP_UPDATE debounce: peer_id -> last sent time
    // Prevents ping-pong loops when both sides send reciprocal LAN_IP_UPDATE
    mutable std::mutex m_lan_ip_update_mutex;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_last_lan_ip_update_sent;
    
    // Peer discovery and message queuing
    std::unordered_set<std::string> m_peers_being_discovered;
    
    // Scheduled events for retries and timeouts
    std::map<std::string, ScheduledEvent> m_scheduledEvents;
    std::mutex m_scheduledEventsMutex;
    
    // SessionManager timer thread (multi-thread mode). Used to push TimerTickEvent every ~100ms.
    // We keep this interruptible so stop() doesn't block on sleep_for.
    std::mutex m_timer_mutex;
    std::condition_variable m_timer_cv;
    std::thread m_timer_thread;

    // Short-lived recovery work is owned by the session manager. stop() joins
    // these workers before dependent state is destroyed.
    std::thread m_network_recovery_thread;
    std::thread m_lan_broadcast_thread;
    std::mutex m_owned_recovery_workers_mutex;
    std::atomic<bool> m_network_recovery_in_progress{false};
    std::atomic<bool> m_lan_broadcast_in_progress{false};

    std::unique_ptr<SignalingClient> m_signaling_client;
    std::atomic<bool> m_signaling_registered{false};
    // Monotonic (steady_clock) ms timestamp of last signaling message received.
    // Used to detect stalled-but-connected sockets and force re-register.
    std::atomic<int64_t> m_last_signaling_rx_ms{0};
    // Monotonic (steady_clock) ms timestamp of last forced re-register due to signaling staleness.
    std::atomic<int64_t> m_last_signaling_forced_reregister_ms{0};
    // When true, bypass the "already connected" fast-path and force a full signaling reconnect.
    // This is set on network transitions where the old TCP route may be stale (common on Android).
    std::atomic<bool> m_force_signaling_reconnect_requested{false};
    // Dedupe: remember the network-change timestamp for which we already initiated a forced reconnect.
    // If a forced reconnect attempt fails, we clear this so the next tick can retry.
    std::atomic<int64_t> m_last_forced_signaling_reconnect_change_ms{0};
    // Monotonic ms timestamp of last detected network transition (used for recovery tuning/logging).
    std::atomic<int64_t> m_last_network_change_ms{0};
    // Sequence counter for reconnect attempts (observability).
    std::atomic<uint64_t> m_signaling_reconnect_seq{0};
    std::mutex m_signaling_update_mutex;
    std::string m_pending_signaling_network_id;
    // Joinable signaling reconnect thread (replaces detached thread to avoid UAF during teardown).
    std::thread m_signaling_reconnect_thread;
    std::thread m_nat_detect_thread;

    // NATTraversal observer id (hole punching completion).
    int m_nat_punch_observer_id{-1};

    // Runtime state for signaling/NAT reconnection.
    int m_listen_port{0};
    bool m_signaling_enabled{false};
    std::string m_signaling_url;
    std::atomic<bool> m_signaling_reconnect_in_progress{false};
    std::chrono::steady_clock::time_point m_last_signaling_reconnect_attempt{};
    std::atomic<bool> m_nat_detect_in_progress{false};
    std::atomic<bool> m_network_available{true};
    // Track last observed network type so we can treat WiFi<->cell transitions as network changes
    // even if "available" never flips false (common on Android during LTE->WiFi handoff).
    // Default to true so that LAN endpoints are preferred on startup.
    // The Android/iOS side should call set_network_info() to update this
    // when the actual network state is known.
    // IMPORTANT: Defaulting to false causes LAN_IP_UPDATE handling to be
    // skipped during initial connection, resulting in WAN-only handshakes
    // even when both peers are on the same LAN.
    std::atomic<bool> m_is_wifi{true};
    std::mutex m_signaling_lifecycle_mutex;
    
    // PRODUCTION-READY: IP change detection
    std::string m_last_known_primary_ip;
    std::thread m_ip_monitor_thread;
    std::atomic<bool> m_ip_monitor_running{false};
    std::mutex m_ip_monitor_wait_mutex;
    std::condition_variable m_ip_monitor_wait_cv;
    void start_ip_monitor();
    void stop_ip_monitor();
    void ip_monitor_loop();

    // DB-first reconnect and on-demand signaling bootstrap.
    std::deque<std::string> m_db_reconnect_queue;
    std::chrono::steady_clock::time_point m_last_db_reconnect_attempt{};
    std::chrono::steady_clock::time_point m_last_db_candidate_reload{};
    std::chrono::steady_clock::time_point m_db_cycle_exhausted_at{};
    std::chrono::steady_clock::time_point m_last_peer_db_prune{};
    std::chrono::steady_clock::time_point m_last_signaling_peer_list_request{};
    std::atomic<bool> m_signaling_bootstrap_requested{false};
    // Once DB is empty/exhausted and we fall back to signaling, keep a best-effort
    // persistent signaling connection (no tight polling; LIST_PEERS stays throttled).
    std::atomic<bool> m_signaling_persistent_after_db_exhausted{false};

    static constexpr int MAX_QUEUED_MESSAGES = 100;
};
