#include "session_manager.h"
#include "discovery.h"
#include "peer_index.h"
#include "logger.h"
#include "session_events.h"
#include "constants.h"
#include "nat_traversal.h"
#include "peer_reconnect_policy.h"
#include "peer_tier_manager.h"
#include "tier_system_failsafe.h"
#include "broadcast_discovery_manager.h"
#include "file_transfer_manager.h"
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

struct HandshakeState {
    enum Status { PENDING, IN_PROGRESS, COMPLETE, FAILED };
    Status status;
    std::chrono::steady_clock::time_point initiated_time;
    int retry_count;
};

// Implementation class
class SessionManager::Impl {
public:
    Impl();
    ~Impl();
    
    void start(int port, std::function<void(const std::vector<Peer>&)> cb, const std::string& comms_mode, const std::string& peer_id);
    void stop();
    void connectToPeer(const std::string& peer_id);
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);
    void set_battery_level_public(int percent, bool is_charging);
    void set_network_info_public(bool is_wifi, bool is_available);
    std::string get_reconnect_status_json_public() const;

    BatteryOptimizer* get_battery_optimizer();
    SessionCache* get_session_cache();
    MessageBatcher* get_message_batcher();
    PeerIndex* get_peer_index();
    FileTransferManager* get_file_transfer_manager();

#if HAVE_NOISE_PROTOCOL
    NoiseNKManager* get_noise_nk_manager();
    NoiseKeyStore* get_noise_key_store();
#endif

    void enable_noise_nk();
    bool is_noise_nk_enabled() const;

private:
    // Event handlers
    void pushEvent(SessionEvent event);
    void onData(const std::string& network_id, const std::string& data);
    void onDisconnect(const std::string& network_id);
    void timerLoop();
    void processEventQueue();
    
    void handlePeerDiscoveredEvent(const PeerDiscoveredEvent& event);
    void handleDataReceivedEvent(const DataReceivedEvent& event);
    void handlePeerDisconnectEvent(const PeerDisconnectEvent& event);
    void handleConnectToPeerEvent(const ConnectToPeerEvent& event);
    void handleSendMessageEvent(const SendMessageEvent& event);
    void handleTimerTickEvent(const TimerTickEvent&);
    
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
#endif

    void handleDiscoveryResponse(const std::string& discovered_peer_id);
    void handlePeerDiscovered(const std::string& network_id, const std::string& peer_id);

    // Helper functions for fast peer lookups
    Peer* find_peer_by_id(const std::string& peer_id);
    const Peer* find_peer_by_id(const std::string& peer_id) const;
    Peer* find_peer_by_network_id(const std::string& network_id);
    const Peer* find_peer_by_network_id(const std::string& network_id) const;
    void update_peer_indexes();
    void remove_peer_from_indexes(size_t index);
    
    // Safely remove a peer by ID, updating indexes
    void remove_peer_by_id(const std::string& peer_id);

    // Unified communication interface to reduce code duplication
    void send_message_to_peer(const std::string& network_id, const std::string& message);

    // Member variables
    std::atomic<bool> m_running;
    ConnectionManager m_tcpConnectionManager;
    UdpConnectionManager m_udpConnectionManager;
    std::unordered_map<std::string, Peer> m_peers; // Key: peer.id
    std::function<void(const std::vector<Peer>&)> m_peer_update_cb;
    std::string m_localPeerId;
    std::string m_comms_mode;
    
    std::unique_ptr<PeerIndex> m_peer_index;
    std::map<std::string, std::chrono::steady_clock::time_point> m_keepalive_due;
    std::mutex m_keepalive_mutex;
    
    std::unique_ptr<TierSystemFailsafe> m_failsafe;
    std::unique_ptr<PeerTierManager> m_peer_tier_manager;
    std::unique_ptr<BroadcastDiscoveryManager> m_broadcast_discovery;
    std::unique_ptr<FileTransferManager> m_file_transfer_manager;
    
    std::unordered_map<std::string, std::vector<std::string>> m_pending_messages;
    std::mutex m_pending_messages_mutex;
    std::unordered_set<std::string> m_peers_being_discovered;
    
    struct ScheduledEvent {
        SessionEvent event;
        std::chrono::steady_clock::time_point due_time;
    };
    std::map<std::string, ScheduledEvent> m_scheduled_events;
    std::mutex m_scheduled_events_mutex;
    
    std::queue<SessionEvent> m_eventQueue;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCv;
    std::thread m_processingThread;
    std::thread m_timerThread;
    std::mutex m_peers_mutex;

    bool m_use_noise_protocol;
    bool m_noise_nk_enabled;
#if HAVE_NOISE_PROTOCOL
    std::unique_ptr<SecureSessionManager> m_secure_session_manager;
    std::unique_ptr<NoiseNKManager> m_noise_nk_manager;
    std::unique_ptr<NoiseKeyStore> m_noise_key_store;
    std::map<std::string, HandshakeState> m_handshake_states;
#endif
    std::mutex m_secure_session_mutex;
    
    std::unique_ptr<BatteryOptimizer> m_battery_optimizer;
    std::unique_ptr<SessionCache> m_session_cache;
    std::unique_ptr<MessageBatcher> m_message_batcher;
    
    static constexpr int MAX_QUEUED_MESSAGES = 100;
    static constexpr int HANDSHAKE_TIMEOUT_SEC = 3;
    static constexpr int MAX_HANDSHAKE_RETRIES = 3;
};

// ============================================================================
// IMPLEMENTATION
// ============================================================================

SessionManager::Impl::Impl()
    : m_running(false), m_use_noise_protocol(false), m_noise_nk_enabled(false),
      m_peer_index(std::make_unique<PeerIndex>()),
      m_battery_optimizer(std::make_unique<BatteryOptimizer>()),
      m_session_cache(std::make_unique<SessionCache>()),
      m_message_batcher(std::make_unique<MessageBatcher>(BATCH_DELAY_MS, BATCH_MAX_MESSAGES)),
      m_failsafe(std::make_unique<TierSystemFailsafe>()),
      m_peer_tier_manager(nullptr),
      m_broadcast_discovery(nullptr),
      m_file_transfer_manager(std::make_unique<FileTransferManager>(100, 32)) {
    
    m_battery_optimizer->set_optimization_level(BatteryOptimizer::OptimizationLevel::BALANCED);
    LOG_INFO("SM: Battery optimization enabled (BALANCED mode)");
    
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.initialize(100, true);
    LOG_INFO("SM: Reconnect policy initialized");
    
#if HAVE_NOISE_PROTOCOL
    m_use_noise_protocol = true;
    m_secure_session_manager = std::make_unique<SecureSessionManager>();
    m_noise_nk_manager = std::make_unique<NoiseNKManager>();
    m_noise_key_store = std::make_unique<NoiseKeyStore>();
    m_noise_key_store->initialize();
    LOG_INFO("SM: Noise Protocol support enabled");
#else
    LOG_INFO("SM: Noise Protocol not available");
#endif
}

SessionManager::Impl::~Impl() {
    stop();
}

void SessionManager::Impl::start(int port, std::function<void(const std::vector<Peer>&)> cb, 
                                 const std::string& comms_mode, const std::string& peer_id) {
    if (m_running) {
        LOG_WARN("SM: Session manager already running, ignoring start request.");
        return;
    }
    
    m_running = true;
    m_peer_update_cb = cb;
    m_comms_mode = comms_mode;
    m_localPeerId = peer_id;
    
    m_peer_tier_manager = std::make_unique<PeerTierManager>();
    m_broadcast_discovery = std::make_unique<BroadcastDiscoveryManager>();
    
    // Initialize broadcast discovery manager
    if (!m_broadcast_discovery->initialize()) {
        LOG_WARN("SM: Failed to initialize broadcast discovery manager");
    } else {
        LOG_INFO("SM: Broadcast discovery manager initialized successfully");
    }
    
    // Start the low-level UDP discovery service
    Discovery* discovery = getGlobalDiscoveryInstance();
    discovery->start(port, peer_id);
    discovery->setCallback([this](const std::string& network_id, const std::string& peer_id) {
        handlePeerDiscovered(network_id, peer_id);
    });
    
    LOG_INFO("SM: Starting session manager on port " + std::to_string(port));
    LOG_INFO("SM: Comms mode: " + comms_mode);
    
    initializeTierSystemCallbacks();
    
    if (comms_mode == "TCP") {
        m_tcpConnectionManager.startServer(port, 
            [this](const std::string& id, const std::string& data) { onData(id, data); },
            [this](const std::string& id) { onDisconnect(id); });
    } else {
        m_udpConnectionManager.startServer(port,
            [this](const std::string& id, const std::string& data) { onData(id, data); },
            [this](const std::string& id) { onDisconnect(id); });
    }
    
    m_processingThread = std::thread([this] { processEventQueue(); });
    m_timerThread = std::thread([this] { timerLoop(); });
    
    LOG_INFO("SM: Session manager started successfully");
}

void SessionManager::Impl::stop() {
    if (!m_running) {
        LOG_WARN("SM: Session manager not running, ignoring stop request.");
        return;
    }
    
    LOG_INFO("SM: Stopping session manager...");
    m_running = false;
    m_eventCv.notify_all();
    
    // Stop the low-level UDP discovery service first to prevent blocking
    LOG_INFO("SM: Stopping discovery service...");
    Discovery* discovery = getGlobalDiscoveryInstance();
    discovery->stop();
    LOG_INFO("SM: Discovery service stopped.");
    
    // Join threads before cleaning up resources they might be using
    LOG_INFO("SM: Joining processing thread...");
    if (m_processingThread.joinable()) m_processingThread.join();
    LOG_INFO("SM: Processing thread joined.");
    
    LOG_INFO("SM: Joining timer thread...");
    if (m_timerThread.joinable()) m_timerThread.join();
    LOG_INFO("SM: Timer thread joined.");
    
    if (m_comms_mode == "TCP") {
        LOG_INFO("SM: Stopping TCP connection manager...");
        m_tcpConnectionManager.stop();
        LOG_INFO("SM: TCP connection manager stopped.");
    } else {
        LOG_INFO("SM: Stopping UDP connection manager...");
        m_udpConnectionManager.stop();
        LOG_INFO("SM: UDP connection manager stopped.");
    }
    
    // Clear peer data
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        m_peers.clear();
        m_peers_being_discovered.clear();
    }
    
    // Clear scheduled events
    {
        std::lock_guard<std::mutex> lock(m_scheduled_events_mutex);
        m_scheduled_events.clear();
    }
    
    // Clear pending messages
    {
        std::lock_guard<std::mutex> lock(m_pending_messages_mutex);
        m_pending_messages.clear();
    }
    
    // Reset unique pointers to ensure clean state
    LOG_INFO("SM: Resetting unique pointers...");
    m_broadcast_discovery.reset();
    m_peer_tier_manager.reset();
    m_file_transfer_manager.reset();
    m_session_cache.reset();
    m_message_batcher.reset();
    m_peer_index.reset();
    m_battery_optimizer.reset();
    
#if HAVE_NOISE_PROTOCOL
    m_secure_session_manager.reset();
    m_noise_nk_manager.reset();
    m_noise_key_store.reset();
    m_handshake_states.clear();
#endif
    
    LOG_INFO("SM: Session manager stopped");
}

void SessionManager::Impl::connectToPeer(const std::string& peer_id) {
    LOG_INFO("SM: UI requested connection to peer: " + peer_id);
    pushEvent(ConnectToPeerEvent{peer_id});
}

void SessionManager::Impl::sendMessageToPeer(const std::string& peer_id, const std::string& message) {
    pushEvent(SendMessageEvent{peer_id, message});
}

void SessionManager::Impl::set_battery_level_public(int percent, bool is_charging) {
    set_battery_level(percent, is_charging);
}

void SessionManager::Impl::set_network_info_public(bool is_wifi, bool is_available) {
    set_network_info(is_wifi, is_available);
}

std::string SessionManager::Impl::get_reconnect_status_json_public() const {
    return get_reconnect_status_json();
}

BatteryOptimizer* SessionManager::Impl::get_battery_optimizer() {
    return m_battery_optimizer.get();
}

SessionCache* SessionManager::Impl::get_session_cache() {
    return m_session_cache.get();
}

MessageBatcher* SessionManager::Impl::get_message_batcher() {
    return m_message_batcher.get();
}

PeerIndex* SessionManager::Impl::get_peer_index() {
    return m_peer_index.get();
}

FileTransferManager* SessionManager::Impl::get_file_transfer_manager() {
    return m_file_transfer_manager.get();
}

#if HAVE_NOISE_PROTOCOL
NoiseNKManager* SessionManager::Impl::get_noise_nk_manager() {
    return m_noise_nk_manager.get();
}

NoiseKeyStore* SessionManager::Impl::get_noise_key_store() {
    return m_noise_key_store.get();
}
#endif

void SessionManager::Impl::enable_noise_nk() {
    m_noise_nk_enabled = true;
    LOG_INFO("SM: Noise NK MITM protection enabled");
}

bool SessionManager::Impl::is_noise_nk_enabled() const {
    return m_noise_nk_enabled;
}

void SessionManager::Impl::pushEvent(SessionEvent event) {
    {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        m_eventQueue.push(event);
    }
    m_eventCv.notify_one();
}

void SessionManager::Impl::onData(const std::string& network_id, const std::string& data) {
    auto now = std::chrono::steady_clock::now();
    pushEvent(DataReceivedEvent{network_id, data, now});
}

void SessionManager::Impl::onDisconnect(const std::string& network_id) {
    pushEvent(PeerDisconnectEvent{network_id});
}

void SessionManager::Impl::processEventQueue() {
    while (m_running) {
        std::unique_lock<std::mutex> lock(m_eventMutex);
        m_eventCv.wait(lock, [this] { return !m_eventQueue.empty() || !m_running; });
        
        if (!m_running) break;
        
        if (m_eventQueue.empty()) continue;
        
        SessionEvent event = m_eventQueue.front();
        m_eventQueue.pop();
        lock.unlock();
        
        try {
            if (auto* e = std::get_if<PeerDiscoveredEvent>(&event)) {
                handlePeerDiscoveredEvent(*e);
            } else if (auto* e = std::get_if<DataReceivedEvent>(&event)) {
                handleDataReceivedEvent(*e);
            } else if (auto* e = std::get_if<PeerDisconnectEvent>(&event)) {
                handlePeerDisconnectEvent(*e);
            } else if (auto* e = std::get_if<ConnectToPeerEvent>(&event)) {
                handleConnectToPeerEvent(*e);
            } else if (auto* e = std::get_if<SendMessageEvent>(&event)) {
                handleSendMessageEvent(*e);
            } else if (auto* e = std::get_if<TimerTickEvent>(&event)) {
                handleTimerTickEvent(*e);
            } else if (auto* e = std::get_if<DiscoveryInitiatedEvent>(&event)) {
                // Handle discovery initiation (queued from handleSendMessageEvent)
                if (m_broadcast_discovery && m_broadcast_discovery->is_running()) {
                    m_broadcast_discovery->discover_peer(e->peerId, 
                        [this](const DiscoveryResponse& response) {
                            handleDiscoveryResponse(response.responder_peer_id);
                        });
                }
            }
        } catch (const std::exception& e) {
            LOG_WARN("SM: Error processing event: " + std::string(e.what()));
        }
    }
}

void SessionManager::Impl::timerLoop() {
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Process scheduled events
        {
            std::lock_guard<std::mutex> lock(m_scheduled_events_mutex);
            auto now = std::chrono::steady_clock::now();
            auto it = m_scheduled_events.begin();
            while (it != m_scheduled_events.end()) {
                if (now >= it->second.due_time) {
                    pushEvent(it->second.event);
                    it = m_scheduled_events.erase(it);
                } else {
                    ++it;
                }
            }
        }
        
        pushEvent(TimerTickEvent{});
    }
}

void SessionManager::Impl::handlePeerDiscoveredEvent(const PeerDiscoveredEvent& event) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    
    auto it = m_peers.find(event.peerId);
    
    if (it == m_peers.end()) {
        Peer new_peer;
        new_peer.id = event.peerId;
        new_peer.ip = event.ip;
        new_peer.port = event.port;
        new_peer.network_id = event.ip + ":" + std::to_string(event.port);
        new_peer.last_seen = std::chrono::steady_clock::now();
        m_peers.insert({new_peer.id, new_peer});
        
        LOG_INFO("SM: New peer discovered: " + event.peerId);
        notifyPeerUpdate();
    }
}

void SessionManager::Impl::handlePeerDiscovered(const std::string& network_id, const std::string& peer_id) {
    // Parse network_id to extract IP and port
    size_t colon_pos = network_id.find(":");
    if (colon_pos == std::string::npos) {
        LOG_WARN("SM: Invalid network_id format: " + network_id);
        return;
    }
    
    std::string ip = network_id.substr(0, colon_pos);
    int port = std::stoi(network_id.substr(colon_pos + 1));
    
    // Create PeerDiscoveredEvent and push to event queue
    pushEvent(PeerDiscoveredEvent{ip, port, peer_id});
    LOG_INFO("SM: Discovery callback received for peer: " + peer_id + " at " + network_id);
}

void SessionManager::Impl::handleDataReceivedEvent(const DataReceivedEvent& event) {
    std::string peer_id;
    std::chrono::steady_clock::time_point last_seen;
    
    // Extract peer info with minimal lock
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        
        // Use fast lookup instead of linear search
        Peer* peer = find_peer_by_network_id(event.network_id);
        if (!peer) return;
        
        peer_id = peer->id;
        last_seen = event.arrival_time;
        peer->last_seen = event.arrival_time;
    }  // Lock released before any processing
    
    bool needs_update = false;
    
    try {
#if HAVE_NOISE_PROTOCOL
        // Handle Noise Protocol handshake messages
        if (event.data.rfind("NOISE:", 0) == 0 && m_use_noise_protocol) {
            std::string handshake_msg = event.data.substr(6);
            LOG_INFO("SM: Received Noise handshake from " + peer_id);
            
            std::string response = processNoiseHandshakeMessage(peer_id, handshake_msg);
            if (!response.empty()) {
                if (m_comms_mode == "TCP") {
                    m_tcpConnectionManager.sendMessageToPeer(event.network_id, "NOISE:" + response);
                } else {
                    m_udpConnectionManager.sendMessageToPeer(event.network_id, "NOISE:" + response);
                }
            }
            return;
        }
        
        // Handle encrypted application messages
        if (event.data.rfind("ENCRYPTED:", 0) == 0 && m_use_noise_protocol) {
            std::string ciphertext = event.data.substr(10);
            
            std::lock_guard<std::mutex> ssl_lock(m_secure_session_mutex);
            auto session = m_secure_session_manager->get_session(peer_id);
            if (!session || !session->is_ready()) {
                LOG_WARN("SM: Received encrypted message but session not ready for " + peer_id);
                return;
            }
            
            std::string plaintext = session->receive_message(ciphertext);
            LOG_INFO("SM: Decrypted message from " + peer_id);
            
            // Process decrypted message (recurse for control messages)
            if (plaintext.rfind("PING:", 0) == 0) {
                pushEvent(SendMessageEvent{peer_id, "PONG:" + plaintext.substr(5)});
            } else if (plaintext.rfind("PONG:", 0) == 0) {
                std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
                auto it = m_peers.find(peer_id);
                if (it != m_peers.end()) {
                    it->second.latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                        event.arrival_time - std::chrono::steady_clock::time_point(
                            std::chrono::milliseconds(std::stoll(plaintext.substr(5)))
                        )
                    ).count();
                    if (m_peer_tier_manager) {
                        m_peer_tier_manager->record_latency(peer_id, it->second.latency);
                    }
                    needs_update = true;
                }
            }
            return;
        }
#endif
        
        // Legacy message handling
        if (event.data.rfind("PING:", 0) == 0) {
            pushEvent(SendMessageEvent{peer_id, "PONG:" + event.data.substr(5)});
        } else if (event.data.rfind("PONG:", 0) == 0) {
            try {
                auto sent_time = std::chrono::steady_clock::time_point(
                    std::chrono::milliseconds(std::stoll(event.data.substr(5)))
                );
                
                std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
                auto it = m_peers.find(peer_id);
                if (it != m_peers.end()) {
                    it->second.latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                        event.arrival_time - sent_time
                    ).count();
                    if (m_peer_tier_manager) {
                        m_peer_tier_manager->record_latency(peer_id, it->second.latency);
                    }
                    needs_update = true;
                }
            } catch (...) {
                LOG_WARN("SM: Failed to parse PONG timestamp");
            }
        } else if (event.data.rfind("CONNECT:", 0) == 0) {
            std::string requesting_peer_id = event.data.substr(8);
            // Accept connection from any peer (the requesting peer ID is who wants to connect to us)
            std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
            auto it = m_peers.find(requesting_peer_id);
            if (it != m_peers.end()) {
                it->second.connected = true;
                pushEvent(SendMessageEvent{requesting_peer_id, "CONNECT_ACK:" + m_localPeerId});
                needs_update = true;
                LOG_INFO("SM: Accepted connection from " + requesting_peer_id);
            } else {
                // Add the peer if not already known
                Peer new_peer;
                new_peer.id = requesting_peer_id;
                new_peer.network_id = event.network_id;
                new_peer.connected = true;
                new_peer.last_seen = std::chrono::steady_clock::now();
                m_peers[requesting_peer_id] = new_peer;
                pushEvent(SendMessageEvent{requesting_peer_id, "CONNECT_ACK:" + m_localPeerId});
                needs_update = true;
                LOG_INFO("SM: Accepted connection from new peer " + requesting_peer_id);
            }
        } else if (event.data.rfind("CONNECT_ACK:", 0) == 0) {
            std::string ack_peer_id = event.data.substr(12);
            // Mark the connection as established when we receive an ACK
            std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
            auto it = m_peers.find(ack_peer_id);
            if (it != m_peers.end()) {
                it->second.connected = true;
                needs_update = true;
                LOG_INFO("SM: Connection confirmed with " + ack_peer_id);
            } else {
                // Add the peer if not already known
                Peer new_peer;
                new_peer.id = ack_peer_id;
                new_peer.network_id = event.network_id;
                new_peer.connected = true;
                new_peer.last_seen = std::chrono::steady_clock::now();
                m_peers[ack_peer_id] = new_peer;
                needs_update = true;
                LOG_INFO("SM: Connection confirmed with new peer " + ack_peer_id);
            }
        }
    } catch (const std::exception& e) {
        LOG_WARN("SM: Error in data handler: " + std::string(e.what()));
    }
    
    if (needs_update) notifyPeerUpdate();
}

void SessionManager::Impl::handlePeerDisconnectEvent(const PeerDisconnectEvent& event) {
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    
    // Use fast lookup instead of linear search
    Peer* peer = find_peer_by_network_id(event.network_id);
    if (!peer || !peer->connected) return;
    
    peer->connected = false;
    policy.on_connection_failure(peer->id, "DISCONNECT");
    LOG_INFO("SM: Peer disconnected: " + peer->id);
    
    {
        std::lock_guard<std::mutex> ka_lock(m_keepalive_mutex);
        m_keepalive_due.erase(peer->id);
    }
    
    auto strategy = policy.get_retry_strategy(peer->id);
    if (strategy.should_retry && strategy.backoff_ms > 0) {
        std::lock_guard<std::mutex> sched_lock(m_scheduled_events_mutex);
        m_scheduled_events[peer->id] = {
            ConnectToPeerEvent{peer->id},
            std::chrono::steady_clock::now() + std::chrono::milliseconds(strategy.backoff_ms)
        };
        LOG_INFO("SM: Scheduled reconnect for " + peer->id);
    }
    
    notifyPeerUpdate();
}

void SessionManager::Impl::handleConnectToPeerEvent(const ConnectToPeerEvent& event) {
    LOG_INFO("SM: Connection attempt to " + event.peerId);
    
    try {
        NATTraversal& nat = NATTraversal::getInstance();
        PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
        
        // Get peer info with minimal lock scope
        std::string peer_id, peer_ip, network_id;
        int peer_port;
        PeerReconnectPolicy::RetryStrategy retry_strategy;
        PeerTier peer_tier = PeerTier::TIER_1;
        
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            
            // Use fast lookup instead of linear search
            Peer* peer = find_peer_by_id(event.peerId);
            if (!peer) {
                LOG_WARN("SM: Peer not found: " + event.peerId);
                return;
            }
            
            peer_id = peer->id;
            peer_ip = peer->ip;
            peer_port = peer->port;
            network_id = peer->network_id;
            
            retry_strategy = policy.get_retry_strategy(peer->id);
            
            if (m_peer_tier_manager) {
                m_peer_tier_manager->record_latency(peer->id, 0);
                peer_tier = m_peer_tier_manager->get_peer_tier(peer->id);
            }
            
#if HAVE_NOISE_PROTOCOL
            if (m_use_noise_protocol) {
                initializeNoiseHandshake(peer->id);
            }
#endif
        } // Lock released here
        
        bool success = false;
        
        // Try TCP first (without holding the peers mutex)
        if (std::find(retry_strategy.methods.begin(), retry_strategy.methods.end(), "TCP") != retry_strategy.methods.end()) {
            if (m_tcpConnectionManager.connectToPeer(peer_ip, peer_port)) {
                LOG_INFO("SM: Connected to peer via TCP: " + peer_id + " IP: " + peer_ip + " Port: " + std::to_string(peer_port));
                {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    Peer* peer2 = find_peer_by_id(event.peerId);
                    if (peer2) {
                        peer2->connected = true;
                        peer2->network_id = peer_ip + ":" + std::to_string(peer_port);
                        policy.on_connection_success(peer_id, "TCP", 50);
                        notifyPeerUpdate();
                        return;
                    }
                }
                success = true;
            }
        }
        
        // Try UDP (without holding the peers mutex)
        if (m_comms_mode == "UDP" && !success) {
            std::string connect_msg = "CONNECT:" + m_localPeerId;
            m_udpConnectionManager.sendMessageToPeer(network_id, connect_msg);
            LOG_INFO("SM: Sent CONNECT via UDP to peer: " + peer_id + " IP: " + peer_ip + " Port: " + std::to_string(peer_port) + " Network ID: " + network_id);
            return;
        }
        
        // Connection failed - handle retry logic
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            Peer* peer = find_peer_by_id(event.peerId);
            if (!peer) {
                LOG_WARN("SM: Peer disappeared during connection attempt: " + event.peerId);
                return;
            }
            
            policy.on_connection_failure(peer->id, m_comms_mode);
            auto next_strategy = policy.get_retry_strategy(peer->id);
            
            if (m_peer_tier_manager) {
                PeerTier tier = m_peer_tier_manager->get_peer_tier(peer->id);
                if (tier == PeerTier::TIER_3 && m_broadcast_discovery && m_broadcast_discovery->is_running()) {
                    if (m_peers_being_discovered.find(peer->id) == m_peers_being_discovered.end()) {
                        m_peers_being_discovered.insert(peer->id);
                        LOG_INFO("SM: Initiating broadcast discovery for TIER_3 peer " + peer->id);
                        m_broadcast_discovery->discover_peer(peer->id, [this](const DiscoveryResponse& response) {
                            handleDiscoveryResponse(response.responder_peer_id);
                        });
                    }
                    return;
                }
            }
            
            LOG_WARN("SM: Connection failed to " + peer->id);
            
            if (next_strategy.should_retry && next_strategy.backoff_ms > 0) {
                std::lock_guard<std::mutex> sched_lock(m_scheduled_events_mutex);
                m_scheduled_events[peer->id] = {
                    ConnectToPeerEvent{peer->id},
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(next_strategy.backoff_ms)
                };
                LOG_INFO("SM: Scheduled reconnect for " + peer->id + " in " + std::to_string(next_strategy.backoff_ms) + "ms");
            }
        }
    } catch (const std::exception& e) {
        LOG_WARN("SM: Connection attempt failed: " + std::string(e.what()));
    } catch (...) {
        LOG_WARN("SM: Connection attempt failed with unknown error");
    }
}

void SessionManager::Impl::handleSendMessageEvent(const SendMessageEvent& event) {
    std::string network_id;
    PeerTier peer_tier;
    bool peer_connected = false;
    
    // SCOPE: Minimal lock hold time
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        
        // Use fast lookup instead of linear search
        const Peer* peer = find_peer_by_id(event.peerId);
        if (!peer) {
            LOG_WARN("SM: Peer not found: " + event.peerId);
            return;
        }
        
        network_id = peer->network_id;
        peer_connected = peer->connected;
    }  // Lock released here - before any blocking operations
    
    try {
        std::string internal_msg = event.message;
        if (internal_msg.rfind("MSG:", 0) != 0 && 
            internal_msg.rfind("PING:", 0) != 0 && 
            internal_msg.rfind("PONG:", 0) != 0) {
            internal_msg = "MSG:" + internal_msg;
        }
        
        bool is_control = (internal_msg.rfind("PING:", 0) == 0 || internal_msg.rfind("PONG:", 0) == 0);
        
        peer_tier = (m_peer_tier_manager) ? m_peer_tier_manager->get_peer_tier(event.peerId) : PeerTier::TIER_1;
        
        // TIER-based logic
        if (peer_tier == PeerTier::TIER_2 && !peer_connected) {
            std::lock_guard<std::mutex> pend_lock(m_pending_messages_mutex);
            m_pending_messages[event.peerId].push_back(internal_msg);
            return;
        } else if (peer_tier == PeerTier::TIER_3 && !peer_connected) {
            {
                std::lock_guard<std::mutex> pend_lock(m_pending_messages_mutex);
                m_pending_messages[event.peerId].push_back(internal_msg);
                
                if (m_peers_being_discovered.find(event.peerId) == m_peers_being_discovered.end() && m_broadcast_discovery) {
                    m_peers_being_discovered.insert(event.peerId);
                    // Queue discovery event instead of direct callback
                    pushEvent(DiscoveryInitiatedEvent{event.peerId});
                }
            }
            return;
        }
        
        // Use message batcher for non-control messages
        if (!is_control) {
            int batch_id = m_message_batcher->enqueue_message(event.peerId, internal_msg, false);
            if (batch_id != -1) {
                return;
            }
        }
        
#if HAVE_NOISE_PROTOCOL
        if (m_use_noise_protocol) {
            std::string ciphertext;
            {
                std::lock_guard<std::mutex> ssl_lock(m_secure_session_mutex);
                
                auto session = m_secure_session_manager->get_session(event.peerId);
                if (!session) {
                    queueMessage(event.peerId, internal_msg);
                    initializeNoiseHandshake(event.peerId);
                    return;
                }
                
                if (!session->is_ready()) {
                    queueMessage(event.peerId, internal_msg);
                    return;
                }
                
                try {
                    ciphertext = session->send_message(internal_msg);
                } catch (const std::exception& e) {
                    LOG_WARN("SM: Encryption error: " + std::string(e.what()));
                    ciphertext = "";
                }
            }  // Lock released before send
            
            if (!ciphertext.empty()) {
                if (m_comms_mode == "TCP") {
                    m_tcpConnectionManager.sendMessageToPeer(network_id, "ENCRYPTED:" + ciphertext);
                } else {
                    m_udpConnectionManager.sendMessageToPeer(network_id, "ENCRYPTED:" + ciphertext);
                }
            } else {
                // Graceful fallback to unencrypted
                if (m_comms_mode == "TCP") {
                    m_tcpConnectionManager.sendMessageToPeer(network_id, internal_msg);
                } else {
                    m_udpConnectionManager.sendMessageToPeer(network_id, internal_msg);
                }
            }
        } else {
            if (m_comms_mode == "TCP") {
                m_tcpConnectionManager.sendMessageToPeer(network_id, internal_msg);
            } else {
                m_udpConnectionManager.sendMessageToPeer(network_id, internal_msg);
            }
        }
#else
        if (m_comms_mode == "TCP") {
            m_tcpConnectionManager.sendMessageToPeer(network_id, internal_msg);
        } else {
            m_udpConnectionManager.sendMessageToPeer(network_id, internal_msg);
        }
#endif
    } catch (const std::exception& e) {
        LOG_WARN("SM: Error in send handler: " + std::string(e.what()));
    }
}

void SessionManager::Impl::handleTimerTickEvent(const TimerTickEvent&) {
    auto now = std::chrono::steady_clock::now();
    bool needs_update = false;
    
    try {
#if HAVE_NOISE_PROTOCOL
        if (m_use_noise_protocol) {
            std::lock_guard<std::mutex> lock(m_secure_session_mutex);
            
            auto it = m_handshake_states.begin();
            while (it != m_handshake_states.end()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.initiated_time
                ).count();
                
                if (it->second.status == HandshakeState::IN_PROGRESS && elapsed > HANDSHAKE_TIMEOUT_SEC) {
                    if (it->second.retry_count < MAX_HANDSHAKE_RETRIES) {
                        it->second.retry_count++;
                        it->second.initiated_time = now;
                        LOG_INFO("SM: Handshake retry for " + it->first);
                        m_secure_session_manager->remove_session(it->first);
                        initializeNoiseHandshake(it->first);
                    } else {
                        LOG_WARN("SM: Handshake failed for " + it->first);
                        it->second.status = HandshakeState::FAILED;
                        m_secure_session_manager->remove_session(it->first);
                    }
                } else if (it->second.status == HandshakeState::FAILED && elapsed > HANDSHAKE_TIMEOUT_SEC * 2) {
                    it = m_handshake_states.erase(it);
                    continue;
                }
                ++it;
            }
        }
#endif
        
        int ping_interval = m_battery_optimizer->get_ping_interval();
        static auto last_ping = std::chrono::steady_clock::now();
        auto elapsed_ping = std::chrono::duration_cast<std::chrono::seconds>(now - last_ping).count();
        
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            for (auto& kv : m_peers) {
                Peer& p = kv.second;
                if (p.connected && elapsed_ping >= ping_interval) {
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()
                    ).count();
                    LOG_INFO("SM: Sending heartbeat (PING) to peer: " + p.id + " at " + std::to_string(now_ms));
                    pushEvent(SendMessageEvent{p.id, "PING:" + std::to_string(now_ms)});
                }
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - p.last_seen).count();
                int timeout = m_battery_optimizer->get_config().peer_timeout_sec;
                if (elapsed > timeout && p.connected) {
                    p.connected = false;
                    p.latency = -1;
                    
#if HAVE_NOISE_PROTOCOL
                    if (m_use_noise_protocol) {
                        std::lock_guard<std::mutex> ssl_lock(m_secure_session_mutex);
                        m_secure_session_manager->remove_session(p.id);
                        m_handshake_states.erase(p.id);
                        m_pending_messages.erase(p.id);
                    }
#endif
                    m_session_cache->invalidate_session(p.id);
                    needs_update = true;
                    LOG_INFO("SM: Peer timeout: " + p.id);
                }
            }
        }
        
        if (elapsed_ping >= ping_interval) {
            last_ping = now;
        }
        
        m_session_cache->cleanup_expired();
    } catch (const std::exception& e) {
        LOG_WARN("SM: Error in timer handler: " + std::string(e.what()));
    }
    
    if (needs_update) notifyPeerUpdate();
}

void SessionManager::Impl::handleDiscoveryResponse(const std::string& discovered_peer_id) {
    LOG_INFO("SM: Discovery response for " + discovered_peer_id);
    
    {
        std::lock_guard<std::mutex> lock(m_scheduled_events_mutex);
        m_peers_being_discovered.erase(discovered_peer_id);
    }
    
    handleConnectToPeerEvent(ConnectToPeerEvent{discovered_peer_id});
    
    {
        std::lock_guard<std::mutex> lock(m_pending_messages_mutex);
        auto it = m_pending_messages.find(discovered_peer_id);
        if (it != m_pending_messages.end() && !it->second.empty()) {
            auto messages = it->second;
            m_pending_messages.erase(it);
            
            for (const auto& msg : messages) {
                pushEvent(SendMessageEvent{discovered_peer_id, msg});
            }
        }
    }
}

void SessionManager::Impl::initializeTierSystemCallbacks() {
    if (!m_failsafe) return;
    
    m_failsafe->set_error_callback([this](const SystemError& error) {
        LOG_WARN("SM: Tier error - " + error.component + ": " + error.description);
        
        try {
            if (error.component == "BroadcastDiscovery") {
                std::lock_guard<std::mutex> lock(m_scheduled_events_mutex);
                m_peers_being_discovered.erase(error.context);
            }
        } catch (...) {}
    });
    
    m_failsafe->set_health_callback([this](bool is_healthy) {
        if (!is_healthy) {
            LOG_WARN("SM: Tier system degraded");
        }
    });
    
    LOG_INFO("SM: Tier system callbacks initialized");
}

void SessionManager::Impl::notifyPeerUpdate() {
    if (m_peer_update_cb) {
        // Convert map to vector for callback compatibility
        std::vector<Peer> peer_list;
        peer_list.reserve(m_peers.size());
        for (const auto& kv : m_peers) {
            peer_list.push_back(kv.second);
        }
        m_peer_update_cb(peer_list);
    }
}

void SessionManager::Impl::set_battery_level(int percent, bool is_charging) {
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.set_battery_level(percent, is_charging);
    LOG_DEBUG("SM: Battery " + std::to_string(percent) + "%, charging: " + 
             (is_charging ? "true" : "false"));
}

void SessionManager::Impl::set_network_info(bool is_wifi, bool is_available) {
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.set_network_type(is_wifi, is_available);
    LOG_DEBUG("SM: Network - WiFi: " + (is_wifi ? std::string("true") : std::string("false")));
}

std::string SessionManager::Impl::get_reconnect_status_json() const {
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    return policy.get_status_json();
}

#if HAVE_NOISE_PROTOCOL
void SessionManager::Impl::initializeNoiseHandshake(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_secure_session_mutex);
    
    if (m_handshake_states.find(peer_id) == m_handshake_states.end()) {
        m_handshake_states[peer_id] = {
            HandshakeState::PENDING, std::chrono::steady_clock::now(), 0
        };
    }
    
    auto& state = m_handshake_states[peer_id];
    state.status = HandshakeState::IN_PROGRESS;
    state.initiated_time = std::chrono::steady_clock::now();
    
    LOG_INFO("SM: Initializing Noise handshake for " + peer_id);
    
    try {
        // Get or create session for this peer (as initiator)
        auto session = m_secure_session_manager->get_or_create_session(peer_id, NoiseSession::Role::INITIATOR);
        if (!session) {
            LOG_WARN("SM: Failed to create secure session for " + peer_id);
            state.status = HandshakeState::FAILED;
            return;
        }
        
        // Start the handshake and get the first message to send
        std::string handshake_msg = session->start_handshake();
        if (!handshake_msg.empty()) {
            // Send the handshake message to the peer
            std::string network_id;
            {
                std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
                // Use fast lookup instead of linear search
                const Peer* peer = find_peer_by_id(peer_id);
                if (peer) {
                    network_id = peer->network_id;
                }
            }
            
            if (!network_id.empty()) {
                if (m_comms_mode == "TCP") {
                    m_tcpConnectionManager.sendMessageToPeer(network_id, "NOISE:" + handshake_msg);
                } else {
                    m_udpConnectionManager.sendMessageToPeer(network_id, "NOISE:" + handshake_msg);
                }
                LOG_INFO("SM: Sent Noise handshake to " + peer_id);
            } else {
                LOG_WARN("SM: Could not find network ID for peer " + peer_id);
                state.status = HandshakeState::FAILED;
            }
        } else {
            LOG_WARN("SM: Failed to start Noise handshake with " + peer_id);
            state.status = HandshakeState::FAILED;
        }
    } catch (const std::exception& e) {
        LOG_WARN("SM: Exception in initializeNoiseHandshake: " + std::string(e.what()));
        state.status = HandshakeState::FAILED;
    }
}

std::string SessionManager::Impl::processNoiseHandshakeMessage(const std::string& peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_secure_session_mutex);
    LOG_INFO("SM: Processing Noise handshake message from " + peer_id);
    
    try {
        // Get or create session for this peer (as responder)
        auto session = m_secure_session_manager->get_or_create_session(peer_id, NoiseSession::Role::RESPONDER);
        if (!session) {
            LOG_WARN("SM: Failed to create secure session for " + peer_id);
            return "";
        }
        
        // Process the handshake message
        std::string response = session->process_handshake(message);
        
        // Update handshake state
        auto it = m_handshake_states.find(peer_id);
        if (it != m_handshake_states.end()) {
            if (session->is_ready()) {
                it->second.status = HandshakeState::COMPLETE;
                LOG_INFO("SM: Noise handshake completed successfully with " + peer_id);
                
                // Flush any queued messages now that session is ready
                flushQueuedMessages(peer_id);
            } else if (!response.empty()) {
                // Handshake still in progress
                it->second.status = HandshakeState::IN_PROGRESS;
            } else {
                // Handshake failed
                it->second.status = HandshakeState::FAILED;
                LOG_WARN("SM: Noise handshake failed with " + peer_id);
            }
        }
        
        return response;
    } catch (const std::exception& e) {
        LOG_WARN("SM: Exception in processNoiseHandshakeMessage: " + std::string(e.what()));
        // Mark handshake as failed
        auto it = m_handshake_states.find(peer_id);
        if (it != m_handshake_states.end()) {
            it->second.status = HandshakeState::FAILED;
        }
        return "";
    }
}

void SessionManager::Impl::queueMessage(const std::string& peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_pending_messages_mutex);
    auto& queue = m_pending_messages[peer_id];
    
    if (queue.size() < MAX_QUEUED_MESSAGES) {
        queue.push_back(message);
    } else {
        // Implement eviction policy: remove oldest message and add new one
        // This maintains the queue size while ensuring the most recent messages are kept
        queue.erase(queue.begin()); // Remove oldest message
        queue.push_back(message);   // Add new message at the end
        LOG_DEBUG("SM: Evicted oldest message for peer " + peer_id + " to maintain queue size");
    }
}

void SessionManager::Impl::flushQueuedMessages(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_pending_messages_mutex);
    auto it = m_pending_messages.find(peer_id);
    if (it != m_pending_messages.end()) {
        it->second.clear();
    }
}
#endif

// Helper functions for fast peer lookups
Peer* SessionManager::Impl::find_peer_by_id(const std::string& peer_id) {
    auto it = m_peers.find(peer_id);
    if (it != m_peers.end()) {
        return &it->second;
    }
    return nullptr;
}

const Peer* SessionManager::Impl::find_peer_by_id(const std::string& peer_id) const {
    auto it = m_peers.find(peer_id);
    if (it != m_peers.end()) {
        return &it->second;
    }
    return nullptr;
}

Peer* SessionManager::Impl::find_peer_by_network_id(const std::string& network_id) {
    auto it = m_peers.begin();
    while (it != m_peers.end()) {
        if (it->second.network_id == network_id) {
            return &it->second;
        }
        ++it;
    }
    return nullptr;
}

const Peer* SessionManager::Impl::find_peer_by_network_id(const std::string& network_id) const {
    auto it = m_peers.begin();
    while (it != m_peers.end()) {
        if (it->second.network_id == network_id) {
            return &it->second;
        }
        ++it;
    }
    return nullptr;
}

void SessionManager::Impl::update_peer_indexes() {
    // No-op: indexes are implicit in the unordered_map
}

void SessionManager::Impl::remove_peer_from_indexes(size_t index) {
    // No-op: indexes are implicit in the unordered_map
}

// Safely remove a peer by ID, updating indexes
void SessionManager::Impl::remove_peer_by_id(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    m_peers.erase(peer_id);
}

// Unified communication interface to reduce code duplication
void SessionManager::Impl::send_message_to_peer(const std::string& network_id, const std::string& message) {
    if (m_comms_mode == "TCP") {
        m_tcpConnectionManager.sendMessageToPeer(network_id, message);
    } else {
        m_udpConnectionManager.sendMessageToPeer(network_id, message);
    }
}

// ============================================================================
// PUBLIC SESSIONMANAGER CLASS
// ============================================================================

SessionManager::SessionManager() : m_impl(std::make_unique<Impl>()) {}
SessionManager::~SessionManager() = default;

void SessionManager::start(int p, std::function<void(const std::vector<Peer>&)> cb, 
                          const std::string& cm, const std::string& pi) {
    m_impl->start(p, cb, cm, pi);
}

void SessionManager::stop() { m_impl->stop(); }
void SessionManager::connectToPeer(const std::string& pid) { m_impl->connectToPeer(pid); }
void SessionManager::sendMessageToPeer(const std::string& pid, const std::string& msg) { m_impl->sendMessageToPeer(pid, msg); }

void SessionManager::set_optimization_level(BatteryOptimizer::OptimizationLevel level) {
    auto* opt = m_impl->get_battery_optimizer();
    if (opt) opt->set_optimization_level(level);
}

void SessionManager::set_network_type(BatteryOptimizer::NetworkType type) {
    auto* opt = m_impl->get_battery_optimizer();
    if (opt) opt->set_network_type(type);
}

int SessionManager::get_cached_session_count() const {
    auto* cache = m_impl->get_session_cache();
    return cache ? cache->get_cached_count() : 0;
}

int SessionManager::get_session_cache_hit_rate() const {
    auto* cache = m_impl->get_session_cache();
    return cache ? cache->get_hit_rate() : 0;
}

BatteryOptimizer::OptimizationConfig SessionManager::get_optimization_config() const {
    auto* opt = m_impl->get_battery_optimizer();
    return opt ? opt->get_config() : BatteryOptimizer::OptimizationConfig();
}

void SessionManager::enable_noise_nk() {
    m_impl->enable_noise_nk();
}

bool SessionManager::is_noise_nk_enabled() const {
    return m_impl->is_noise_nk_enabled();
}

std::vector<uint8_t> SessionManager::get_local_static_public_key() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) return store->get_local_static_public_key();
#endif
    return {};
}

void SessionManager::register_peer_nk_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk) {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) store->register_peer_key(peer_id, static_pk);
    auto* mgr = m_impl->get_noise_nk_manager();
    if (mgr) mgr->register_peer_key(peer_id, static_pk);
#endif
}

bool SessionManager::has_peer_nk_key(const std::string& peer_id) const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) return store->has_peer_key(peer_id);
#endif
    return false;
}

int SessionManager::get_nk_peer_count() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) return store->get_peer_count();
#endif
    return 0;
}

std::vector<std::string> SessionManager::get_nk_peer_ids() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) return store->get_all_peer_ids();
#endif
    return {};
}

bool SessionManager::import_nk_peer_keys_hex(const std::map<std::string, std::string>& hex_keys) {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) return store->import_peer_keys_hex(hex_keys);
#endif
    return false;
}

std::map<std::string, std::string> SessionManager::export_nk_peer_keys_hex() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) return store->export_peer_keys_hex();
#endif
    return {};
}

void SessionManager::set_battery_level(int batteryPercent, bool isCharging) {
    m_impl->set_battery_level_public(batteryPercent, isCharging);
}

void SessionManager::set_network_info(bool isWiFi, bool isNetworkAvailable) {
    m_impl->set_network_info_public(isWiFi, isNetworkAvailable);
}

std::string SessionManager::get_reconnect_status_json() const {
    return m_impl->get_reconnect_status_json_public();
}

std::string SessionManager::send_file(const std::string& peer_id, const std::string& file_path,
                                     const std::string& transfer_id, int priority,
                                     TransferPriority transfer_priority, PathSelectionStrategy strategy) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    if (!ft_mgr) return "";
    // Extract peer IP and port from peer list if available
    return ft_mgr->send_file(file_path, peer_id, "", 0, transfer_priority, strategy);
}

bool SessionManager::receive_file(const std::string& peer_id, const std::string& file_name,
                                 const std::string& save_path, const std::string& checkpoint_path,
                                 int priority, uint64_t max_transfer_time_ms) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->receive_file("", save_path, peer_id, "", 0, 0) : false;
}

bool SessionManager::pause_transfer(const std::string& transfer_id) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->pause_transfer(transfer_id) : false;
}

bool SessionManager::resume_transfer(const std::string& transfer_id) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->resume_transfer(transfer_id) : false;
}

bool SessionManager::cancel_transfer(const std::string& transfer_id) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->cancel_transfer(transfer_id) : false;
}

std::string SessionManager::register_network_path(const std::string& path_id, const std::string& host,
                                                 const std::string& ip, int port, int bandwidth_mbps,
                                                 int latency_ms) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->register_network_path(path_id, host, ip, port, latency_ms, bandwidth_mbps * 1000) : "";
}

std::string SessionManager::request_file_transfer(const std::string& peer_id, const std::string& file_path,
                                                  TransferPriority priority, PathSelectionStrategy strategy) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    if (!ft_mgr) return "";
    // Generate transfer ID and initiate transfer
    std::string transfer_id = peer_id + "_" + file_path;
    return ft_mgr->send_file(file_path, peer_id, "", 0, priority, strategy);
}

std::string SessionManager::find_optimal_path(const std::string& peer_id, PathSelectionStrategy strategy) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    if (!ft_mgr) return "";
    auto path = ft_mgr->find_optimal_path(peer_id, strategy);
    return path ? path->path_id : "";
}

float SessionManager::get_transfer_progress(const std::string& transfer_id) const {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->get_transfer_progress(transfer_id) : 0.0f;
}

float SessionManager::get_transfer_speed(const std::string& transfer_id) const {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->get_transfer_speed(transfer_id) : 0.0f;
}

std::vector<std::string> SessionManager::get_active_transfers() const {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->get_active_transfers() : std::vector<std::string>();
}

void SessionManager::report_congestion(const std::string& path_id, const CongestionMetrics& metrics) {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    if (ft_mgr) ft_mgr->report_congestion(path_id, metrics);
}

uint32_t SessionManager::get_adaptive_rate_limit() const {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->get_adaptive_rate_limit() : 1024;
}

bool SessionManager::can_resume_transfer(const std::string& checkpoint_path) const {
    auto* ft_mgr = m_impl->get_file_transfer_manager();
    return ft_mgr ? ft_mgr->can_resume_transfer(checkpoint_path) : false;
}
