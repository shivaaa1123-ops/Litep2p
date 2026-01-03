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

// Implementation class
class SessionManager::Impl {
public:
    Impl(std::shared_ptr<ISessionDependenciesFactory> factory);
    ~Impl();
    
    void start(int port, std::function<void(const std::vector<Peer>&)> cb, const std::string& comms_mode, const std::string& peer_id);
    void stop();
    void stopAsync(std::function<void()> completionCallback);
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
    
    // Message handling
    void handleSendMessageWithRetry(const std::string& peer_id, const std::string& network_id, 
                                   const std::string& message, const std::string& message_id = "");
    void handleMessageSendComplete(const MessageSendCompleteEvent& event);
    
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
    void handleFSMEvent(const FSMEvent& event);
    
    // Helper function to convert PeerState to string
    std::string state_to_string(PeerState state) const;
    
    // Synchronization for async operations
    mutable std::mutex m_stop_mutex;
    std::condition_variable m_stop_cv;
    std::atomic<bool> m_stopped;

    // Helper functions for fast peer lookups
    Peer* find_peer_by_id(const std::string& peer_id);
    const Peer* find_peer_by_id(const std::string& peer_id) const;
    Peer* find_peer_by_network_id(const std::string& network_id);
    const Peer* find_peer_by_network_id(const std::string& network_id) const;
    
    // Network ID index management
    void add_peer_to_network_index(const std::string& peer_id, const std::string& network_id);
    void remove_peer_from_network_index(const std::string& network_id);
    void update_peer_network_index(const std::string& old_network_id, const std::string& peer_id, const std::string& new_network_id);
    void update_peer_indexes();
    void remove_peer_from_indexes(size_t index);
    
    // Safely remove a peer by ID, updating indexes
    void remove_peer_by_id(const std::string& peer_id);

    // Unified communication interface to reduce code duplication
    void send_message_to_peer(const std::string& network_id, const std::string& message);

    // Member variables
    std::atomic<bool> m_running;
    std::unique_ptr<ITcpConnectionManager> m_tcpConnectionManager;
    std::unique_ptr<IUdpConnectionManager> m_udpConnectionManager;
    std::unordered_map<std::string, Peer> m_peers; // Key: peer.id
    std::function<void(const std::vector<Peer>&)> m_peer_update_cb;
    std::string m_localPeerId;
    std::string m_comms_mode;
    
    std::shared_ptr<ISessionDependenciesFactory> m_factory;
    std::unique_ptr<PeerIndex> m_peer_index;
    std::mutex m_keepalive_mutex;
    
    // Network ID to Peer ID mapping for O(1) lookups
    std::unordered_map<std::string, std::string> m_network_id_to_peer_id;
    mutable std::mutex m_network_index_mutex;
    
    std::unique_ptr<TierSystemFailsafe> m_failsafe;
    std::unique_ptr<PeerTierManager> m_peer_tier_manager;
    std::unique_ptr<BroadcastDiscoveryManager> m_broadcast_discovery;
    std::unique_ptr<FileTransferManager> m_file_transfer_manager;
    std::unique_ptr<EventManager> m_event_manager;
    
    // Peer State Machine
    PeerStateMachine m_peer_fsm;
    std::unordered_map<std::string, PeerContext> m_peer_contexts; // Key: peer.id
    
    std::queue<SessionEvent> m_eventQueue;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCv;
    mutable std::mutex m_peers_mutex;

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
    
    // Peer discovery and message queuing
    std::unordered_set<std::string> m_peers_being_discovered;
    
    // Scheduled events for retries and timeouts
    std::map<std::string, ScheduledEvent> m_scheduledEvents;
    std::mutex m_scheduledEventsMutex;
    
    static constexpr int MAX_QUEUED_MESSAGES = 100;
};

// ============================================================================
// IMPLEMENTATION
// ============================================================================

SessionManager::Impl::Impl(std::shared_ptr<ISessionDependenciesFactory> factory)
    : m_factory(factory ? factory : std::make_shared<DefaultSessionDependenciesFactory>()),
      m_running(false), m_use_noise_protocol(false), m_noise_nk_enabled(false),
      m_peer_tier_manager(nullptr),
      m_broadcast_discovery(nullptr),
      m_stopped(false) {
    
    // Initialize dependent members after m_factory is initialized
    m_peer_index = m_factory->createPeerIndex();
    m_battery_optimizer = m_factory->createBatteryOptimizer();
    m_session_cache = m_factory->createSessionCache();
    m_message_batcher = m_factory->createMessageBatcher(100, 10);  // Using default values
    m_failsafe = m_factory->createTierSystemFailsafe();
    m_file_transfer_manager = m_factory->createFileTransferManager();
    m_event_manager = m_factory->createEventManager();
    m_tcpConnectionManager = m_factory->createTcpConnectionManager();
    m_udpConnectionManager = m_factory->createUdpConnectionManager();
    
    m_battery_optimizer->set_optimization_level(BatteryOptimizer::OptimizationLevel::BALANCED);
    LOG_INFO("SM: Battery optimization enabled (BALANCED mode)");
    
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.initialize(100, true);
    LOG_INFO("SM: Reconnect policy initialized");
    
#if HAVE_NOISE_PROTOCOL
    m_use_noise_protocol = true;
    m_secure_session_manager = m_factory->createSecureSessionManager();
    m_noise_nk_manager = m_factory->createNoiseNKManager();
    m_noise_key_store = m_factory->createNoiseKeyStore();
    m_noise_key_store->initialize();
    if (m_secure_session_manager && m_noise_nk_manager && m_noise_key_store) {
        m_secure_session_manager->set_noise_backend(m_noise_nk_manager.get(), m_noise_key_store.get());
    }
    LOG_INFO("SM: Noise Protocol support enabled");
#else
    LOG_INFO("SM: Noise Protocol not available");
#endif
}

std::string SessionManager::Impl::state_to_string(PeerState state) const {
    switch (state) {
        case PeerState::UNKNOWN: return "UNKNOWN";
        case PeerState::DISCOVERED: return "DISCOVERED";
        case PeerState::CONNECTING: return "CONNECTING";
        case PeerState::CONNECTED: return "CONNECTED";
        case PeerState::HANDSHAKING: return "HANDSHAKING";
        case PeerState::READY: return "READY";
        case PeerState::DEGRADED: return "DEGRADED";
        case PeerState::DISCONNECTED: return "DISCONNECTED";
        case PeerState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
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
    
    m_peer_tier_manager = m_factory->createPeerTierManager();
    m_broadcast_discovery = m_factory->createBroadcastDiscoveryManager();
    
    // Initialize broadcast discovery manager
    if (!m_broadcast_discovery->initialize()) {
        LOG_WARN("SM: Failed to initialize broadcast discovery manager");
    } else {
        LOG_INFO("SM: Broadcast discovery manager initialized successfully");
    }
    
    // Clear peer contexts when starting
    m_peer_contexts.clear();
    Discovery* discovery = getGlobalDiscoveryInstance();
    discovery->start(port, peer_id);
    discovery->setCallback([this](const std::string& network_id, const std::string& peer_id) {
        handlePeerDiscovered(network_id, peer_id);
    });
    
    LOG_INFO("SM: Starting session manager on port " + std::to_string(port));
    LOG_INFO("SM: Comms mode: " + comms_mode);
    
    initializeTierSystemCallbacks();
    
    if (comms_mode == "TCP") {
        // For now, we'll still create the connection managers directly since they're 
        // part of the core transport layer and not easily mockable
        m_tcpConnectionManager->startServer(port, 
            [this](const std::string& id, const std::string& data) { onData(id, data); },
            [this](const std::string& id) { onDisconnect(id); });
    } else {
        m_udpConnectionManager->startServer(port,
            [this](const std::string& id, const std::string& data) { onData(id, data); },
            [this](const std::string& id) { onDisconnect(id); });
    }
    
    // Start the EventManager with our event handler
    if (m_event_manager) {
        m_event_manager->startEventProcessing([this](const SessionEvent& event) {
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
                } else if (auto* e = std::get_if<MessageSendCompleteEvent>(&event)) {
                    handleMessageSendComplete(*e);
                } else if (auto* e = std::get_if<FSMEvent>(&event)) {
                    handleFSMEvent(*e);
                }
            } catch (const std::exception& e) {
                LOG_WARN("SM: Error processing event: " + std::string(e.what()));
            }
        });
    }
    
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
    
    // Notify all peers of shutdown using FSM
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        for (auto& pair : m_peer_contexts) {
            pushEvent(SessionEvent(FSMEvent{pair.first, PeerEvent::SHUTDOWN}));
        }
    }
    
    // Stop the EventManager
    if (m_event_manager) {
        m_event_manager->stopEventProcessing();
    }
    
    // Stop the low-level UDP discovery service first to prevent blocking
    LOG_INFO("SM: Stopping discovery service...");
    Discovery* discovery = getGlobalDiscoveryInstance();
    discovery->stop();
    LOG_INFO("SM: Discovery service stopped.");
    
    if (m_comms_mode == "TCP") {
        LOG_INFO("SM: Stopping TCP connection manager...");
        m_tcpConnectionManager->stop();
        LOG_INFO("SM: TCP connection manager stopped.");
    } else {
        LOG_INFO("SM: Stopping UDP connection manager...");
        m_udpConnectionManager->stop();
        LOG_INFO("SM: UDP connection manager stopped.");
    }
    
    // Clear peer data
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        m_peers.clear();
        m_peer_contexts.clear();
        // Clear network index
        {
            std::lock_guard<std::mutex> index_lock(m_network_index_mutex);
            m_network_id_to_peer_id.clear();
        }
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
    if (m_event_manager) {
        m_event_manager->pushEvent(std::move(event));
    } else {
        // Fallback to original implementation if EventManager is not available
        {
            std::lock_guard<std::mutex> lock(m_eventMutex);
            m_eventQueue.push(std::move(event));
        }
        m_eventCv.notify_one();
    }
}

void SessionManager::Impl::handleSendMessageWithRetry(const std::string& peer_id, 
                                                     const std::string& network_id, 
                                                     const std::string& message,
                                                     const std::string& message_id) {
    std::string actual_message_id = message_id.empty() ? 
        peer_id + "_" + std::to_string(std::hash<std::string>{}(message)) : message_id;
    
    std::string message_with_ack = message;
    
    // Send the message
    bool send_initiated = false;
    
#if HAVE_NOISE_PROTOCOL
    if (m_use_noise_protocol) {
        std::string ciphertext;
        {
            std::lock_guard<std::mutex> ssl_lock(m_secure_session_mutex);
            
            auto session = m_secure_session_manager->get_session(peer_id);
            if (!session) {
                queueMessage(peer_id, message_with_ack);
                // FSM will handle handshake initiation through side effects
                return;
            }
            
            // Check peer state instead of session readiness
            bool is_peer_ready = false;
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                auto it = m_peer_contexts.find(peer_id);
                if (it != m_peer_contexts.end()) {
                    is_peer_ready = (it->second.state == PeerState::READY);
                }
            }
            
            if (!is_peer_ready) {
                queueMessage(peer_id, message_with_ack);
                return;
            }
            
            try {
                ciphertext = session->send_message(message_with_ack);
            } catch (const std::exception& e) {
                LOG_WARN("SM: Encryption error: " + std::string(e.what()));
                ciphertext = "";
            }
        }  // Lock released before send
        
        if (!ciphertext.empty()) {
            if (m_comms_mode == "TCP") {
                m_tcpConnectionManager->sendMessageToPeer(network_id, "ENCRYPTED:" + ciphertext);
                send_initiated = true;
                // For TCP, we assume success and immediately send completion event
                pushEvent(MessageSendCompleteEvent{peer_id, actual_message_id, true, ""});
            } else {
                m_udpConnectionManager->sendMessageToPeer(network_id, "ENCRYPTED:" + ciphertext);
                send_initiated = true;
                // For UDP, FSM will handle acknowledgment through side effects
                LOG_DEBUG("SM: Sent UDP message: " + actual_message_id);
            }
        } else {
            // Graceful fallback to unencrypted
            if (m_comms_mode == "TCP") {
                m_tcpConnectionManager->sendMessageToPeer(network_id, message_with_ack);
                send_initiated = true;
                // For TCP, we assume success and immediately send completion event
                pushEvent(SessionEvent(MessageSendCompleteEvent{peer_id, actual_message_id, true, ""}));
            } else {
                m_udpConnectionManager->sendMessageToPeer(network_id, message_with_ack);
                send_initiated = true;
                // For UDP, FSM will handle acknowledgment through side effects
                LOG_DEBUG("SM: Sent UDP message: " + actual_message_id);
            }
        }
    } else {
        if (m_comms_mode == "TCP") {
            m_tcpConnectionManager->sendMessageToPeer(network_id, message_with_ack);
            send_initiated = true;
            // For TCP, we assume success and immediately send completion event
            pushEvent(SessionEvent(MessageSendCompleteEvent{peer_id, actual_message_id, true, ""}));
        } else {
            m_udpConnectionManager->sendMessageToPeer(network_id, message_with_ack);
            send_initiated = true;
            // For UDP, FSM will handle acknowledgment through side effects
            LOG_DEBUG("SM: Sent UDP message: " + actual_message_id);
        }
    }
#else
    if (m_comms_mode == "TCP") {
        m_tcpConnectionManager->sendMessageToPeer(network_id, message_with_ack);
        send_initiated = true;
        // For TCP, we assume success and immediately send completion event
        pushEvent(MessageSendCompleteEvent{peer_id, actual_message_id, true, ""});
    } else {
        m_udpConnectionManager->sendMessageToPeer(network_id, message_with_ack);
        send_initiated = true;
        // For UDP, FSM will handle acknowledgment through side effects
        LOG_DEBUG("SM: Sent UDP message: " + actual_message_id);
    }
#endif
    
    // If we couldn't even initiate the send, handle immediate failure
    if (!send_initiated) {
        LOG_WARN("SM: Failed to initiate message send to peer: " + peer_id);
        // Push a failure event immediately
        pushEvent(SessionEvent(MessageSendCompleteEvent{peer_id, actual_message_id, false, "Failed to initiate send"}));
    }
    // FSM will handle all message completion and retry logic through side effects
}

void SessionManager::Impl::handleMessageSendComplete(const MessageSendCompleteEvent& event) {
    // FSM will handle message send completion through its state transitions
    // No need to track message retries or acknowledgments outside the FSM
}

void SessionManager::Impl::onData(const std::string& network_id, const std::string& data) {
    auto now = std::chrono::steady_clock::now();
    pushEvent(DataReceivedEvent{network_id, data, now});
}

void SessionManager::Impl::onDisconnect(const std::string& network_id) {
    pushEvent(PeerDisconnectEvent{network_id});
}

void SessionManager::Impl::processEventQueue() {
    // This method is no longer used as we're now using EventManager
    // The implementation has been moved to EventManager::processEventQueue
}

void SessionManager::Impl::timerLoop() {
    // This method is no longer used as we're now using EventManager
    // The implementation has been moved to EventManager::timerLoop
}

void SessionManager::Impl::handlePeerDiscoveredEvent(const PeerDiscoveredEvent& event) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    
    // Create or update peer context
    auto& peer_ctx = m_peer_contexts[event.peerId];
    if (peer_ctx.peer_id.empty()) {
        // New peer
        peer_ctx = PeerContext(event.peerId, event.ip + ":" + std::to_string(event.port));
        peer_ctx.last_seen = std::chrono::steady_clock::now();
        
        // Apply FSM event through EventManager to avoid running under lock
        pushEvent(SessionEvent(FSMEvent{event.peerId, PeerEvent::DISCOVERED}));
    } else {
        // Existing peer, update last seen
        peer_ctx.last_seen = std::chrono::steady_clock::now();
    }
    
    // Update the legacy peer structure for compatibility
    auto it = m_peers.find(event.peerId);
    if (it == m_peers.end()) {
        Peer new_peer;
        new_peer.id = event.peerId;
        new_peer.ip = event.ip;
        new_peer.port = event.port;
        new_peer.network_id = event.ip + ":" + std::to_string(event.port);
        new_peer.last_seen = std::chrono::steady_clock::now();
        m_peers.insert({new_peer.id, new_peer});
        
        // Add to network index
        add_peer_to_network_index(new_peer.id, new_peer.network_id);
        
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
        
        // Update peer state using FSM for message received
        auto it = m_peer_contexts.find(peer_id);
        if (it != m_peer_contexts.end()) {
            pushEvent(SessionEvent(FSMEvent{peer_id, PeerEvent::MESSAGE_RECEIVED}));
        }
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
                    m_tcpConnectionManager->sendMessageToPeer(event.network_id, "NOISE:" + response);
                } else {
                    m_udpConnectionManager->sendMessageToPeer(event.network_id, "NOISE:" + response);
                }
            }
            return;
        }
        
        // Handle encrypted application messages
        if (event.data.rfind("ENCRYPTED:", 0) == 0 && m_use_noise_protocol) {
            std::string ciphertext = event.data.substr(10);
            
            std::lock_guard<std::mutex> ssl_lock(m_secure_session_mutex);
            auto session = m_secure_session_manager->get_session(peer_id);
            // Check peer state instead of session readiness
            bool is_peer_ready = false;
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                auto it = m_peer_contexts.find(peer_id);
                if (it != m_peer_contexts.end()) {
                    is_peer_ready = (it->second.state == PeerState::READY);
                }
            }
            
            if (!session || !is_peer_ready) {
                LOG_WARN("SM: Received encrypted message but peer not ready for " + peer_id);
                return;
            }
            
            std::string plaintext = session->receive_message(ciphertext);
            LOG_INFO("SM: Decrypted message from " + peer_id);
            
            // Process decrypted message (recurse for control messages)
            if (plaintext.rfind("PING:", 0) == 0) {
                pushEvent(SessionEvent(SendMessageEvent{peer_id, "PONG:" + plaintext.substr(5)}));
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
        
        // Handle messages with acknowledgment requests
        std::string message_content = event.data;
        size_t ack_pos = event.data.find("|ACK_ID:");
        if (ack_pos != std::string::npos) {
            message_content = event.data.substr(0, ack_pos);
            std::string ack_id = event.data.substr(ack_pos + 8); // Skip "|ACK_ID:"
            
            // Send acknowledgment back to sender
            if (m_comms_mode == "UDP") {
                std::string ack_message = "ACK:" + ack_id;
                if (m_comms_mode == "TCP") {
                    m_tcpConnectionManager->sendMessageToPeer(event.network_id, ack_message);
                } else {
                    m_udpConnectionManager->sendMessageToPeer(event.network_id, ack_message);
                }
                LOG_DEBUG("SM: Sent acknowledgment for message: " + ack_id);
            }
        }
        
        // Legacy message handling
        if (message_content.rfind("PING:", 0) == 0) {
            pushEvent(SessionEvent(SendMessageEvent{peer_id, "PONG:" + message_content.substr(5)}));
        } else if (message_content.rfind("PONG:", 0) == 0) {
            try {
                auto sent_time = std::chrono::steady_clock::time_point(
                    std::chrono::milliseconds(std::stoll(message_content.substr(5)))
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
        } else if (message_content.rfind("CONNECT:", 0) == 0) {
            std::string requesting_peer_id = message_content.substr(8);
            // Accept connection from any peer (the requesting peer ID is who wants to connect to us)
            std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
            auto it = m_peers.find(requesting_peer_id);
            if (it != m_peers.end()) {
                // Update peer state using FSM instead of directly modifying the connected field
                auto ctx_it = m_peer_contexts.find(requesting_peer_id);
                if (ctx_it != m_peer_contexts.end()) {
                    pushEvent(SessionEvent(FSMEvent{requesting_peer_id, PeerEvent::CONNECT_SUCCESS}));
                }
                pushEvent(SessionEvent(SendMessageEvent{requesting_peer_id, "CONNECT_ACK:" + m_localPeerId}));
                needs_update = true;
                LOG_INFO("SM: Accepted connection from " + requesting_peer_id);
            } else {
                // Add the peer if not already known
                Peer new_peer;
                new_peer.id = requesting_peer_id;
                new_peer.network_id = event.network_id;
                new_peer.last_seen = std::chrono::steady_clock::now();
                m_peers[requesting_peer_id] = new_peer;
                // Add to network index
                add_peer_to_network_index(new_peer.id, new_peer.network_id);
                // Add peer context for FSM
                auto& peer_ctx = m_peer_contexts[requesting_peer_id];
                peer_ctx = PeerContext(requesting_peer_id, event.network_id);
                pushEvent(SessionEvent(FSMEvent{requesting_peer_id, PeerEvent::CONNECT_SUCCESS}));
                pushEvent(SessionEvent(SendMessageEvent{requesting_peer_id, "CONNECT_ACK:" + m_localPeerId}));
                needs_update = true;
                LOG_INFO("SM: Accepted connection from new peer " + requesting_peer_id);
            }
        } else if (message_content.rfind("CONNECT_ACK:", 0) == 0) {
            std::string ack_peer_id = message_content.substr(12);
            // Mark the connection as established when we receive an ACK
            std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
            auto it = m_peers.find(ack_peer_id);
            if (it != m_peers.end()) {
                // Update peer state using FSM instead of directly modifying the connected field
                auto ctx_it = m_peer_contexts.find(ack_peer_id);
                if (ctx_it != m_peer_contexts.end()) {
                    pushEvent(SessionEvent(FSMEvent{ack_peer_id, PeerEvent::CONNECT_SUCCESS}));
                }
                needs_update = true;
                LOG_INFO("SM: Connection confirmed with " + ack_peer_id);
            } else {
                // Add the peer if not already known
                Peer new_peer;
                new_peer.id = ack_peer_id;
                new_peer.network_id = event.network_id;
                new_peer.last_seen = std::chrono::steady_clock::now();
                m_peers[ack_peer_id] = new_peer;
                // Add to network index
                add_peer_to_network_index(new_peer.id, new_peer.network_id);
                // Add peer context for FSM
                auto& peer_ctx = m_peer_contexts[ack_peer_id];
                peer_ctx = PeerContext(ack_peer_id, event.network_id);
                pushEvent(SessionEvent(FSMEvent{ack_peer_id, PeerEvent::CONNECT_SUCCESS}));
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
    if (!peer) return;
    
    policy.on_connection_failure(peer->id, "DISCONNECT");
    
    // Update peer state using FSM
    auto it = m_peer_contexts.find(peer->id);
    if (it != m_peer_contexts.end()) {
        pushEvent(SessionEvent(FSMEvent{peer->id, PeerEvent::DISCONNECT_DETECTED}));
    }
    
    LOG_INFO("SM: Peer disconnected: " + peer->id);
    
    notifyPeerUpdate();
}

void SessionManager::Impl::handleConnectToPeerEvent(const ConnectToPeerEvent& event) {
    LOG_INFO("SM: Connection attempt to " + event.peerId);
    
    // Update peer state using FSM
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = m_peer_contexts.find(event.peerId);
        if (it != m_peer_contexts.end()) {
            pushEvent(SessionEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_REQUESTED}));
        }
    }
    
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
            
            // Handshake initiation will be handled by the FSM through PeerAction::INITIATE_HANDSHAKE
        } // Lock released here
        
        bool success = false;
        
        // Try TCP first (without holding the peers mutex)
        if (std::find(retry_strategy.methods.begin(), retry_strategy.methods.end(), "TCP") != retry_strategy.methods.end()) {
            if (m_tcpConnectionManager->connectToPeer(peer_ip, peer_port)) {
                LOG_INFO("SM: Connected to peer via TCP: " + peer_id + " IP: " + peer_ip + " Port: " + std::to_string(peer_port));
                {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    Peer* peer2 = find_peer_by_id(event.peerId);
                    if (peer2) {
                        std::string old_network_id = peer2->network_id;
                        peer2->network_id = peer_ip + ":" + std::to_string(peer_port);
                        // Update network index
                        update_peer_network_index(old_network_id, peer_id, peer2->network_id);
                        policy.on_connection_success(peer_id, "TCP", 50);
                        
                        // Update peer state using FSM
                        auto it = m_peer_contexts.find(event.peerId);
                        if (it != m_peer_contexts.end()) {
                            pushEvent(SessionEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_SUCCESS}));
                        }
                        
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
            m_udpConnectionManager->sendMessageToPeer(network_id, connect_msg);
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
            
            // Update peer state using FSM
            auto it = m_peer_contexts.find(event.peerId);
            if (it != m_peer_contexts.end()) {
                pushEvent(SessionEvent(FSMEvent{event.peerId, PeerEvent::CONNECT_FAILED}));
            }
            
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
    PeerState peer_state = PeerState::UNKNOWN;
    
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
        // Check if peer is connected using FSM state instead of the connected field
        auto ctx_it = m_peer_contexts.find(event.peerId);
        if (ctx_it != m_peer_contexts.end()) {
            peer_connected = (ctx_it->second.state == PeerState::READY || 
                             ctx_it->second.state == PeerState::CONNECTED ||
                             ctx_it->second.state == PeerState::HANDSHAKING);
        }
        
        // Get peer state from FSM
        if (ctx_it != m_peer_contexts.end()) {
            peer_state = ctx_it->second.state;
        }
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
        
        // Handle message based on peer state according to FSM rules
        switch (peer_state) {
            case PeerState::READY:
                // Send immediately
                break;
                
            case PeerState::HANDSHAKING:
            case PeerState::CONNECTED:
                // Queue message in the FSM
                {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    auto it = m_peer_contexts.find(event.peerId);
                    if (it != m_peer_contexts.end()) {
                        it->second.pending_messages.push_back(internal_msg);
                    }
                }
                return;
                
            case PeerState::DEGRADED:
                // Drop or queue based on tier
                if (peer_tier == PeerTier::TIER_1) {
                    // Queue for TIER_1 in the FSM
                    {
                        std::lock_guard<std::mutex> lock(m_peers_mutex);
                        auto it = m_peer_contexts.find(event.peerId);
                        if (it != m_peer_contexts.end()) {
                            it->second.pending_messages.push_back(internal_msg);
                        }
                    }
                    return;
                } else {
                    // Drop for other tiers
                    LOG_DEBUG("SM: Dropping message for DEGRADED peer " + event.peerId);
                    return;
                }
                
            case PeerState::FAILED:
            case PeerState::DISCONNECTED:
            case PeerState::UNKNOWN:
                // Drop message
                LOG_DEBUG("SM: Dropping message for " + state_to_string(peer_state) + " peer " + event.peerId);
                return;
                
            default:
                // For other states, drop the message
                LOG_DEBUG("SM: Dropping message for unknown state peer " + event.peerId);
                return;
        }
        
        // Use message batcher for non-control messages
        if (!is_control) {
            int batch_id = m_message_batcher->enqueue_message(event.peerId, internal_msg, false);
            if (batch_id != -1) {
                return;
            }
        }
        
        // Send message
        handleSendMessageWithRetry(event.peerId, network_id, internal_msg, "");
    } catch (const std::exception& e) {
        LOG_WARN("SM: Error in send handler: " + std::string(e.what()));
    }
}

void SessionManager::Impl::handleTimerTickEvent(const TimerTickEvent&) {
    auto now = std::chrono::steady_clock::now();
    bool needs_update = false;
    
    try {
        int ping_interval = m_battery_optimizer->get_ping_interval();
        static auto last_ping = std::chrono::steady_clock::now();
        auto elapsed_ping = std::chrono::duration_cast<std::chrono::seconds>(now - last_ping).count();
        
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            for (auto& kv : m_peers) {
                Peer& p = kv.second;
                // Check if peer is connected using FSM state instead of the connected field
                bool is_peer_connected = false;
                auto ctx_it = m_peer_contexts.find(p.id);
                if (ctx_it != m_peer_contexts.end()) {
                    is_peer_connected = (ctx_it->second.state == PeerState::READY || 
                                        ctx_it->second.state == PeerState::CONNECTED ||
                                        ctx_it->second.state == PeerState::HANDSHAKING);
                }
                
                if (is_peer_connected && elapsed_ping >= ping_interval) {
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()
                    ).count();
                    LOG_INFO("SM: Sending heartbeat (PING) to peer: " + p.id + " at " + std::to_string(now_ms));
                    pushEvent(SendMessageEvent{p.id, "PING:" + std::to_string(now_ms)});
                }
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - p.last_seen).count();
                int timeout = m_battery_optimizer->get_config().peer_timeout_sec;
                if (elapsed > timeout && is_peer_connected) {
                    // Update peer state using FSM instead of directly modifying the connected field
                    auto ctx_it = m_peer_contexts.find(p.id);
                    if (ctx_it != m_peer_contexts.end()) {
                        pushEvent(SessionEvent(FSMEvent{p.id, PeerEvent::TIMEOUT}));
                    }
                    p.latency = -1;
                    
#if HAVE_NOISE_PROTOCOL
                    if (m_use_noise_protocol) {
                        std::lock_guard<std::mutex> ssl_lock(m_secure_session_mutex);
                        m_secure_session_manager->remove_session(p.id);
                        // PeerContext pending_messages will be managed by the FSM
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
        std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
        m_peers_being_discovered.erase(discovered_peer_id);
    }
    
    handleConnectToPeerEvent(ConnectToPeerEvent{discovered_peer_id});
}

void SessionManager::Impl::initializeTierSystemCallbacks() {
    if (!m_failsafe) return;
    
    m_failsafe->set_error_callback([this](const SystemError& error) {
        LOG_WARN("SM: Tier error - " + error.component + ": " + error.description);
        
        try {
            if (error.component == "BroadcastDiscovery") {
                std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
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

void SessionManager::Impl::handleFSMEvent(const FSMEvent& event) {
    // Handle FSM events without holding any locks
    // We need to find the peer context and apply the FSM event to it
    
    // First, we need to get the peer context
    PeerContext peer_context;
    std::string peer_id = event.peerId;
    bool peer_found = false;
    
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = m_peer_contexts.find(event.peerId);
        if (it != m_peer_contexts.end()) {
            peer_context = it->second;
            peer_found = true;
        }
    }
    
    if (peer_found) {
        // Apply the FSM event to a copy of the peer context
        FSMResult result = m_peer_fsm.handle_event(peer_context, event.fsmEvent);
        
        // Update the peer context in the map with the new state
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            auto it = m_peer_contexts.find(peer_id);
            if (it != m_peer_contexts.end()) {
                // Copy the entire peer context back
                it->second = peer_context;
                // Update the state and last_state_change which might have been modified by the FSM
                it->second.state = result.new_state;
                it->second.last_state_change = std::chrono::steady_clock::now();
            }
        }
        
        // Handle all actions from the FSM result
        for (const auto& action : result.actions) {
            switch (action) {
                case PeerAction::FLUSH_QUEUED_MESSAGES:
                    flushQueuedMessages(event.peerId);
                    break;
                case PeerAction::RETRY_HANDSHAKE:
                    // FSM indicates we should retry the handshake
#if HAVE_NOISE_PROTOCOL
                    if (m_use_noise_protocol) {
                        initializeNoiseHandshake(event.peerId);
                    }
#endif
                    break;
                case PeerAction::INITIATE_HANDSHAKE:
                    // FSM indicates we should initiate a handshake
#if HAVE_NOISE_PROTOCOL
                    if (m_use_noise_protocol) {
                        initializeNoiseHandshake(event.peerId);
                    }
#endif
                    break;
                case PeerAction::CLEANUP_RESOURCES:
                    // FSM indicates we should clean up resources
                    break;
                default:
                    break;
            }
        }
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

void SessionManager::Impl::stopAsync(std::function<void()> completionCallback) {
    // Instead of launching a thread, we'll use the EventManager to handle the async stop
    // Push a special event to handle the stop operation
    if (completionCallback) {
        // For now, we'll execute the stop synchronously and then call the callback
        // In a more sophisticated implementation, we could push an event to the EventManager
        stop();
        completionCallback();
    } else {
        stop();
    }
}

#if HAVE_NOISE_PROTOCOL
void SessionManager::Impl::initializeNoiseHandshake(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_secure_session_mutex);
    
    LOG_INFO("SM: Initializing Noise handshake for " + peer_id);
    
    try {
        // Get or create session for this peer (as initiator)
        auto session = m_secure_session_manager->get_or_create_session(peer_id, NoiseNKSession::Role::INITIATOR);
        if (!session) {
            LOG_WARN("SM: Failed to create secure session for " + peer_id);
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
                    m_tcpConnectionManager->sendMessageToPeer(network_id, "NOISE:" + handshake_msg);
                } else {
                    m_udpConnectionManager->sendMessageToPeer(network_id, "NOISE:" + handshake_msg);
                }
                LOG_INFO("SM: Sent Noise handshake to " + peer_id);
            } else {
                LOG_WARN("SM: Could not find network ID for peer " + peer_id);
            }
        } else {
            LOG_WARN("SM: Failed to start Noise handshake with " + peer_id);
        }
    } catch (const std::exception& e) {
        LOG_WARN("SM: Exception in initializeNoiseHandshake: " + std::string(e.what()));
    }
}

std::string SessionManager::Impl::processNoiseHandshakeMessage(const std::string& peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_secure_session_mutex);
    LOG_INFO("SM: Processing Noise handshake message from " + peer_id);
    
    try {
        // Get or create session for this peer (as responder)
        auto session = m_secure_session_manager->get_or_create_session(peer_id, NoiseNKSession::Role::RESPONDER);
        if (!session) {
            LOG_WARN("SM: Failed to create secure session for " + peer_id);
            return "";
        }
        
        // Process the handshake message
        std::string response = session->process_handshake(message);
        
        // Check peer state to determine if handshake is complete
        bool is_peer_ready = false;
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            auto it = m_peer_contexts.find(peer_id);
            if (it != m_peer_contexts.end()) {
                is_peer_ready = (it->second.state == PeerState::READY);
            }
        }
        
        if (is_peer_ready) {
            LOG_INFO("SM: Noise handshake completed successfully with " + peer_id);
        } else if (!response.empty()) {
            // Handshake still in progress
            LOG_INFO("SM: Noise handshake in progress with " + peer_id);
        } else {
            // Handshake failed
            LOG_WARN("SM: Noise handshake failed with " + peer_id);
        }
        
        return response;
    } catch (const std::exception& e) {
        LOG_WARN("SM: Exception in processNoiseHandshakeMessage: " + std::string(e.what()));
        return "";
    }
}

void SessionManager::Impl::queueMessage(const std::string& peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    auto it = m_peer_contexts.find(peer_id);
    if (it != m_peer_contexts.end()) {
        if (it->second.pending_messages.size() < MAX_QUEUED_MESSAGES) {
            it->second.pending_messages.push_back(message);
        } else {
            // Implement eviction policy: remove oldest message and add new one
            // This maintains the queue size while ensuring the most recent messages are kept
            it->second.pending_messages.pop_front(); // Remove oldest message
            it->second.pending_messages.push_back(message);   // Add new message at the end
            LOG_DEBUG("SM: Evicted oldest message for peer " + peer_id + " to maintain queue size");
        }
    }
}

void SessionManager::Impl::flushQueuedMessages(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    auto it = m_peer_contexts.find(peer_id);
    if (it != m_peer_contexts.end()) {
        it->second.pending_messages.clear();
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
    // Use O(1) lookup via network index instead of O(N) linear search
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    auto it = m_network_id_to_peer_id.find(network_id);
    if (it != m_network_id_to_peer_id.end()) {
        // Found the peer ID, now look up the peer in the main map
        std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
        auto peer_it = m_peers.find(it->second);
        if (peer_it != m_peers.end()) {
            return &peer_it->second;
        }
    }
    return nullptr;
}

const Peer* SessionManager::Impl::find_peer_by_network_id(const std::string& network_id) const {
    // Use O(1) lookup via network index instead of O(N) linear search
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    auto it = m_network_id_to_peer_id.find(network_id);
    if (it != m_network_id_to_peer_id.end()) {
        // Found the peer ID, now look up the peer in the main map
        std::lock_guard<std::mutex> peers_lock(m_peers_mutex);
        auto peer_it = m_peers.find(it->second);
        if (peer_it != m_peers.end()) {
            return &peer_it->second;
        }
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
    auto it = m_peers.find(peer_id);
    if (it != m_peers.end()) {
        // Remove from network index
        remove_peer_from_network_index(it->second.network_id);
        // Remove from main peer map
        m_peers.erase(it);
    }
}

// Network ID index management methods
void SessionManager::Impl::add_peer_to_network_index(const std::string& peer_id, const std::string& network_id) {
    if (!network_id.empty()) {
        std::lock_guard<std::mutex> lock(m_network_index_mutex);
        m_network_id_to_peer_id[network_id] = peer_id;
    }
}

void SessionManager::Impl::remove_peer_from_network_index(const std::string& network_id) {
    if (!network_id.empty()) {
        std::lock_guard<std::mutex> lock(m_network_index_mutex);
        m_network_id_to_peer_id.erase(network_id);
    }
}

void SessionManager::Impl::update_peer_network_index(const std::string& old_network_id, 
                                                     const std::string& peer_id, 
                                                     const std::string& new_network_id) {
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    if (!old_network_id.empty()) {
        m_network_id_to_peer_id.erase(old_network_id);
    }
    if (!new_network_id.empty()) {
        m_network_id_to_peer_id[new_network_id] = peer_id;
    }
}

// Unified communication interface to reduce code duplication
void SessionManager::Impl::send_message_to_peer(const std::string& network_id, const std::string& message) {
    if (m_comms_mode == "TCP") {
        m_tcpConnectionManager->sendMessageToPeer(network_id, message);
    } else {
        m_udpConnectionManager->sendMessageToPeer(network_id, message);
    }
}

// ============================================================================
// PUBLIC SESSIONMANAGER CLASS
// ============================================================================

SessionManager::SessionManager(std::shared_ptr<ISessionDependenciesFactory> factory) 
    : m_impl(std::make_unique<Impl>(factory)) {}
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

void SessionManager::stopAsync(std::function<void()> completionCallback) {
    m_impl->stopAsync(completionCallback);
}
 
