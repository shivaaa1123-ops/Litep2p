#include "session_manager.h"
#include "discovery.h"
#include "logger.h"
#include "session_events.h"
#include "constants.h"
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
#include <variant>
#include <map>

std::string generate_session_id(size_t len);

// Handshake state tracking per peer
struct HandshakeState {
    enum Status { PENDING, IN_PROGRESS, COMPLETE, FAILED };
    Status status;
    std::chrono::steady_clock::time_point initiated_time;
    int retry_count;
};

class SessionManager::Impl {
public:
    Impl() : m_running(false), m_use_noise_protocol(false), m_noise_nk_enabled(false) {
        // Initialize battery optimizer
        m_battery_optimizer = std::make_unique<BatteryOptimizer>();
        m_battery_optimizer->set_optimization_level(BatteryOptimizer::OptimizationLevel::BALANCED);
        
        // Initialize session cache
        m_session_cache = std::make_unique<SessionCache>();
        
        // Initialize message batcher
        m_message_batcher = std::make_unique<MessageBatcher>(BATCH_DELAY_MS, BATCH_MAX_MESSAGES);
        
#if HAVE_NOISE_PROTOCOL
        m_use_noise_protocol = true;
        m_secure_session_manager = std::make_unique<SecureSessionManager>();
        m_noise_nk_manager = std::make_unique<NoiseNKManager>();
        m_noise_key_store = std::make_unique<NoiseKeyStore>();
        m_noise_key_store->initialize();
        nativeLog("SM: Noise Protocol support enabled");
        nativeLog("SM: Noise NK MITM protection available");
#else
        nativeLog("SM: Noise Protocol not available (libsodium not found)");
#endif
        nativeLog("SM: Battery optimization enabled (BALANCED mode)");
    }

    // Public getters for battery optimizer members (for SessionManager wrapper)
    BatteryOptimizer* get_battery_optimizer() { return m_battery_optimizer.get(); }
    SessionCache* get_session_cache() { return m_session_cache.get(); }
    MessageBatcher* get_message_batcher() { return m_message_batcher.get(); }

#if HAVE_NOISE_PROTOCOL
    NoiseNKManager* get_noise_nk_manager() { return m_noise_nk_manager.get(); }
    NoiseKeyStore* get_noise_key_store() { return m_noise_key_store.get(); }
#endif

    void enable_noise_nk() {
        m_noise_nk_enabled = true;
        nativeLog("SM: Noise NK MITM protection enabled");
    }

    bool is_noise_nk_enabled() const {
        return m_noise_nk_enabled;
    }

    void start(int port, std::function<void(const std::vector<Peer>&)> peer_update_cb, const std::string& comms_mode, const std::string& peer_id) {
        if (m_running) return;
        m_peer_update_cb = peer_update_cb;
        m_comms_mode = comms_mode;
        m_localPeerId = peer_id;

        m_running = true;
        m_processingThread = std::thread(&Impl::processEventQueue, this);
        m_timerThread = std::thread(&Impl::timerLoop, this);

        if (m_comms_mode == "TCP") {
            m_tcpConnectionManager.startServer(port,
                [this](const std::string& pid, const std::string& data) { onData(pid, data); },
                [this](const std::string& pid) { onDisconnect(pid); }
            );
        } else {
            m_udpConnectionManager.startServer(port,
                [this](const std::string& pid, const std::string& data) { onData(pid, data); },
                [this](const std::string& pid) { onDisconnect(pid); }
            );
        }
        
        getGlobalDiscoveryInstance()->setCallback([this](const std::string& ip, const std::string& peerId) {
            pushEvent(PeerDiscoveredEvent{ip, 0, peerId});
        });
        getGlobalDiscoveryInstance()->start(port, m_localPeerId);

        nativeLog("Session Manager started.");
    }

    void stop() {
        m_running = false;
        m_eventCv.notify_one();
        getGlobalDiscoveryInstance()->stop();
        if (m_comms_mode == "TCP") m_tcpConnectionManager.stop();
        else m_udpConnectionManager.stop();
        if (m_processingThread.joinable()) m_processingThread.join();
        if (m_timerThread.joinable()) m_timerThread.join();
    }

    void connectToPeer(const std::string& peer_id) {
        pushEvent(ConnectToPeerEvent{peer_id});
    }

    void sendMessageToPeer(const std::string& peer_id, const std::string& message) {
        nativeLog("SM: Queuing message for " + peer_id);
        pushEvent(SendMessageEvent{peer_id, message});
    }

private:
    void pushEvent(SessionEvent event) {
        {
            std::lock_guard<std::mutex> lock(m_eventMutex);
            m_eventQueue.push(std::move(event));
        }
        m_eventCv.notify_one();
    }

    // Initialize Noise handshake for a peer
#if HAVE_NOISE_PROTOCOL
    void initializeNoiseHandshake(const std::string& peer_id) {
        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
        
        try {
            auto session = m_secure_session_manager->get_or_create_session(
                peer_id,
                NoiseSession::Role::INITIATOR
            );
            
            std::string handshake_msg = session->start_handshake();
            if (handshake_msg.empty()) {
                nativeLog("ERROR: Failed to start Noise handshake for " + peer_id);
                m_handshake_states[peer_id] = {HandshakeState::FAILED, std::chrono::steady_clock::now(), 0};
                return;
            }
            
            m_handshake_states[peer_id] = {HandshakeState::IN_PROGRESS, std::chrono::steady_clock::now(), 0};
            nativeLog("SM: Noise handshake initiated for peer " + peer_id);
            
            // Send handshake message
            for (auto& p : m_peers) {
                if (p.id == peer_id && !p.network_id.empty()) {
                    if (m_comms_mode == "TCP") {
                        m_tcpConnectionManager.sendMessageToPeer(p.network_id, "NOISE:" + handshake_msg);
                    } else {
                        m_udpConnectionManager.sendMessageToPeer(p.network_id, "NOISE:" + handshake_msg);
                    }
                    break;
                }
            }
        } catch (const std::exception& e) {
            nativeLog("ERROR: Exception during Noise handshake init: " + std::string(e.what()));
            m_handshake_states[peer_id] = {HandshakeState::FAILED, std::chrono::steady_clock::now(), 0};
        }
    }

    // Process Noise handshake message
    std::string processNoiseHandshakeMessage(const std::string& peer_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
        
        try {
            auto session = m_secure_session_manager->get_session(peer_id);
            if (!session) {
                // Create responder session
                session = m_secure_session_manager->get_or_create_session(
                    peer_id,
                    NoiseSession::Role::RESPONDER
                );
            }
            
            std::string response = session->process_handshake(message);
            
            if (session->is_ready()) {
                m_handshake_states[peer_id] = {HandshakeState::COMPLETE, std::chrono::steady_clock::now(), 0};
                nativeLog("SM: Noise handshake COMPLETE with peer " + peer_id);
                
                // Flush any pending messages
                flushQueuedMessages(peer_id);
            } else if (!response.empty()) {
                m_handshake_states[peer_id] = {HandshakeState::IN_PROGRESS, std::chrono::steady_clock::now(), 0};
            }
            
            return response;
        } catch (const std::exception& e) {
            nativeLog("ERROR: Exception processing Noise handshake: " + std::string(e.what()));
            m_handshake_states[peer_id] = {HandshakeState::FAILED, std::chrono::steady_clock::now(), 0};
            return "";
        }
    }

    // Queue a message for a peer awaiting handshake
    void queueMessage(const std::string& peer_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
        
        auto& queue = m_pending_messages[peer_id];
        if (queue.size() >= MAX_QUEUED_MESSAGES) {
            nativeLog("ERROR: Message queue full for peer " + peer_id + ", dropping oldest message");
            queue.erase(queue.begin());
        }
        queue.push_back(message);
    }

    // Flush queued messages for a peer
    void flushQueuedMessages(const std::string& peer_id) {
        auto it = m_pending_messages.find(peer_id);
        if (it == m_pending_messages.end()) return;
        
        try {
            auto session = m_secure_session_manager->get_session(peer_id);
            if (!session || !session->is_ready()) {
                nativeLog("WARNING: Cannot flush messages, session not ready for " + peer_id);
                return;
            }
            
            for (const auto& msg : it->second) {
                std::string ciphertext = session->send_message(msg);
                for (auto& p : m_peers) {
                    if (p.id == peer_id && !p.network_id.empty()) {
                        if (m_comms_mode == "TCP") {
                            m_tcpConnectionManager.sendMessageToPeer(p.network_id, "ENCRYPTED:" + ciphertext);
                        } else {
                            m_udpConnectionManager.sendMessageToPeer(p.network_id, "ENCRYPTED:" + ciphertext);
                        }
                        break;
                    }
                }
            }
            nativeLog("SM: Flushed " + std::to_string(it->second.size()) + " queued messages for " + peer_id);
            m_pending_messages.erase(it);
        } catch (const std::exception& e) {
            nativeLog("ERROR: Exception flushing queued messages: " + std::string(e.what()));
        }
    }
#else
    // Noise Protocol not available - stubs
    void initializeNoiseHandshake(const std::string& peer_id) {
        nativeLog("WARNING: Noise Protocol not available, skipping handshake for " + peer_id);
    }
    
    std::string processNoiseHandshakeMessage(const std::string& peer_id, const std::string& message) {
        return "";
    }
    
    void queueMessage(const std::string& peer_id, const std::string& message) {}
    
    void flushQueuedMessages(const std::string& peer_id) {}
#endif

    void onData(const std::string& network_id, const std::string& data) {
        nativeLog("SM: Received raw data from " + network_id);
        pushEvent(DataReceivedEvent{network_id, data, std::chrono::steady_clock::now()});
    }

    void onDisconnect(const std::string& network_id) {
        pushEvent(PeerDisconnectEvent{network_id});
    }

    void timerLoop() {
        while (m_running) {
            std::this_thread::sleep_for(std::chrono::seconds(TIMER_TICK_INTERVAL_SEC));
            if (!m_running) break;
            pushEvent(TimerTickEvent{});
        }
    }

    void processEventQueue() {
        while (m_running) {
            std::unique_lock<std::mutex> lock(m_eventMutex);
            m_eventCv.wait(lock, [this] { return !m_eventQueue.empty() || !m_running; });

            if (!m_running && m_eventQueue.empty()) break;

            SessionEvent event = std::move(m_eventQueue.front());
            m_eventQueue.pop();
            lock.unlock();

            std::visit([this](auto&& arg) { handleEvent(arg); }, event);
        }
    }

    void handleEvent(const PeerDiscoveredEvent& event) {
        if (event.peerId == m_localPeerId) return;
        auto it = std::find_if(m_peers.begin(), m_peers.end(), [&](const Peer& p) { return p.id == event.peerId; });
        if (it != m_peers.end()) {
            it->last_seen = std::chrono::steady_clock::now();
            if (it->ip != event.ip) {
                it->ip = event.ip;
                notifyPeerUpdate();
            }
        } else {
            Peer new_peer;
            new_peer.id = event.peerId;
            new_peer.ip = event.ip;
            new_peer.port = DEFAULT_SERVER_PORT; 
            new_peer.connected = (m_comms_mode == "UDP");
            if (m_comms_mode == "UDP") new_peer.network_id = event.ip + ":" + std::to_string(new_peer.port);
            m_peers.push_back(new_peer);
            notifyPeerUpdate();
        }
    }

    void handleEvent(const DataReceivedEvent& event) {
        nativeLog("SM: Processing data from " + event.network_id);
        std::string ip_from_network = event.network_id.substr(0, event.network_id.find(':'));
        auto it = std::find_if(m_peers.begin(), m_peers.end(), [&](const Peer& p) { return p.ip == ip_from_network; });

        if (it != m_peers.end()) {
            it->last_seen = event.arrival_time;
            bool needs_update = false;
            if (!it->connected) { it->connected = true; needs_update = true; }
            it->network_id = event.network_id;

            try {
#if HAVE_NOISE_PROTOCOL
                // Handle Noise Protocol handshake messages
                if (event.data.rfind("NOISE:", 0) == 0 && m_use_noise_protocol) {
                    std::string handshake_msg = event.data.substr(6);
                    nativeLog("SM: Received Noise handshake from " + it->id);
                    
                    std::string response = processNoiseHandshakeMessage(it->id, handshake_msg);
                    if (!response.empty()) {
                        // Send handshake response
                        if (m_comms_mode == "TCP") {
                            m_tcpConnectionManager.sendMessageToPeer(it->network_id, "NOISE:" + response);
                        } else {
                            m_udpConnectionManager.sendMessageToPeer(it->network_id, "NOISE:" + response);
                        }
                    }
                    return;
                }
                
                // Handle encrypted application messages
                if (event.data.rfind("ENCRYPTED:", 0) == 0 && m_use_noise_protocol) {
                    std::string ciphertext = event.data.substr(10);
                    nativeLog("SM: Received encrypted message from " + it->id);
                    
                    std::lock_guard<std::mutex> lock(m_secure_session_mutex);
                    auto session = m_secure_session_manager->get_session(it->id);
                    if (!session || !session->is_ready()) {
                        nativeLog("WARNING: Received encrypted message but session not ready for " + it->id);
                        return;
                    }
                    
                    std::string plaintext = session->receive_message(ciphertext);
                    nativeLog("SM: Decrypted message from " + it->id + ": " + plaintext);
                    
                    // Process decrypted message
                    if (plaintext.rfind("MSG:", 0) == 0) {
                        nativeLog("SM: Application message from " + it->id + ": " + plaintext.substr(4));
                    } else if (plaintext.rfind("PING:", 0) == 0) {
                        nativeLog("SM: Received PING from " + it->id + ", sending PONG.");
                        pushEvent(SendMessageEvent{it->id, "PONG:" + plaintext.substr(5)});
                    } else if (plaintext.rfind("PONG:", 0) == 0) {
                        auto sent_time = std::chrono::steady_clock::time_point(
                            std::chrono::milliseconds(std::stoll(plaintext.substr(5)))
                        );
                        it->latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                            event.arrival_time - sent_time
                        ).count();
                        nativeLog("SM: Updated latency for " + it->id + " to " + std::to_string(it->latency) + "ms");
                        needs_update = true;
                    }
                    return;
                }
#endif

                // Legacy message handling (without Noise)
                if (event.data.rfind("MSG:", 0) == 0) {
                    nativeLog("SM: Message from " + it->id + ": " + event.data.substr(4));
                } else if (event.data.rfind("PING:", 0) == 0) {
                    nativeLog("SM: Received PING from " + it->id + ", sending PONG.");
                    pushEvent(SendMessageEvent{it->id, "PONG:" + event.data.substr(5)});
                } else if (event.data.rfind("PONG:", 0) == 0) {
                    auto sent_time = std::chrono::steady_clock::time_point(std::chrono::milliseconds(std::stoll(event.data.substr(5))));
                    it->latency = std::chrono::duration_cast<std::chrono::milliseconds>(event.arrival_time - sent_time).count();
                    nativeLog("SM: Updated latency for " + it->id + " to " + std::to_string(it->latency) + "ms");
                    needs_update = true;
                }
            } catch (const std::exception& e) {
                nativeLog("ERROR: Exception in DataReceivedEvent handler: " + std::string(e.what()));
            }
            
            if (needs_update) notifyPeerUpdate();
        }
    }
    
    void handleEvent(const PeerDisconnectEvent& event) {
        bool needs_update = false;
        for (auto& p : m_peers) {
            if (p.network_id == event.network_id && p.connected) {
                p.connected = false;
                needs_update = true;
                break;
            }
        }
        if (needs_update) notifyPeerUpdate();
    }
    
    void handleEvent(const ConnectToPeerEvent& event) {
        if (m_comms_mode == "UDP") return;
        
        try {
            for (auto& p : m_peers) {
                if (p.id == event.peerId) {
                    nativeLog("SM: Attempting to connect to " + p.id);
                    if (m_tcpConnectionManager.connectToPeer(p.ip, p.port)) {
                        p.connected = true;
                        p.network_id = p.ip + ":" + std::to_string(p.port);
                        nativeLog("SM: Connection successful for " + p.id);
                        
                        // Initialize Noise Protocol handshake if enabled
                        if (m_use_noise_protocol) {
                            initializeNoiseHandshake(p.id);
                        }
                        
                        notifyPeerUpdate();
                    } else {
                        nativeLog("SM: Connection failed for " + p.id);
                    }
                    break;
                }
            }
        } catch (const std::exception& e) {
            nativeLog("ERROR: Exception in ConnectToPeerEvent handler: " + std::string(e.what()));
        }
    }
    
    void handleEvent(const SendMessageEvent& event) {
        std::string network_id_to_send;
        for (const auto& p : m_peers) {
            if (p.id == event.peerId) {
                network_id_to_send = p.network_id;
                break;
            }
        }
        
        if (network_id_to_send.empty()) {
            nativeLog("SM Error: Could not find network_id for peer " + event.peerId);
            return;
        }

        try {
            nativeLog("SM: Queuing message for " + event.peerId);
            std::string internal_msg = (event.message.rfind("PONG:", 0) == 0) ? event.message : "MSG:" + event.message;
            
#if HAVE_NOISE_PROTOCOL
            // Handle Noise Protocol encryption
            if (m_use_noise_protocol) {
                std::lock_guard<std::mutex> lock(m_secure_session_mutex);
                
                auto session = m_secure_session_manager->get_session(event.peerId);
                if (!session) {
                    // Session doesn't exist - initiate handshake and queue message
                    nativeLog("SM: No session for peer " + event.peerId + ", initiating handshake");
                    queueMessage(event.peerId, internal_msg);
                    initializeNoiseHandshake(event.peerId);
                    return;
                }
                
                if (!session->is_ready()) {
                    // Handshake in progress - queue message
                    nativeLog("SM: Handshake pending for " + event.peerId + ", queuing message");
                    queueMessage(event.peerId, internal_msg);
                    return;
                }
                
                // Session ready - encrypt and send
                try {
                    std::string ciphertext = session->send_message(internal_msg);
                    if (m_comms_mode == "TCP") {
                        m_tcpConnectionManager.sendMessageToPeer(network_id_to_send, "ENCRYPTED:" + ciphertext);
                    } else {
                        m_udpConnectionManager.sendMessageToPeer(network_id_to_send, "ENCRYPTED:" + ciphertext);
                    }
                    nativeLog("SM: Sent encrypted message to " + event.peerId);
                } catch (const std::exception& e) {
                    nativeLog("ERROR: Encryption failed for peer " + event.peerId + ": " + std::string(e.what()));
                    // Fall back to unencrypted send (graceful degradation)
                    if (m_comms_mode == "TCP") {
                        m_tcpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
                    } else {
                        m_udpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
                    }
                }
            } else {
                // Legacy mode - send without encryption
                if (m_comms_mode == "TCP") {
                    m_tcpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
                } else {
                    m_udpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
                }
            }
#else
            // Noise Protocol not available - send without encryption
            if (m_comms_mode == "TCP") {
                m_tcpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
            } else {
                m_udpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
            }
#endif
        } catch (const std::exception& e) {
            nativeLog("ERROR: Exception in SendMessageEvent handler: " + std::string(e.what()));
        }
    }

    void handleEvent(const TimerTickEvent&) {
        bool needs_update = false;
        auto now = std::chrono::steady_clock::now();
        
        try {
#if HAVE_NOISE_PROTOCOL
            // Check for handshake timeouts and cleanup
            if (m_use_noise_protocol) {
                std::lock_guard<std::mutex> lock(m_secure_session_mutex);
                
                auto state_it = m_handshake_states.begin();
                while (state_it != m_handshake_states.end()) {
                    const auto& peer_id = state_it->first;
                    auto& state = state_it->second;
                    
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - state.initiated_time).count();
                    
                    // Timeout check for in-progress handshakes
                    if (state.status == HandshakeState::IN_PROGRESS && elapsed > HANDSHAKE_TIMEOUT_SEC) {
                        if (state.retry_count < MAX_HANDSHAKE_RETRIES) {
                            nativeLog("SM: Handshake timeout for " + peer_id + ", retrying (" + 
                                    std::to_string(state.retry_count + 1) + "/" + std::to_string(MAX_HANDSHAKE_RETRIES) + ")");
                            state.retry_count++;
                            state.initiated_time = now;
                            
                            // Recreate session and retry
                            m_secure_session_manager->remove_session(peer_id);
                            initializeNoiseHandshake(peer_id);
                        } else {
                            nativeLog("ERROR: Handshake failed for " + peer_id + " after " + 
                                    std::to_string(MAX_HANDSHAKE_RETRIES) + " retries");
                            state.status = HandshakeState::FAILED;
                            m_secure_session_manager->remove_session(peer_id);
                            m_pending_messages.erase(peer_id);
                        }
                    }
                    
                    // Clean up failed handshakes after a while
                    if (state.status == HandshakeState::FAILED && elapsed > HANDSHAKE_TIMEOUT_SEC * 2) {
                        nativeLog("SM: Cleaning up failed handshake state for " + peer_id);
                        state_it = m_handshake_states.erase(state_it);
                        continue;
                    }
                    
                    ++state_it;
                }
            }
#endif
            
            // Peer timeout and ping checks
            // Use battery-optimized ping interval
            int ping_interval = m_battery_optimizer->get_ping_interval();
            static auto last_ping_time = std::chrono::steady_clock::now();
            auto elapsed_since_ping = std::chrono::duration_cast<std::chrono::seconds>(
                now - last_ping_time
            ).count();
            
            for (auto& p : m_peers) {
                if (p.connected && elapsed_since_ping >= ping_interval) {
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                    pushEvent(SendMessageEvent{p.id, "PING:" + std::to_string(now_ms)});
                }
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - p.last_seen).count();
                int peer_timeout = m_battery_optimizer->get_config().peer_timeout_sec;
                if (elapsed > peer_timeout && p.connected) {
                    p.connected = false;
                    p.latency = -1;
                    
#if HAVE_NOISE_PROTOCOL
                    // Clean up Noise session if peer times out
                    if (m_use_noise_protocol) {
                        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
                        m_secure_session_manager->remove_session(p.id);
                        m_handshake_states.erase(p.id);
                        m_pending_messages.erase(p.id);
                    }
#endif
                    // Invalidate cached session on timeout
                    m_session_cache->invalidate_session(p.id);
                    
                    needs_update = true;
                }
            }
            
            if (elapsed_since_ping >= ping_interval) {
                last_ping_time = now;
            }
            
            // Cleanup expired sessions and handshakes
            m_session_cache->cleanup_expired();
        } catch (const std::exception& e) {
            nativeLog("ERROR: Exception in TimerTickEvent handler: " + std::string(e.what()));
        }
        
        if (needs_update) notifyPeerUpdate();
    }
    
    void notifyPeerUpdate() {
        if (m_peer_update_cb) {
            m_peer_update_cb(m_peers);
        }
    }

    std::atomic<bool> m_running;
    ConnectionManager m_tcpConnectionManager;
    UdpConnectionManager m_udpConnectionManager;
    std::vector<Peer> m_peers;
    std::function<void(const std::vector<Peer>&)> m_peer_update_cb;
    std::string m_localPeerId;
    std::string m_comms_mode;
    
    std::queue<SessionEvent> m_eventQueue;
    std::mutex m_eventMutex;
    std::condition_variable m_eventCv;
    std::thread m_processingThread;
    std::thread m_timerThread;

    // Noise Protocol integration
    bool m_use_noise_protocol;
    bool m_noise_nk_enabled;
#if HAVE_NOISE_PROTOCOL
    std::unique_ptr<SecureSessionManager> m_secure_session_manager;
    std::unique_ptr<NoiseNKManager> m_noise_nk_manager;
    std::unique_ptr<NoiseKeyStore> m_noise_key_store;
    std::map<std::string, HandshakeState> m_handshake_states;
    std::map<std::string, std::vector<std::string>> m_pending_messages;
#endif
    std::mutex m_secure_session_mutex;
    static constexpr int MAX_QUEUED_MESSAGES = 100;
    static constexpr int HANDSHAKE_TIMEOUT_SEC = 5;
    static constexpr int MAX_HANDSHAKE_RETRIES = 3;
    
    // Battery optimization
    std::unique_ptr<BatteryOptimizer> m_battery_optimizer;
    std::unique_ptr<SessionCache> m_session_cache;
    std::unique_ptr<MessageBatcher> m_message_batcher;
};

SessionManager::SessionManager() : m_impl(std::make_unique<Impl>()) {}
SessionManager::~SessionManager() = default;
void SessionManager::start(int p, std::function<void(const std::vector<Peer>&)> cb, const std::string& cm, const std::string& pi) { m_impl->start(p, cb, cm, pi); }
void SessionManager::stop() { m_impl->stop(); }
void SessionManager::connectToPeer(const std::string& pid) { m_impl->connectToPeer(pid); }
void SessionManager::sendMessageToPeer(const std::string& pid, const std::string& msg) { m_impl->sendMessageToPeer(pid, msg); }

// Battery optimization APIs
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

// Noise NK MITM Protection APIs
void SessionManager::enable_noise_nk() {
    m_impl->enable_noise_nk();
}

bool SessionManager::is_noise_nk_enabled() const {
    return m_impl->is_noise_nk_enabled();
}

std::vector<uint8_t> SessionManager::get_local_static_public_key() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) {
        return store->get_local_static_public_key();
    }
#endif
    return {};
}

void SessionManager::register_peer_nk_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk) {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) {
        store->register_peer_key(peer_id, static_pk);
    }
    auto* mgr = m_impl->get_noise_nk_manager();
    if (mgr) {
        mgr->register_peer_key(peer_id, static_pk);
    }
#endif
}

bool SessionManager::has_peer_nk_key(const std::string& peer_id) const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) {
        return store->has_peer_key(peer_id);
    }
#endif
    return false;
}

int SessionManager::get_nk_peer_count() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) {
        return store->get_peer_count();
    }
#endif
    return 0;
}

std::vector<std::string> SessionManager::get_nk_peer_ids() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) {
        return store->get_all_peer_ids();
    }
#endif
    return {};
}

bool SessionManager::import_nk_peer_keys_hex(const std::map<std::string, std::string>& hex_keys) {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) {
        return store->import_peer_keys_hex(hex_keys);
    }
#endif
    return false;
}

std::map<std::string, std::string> SessionManager::export_nk_peer_keys_hex() const {
#if HAVE_NOISE_PROTOCOL
    auto* store = m_impl->get_noise_key_store();
    if (store) {
        return store->export_peer_keys_hex();
    }
#endif
    return {};
}
