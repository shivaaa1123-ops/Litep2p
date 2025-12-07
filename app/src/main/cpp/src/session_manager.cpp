#include "session_manager.h"
#include "discovery.h"
#include "logger.h"
#include "session_events.h"
#include <mutex>
#include <thread>
#include <chrono>
#include <algorithm>
#include <condition_variable>
#include <vector>
#include <queue>
#include <variant>

std::string generate_session_id(size_t len);

class SessionManager::Impl {
public:
    Impl() : m_running(false) {}

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

    void onData(const std::string& network_id, const std::string& data) {
        nativeLog("SM: Received raw data from " + network_id);
        pushEvent(DataReceivedEvent{network_id, data, std::chrono::steady_clock::now()});
    }

    void onDisconnect(const std::string& network_id) {
        pushEvent(PeerDisconnectEvent{network_id});
    }

    void timerLoop() {
        while (m_running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
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
            new_peer.port = 30001; 
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
        for (auto& p : m_peers) {
            if (p.id == event.peerId) {
                nativeLog("SM: Attempting to connect to " + p.id);
                if (m_tcpConnectionManager.connectToPeer(p.ip, p.port)) {
                    p.connected = true;
                    p.network_id = p.ip + ":" + std::to_string(p.port);
                    nativeLog("SM: Connection successful for " + p.id);
                    notifyPeerUpdate();
                } else {
                    nativeLog("SM: Connection failed for " + p.id);
                }
                break;
            }
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
        
        if (!network_id_to_send.empty()) {
            nativeLog("SM: Forwarding message to CM for " + event.peerId);
            std::string internal_msg = (event.message.rfind("PONG:", 0) == 0) ? event.message : "MSG:" + event.message;
            if (m_comms_mode == "TCP") m_tcpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
            else m_udpConnectionManager.sendMessageToPeer(network_id_to_send, internal_msg);
        } else {
            nativeLog("SM Error: Could not find network_id for peer " + event.peerId);
        }
    }

    void handleEvent(const TimerTickEvent&) {
        bool needs_update = false;
        auto now = std::chrono::steady_clock::now();
        for (auto& p : m_peers) {
            if (p.connected) {
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                pushEvent(SendMessageEvent{p.id, "PING:" + std::to_string(now_ms)});
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - p.last_seen).count();
            if (elapsed > 20 && p.connected) {
                p.connected = false;
                p.latency = -1;
                needs_update = true;
            }
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
};

SessionManager::SessionManager() : m_impl(new Impl()) {}
SessionManager::~SessionManager() { delete m_impl; }
void SessionManager::start(int p, std::function<void(const std::vector<Peer>&)> cb, const std::string& cm, const std::string& pi) { m_impl->start(p, cb, cm, pi); }
void SessionManager::stop() { m_impl->stop(); }
void SessionManager::connectToPeer(const std::string& pid) { m_impl->connectToPeer(pid); }
void SessionManager::sendMessageToPeer(const std::string& pid, const std::string& msg) { m_impl->sendMessageToPeer(pid, msg); }
