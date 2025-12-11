#include "peer_manager.h"
#include "logger.h"
#include "connection_manager.h"
#include <mutex>
#include <vector>
#include <algorithm>

class PeerManagerImpl {
public:
    PeerManagerImpl() : m_connection_manager() {}
    
    ~PeerManagerImpl() {
        stop();
    }
    
    void start(int port) {
        nativeLog("PeerManager: Starting on port " + std::to_string(port));
        
        auto on_data = [this](const std::string& peer_id, const std::string& data) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_on_update_cb) {
                m_on_update_cb(m_peers);
            }
        };
        
        auto on_disconnect = [this](const std::string& peer_id) {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = std::find_if(m_peers.begin(), m_peers.end(), 
                                  [&](const Peer& p) { return p.id == peer_id; });
            if (it != m_peers.end()) {
                m_peers.erase(it);
                if (m_on_update_cb) {
                    m_on_update_cb(m_peers);
                }
            }
        };
        
        m_connection_manager.startServer(port, on_data, on_disconnect);
    }
    
    void stop() {
        nativeLog("PeerManager: Stopping");
        m_connection_manager.stop();
    }
    
    void connectTo(const std::string& ip, int port) {
        nativeLog("PeerManager: Connecting to " + ip + ":" + std::to_string(port));
        m_connection_manager.connectToPeer(ip, port);
    }
    
    void addPeer(const Peer& peer) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(m_peers.begin(), m_peers.end(),
                              [&](const Peer& p) { return p.id == peer.id; });
        if (it == m_peers.end()) {
            m_peers.push_back(peer);
            if (m_on_update_cb) {
                m_on_update_cb(m_peers);
            }
        }
    }
    
    void sendDirect(const std::string& peerId, const std::string& msg) {
        nativeLog("PeerManager: Sending message to " + peerId);
        m_connection_manager.sendMessageToPeer(peerId, msg);
    }
    
    void broadcastMessage(const std::string& msg) {
        nativeLog("PeerManager: Broadcasting message to " + std::to_string(m_peers.size()) + " peers");
        for (const auto& peer : m_peers) {
            m_connection_manager.sendMessageToPeer(peer.id, msg);
        }
    }
    
    void setPeerUpdateCallback(std::function<void(const std::vector<Peer>&)> cb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_on_update_cb = cb;
    }
    
private:
    mutable std::mutex m_mutex;
    std::vector<Peer> m_peers;
    ConnectionManager m_connection_manager;
    std::function<void(const std::vector<Peer>&)> m_on_update_cb;
};

PeerManager g_peerManager;

PeerManager::PeerManager() : m_impl(std::make_unique<PeerManagerImpl>()) {}
PeerManager::~PeerManager() = default;
void PeerManager::start(int port) { m_impl->start(port); }
void PeerManager::stop() { m_impl->stop(); }
void PeerManager::connectTo(const std::string& ip, int port) { m_impl->connectTo(ip, port); }
void PeerManager::addPeer(const Peer& peer) { m_impl->addPeer(peer); }
void PeerManager::sendDirect(const std::string& peerId, const std::string& msg) { m_impl->sendDirect(peerId, msg); }
void PeerManager::broadcastMessage(const std::string& msg) { m_impl->broadcastMessage(msg); }
void PeerManager::setPeerUpdateCallback(std::function<void(const std::vector<Peer>&)> cb) { m_impl->setPeerUpdateCallback(cb); }
