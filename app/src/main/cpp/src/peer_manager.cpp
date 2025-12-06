#include "peer_manager.h"
#include "logger.h"
#include "network.h"

#include <thread>
#include <chrono>

static Network g_network;
PeerManager g_peerManager;

PeerManager::~PeerManager() {
    stop();
}

bool PeerManager::startServer(int port) {
    nativeLog("PeerManager: server started on port " + std::to_string(port));

    // Set up network data callback
    g_network.setDataCallback([this](const std::string& peerId, const std::string& data) {
        nativeLog("PeerManager: received data from " + peerId + " (" + std::to_string(data.size()) + " bytes)");
        // Process received data here
    });

    return g_network.startServer(port);
}

void PeerManager::stop() {
    g_network.stopServer();
    nativeLog("PeerManager: stopped");
}

void PeerManager::connect(const std::string& ip, int port) {
    nativeLog("PeerManager: connecting to " + ip + ":" + std::to_string(port));

    std::string peerId;
    if (g_network.connectToPeer(ip, port, peerId)) {
        Peer p;
        p.id = peerId;
        p.ip = ip;
        p.port = port;
        p.latency = 42;
        p.connected = true;
        p.lastSeenMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

        updatePeer(p);
    } else {
        nativeLog("PeerManager: failed to connect to " + ip + ":" + std::to_string(port));
    }
}

void PeerManager::send(const std::string& peerId, const std::vector<uint8_t>& data) {
    std::string dataStr(data.begin(), data.end());
    nativeLog("PeerManager: send to " + peerId + " (" + std::to_string(data.size()) + " bytes)");
    g_network.sendToPeer(peerId, dataStr);
}

void PeerManager::setCallback(std::function<void(const std::vector<Peer>&)> cb) {
    m_cb = cb;
}

void PeerManager::notify() {
    if (m_cb) {
        m_cb(m_peers);
    }
}

void PeerManager::updatePeer(const Peer& p) {
    std::lock_guard<std::mutex> lock(m_mutex);

    bool found = false;
    for (auto& existing : m_peers) {
        if (existing.id == p.id) {
            existing = p;
            found = true;
            break;
        }
    }

    if (!found) {
        m_peers.push_back(p);
    }

    notify();
}
