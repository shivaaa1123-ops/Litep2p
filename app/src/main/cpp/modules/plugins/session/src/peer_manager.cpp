#include "peer_manager.h"
#include "logger.h"
#include "connection_manager.h"
#include "peer_index.h"

#include <mutex>
#include <vector>
#include <algorithm>
#include <future>
#include <unordered_set>

// ======================================================
// INTERNAL IMPLEMENTATION
// ======================================================

class PeerManagerImpl {
public:
    PeerManagerImpl()
        : m_peer_index(std::make_unique<PeerIndex>()) {
        // Stabilize Peer* addresses as much as possible
        m_peers.reserve(64);
    }

    ~PeerManagerImpl() {
        stop();
    }

    // =========================
    // LIFECYCLE
    // =========================

    void start(int port) {
        nativeLog("PeerManager: Starting on port " + std::to_string(port));

        auto on_data = [this](const std::string&, const std::string&) {
            notifyUpdate();
        };

        auto on_disconnect = [this](const std::string& peer_id) {
            removePeer(peer_id);
        };

        m_connection_manager.startServer(port, on_data, on_disconnect);
    }

    void stop() {
        nativeLog("PeerManager: Stopping");
        m_connection_manager.stop();
    }

    // =========================
    // NETWORK
    // =========================

    void connectTo(const std::string& ip, int port) {
        nativeLog("PeerManager: Connecting to " + ip + ":" + std::to_string(port));
        m_connection_manager.connectToPeer(ip, port);
    }

    void sendDirect(const std::string& peerId, const std::string& msg) {
        m_connection_manager.sendMessageToPeer(peerId, msg);
    }

    void broadcastMessage(const std::string& msg) {
        std::vector<Peer> snapshot;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            snapshot = m_peers;
        }

        for (const auto& peer : snapshot) {
            m_connection_manager.sendMessageToPeer(peer.id, msg);
        }
    }

    // =========================
    // PEER MANAGEMENT
    // =========================

    void addPeer(const Peer& peer) {
        bool added = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = std::find_if(
                m_peers.begin(), m_peers.end(),
                [&](const Peer& p) { return p.id == peer.id; });

            if (it == m_peers.end()) {
                m_peers.push_back(peer);
                added = true;
            }
        }

        if (added) {
            notifyUpdate();
        }
    }

    void removePeer(const std::string& peer_id) {
        bool removed = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = std::find_if(
                m_peers.begin(), m_peers.end(),
                [&](const Peer& p) { return p.id == peer_id; });

            if (it != m_peers.end()) {
                m_peers.erase(it);
                removed = true;
            }
        }

        if (removed) {
            notifyUpdate();
        }
    }

    bool hasPeer(const std::string& peer_id) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return std::any_of(
            m_peers.begin(), m_peers.end(),
            [&](const Peer& p) { return p.id == peer_id; });
    }

    // =========================
    // LOOKUP (POINTER API PRESERVED)
    // =========================

    Peer* findPeerById(const std::string& peer_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(
            m_peers.begin(), m_peers.end(),
            [&](Peer& p) { return p.id == peer_id; });
        return (it != m_peers.end()) ? &(*it) : nullptr;
    }

    const Peer* findPeerById(const std::string& peer_id) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(
            m_peers.begin(), m_peers.end(),
            [&](const Peer& p) { return p.id == peer_id; });
        return (it != m_peers.end()) ? &(*it) : nullptr;
    }

    Peer* findPeerByNetworkId(const std::string& network_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(
            m_peers.begin(), m_peers.end(),
            [&](Peer& p) { return p.network_id == network_id; });
        return (it != m_peers.end()) ? &(*it) : nullptr;
    }

    const Peer* findPeerByNetworkId(const std::string& network_id) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(
            m_peers.begin(), m_peers.end(),
            [&](const Peer& p) { return p.network_id == network_id; });
        return (it != m_peers.end()) ? &(*it) : nullptr;
    }

    // =========================
    // ASYNC (NO THREAD SPAWN)
    // =========================

    std::future<Peer*> asyncFindPeerById(const std::string& peer_id) {
        return std::async(std::launch::deferred, [this, peer_id] {
            return findPeerById(peer_id);
        });
    }

    std::future<Peer*> asyncFindPeerByNetworkId(const std::string& network_id) {
        return std::async(std::launch::deferred, [this, network_id] {
            return findPeerByNetworkId(network_id);
        });
    }

    std::future<std::vector<Peer>> asyncGetAllPeers() const {
        return std::async(std::launch::deferred, [this] {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_peers;
        });
    }

    std::future<void> asyncAddPeer(const Peer& peer) {
        return std::async(std::launch::deferred, [this, peer] {
            addPeer(peer);
        });
    }

    std::future<void> asyncRemovePeer(const std::string& peer_id) {
        return std::async(std::launch::deferred, [this, peer_id] {
            removePeer(peer_id);
        });
    }

    std::future<bool> asyncUpdatePeer(
        const std::string& peer_id,
        std::function<void(Peer&)> updater) {

        return std::async(std::launch::deferred, [this, peer_id, updater] {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = std::find_if(
                m_peers.begin(), m_peers.end(),
                [&](Peer& p) { return p.id == peer_id; });

            if (it != m_peers.end()) {
                updater(*it);
                return true;
            }
            return false;
        });
    }

    // =========================
    // DATA ACCESS
    // =========================

    std::vector<Peer> getAllPeers() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_peers;
    }

    size_t getPeerCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_peers.size();
    }

    PeerIndex* getPeerIndex() {
        return m_peer_index.get();
    }

    // =========================
    // DISCOVERY
    // =========================

    void addPeerToDiscovery(const std::string& peer_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_peers_being_discovered.insert(peer_id);
    }

    bool isPeerBeingDiscovered(const std::string& peer_id) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_peers_being_discovered.count(peer_id) != 0;
    }

    void removePeerFromDiscovery(const std::string& peer_id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_peers_being_discovered.erase(peer_id);
    }

    // =========================
    // CALLBACK
    // =========================

    void setPeerUpdateCallback(
        std::function<void(const std::vector<Peer>&)> cb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_on_update_cb = cb;
    }

private:
    void notifyUpdate() {
        std::function<void(const std::vector<Peer>&)> cb;
        std::vector<Peer> snapshot;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            cb = m_on_update_cb;
            snapshot = m_peers;
        }

        if (cb) {
            cb(snapshot);
        }
    }

private:
    mutable std::mutex m_mutex;
    std::vector<Peer> m_peers;
    std::unordered_set<std::string> m_peers_being_discovered;
    ConnectionManager m_connection_manager;
    std::unique_ptr<PeerIndex> m_peer_index;
    std::function<void(const std::vector<Peer>&)> m_on_update_cb;
};

// ======================================================
// PUBLIC FACADE (UNCHANGED API)
// ======================================================

PeerManager g_peerManager;

PeerManager::PeerManager()
    : m_impl(std::make_unique<PeerManagerImpl>()) {}

PeerManager::~PeerManager() = default;

void PeerManager::start(int port) { m_impl->start(port); }
void PeerManager::stop() { m_impl->stop(); }

void PeerManager::connectTo(const std::string& ip, int port) {
    m_impl->connectTo(ip, port);
}

void PeerManager::sendDirect(const std::string& peerId, const std::string& msg) {
    m_impl->sendDirect(peerId, msg);
}

void PeerManager::broadcastMessage(const std::string& msg) {
    m_impl->broadcastMessage(msg);
}

void PeerManager::addPeer(const Peer& peer) { m_impl->addPeer(peer); }
void PeerManager::removePeer(const std::string& peer_id) { m_impl->removePeer(peer_id); }
bool PeerManager::hasPeer(const std::string& peer_id) const { return m_impl->hasPeer(peer_id); }

Peer* PeerManager::findPeerById(const std::string& peer_id) {
    return m_impl->findPeerById(peer_id);
}

const Peer* PeerManager::findPeerById(const std::string& peer_id) const {
    return m_impl->findPeerById(peer_id);
}

Peer* PeerManager::findPeerByNetworkId(const std::string& network_id) {
    return m_impl->findPeerByNetworkId(network_id);
}

const Peer* PeerManager::findPeerByNetworkId(const std::string& network_id) const {
    return m_impl->findPeerByNetworkId(network_id);
}

// =========================
// ASYNC API – FIXED CONST VARIANTS
// =========================

std::future<Peer*> PeerManager::asyncFindPeerById(const std::string& peer_id) {
    return m_impl->asyncFindPeerById(peer_id);
}

std::future<const Peer*> PeerManager::asyncFindPeerById(
    const std::string& peer_id) const {

    auto fut = m_impl->asyncFindPeerById(peer_id);

    return std::async(std::launch::deferred,
        [fut = std::move(fut)]() mutable -> const Peer* {
            return fut.get();
        }
    );
}

std::future<Peer*> PeerManager::asyncFindPeerByNetworkId(const std::string& network_id) {
    return m_impl->asyncFindPeerByNetworkId(network_id);
}

std::future<const Peer*> PeerManager::asyncFindPeerByNetworkId(
    const std::string& network_id) const {

    auto fut = m_impl->asyncFindPeerByNetworkId(network_id);

    return std::async(std::launch::deferred,
        [fut = std::move(fut)]() mutable -> const Peer* {
            return fut.get();
        }
    );
}

std::future<std::vector<Peer>> PeerManager::asyncGetAllPeers() const {
    return m_impl->asyncGetAllPeers();
}

std::future<void> PeerManager::asyncAddPeer(const Peer& peer) {
    return m_impl->asyncAddPeer(peer);
}

std::future<void> PeerManager::asyncRemovePeer(const std::string& peer_id) {
    return m_impl->asyncRemovePeer(peer_id);
}

std::future<bool> PeerManager::asyncUpdatePeer(
    const std::string& peer_id,
    std::function<void(Peer&)> updater) {
    return m_impl->asyncUpdatePeer(peer_id, updater);
}

// =========================
// DATA ACCESS
// =========================

std::vector<Peer> PeerManager::getAllPeers() const {
    return m_impl->getAllPeers();
}

size_t PeerManager::getPeerCount() const {
    return m_impl->getPeerCount();
}

PeerIndex* PeerManager::getPeerIndex() {
    return m_impl->getPeerIndex();
}

void PeerManager::setPeerUpdateCallback(
    std::function<void(const std::vector<Peer>&)> cb) {
    m_impl->setPeerUpdateCallback(cb);
}

// =========================
// DISCOVERY
// =========================

void PeerManager::addPeerToDiscovery(const std::string& peer_id) {
    m_impl->addPeerToDiscovery(peer_id);
}

bool PeerManager::isPeerBeingDiscovered(const std::string& peer_id) const {
    return m_impl->isPeerBeingDiscovered(peer_id);
}

void PeerManager::removePeerFromDiscovery(const std::string& peer_id) {
    m_impl->removePeerFromDiscovery(peer_id);
}