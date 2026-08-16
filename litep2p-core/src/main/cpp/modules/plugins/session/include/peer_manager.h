#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include "peer.h"
#include "peer_index.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <future>
#include <shared_mutex>

class PeerManagerImpl;

class PeerManager {
public:
    PeerManager();
    ~PeerManager();
    
    // Peer lifecycle management
    void start(int port);
    void stop();
    
    // Network operations
    void connectTo(const std::string& ip, int port);
    void sendDirect(const std::string& peerId, const std::string& msg);
    void broadcastMessage(const std::string& msg);
    
    // Peer management
    void addPeer(const Peer& peer);
    void removePeer(const std::string& peer_id);
    bool hasPeer(const std::string& peer_id) const;
    
    // Peer lookup operations
    Peer* findPeerById(const std::string& peer_id);
    const Peer* findPeerById(const std::string& peer_id) const;
    Peer* findPeerByNetworkId(const std::string& network_id);
    const Peer* findPeerByNetworkId(const std::string& network_id) const;
    
    // Peer indexing operations
    void updatePeerIndexes();
    void removePeerFromIndexes(size_t index);
    
    // Async peer operations
    std::future<Peer*> asyncFindPeerById(const std::string& peer_id);
    std::future<const Peer*> asyncFindPeerById(const std::string& peer_id) const;
    std::future<Peer*> asyncFindPeerByNetworkId(const std::string& network_id);
    std::future<const Peer*> asyncFindPeerByNetworkId(const std::string& network_id) const;
    std::future<std::vector<Peer>> asyncGetAllPeers() const;
    std::future<void> asyncAddPeer(const Peer& peer);
    std::future<void> asyncRemovePeer(const std::string& peer_id);
    std::future<bool> asyncUpdatePeer(const std::string& peer_id, std::function<void(Peer&)> updater);
    
    // Peer data access
    std::vector<Peer> getAllPeers() const;
    size_t getPeerCount() const;
    
    // Peer index access
    PeerIndex* getPeerIndex();
    
    // Callback management
    void setPeerUpdateCallback(std::function<void(const std::vector<Peer>&)> cb);
    
    // Discovery management
    void addPeerToDiscovery(const std::string& peer_id);
    bool isPeerBeingDiscovered(const std::string& peer_id) const;
    void removePeerFromDiscovery(const std::string& peer_id);
    
    // Helper methods for common operations
    std::future<bool> updateConnectionStatus(const std::string& peer_id, bool connected);
    std::future<bool> updatePeerNetworkId(const std::string& peer_id, const std::string& network_id, bool connected = false);
    std::future<bool> updatePeerLatency(const std::string& peer_id, int latency);
    std::future<bool> isPeerConnected(const std::string& peer_id) const;

private:
    std::unique_ptr<PeerManagerImpl> m_impl;
};

extern PeerManager g_peerManager;

#endif