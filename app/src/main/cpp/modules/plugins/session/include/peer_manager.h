#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include "peer.h"
#include <string>
#include <vector>
#include <functional>
#include <memory>

class PeerManagerImpl;

class PeerManager {
public:
    PeerManager();
    ~PeerManager();
    void start(int port);
    void stop();
    void connectTo(const std::string& ip, int port);
    void addPeer(const Peer& peer);
    void sendDirect(const std::string& peerId, const std::string& msg);
    void broadcastMessage(const std::string& msg);
    void setPeerUpdateCallback(std::function<void(const std::vector<Peer>&)> cb);
private:
    std::unique_ptr<PeerManagerImpl> m_impl;
};

extern PeerManager g_peerManager;

#endif