#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <functional>
#include <vector>
#include <string>
#include "peer.h"  // Include full Peer definition

class PeerManager {
public:
    ~PeerManager();

    bool startServer(int port);
    void stop();
    void connect(const std::string& ip, int port);
    void send(const std::string& peerId, const std::vector<uint8_t>& data);
    void setCallback(std::function<void(const std::vector<Peer>&)> cb);

private:
    std::function<void(const std::vector<Peer>&)> m_cb;
    std::vector<Peer> m_peers;
    std::mutex m_mutex;

    void notify();
    void updatePeer(const Peer& p);
};

extern PeerManager g_peerManager;

#endif // PEER_MANAGER_H
