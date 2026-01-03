#ifndef PEER_H
#define PEER_H

#include <string>
#include <chrono>
#include "peer_tier.h"

struct Peer {
    std::string id;
    std::string ip;
    int port = -1;
    std::chrono::steady_clock::time_point last_seen;
    // Timestamp of last *discovery* announcement observed for this peer.
    // IMPORTANT: For connected peers, discovery traffic must not be treated as liveness for the
    // encrypted session. Otherwise a restarted peer (new Noise keys) can keep an old READY session
    // "alive" forever via discovery while PING/PONG cannot decrypt, preventing reconnection.
    std::chrono::steady_clock::time_point last_discovery_seen;
    int latency = -1;
    std::string network_id; // --- The actual network address (ip:port) of the connection ---
    bool connected = false;
    PeerTier tier = PeerTier::TIER_1;
};

#endif // PEER_H
