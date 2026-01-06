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
    // Active endpoint used for the current session and for sending traffic.
    // For UDP this is the ip:port we last connected to (or discovered on LAN).
    std::string network_id;

    // Latest endpoint advertised via discovery/signaling. This may differ from `network_id`
    // while we are actively connected (e.g., peer switches LAN->WAN or restarts and updates
    // its public mapping). We keep it separate so we can switch cleanly on reconnect
    // without breaking an otherwise healthy LAN session.
    std::string advertised_network_id;
    bool connected = false;
    PeerTier tier = PeerTier::TIER_1;
};

#endif // PEER_H
