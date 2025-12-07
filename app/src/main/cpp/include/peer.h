#ifndef PEER_H
#define PEER_H

#include <string>
#include <chrono>

struct Peer {
    std::string id;
    std::string ip;
    int port;
    bool connected = false;
    std::chrono::steady_clock::time_point last_seen;
    int latency = -1;
    std::string network_id; // --- The actual network address (ip:port) of the connection ---
};

#endif // PEER_H
