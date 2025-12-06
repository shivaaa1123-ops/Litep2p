// peer.h
#ifndef PEER_H
#define PEER_H

#include <string>

struct Peer {
    std::string id;
    std::string ip;
    int port;
    long long latency;
    bool connected;
    long long lastSeenMs;
};

#endif // PEER_H
