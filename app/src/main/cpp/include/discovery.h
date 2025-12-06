#ifndef LITEP2P_DISCOVERY_H
#define LITEP2P_DISCOVERY_H

#include <functional>
#include "peer.h"

using DiscoveryCb = std::function<void(const Peer&)>;

class DiscoveryImpl;   // internal, hidden

class Discovery {
public:
    Discovery();
    ~Discovery();

    bool start(int port);
    void stop();
    void setCallback(DiscoveryCb cb);
};

// Exported factory method used by JNI layer
Discovery* getGlobalDiscoveryInstance();

#endif