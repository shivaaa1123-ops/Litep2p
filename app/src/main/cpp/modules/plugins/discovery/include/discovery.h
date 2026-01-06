#ifndef DISCOVERY_H
#define DISCOVERY_H

#include <string>
#include <functional>

class Discovery {
public:
    virtual ~Discovery() {}
    virtual void start(int port, const std::string& peer_id) = 0;
    
    // Single-threaded mode: start without spawning threads
    // Returns the socket fd for polling, caller must call processBroadcast() and processIncoming()
    virtual int startEventLoop(int port, const std::string& peer_id) = 0;
    
    virtual void stop() = 0;
    virtual void setCallback(std::function<void(const std::string&, const std::string&)> cb) = 0;
    
    // Single-threaded mode: send a broadcast (call periodically from event loop timer)
    virtual void sendBroadcast() = 0;
    
    // Single-threaded mode: process incoming discovery packet (call when socket is readable)
    virtual void processIncoming() = 0;
    
    // Get socket fd for event loop registration
    virtual int getSocketFd() const = 0;
};

Discovery* getGlobalDiscoveryInstance();

#endif // DISCOVERY_H
