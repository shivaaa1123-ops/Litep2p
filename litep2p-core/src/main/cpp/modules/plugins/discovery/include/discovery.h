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
    
    // Send a direct discovery probe to a specific IP:port (bypasses broadcast)
    // This is useful when AP isolation blocks broadcasts but we know the peer's LAN IP
    virtual void sendDirectProbe(const std::string& ip, int port) = 0;
    
    // Get the local LAN IP address (first private IP found on a non-loopback interface)
    virtual std::string getLocalLanIP() const = 0;

    // Update the connection port advertised in discovery broadcasts. Used when
    // the listener bound to an ephemeral port (configured port was contended by
    // another process on the same device) so peers learn the real endpoint.
    virtual void setConnectionPort(int port) = 0;
};

Discovery* getGlobalDiscoveryInstance();

// Parse a discovery announcement (legacy "<magic>:<peer_id>:<port>" or the
// obfuscated "<magic> || nonce(12) || AEAD_ct" form when a shared key is
// configured). Magic + key come from ConfigManager (network.discovery_magic /
// discovery_shared_key). Thread-safe, exception-safe, never throws. Returns
// false for anything malformed. Exposed as a free function so the parser can
// be fuzzed and unit-tested without a live socket.
bool parse_discovery_announcement(const std::string& raw,
                                  std::string& out_peer_id, int& out_port);

#endif // DISCOVERY_H
