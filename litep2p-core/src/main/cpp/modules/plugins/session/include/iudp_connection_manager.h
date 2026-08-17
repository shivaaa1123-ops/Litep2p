#ifndef IUDP_CONNECTION_MANAGER_H
#define IUDP_CONNECTION_MANAGER_H

#include "iconnection_manager.h"
#include <cstdint>
#include <vector>
#include <functional>

class IUdpConnectionManager : public IConnectionManager {
public:
    virtual ~IUdpConnectionManager() = default;
    // UDP-specific methods
    virtual void sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) = 0;
    
    using OnStunPacketCallback = std::function<void(const std::string& ip, int port, const std::vector<uint8_t>& data)>;
    virtual void setStunPacketCallback(OnStunPacketCallback callback) = 0;
    
    // Restart the socket after network interface change (WiFi<->LTE)
    // Returns true if socket was successfully restarted
    virtual bool restartSocket() = 0;

    // Actual port the listener bound to. Differs from the requested port when
    // an ephemeral port was requested (port 0, e.g. when the configured port is
    // already held by another process on the same device). -1 when not bound.
    virtual int getBoundPort() const { return -1; }
};

#endif // IUDP_CONNECTION_MANAGER_H