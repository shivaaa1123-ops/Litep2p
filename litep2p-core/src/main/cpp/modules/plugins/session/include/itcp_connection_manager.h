#ifndef ITCP_CONNECTION_MANAGER_H
#define ITCP_CONNECTION_MANAGER_H

#include "iconnection_manager.h"

class ITcpConnectionManager : public IConnectionManager {
public:
    virtual ~ITcpConnectionManager() = default;
    // TCP-specific methods can be added here if needed

    // Actual port the TCP listener bound to. -1 when not bound. Used to
    // advertise a real endpoint when the configured port was contended by
    // another process on the same device (ephemeral-port fallback).
    virtual int getBoundPort() const { return -1; }
};

#endif // ITCP_CONNECTION_MANAGER_H