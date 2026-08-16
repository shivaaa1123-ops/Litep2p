#ifndef ITCP_CONNECTION_MANAGER_H
#define ITCP_CONNECTION_MANAGER_H

#include "iconnection_manager.h"

class ITcpConnectionManager : public IConnectionManager {
public:
    virtual ~ITcpConnectionManager() = default;
    // TCP-specific methods can be added here if needed
};

#endif // ITCP_CONNECTION_MANAGER_H