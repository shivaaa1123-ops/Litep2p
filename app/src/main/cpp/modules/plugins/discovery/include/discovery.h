#ifndef DISCOVERY_H
#define DISCOVERY_H

#include <string>
#include <functional>

class Discovery {
public:
    virtual ~Discovery() {}
    virtual void start(int port, const std::string& peer_id) = 0;
    virtual void stop() = 0;
    virtual void setCallback(std::function<void(const std::string&, const std::string&)> cb) = 0;
};

Discovery* getGlobalDiscoveryInstance();

#endif // DISCOVERY_H
