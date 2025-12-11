
#ifndef NETWORK_H
#define NETWORK_H

#include <functional>
#include <string>
#include <memory>

class NetworkImpl;

using DataCallback = std::function<void(const std::string& peerId, const std::string& data)>;
using DisconnectCallback = std::function<void(const std::string& peerId)>;

class Network {
public:
    Network();
    ~Network();

    bool startServer(int port);
    void stop();
    bool connect(const std::string &ip, int port);
    void send(const std::string &peerId, const std::string &data);
    void setCallbacks(DataCallback onData, DisconnectCallback onDisconnect);

private:
    std::unique_ptr<NetworkImpl> m_impl;
};

#endif
