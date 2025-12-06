#ifndef NETWORK_H
#define NETWORK_H

#include <functional>
#include <string>

using DataCallback = std::function<void(const std::string&, const std::string&)>;

class Network {
public:
    Network();
    ~Network();

    bool startServer(int port);
    void stopServer();
    bool connectToPeer(const std::string &ip, int port, std::string &peerId);
    void sendToPeer(const std::string &peerId, const std::string &data);
    void setDataCallback(DataCallback cb);
};

#endif
