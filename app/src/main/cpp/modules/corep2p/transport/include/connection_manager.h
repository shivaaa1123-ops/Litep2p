#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <string>
#include <vector>
#include <functional>
#include <memory>

class ConnectionManager {
public:
    using OnDataCallback = std::function<void(const std::string&, const std::string&)>;
    using OnDisconnectCallback = std::function<void(const std::string&)>;

    ConnectionManager();
    ~ConnectionManager();

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect);
    void stop();

    bool connectToPeer(const std::string& ip, int port);
    void sendMessageToPeer(const std::string& network_id, const std::string& message);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

#endif // CONNECTION_MANAGER_H
