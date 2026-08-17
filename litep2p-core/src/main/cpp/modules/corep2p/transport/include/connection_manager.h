#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include "../../../plugins/session/include/itcp_connection_manager.h"

class ConnectionManager : public ITcpConnectionManager {
public:
    using OnDataCallback = std::function<void(const std::string&, const std::string&)>;
    using OnDisconnectCallback = std::function<void(const std::string&)>;

    ConnectionManager();
    ~ConnectionManager();

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect);
    void stop();

    bool connectToPeer(const std::string& ip, int port);
    void sendMessageToPeer(const std::string& network_id, const std::string& message);
    bool disconnectPeer(const std::string& network_id) override;

    // Actual port the TCP listener bound to. -1 when not running. Used to
    // advertise a real endpoint when the configured port was contended by
    // another process on the same device (ephemeral-port fallback).
    int getBoundPort() const override;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

#endif // CONNECTION_MANAGER_H
