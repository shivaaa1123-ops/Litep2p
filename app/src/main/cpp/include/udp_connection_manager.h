#ifndef UDP_CONNECTION_MANAGER_H
#define UDP_CONNECTION_MANAGER_H

#include <string>
#include <functional>
#include <vector>
#include <memory>

class UdpConnectionManager {
public:
    // Callback for when data is received
    using OnDataCallback = std::function<void(const std::string&, const std::string&)>;
    // Callback for when a peer disconnects (or times out)
    using OnDisconnectCallback = std::function<void(const std::string&)>;

    UdpConnectionManager();
    ~UdpConnectionManager();

    // Starts the UDP listener on the specified port
    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect);

    // Stops the listener and all related threads
    void stop();

    // Sends a message to a specific peer
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);

private:
    class UdpImpl;
    std::unique_ptr<UdpImpl> m_impl;
};

#endif // UDP_CONNECTION_MANAGER_H
