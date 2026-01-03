#ifndef UDP_CONNECTION_MANAGER_H
#define UDP_CONNECTION_MANAGER_H

#include <string>
#include <functional>
#include <vector>
#include <memory>
#include "../../../plugins/session/include/iudp_connection_manager.h"

class UdpConnectionManager : public IUdpConnectionManager {
public:
    // Callback for when data is received
    using OnDataCallback = std::function<void(const std::string&, const std::string&)>;
    // Callback for when a peer disconnects (or times out)
    using OnDisconnectCallback = std::function<void(const std::string&)>;

    UdpConnectionManager();
    ~UdpConnectionManager();

    // Starts the UDP listener on the specified port
    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) override;
    
    // Single-threaded mode: start without spawning a listener thread
    // The caller must poll getSocketFd() and call processIncomingData() when data is available
    bool startServerEventLoop(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect);

    // Stops the listener and all related threads
    void stop() override;

    // Connects to a peer.
    // UDP is connectionless, but higher layers use this to decide whether to send CONTROL_CONNECT.
    // We validate inputs and return true when the local UDP socket is running.
    bool connectToPeer(const std::string& ip, int port) override;

    // Sends a message to a specific peer
    void sendMessageToPeer(const std::string& peer_id, const std::string& message) override;

    // Sends a raw packet (unencrypted) - used for STUN/NAT traversal
    void sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) override;

    void setStunPacketCallback(OnStunPacketCallback callback) override;
    
    // Single-threaded mode: get the socket file descriptor for polling
    int getSocketFd() const;
    
    // Single-threaded mode: process one incoming packet (call when socket is readable)
    void processIncomingData();

private:
    class UdpImpl;
    std::unique_ptr<UdpImpl> m_impl;
};

#endif // UDP_CONNECTION_MANAGER_H
