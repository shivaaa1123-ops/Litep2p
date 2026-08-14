#ifndef QUIC_CONNECTION_MANAGER_H
#define QUIC_CONNECTION_MANAGER_H

#include <string>
#include <functional>
#include <vector>
#include <memory>
#include "../../../plugins/session/include/iudp_connection_manager.h"

class RealQuicTransport; // global forward declaration (picoquic-backed transport)

// QuicConnectionManager implements the UDP interface but uses QUIC framing
class QuicConnectionManager : public IUdpConnectionManager {
public:
    using OnDataCallback = std::function<void(const std::string&, const std::string&)>;
    using OnDisconnectCallback = std::function<void(const std::string&)>;

    QuicConnectionManager();
    ~QuicConnectionManager();

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) override;
    void stop() override;

    // Not used for connectionless protocols usually, but QUIC has connections
    bool connectToPeer(const std::string& ip, int port) override;

    void sendMessageToPeer(const std::string& peer_id, const std::string& message) override;
    void sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) override;
    void setStunPacketCallback(OnStunPacketCallback callback) override;
    
    // Restart socket for network interface change - not fully implemented for QUIC yet
    bool restartSocket() override { return false; }

private:
    class QuicImpl;
    std::unique_ptr<QuicImpl> m_impl;

    // Real QUIC (picoquic) transport, used when LITEP2P_ENABLE_REAL_QUIC=1.
    std::unique_ptr<RealQuicTransport> m_real;
    bool m_using_real = false;
};

#endif // QUIC_CONNECTION_MANAGER_H
