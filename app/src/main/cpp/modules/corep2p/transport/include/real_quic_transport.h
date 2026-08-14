#ifndef REAL_QUIC_TRANSPORT_H
#define REAL_QUIC_TRANSPORT_H

/**
 * Real QUIC (RFC 9000) transport adapter built on picoquic + picotls
 * (minicrypto). Messages are carried in QUIC DATAGRAM frames (RFC 9221);
 * reliability/ordering is provided by the session layer above (message ACKs,
 * retransmission), exactly like the UDP transport.
 *
 * Only compiled when LITEP2P_ENABLE_REAL_QUIC=1; otherwise the methods are
 * no-op stubs so callers can link unconditionally.
 *
 * IPv6: the listener binds an AF_INET6 dual-stack socket (IPv4-mapped
 * addresses accepted), and outbound connects prefer IPv6 addresses when the
 * host resolves to both families.
 */

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <cstdint>

class RealQuicTransport {
public:
    using OnDataCb = std::function<void(const std::string& peer_id, const std::string& data)>;
    using OnReadyCb = std::function<void(const std::string& peer_id)>;
    using OnDisconnectCb = std::function<void(const std::string& peer_id)>;

    RealQuicTransport();
    ~RealQuicTransport();

    // Start listener on `port`. Returns false if QUIC is unavailable or the
    // listener could not be created.
    bool start(uint16_t port, OnDataCb on_data, OnReadyCb on_ready,
               OnDisconnectCb on_disconnect);

    void stop();

    // Connect to a peer. `host` may be an IPv4/IPv6 literal or a hostname
    // (IPv6 preferred on dual-stack resolution).
    bool connect(const std::string& peer_id, const std::string& host, uint16_t port);

    // Queue a datagram. Returns false if the peer is unknown/not ready.
    bool send(const std::string& peer_id, const std::string& data);

    bool is_connected(const std::string& peer_id) const;

    // True when built with real QUIC support (LITEP2P_ENABLE_REAL_QUIC=1).
    static bool available();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

#endif // REAL_QUIC_TRANSPORT_H
