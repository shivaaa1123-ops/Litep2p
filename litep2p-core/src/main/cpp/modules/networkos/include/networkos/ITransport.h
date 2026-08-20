#pragma once

// Network OS — ITransport (master doc §16 transport abstraction, §89 Phase 1).
//
// Thin facade over the existing TCP/UDP/QUIC transports. Socket details are
// NOT exposed upward; capabilities() lets higher layers decide what is
// possible without touching the socket layer.

#include <cstdint>
#include <string>
#include <vector>

#include "Runtime.h"

namespace networkos {

// An endpoint is a host:port pair (IPv4/IPv6 aware, see device_utils.h).
struct Endpoint {
    std::string host;
    uint16_t port = 0;

    bool empty() const { return host.empty() || port == 0; }
    std::string toString() const { return host + ":" + std::to_string(port); }
};

// Transport capability flags (bitmask returned by capabilities()).
enum TransportCapability : uint32_t {
    kCapTcp       = 1u << 0,
    kCapUdp       = 1u << 1,
    kCapQuic      = 1u << 2,   // only when ENABLE_QUIC is compiled in
    kCapObscured  = 1u << 3,   // OBF1/padding/cover machinery present
    kCapNatTraversal = 1u << 4,
    kCapRelay     = 1u << 5,   // overlay/LPX2 relay path available
};

class ITransport {
public:
    virtual ~ITransport() = default;

    // What this build/device supports. Pure query, never touches sockets.
    virtual uint32_t capabilities() const = 0;

    // Bring the listener up on `port` (0 = pick from network.port_range or an
    // ephemeral port; the bound port is reported via boundPort()).
    virtual Result listen(int port = 0) = 0;

    // Establish (or return) a session path to `ep`. Endpoints are temporary;
    // identity is stable (§74).
    virtual Result connect(const Endpoint& ep) = 0;

    // True when a usable session path to `peer_id` exists.
    virtual bool isConnected(const std::string& peer_id) const = 0;

    // Actual bound listener port, or -1 when not listening.
    virtual int boundPort() const = 0;

    // Tear down the listener and all session paths. No blocked threads left.
    virtual Result close() = 0;
};

} // namespace networkos
