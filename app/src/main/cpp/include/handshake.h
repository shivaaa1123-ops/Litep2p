#ifndef LITEP2P_HANDSHAKE_H
#define LITEP2P_HANDSHAKE_H

#include <string>

// Abstract handshake interface (for pluggable implementations)
class HandshakeInterface {
public:
    virtual ~HandshakeInterface() = default;

    // Perform handshake on connected socket fd. On success, fill remote_id and return true.
    virtual bool doHandshake(int socket_fd, const std::string& our_id, std::string& remote_id, int timeout_ms) = 0;
};

#endif // LITEP2P_HANDSHAKE_H
