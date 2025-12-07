#ifndef LITEP2P_SESSION_MANAGER_H
#define LITEP2P_SESSION_MANAGER_H

#include <string>
#include <functional>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <cstdint>

// forward declare Peer
struct Peer;

struct SessionInfo {
    std::string peer_id;
    std::string addr; // transport address e.g. tcp://1.2.3.4:9000
    int socket_fd;    // connected socket (or -1)
    bool established; // true after handshake
    int64_t created_ms;
};

using SessionCallback = std::function<void(const SessionInfo&)>;

// Simple SessionManager: manages sessions (connect, close) and performs a handshake via HandshakeInterface.
class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    // Start manager background threads if needed
    bool start();

    // Stop and close sessions
    void stop();

    // Create outbound session: connects to addr and performs handshake with peer_id (non-blocking)
    // Returns a temporary session id (or empty string on immediate failure)
    std::string connectToPeer(const std::string& peer_id, const std::string& addr);

    // Close session by peer id
    void closeSession(const std::string& peer_id);

    // Get snapshot of sessions
    std::vector<SessionInfo> listSessions();

    // Set callback when session established/updated
    void setCallback(SessionCallback cb);

private:
    struct Impl;
    Impl* p;
};

#endif // LITEP2P_SESSION_MANAGER_H
