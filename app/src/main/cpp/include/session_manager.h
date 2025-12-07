#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include "peer.h"
#include "connection_manager.h"
#include "udp_connection_manager.h"
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <condition_variable>

class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    void start(int port, std::function<void(const std::vector<Peer>&)> peer_update_cb, const std::string& comms_mode, const std::string& peer_id);
    void stop();

    void connectToPeer(const std::string& peer_id);
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);

private:
    class Impl;
    Impl* m_impl;
};

#endif // SESSION_MANAGER_H
