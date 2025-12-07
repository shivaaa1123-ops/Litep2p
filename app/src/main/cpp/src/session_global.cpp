#include "session_manager.h"
#include <mutex>
#include <thread>
#include "handshake_server.h"

static SessionManager* g_sessionManager = nullptr;
static std::mutex g_session_mutex;
static HandshakeAcceptor* g_acceptor = nullptr;

SessionManager* getGlobalSessionManager() {
    std::lock_guard<std::mutex> lk(g_session_mutex);
    if (!g_sessionManager) {
        g_sessionManager = new SessionManager();
        // start a handshake acceptor on default port 9999
        g_acceptor = new HandshakeAcceptor(9999);
        g_acceptor->start([](int client_fd, const std::string& remote_addr){
            // For now, just log and close socket
            // In future, we should perform secure handshake and register session
            // close immediately to avoid leaking descriptors
            (void)client_fd; (void)remote_addr;
            // Note: leaving socket open could be used to continue session; currently close
            if (client_fd >= 0) close(client_fd);
        });
    }
    return g_sessionManager;
}

void destroyGlobalSessionManager() {
    std::lock_guard<std::mutex> lk(g_session_mutex);
    if (g_acceptor) {
        g_acceptor->stop();
        delete g_acceptor;
        g_acceptor = nullptr;
    }
    if (g_sessionManager) {
        g_sessionManager->stop();
        delete g_sessionManager;
        g_sessionManager = nullptr;
    }
}
