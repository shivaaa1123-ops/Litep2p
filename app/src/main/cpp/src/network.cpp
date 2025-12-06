#include "network.h"
#include "logger.h"
#include <thread>
#include <map>
#include <mutex>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <string.h>

struct ConnInfo { int fd; std::string peerId; };

class NetworkImpl {
public:
    NetworkImpl(): m_serverFd(-1), m_running(false) {}
    ~NetworkImpl(){ stopServer(); }

    bool startServer(int port) {
        if (m_running) return false;
        m_serverFd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_serverFd < 0) { nativeLog("Network: socket() failed"); return false; }
        int opt = 1; setsockopt(m_serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(port);
        if (bind(m_serverFd, (sockaddr*)&addr, sizeof(addr)) < 0) { nativeLog("Network: bind failed"); close(m_serverFd); m_serverFd=-1; return false; }
        if (listen(m_serverFd, 10) < 0) { nativeLog("Network: listen failed"); close(m_serverFd); m_serverFd=-1; return false; }
        nativeLog(std::string("Network: server listening on ") + std::to_string(port));
        m_running = true;
        m_acceptThread = std::thread([this](){ acceptLoop(); });
        return true;
    }

    void stopServer() {
        m_running = false;
        if (m_serverFd >= 0) { close(m_serverFd); m_serverFd = -1; }
        if (m_acceptThread.joinable()) m_acceptThread.join();
        std::lock_guard<std::mutex> l(m_lock);
        for (auto &kv : m_conns) { close(kv.second.fd); }
        m_conns.clear();
    }

    bool connectToPeer(const std::string &ip, int port, std::string &peerId) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return false; }
        // make non-blocking
        int flags = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        peerId = ip + ":" + std::to_string(port);
        std::lock_guard<std::mutex> l(m_lock);
        m_conns[peerId] = {fd, peerId};
        nativeLog(std::string("Network: connected to ") + peerId);
        return true;
    }

    void sendToPeer(const std::string &peerId, const std::string &data) {
        std::lock_guard<std::mutex> l(m_lock);
        auto it = m_conns.find(peerId);
        if (it == m_conns.end()) { nativeLog(std::string("Network: no conn for ") + peerId); return; }
        send(it->second.fd, data.data(), data.size(), 0);
    }

    void setDataCallback(DataCallback cb) { m_cb = cb; }

private:
    int m_serverFd;
    bool m_running;
    std::thread m_acceptThread;
    std::map<std::string, ConnInfo> m_conns;
    std::mutex m_lock;
    DataCallback m_cb;

    void acceptLoop() {
        while (m_running) {
            sockaddr_in remote; socklen_t len = sizeof(remote);
            int fd = accept(m_serverFd, (sockaddr*)&remote, &len);
            if (fd < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }
            // make non-blocking
            int flags = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            char buf[64]; inet_ntop(AF_INET, &remote.sin_addr, buf, sizeof(buf));
            std::string peerId = std::string(buf) + ":" + std::to_string(ntohs(remote.sin_port));
            {
                std::lock_guard<std::mutex> l(m_lock);
                m_conns[peerId] = {fd, peerId};
            }
            nativeLog(std::string("Network: accepted connection from ") + peerId);
            // spawn a reader thread for this connection
            std::thread([this, fd, peerId]() {
                char buffer[1024];
                while (m_running) {
                    ssize_t r = recv(fd, buffer, sizeof(buffer), 0);
                    if (r > 0) {
                        std::string data(buffer, buffer + r);
                        if (m_cb) m_cb(peerId, data);
                    } else if (r == 0) { break; } else {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                }
                close(fd);
                std::lock_guard<std::mutex> l(m_lock);
                m_conns.erase(peerId);
                nativeLog(std::string("Network: connection closed ") + peerId);
            }).detach();
        }
    }
};

static NetworkImpl *g_net = nullptr;

Network::Network() { if (!g_net) g_net = new NetworkImpl(); }
Network::~Network() {
    if (g_net) {
        delete g_net;
        g_net = nullptr;
    }
}
bool Network::startServer(int port) { return g_net && g_net->startServer(port); }
void Network::stopServer() { if (g_net) g_net->stopServer(); }
bool Network::connectToPeer(const std::string &ip, int port, std::string &peerId) { return g_net && g_net->connectToPeer(ip, port, peerId); }
void Network::sendToPeer(const std::string &peerId, const std::string &data) { if (g_net) g_net->sendToPeer(peerId, data); }
void Network::setDataCallback(DataCallback cb) { if (g_net) g_net->setDataCallback(cb); }
