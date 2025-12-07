#include "session_manager.h"
#include <thread>
#include <atomic>
#include <chrono>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <iostream>

using namespace std::chrono;

static int64_t now_ms() {
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// A very small, local-only implementation using blocking connect in a thread.
// This is a pragmatic placeholder; later we will replace connect/handshake with non-blocking epoll-based flow.

struct SessionManager::Impl {
    std::mutex mu;
    std::unordered_map<std::string, SessionInfo> sessions;
    std::atomic<bool> running{false};
    std::thread worker;
    SessionCallback cb;
};

SessionManager::SessionManager(): p(new Impl()) {}
SessionManager::~SessionManager(){ stop(); delete p; }

bool SessionManager::start() {
    if (p->running.load()) return false;
    p->running.store(true);
    // worker could monitor sessions; for now it's idle
    p->worker = std::thread([this](){
        while (p->running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            // optional: sweep stale sessions
        }
    });
    return true;
}

void SessionManager::stop() {
    if (!p->running.load()) return;
    p->running.store(false);
    if (p->worker.joinable()) p->worker.join();
    // close sockets
    std::lock_guard<std::mutex> lk(p->mu);
    for (auto &kv : p->sessions) {
        if (kv.second.socket_fd >= 0) {
            close(kv.second.socket_fd);
            kv.second.socket_fd = -1;
        }
    }
    p->sessions.clear();
}

static int connect_tcp(const std::string& host, int port, std::string& out_err) {
    struct sockaddr_in serv_addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { out_err = "socket failed"; return -1; }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
        close(sock);
        out_err = "invalid address";
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        out_err = "connect failed";
        return -1;
    }
    return sock;
}

// naive parse of "tcp://ip:port"
static bool parse_tcp_addr(const std::string& addr, std::string& host, int& port) {
    if (addr.rfind("tcp://", 0) != 0) return false;
    std::string rest = addr.substr(6);
    auto pos = rest.find(':');
    if (pos==std::string::npos) return false;
    host = rest.substr(0,pos);
    try {
        port = std::stoi(rest.substr(pos+1));
    } catch(...) { return false; }
    return true;
}

// very simple handshake: send "HELLO:<ourid>" and expect "WELCOME:<peerid>"
static bool perform_insecure_handshake(int sock, const std::string& our_id, std::string& remote_id, int timeout_ms=3000) {
    std::string hello = "HELLO:" + our_id + "\n";
    ssize_t w = send(sock, hello.data(), hello.size(), 0);
    if (w != (ssize_t)hello.size()) return false;

    // set recv timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    char buf[512];
    ssize_t r = recv(sock, buf, sizeof(buf)-1, 0);
    if (r <= 0) return false;
    buf[r] = '\0';
    std::string resp(buf);
    if (resp.rfind("WELCOME:", 0) == 0) {
        remote_id = resp.substr(8);
        // strip newline
        if (!remote_id.empty() && remote_id.back()=='\n') remote_id.pop_back();
        return true;
    }
    return false;
}

std::string SessionManager::connectToPeer(const std::string& peer_id, const std::string& addr) {
    std::string host; int port;
    if (!parse_tcp_addr(addr, host, port)) return std::string();

    // create a session entry immediately
    SessionInfo sinfo;
    sinfo.peer_id = peer_id;
    sinfo.addr = addr;
    sinfo.socket_fd = -1;
    sinfo.established = false;
    sinfo.created_ms = now_ms();

    {
        std::lock_guard<std::mutex> lk(p->mu);
        p->sessions[peer_id] = sinfo;
    }

    // perform connect+handshake in background
    std::thread([this, peer_id, addr, host, port](){
        std::string err;
        int sock = connect_tcp(host, port, err);
        if (sock < 0) {
            // remove session
            std::lock_guard<std::mutex> lk(p->mu);
            p->sessions.erase(peer_id);
            return;
        }
        std::string remote_id;
        // for now our id is "local" (caller should set real id in production)
        std::string our_id = "localnode";
        bool ok = perform_insecure_handshake(sock, our_id, remote_id, 3000);
        if (!ok) {
            close(sock);
            std::lock_guard<std::mutex> lk(p->mu);
            p->sessions.erase(peer_id);
            return;
        }
        // success: update session
        {
            std::lock_guard<std::mutex> lk(p->mu);
            auto it = p->sessions.find(peer_id);
            if (it != p->sessions.end()) {
                it->second.socket_fd = sock;
                it->second.established = true;
            }
        }
        // callback
        if (p->cb) p->cb(p->sessions[peer_id]);
    }).detach();

    return peer_id;
}

void SessionManager::closeSession(const std::string& peer_id) {
    std::lock_guard<std::mutex> lk(p->mu);
    auto it = p->sessions.find(peer_id);
    if (it != p->sessions.end()) {
        if (it->second.socket_fd >= 0) close(it->second.socket_fd);
        p->sessions.erase(it);
    }
}

std::vector<SessionInfo> SessionManager::listSessions() {
    std::lock_guard<std::mutex> lk(p->mu);
    std::vector<SessionInfo> out;
    for (auto &kv : p->sessions) out.push_back(kv.second);
    return out;
}

void SessionManager::setCallback(SessionCallback cb) {
    p->cb = cb;
}
