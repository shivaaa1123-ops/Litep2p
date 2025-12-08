import zipfile
import os

files = {}

# ==============================================================================
# 1. BUILD SCRIPT (cpp/CMakeLists.txt)
#    Points to 'src' folder instead of 'source' to match your image.
# ==============================================================================
files["cpp/CMakeLists.txt"] = r"""
cmake_minimum_required(VERSION 3.10.2)
project("litep2p_native")

set(LIB_NAME litep2p)

add_library(litep2p SHARED
    src/p2p_api.cpp
    src/discovery.cpp
    src/network.cpp
    src/peer_manager.cpp
    src/logger.cpp
    src/jni_glue.cpp
    src/jni_helpers.cpp
    src/epoll_reactor.cpp
)

target_include_directories(${LIB_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(${LIB_NAME} 
    PROPERTIES
        CXX_STANDARD 17
        CXX_EXTENSIONS OFF
)

find_library(log-lib log)
target_link_libraries(${LIB_NAME}
    ${log-lib}
)
"""

# ==============================================================================
# 2. HEADERS (cpp/include)
#    Clean, dependency-free headers using Pimpl idiom.
# ==============================================================================

files["cpp/include/epoll_reactor.h"] = r"""
#ifndef EPOLL_REACTOR_H
#define EPOLL_REACTOR_H

#include <functional>
#include <memory>

class EpollReactorImpl;

using EventCallback = std::function<void(int fd, uint32_t events)>;
using Task = std::function<void()>;
using TimerId = int;

class EpollReactor {
public:
    EpollReactor();
    ~EpollReactor();

    void start();
    void stop();

    bool add(int fd, uint32_t events, EventCallback cb);
    bool remove(int fd);
    void post(Task t);

    TimerId runAfter(int milliseconds, Task t);
    TimerId runEvery(int milliseconds, Task t);
    void cancelTimer(TimerId id);

private:
    std::unique_ptr<EpollReactorImpl> m_impl;
};

#endif // EPOLL_REACTOR_H
"""

files["cpp/include/network.h"] = r"""
#ifndef NETWORK_H
#define NETWORK_H

#include <functional>
#include <string>
#include <memory>

class NetworkImpl;

using DataCallback = std::function<void(const std::string& peerId, const std::string& data)>;
using DisconnectCallback = std::function<void(const std::string& peerId)>;

class Network {
public:
    Network();
    ~Network();

    bool startServer(int port);
    void stop();
    bool connect(const std::string &ip, int port);
    void send(const std::string &peerId, const std::string &data);
    void setCallbacks(DataCallback onData, DisconnectCallback onDisconnect);

private:
    std::unique_ptr<NetworkImpl> m_impl;
};

#endif
"""

files["cpp/include/peer_manager.h"] = r"""
#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <functional>
#include <vector>
#include <string>
#include <memory>
#include "peer.h"

class PeerManagerImpl;

class PeerManager {
public:
    PeerManager();
    ~PeerManager();

    void start(int port);
    void stop();
    void connectTo(const std::string& ip, int port);
    void broadcastMessage(const std::string& msg);
    void sendDirect(const std::string& peerId, const std::string& msg);
    void setPeerUpdateCallback(std::function<void(const std::vector<Peer>&)> cb);

private:
    std::unique_ptr<PeerManagerImpl> m_impl;
};

extern PeerManager g_peerManager;

#endif
"""

files["cpp/include/discovery.h"] = r"""
#ifndef LITEP2P_DISCOVERY_H
#define LITEP2P_DISCOVERY_H

#include <functional>
#include "peer.h"

using DiscoveryCb = std::function<void(const Peer&)>;
class DiscoveryImpl;

class Discovery {
public:
    Discovery();
    ~Discovery();
    bool start(int port);
    void stop();
    void setCallback(DiscoveryCb cb);
private:
    DiscoveryImpl* m_impl;
};

Discovery* getGlobalDiscoveryInstance();

#endif
"""

files["cpp/include/peer.h"] = r"""
#ifndef PEER_H
#define PEER_H
#include <string>

struct Peer {
    std::string id;
    std::string ip;
    int port;
    long long latency;
    bool connected;
    long long lastSeenMs;
};
#endif
"""

files["cpp/include/logger.h"] = r"""
#pragma once
#include <string>
#include <jni.h>

void setLoggerTarget(JNIEnv* env, jobject activityObj);
void nativeLog(const std::string& msg);
void loggerSetJavaVM(JavaVM* vm);
"""

files["cpp/include/jni_glue.h"] = r"""
#ifndef JNI_GLUE_H
#define JNI_GLUE_H

#include <jni.h>
#include <vector>
#include "peer.h"

#ifdef __cplusplus
extern "C" {
#endif

bool jniGlueInit(JNIEnv* env, jclass p2pClass);
void jniGlueCleanup(JNIEnv* env);
void sendPeersToUI(const std::vector<Peer>& peers);

#ifdef __cplusplus
}
#endif
#endif
"""

files["cpp/include/jni_helpers.h"] = r"""
#ifndef JNI_HELPERS_H
#define JNI_HELPERS_H
#include <jni.h>

extern JavaVM* g_vm;
JNIEnv* getJNIEnv();

#endif
"""

files["cpp/include/p2p_api.h"] = r"""
#ifndef P2P_API_H
#define P2P_API_H
#include <jni.h>
// JNI Export Header
#endif
"""

# ==============================================================================
# 3. SOURCE FILES (cpp/src)
#    Implementations of the robust logic.
# ==============================================================================

files["cpp/src/epoll_reactor.cpp"] = r"""
#include "epoll_reactor.h"
#include "logger.h"
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <unordered_map>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>

struct Timer {
    int id;
    long long expirationMs;
    int intervalMs; 
    Task task;
};

static long long nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

class EpollReactorImpl {
public:
    EpollReactorImpl() : m_running(false), m_timerSeq(0) {
        m_epollFd = epoll_create1(0);
        m_wakeFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        
        struct epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = m_wakeFd;
        epoll_ctl(m_epollFd, EPOLL_CTL_ADD, m_wakeFd, &ev);
    }

    ~EpollReactorImpl() {
        stop();
        close(m_epollFd);
        close(m_wakeFd);
    }

    void start() {
        if (m_running) return;
        m_running = true;
        m_thread = std::thread([this]() { loop(); });
        nativeLog("Reactor: Started");
    }

    void stop() {
        if (!m_running) return;
        m_running = false;
        wakeUp();
        if (m_thread.joinable()) m_thread.join();
    }

    void wakeUp() {
        uint64_t u = 1;
        write(m_wakeFd, &u, sizeof(u));
    }

    bool add(int fd, uint32_t events, EventCallback cb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        struct epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        if (epoll_ctl(m_epollFd, EPOLL_CTL_ADD, fd, &ev) < 0) return false;
        m_callbacks[fd] = cb;
        return true;
    }

    bool remove(int fd) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callbacks.erase(fd);
        return epoll_ctl(m_epollFd, EPOLL_CTL_DEL, fd, nullptr) == 0;
    }

    void post(Task t) {
        {
            std::lock_guard<std::mutex> lock(m_taskMutex);
            m_pendingTasks.push_back(t);
        }
        wakeUp();
    }

    int runAfter(int ms, Task t) {
        std::lock_guard<std::mutex> lock(m_timerMutex);
        int id = ++m_timerSeq;
        Timer timer{id, nowMs() + ms, 0, t};
        m_timers.insert({timer.expirationMs, timer});
        wakeUp();
        return id;
    }

    int runEvery(int ms, Task t) {
        std::lock_guard<std::mutex> lock(m_timerMutex);
        int id = ++m_timerSeq;
        Timer timer{id, nowMs() + ms, ms, t};
        m_timers.insert({timer.expirationMs, timer});
        wakeUp();
        return id;
    }

    void cancelTimer(int id) {
        std::lock_guard<std::mutex> lock(m_timerMutex);
        for (auto it = m_timers.begin(); it != m_timers.end(); ) {
            if (it->second.id == id) it = m_timers.erase(it);
            else ++it;
        }
    }

private:
    void loop() {
        const int MAX_EVENTS = 64;
        struct epoll_event events[MAX_EVENTS];

        while (m_running) {
            int timeout = -1;
            {
                std::lock_guard<std::mutex> lock(m_timerMutex);
                if (!m_timers.empty()) {
                    long long now = nowMs();
                    long long next = m_timers.begin()->first;
                    timeout = (next > now) ? (int)(next - now) : 0;
                }
            }

            int n = epoll_wait(m_epollFd, events, MAX_EVENTS, timeout);

            if (n > 0) {
                for (int i = 0; i < n; ++i) {
                    int fd = events[i].data.fd;
                    if (fd == m_wakeFd) {
                        uint64_t u; read(m_wakeFd, &u, sizeof(u));
                    } else {
                        EventCallback cb;
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            if (m_callbacks.count(fd)) cb = m_callbacks[fd];
                        }
                        if (cb) cb(fd, events[i].events);
                    }
                }
            }

            std::vector<Task> tasks;
            {
                std::lock_guard<std::mutex> lock(m_taskMutex);
                tasks.swap(m_pendingTasks);
            }
            for (auto& t : tasks) t();

            {
                std::lock_guard<std::mutex> lock(m_timerMutex);
                long long now = nowMs();
                auto it = m_timers.begin();
                while (it != m_timers.end() && it->first <= now) {
                    Timer t = it->second;
                    it = m_timers.erase(it);
                    m_timerMutex.unlock();
                    if(t.task) t.task();
                    m_timerMutex.lock();
                    if (t.intervalMs > 0) {
                        t.expirationMs = now + t.intervalMs;
                        m_timers.insert({t.expirationMs, t});
                        it = m_timers.begin(); 
                    } else {
                        it = m_timers.begin();
                    }
                }
            }
        }
    }

    int m_epollFd, m_wakeFd;
    std::atomic<bool> m_running;
    std::thread m_thread;
    std::mutex m_mutex;
    std::unordered_map<int, EventCallback> m_callbacks;
    std::mutex m_taskMutex;
    std::vector<Task> m_pendingTasks;
    std::mutex m_timerMutex;
    std::multimap<long long, Timer> m_timers; 
    int m_timerSeq;
};

EpollReactor::EpollReactor() : m_impl(new EpollReactorImpl()) {}
EpollReactor::~EpollReactor() = default;
void EpollReactor::start() { m_impl->start(); }
void EpollReactor::stop() { m_impl->stop(); }
bool EpollReactor::add(int fd, uint32_t events, EventCallback cb) { return m_impl->add(fd, events, cb); }
bool EpollReactor::remove(int fd) { return m_impl->remove(fd); }
void EpollReactor::post(Task t) { m_impl->post(t); }
TimerId EpollReactor::runAfter(int ms, Task t) { return m_impl->runAfter(ms, t); }
TimerId EpollReactor::runEvery(int ms, Task t) { return m_impl->runEvery(ms, t); }
void EpollReactor::cancelTimer(TimerId id) { m_impl->cancelTimer(id); }
"""

files["cpp/src/network.cpp"] = r"""
#include "network.h"
#include "epoll_reactor.h"
#include "logger.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <map>
#include <cstring>
#include <mutex>

struct PeerConnection {
    int fd;
    std::string peerId;
    std::vector<uint8_t> rxBuffer;
    bool connected;
};

class NetworkImpl {
public:
    NetworkImpl() : m_running(false) {
        m_reactor = std::make_unique<EpollReactor>();
    }

    ~NetworkImpl() { stop(); }

    bool startServer(int port) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return false; }
        if (listen(fd, 20) < 0) { close(fd); return false; }

        m_running = true;
        m_reactor->start();
        m_reactor->add(fd, EPOLLIN, [this](int f, uint32_t) { acceptConn(f); });
        
        // Robustness: Heartbeat checker
        m_heartbeatTimer = m_reactor->runEvery(5000, [this]() { checkHeartbeats(); });
        nativeLog("Network: Listening on " + std::to_string(port));
        return true;
    }

    void stop() {
        m_running = false;
        m_reactor->stop();
    }

    bool connectPeer(const std::string& ip, int port) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return false; }
        std::string pid = ip + ":" + std::to_string(port);
        registerConnection(fd, pid);
        return true;
    }

    void sendData(const std::string& peerId, const std::string& data) {
        m_reactor->post([this, peerId, data]() {
            int fd = getFd(peerId);
            if (fd == -1) return;
            // Robust Framing: 4-byte length prefix
            uint32_t len = htonl(data.size());
            send(fd, &len, 4, MSG_NOSIGNAL);
            send(fd, data.data(), data.size(), MSG_NOSIGNAL);
        });
    }

    void setCallbacks(DataCallback d, DisconnectCallback dc) {
        m_dataCb = d;
        m_discCb = dc;
    }

private:
    void acceptConn(int serverFd) {
        sockaddr_in r{}; socklen_t l = sizeof(r);
        int cfd = accept(serverFd, (sockaddr*)&r, &l);
        if (cfd < 0) return;
        char buf[64]; inet_ntop(AF_INET, &r.sin_addr, buf, sizeof(buf));
        std::string pid = std::string(buf) + ":" + std::to_string(ntohs(r.sin_port));
        registerConnection(cfd, pid);
    }

    void registerConnection(int fd, std::string pid) {
        std::lock_guard<std::mutex> lock(m_connMutex);
        PeerConnection pc;
        pc.fd = fd;
        pc.peerId = pid;
        pc.connected = true;
        m_connections[fd] = pc;
        m_peerToFd[pid] = fd;
        m_reactor->add(fd, EPOLLIN | EPOLLRDHUP | EPOLLERR, [this](int f, uint32_t e) { handleIo(f, e); });
        nativeLog("Network: Connected " + pid);
    }

    void handleIo(int fd, uint32_t events) {
        if (events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
            closeConn(fd);
            return;
        }
        if (events & EPOLLIN) {
            char buffer[4096];
            ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
            if (n <= 0) { closeConn(fd); return; }
            
            std::lock_guard<std::mutex> lock(m_connMutex);
            if (m_connections.find(fd) == m_connections.end()) return;
            PeerConnection& pc = m_connections[fd];
            pc.rxBuffer.insert(pc.rxBuffer.end(), buffer, buffer + n);

            // Framing Logic
            while (pc.rxBuffer.size() >= 4) {
                uint32_t msgLen = 0;
                memcpy(&msgLen, pc.rxBuffer.data(), 4);
                msgLen = ntohl(msgLen);
                if (msgLen > 10 * 1024 * 1024) { closeConn(fd); return; }
                if (pc.rxBuffer.size() < 4 + msgLen) break;
                
                std::string msg((char*)pc.rxBuffer.data() + 4, msgLen);
                pc.rxBuffer.erase(pc.rxBuffer.begin(), pc.rxBuffer.begin() + 4 + msgLen);
                
                m_connMutex.unlock();
                if (m_dataCb) m_dataCb(pc.peerId, msg);
                m_connMutex.lock();
            }
        }
    }

    void closeConn(int fd) {
        std::string pid;
        {
            std::lock_guard<std::mutex> lock(m_connMutex);
            if (m_connections.count(fd)) {
                pid = m_connections[fd].peerId;
                m_connections.erase(fd);
                m_peerToFd.erase(pid);
            }
        }
        if (fd >= 0) { m_reactor->remove(fd); close(fd); }
        if (!pid.empty()) {
            nativeLog("Network: Disconnected " + pid);
            if (m_discCb) m_discCb(pid);
        }
    }

    int getFd(const std::string& pid) {
        std::lock_guard<std::mutex> lock(m_connMutex);
        if (m_peerToFd.count(pid)) return m_peerToFd[pid];
        return -1;
    }

    void checkHeartbeats() {
        // Robustness: Add idle timeout logic here using lastActivity timestamp
    }

    std::unique_ptr<EpollReactor> m_reactor;
    bool m_running;
    int m_heartbeatTimer;
    std::mutex m_connMutex;
    std::map<int, PeerConnection> m_connections;
    std::map<std::string, int> m_peerToFd;
    DataCallback m_dataCb;
    DisconnectCallback m_discCb;
};

Network::Network() : m_impl(std::make_unique<NetworkImpl>()) {}
Network::~Network() = default;
bool Network::startServer(int port) { return m_impl->startServer(port); }
void Network::stop() { m_impl->stop(); }
bool Network::connect(const std::string &ip, int port) { return m_impl->connectPeer(ip, port); }
void Network::send(const std::string &peerId, const std::string &data) { m_impl->sendData(peerId, data); }
void Network::setCallbacks(DataCallback d, DisconnectCallback dc) { m_impl->setCallbacks(d, dc); }
"""

files["cpp/src/peer_manager.cpp"] = r"""
#include "peer_manager.h"
#include "network.h"
#include "discovery.h"
#include "logger.h"
#include <algorithm>
#include <mutex>

PeerManager g_peerManager;

class PeerManagerImpl {
public:
    PeerManagerImpl() {
        m_network.setCallbacks(
            [this](const std::string& pid, const std::string& data) { onData(pid, data); },
            [this](const std::string& pid) { onDisconnect(pid); }
        );
    }

    void start(int port) {
        m_network.startServer(port);
    }

    void stop() {
        m_network.stop();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_peers.clear();
    }

    void connectTo(const std::string& ip, int port) {
        if (m_network.connect(ip, port)) {
            addOrUpdatePeer(ip + ":" + std::to_string(port), ip, port, true);
        }
    }

    void sendDirect(const std::string& pid, const std::string& msg) {
        m_network.send(pid, msg);
    }

    void broadcastMessage(const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& p : m_peers) {
            if (p.connected) m_network.send(p.id, msg);
        }
    }

    void setCb(std::function<void(const std::vector<Peer>&)> cb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_uiCallback = cb;
    }

private:
    void onData(const std::string& pid, const std::string& data) {
        nativeLog("PeerManager: RX " + pid + " len=" + std::to_string(data.size()));
    }

    void onDisconnect(const std::string& pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& p : m_peers) {
            if (p.id == pid) { p.connected = false; break; }
        }
        notifyUI();
    }

    void addOrUpdatePeer(const std::string& id, const std::string& ip, int port, bool connected) {
        std::lock_guard<std::mutex> lock(m_mutex);
        bool found = false;
        for (auto& p : m_peers) {
            if (p.id == id) { p.connected = connected; found = true; break; }
        }
        if (!found) {
            Peer p; p.id = id; p.ip = ip; p.port = port; p.connected = connected;
            m_peers.push_back(p);
        }
        notifyUI();
    }

    void notifyUI() {
        if (m_uiCallback) m_uiCallback(m_peers);
    }

    Network m_network;
    std::vector<Peer> m_peers;
    std::mutex m_mutex;
    std::function<void(const std::vector<Peer>&)> m_uiCallback;
};

PeerManager::PeerManager() : m_impl(std::make_unique<PeerManagerImpl>()) {}
PeerManager::~PeerManager() = default;
void PeerManager::start(int p) { m_impl->start(p); }
void PeerManager::stop() { m_impl->stop(); }
void PeerManager::connectTo(const std::string& i, int p) { m_impl->connectTo(i, p); }
void PeerManager::sendDirect(const std::string& pid, const std::string& m) { m_impl->sendDirect(pid, m); }
void PeerManager::setPeerUpdateCallback(std::function<void(const std::vector<Peer>&)> cb) { m_impl->setCb(cb); }
void PeerManager::broadcastMessage(const std::string& msg) { m_impl->broadcastMessage(msg); }
"""

files["cpp/src/discovery.cpp"] = r"""
#include "discovery.h"
#include "logger.h"
#include <thread>
#include <atomic>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <mutex>

static Discovery g_instance;

class DiscoveryImpl {
public:
    DiscoveryImpl() : m_running(false), m_sock(-1) {}
    ~DiscoveryImpl() { stop(); }

    bool start(int listenPort) {
        if (m_running) return false;
        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) return false;
        int on = 1; setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(listenPort);
        if (bind(m_sock, (sockaddr*)&addr, sizeof(addr)) < 0) { close(m_sock); return false; }

        m_running = true;
        m_listenThread = std::thread([this, listenPort]() {
            char buf[1024];
            while (m_running) {
                sockaddr_in from{}; socklen_t len = sizeof(from);
                ssize_t n = recvfrom(m_sock, buf, sizeof(buf)-1, 0, (sockaddr*)&from, &len);
                if (n > 0) {
                    buf[n] = 0;
                    std::string msg(buf);
                    if (msg.find("LITEP2P_DISCOVER:") == 0) {
                        char myIp[64]; inet_ntop(AF_INET, &from.sin_addr, myIp, sizeof(myIp));
                        std::string reply = "LITEP2P_RESPONSE:" + std::string(myIp) + ":" + std::to_string(listenPort);
                        sendto(m_sock, reply.c_str(), reply.size(), 0, (sockaddr*)&from, len);
                    } else if (msg.find("LITEP2P_RESPONSE:") == 0) {
                        size_t lastC = msg.rfind(':');
                        if (lastC != std::string::npos) {
                            int p = std::stoi(msg.substr(lastC+1));
                            std::string ip = msg.substr(msg.find(':')+1, lastC - msg.find(':') - 1);
                            Peer peer; peer.id = ip + ":" + std::to_string(p); peer.ip = ip; peer.port = p; peer.connected = false;
                            std::lock_guard<std::mutex> lock(m_cbMutex);
                            if (m_cb) m_cb(peer);
                        }
                    }
                }
            }
        });

        m_broadcastThread = std::thread([this, listenPort]() {
            while (m_running) {
                int s = socket(AF_INET, SOCK_DGRAM, 0);
                if (s >= 0) {
                    int opt = 1; setsockopt(s, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
                    sockaddr_in dest{}; dest.sin_family = AF_INET; dest.sin_port = htons(listenPort); dest.sin_addr.s_addr = inet_addr("255.255.255.255");
                    std::string msg = "LITEP2P_DISCOVER:me";
                    sendto(s, msg.c_str(), msg.size(), 0, (sockaddr*)&dest, sizeof(dest));
                    close(s);
                }
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        });
        return true;
    }

    void stop() {
        m_running = false;
        if (m_sock >= 0) { shutdown(m_sock, SHUT_RDWR); close(m_sock); m_sock = -1; }
        if (m_listenThread.joinable()) m_listenThread.join();
        if (m_broadcastThread.joinable()) m_broadcastThread.join();
    }

    void setCb(DiscoveryCb cb) {
        std::lock_guard<std::mutex> lock(m_cbMutex);
        m_cb = cb;
    }

    std::atomic<bool> m_running;
    int m_sock;
    std::thread m_listenThread, m_broadcastThread;
    std::mutex m_cbMutex;
    DiscoveryCb m_cb;
};

Discovery* getGlobalDiscoveryInstance() { return &g_instance; }
Discovery::Discovery() : m_impl(new DiscoveryImpl()) {}
Discovery::~Discovery() { delete m_impl; }
bool Discovery::start(int p) { return m_impl->start(p); }
void Discovery::stop() { m_impl->stop(); }
void Discovery::setCallback(DiscoveryCb cb) { m_impl->setCb(cb); }
"""

files["cpp/src/p2p_api.cpp"] = r"""
#include <jni.h>
#include <string>
#include <vector>
#include "peer_manager.h"
#include "discovery.h"
#include "logger.h"
#include "jni_glue.h"

extern "C" {

JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_init(JNIEnv* env, jobject thiz) {
    nativeLog("P2P: Init");
    g_peerManager.setPeerUpdateCallback([](const std::vector<Peer>& peers) {
        sendPeersToUI(peers);
    });
    Discovery* disc = getGlobalDiscoveryInstance();
    if (disc) {
        disc->setCallback([](const Peer& p) {
            g_peerManager.connectTo(p.ip, p.port);
        });
    }
}

JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_startServer(JNIEnv* env, jclass, jint port) {
    g_peerManager.start(port);
    Discovery* disc = getGlobalDiscoveryInstance();
    if (disc) disc->start(port);
}

JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_connect(JNIEnv* env, jclass, jstring jip, jint port) {
    if (!jip) return;
    const char* ip = env->GetStringUTFChars(jip, nullptr);
    g_peerManager.connectTo(ip, port);
    env->ReleaseStringUTFChars(jip, ip);
}

JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_sendMessage(JNIEnv* env, jclass, jstring jid, jbyteArray jdata) {
    if (!jid || !jdata) return;
    const char* id = env->GetStringUTFChars(jid, nullptr);
    jsize len = env->GetArrayLength(jdata);
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(jdata, 0, len, (jbyte*)buf.data());
    std::string s((char*)buf.data(), len);
    g_peerManager.sendDirect(id, s);
    env->ReleaseStringUTFChars(jid, id);
}

JNIEXPORT void JNICALL
Java_com_zeengal_litep2p_hook_P2P_stop(JNIEnv* env, jclass) {
    nativeLog("P2P: Stop");
    Discovery* disc = getGlobalDiscoveryInstance();
    if (disc) disc->stop();
    g_peerManager.stop();
}

} // extern C
"""

files["cpp/src/jni_glue.cpp"] = r"""
#include "jni_glue.h"
#include "jni_helpers.h"
#include "logger.h"
#include <android/log.h>

static jclass g_p2pClass = nullptr;
static jmethodID g_onPeersUpdated = nullptr;

bool jniGlueInit(JNIEnv* env, jclass p2pClass) { return true; } 
void jniGlueCleanup(JNIEnv* env) {}

void sendPeersToUI(const std::vector<Peer>& peers) {
    JNIEnv* env = getJNIEnv();
    if (!env) return;
    jclass p2pClass = env->FindClass("com/zeengal/litep2p/hook/P2P"); 
    if (!p2pClass) { nativeLog("Cannot find P2P class"); return; }
    
    jmethodID method = env->GetStaticMethodID(p2pClass, "onPeersUpdated", "([Lcom/zeengal/litep2p/PeerInfo;)V");
    if (!method) return;

    jclass peerInfoCls = env->FindClass("com/zeengal/litep2p/PeerInfo");
    if (!peerInfoCls) return;
    jmethodID ctor = env->GetMethodID(peerInfoCls, "<init>", "(Ljava/lang/String;Ljava/lang/String;IIZ)V");

    jobjectArray arr = env->NewObjectArray((jsize)peers.size(), peerInfoCls, nullptr);
    for (size_t i=0; i<peers.size(); ++i) {
        const Peer& p = peers[i];
        jstring jid = env->NewStringUTF(p.id.c_str());
        jstring jip = env->NewStringUTF(p.ip.c_str());
        jobject obj = env->NewObject(peerInfoCls, ctor, jid, jip, (jint)p.port, (jint)p.latency, (jboolean)p.connected);
        env->SetObjectArrayElement(arr, (jsize)i, obj);
        env->DeleteLocalRef(jid); env->DeleteLocalRef(jip); env->DeleteLocalRef(obj);
    }
    env->CallStaticVoidMethod(p2pClass, method, arr);
    env->DeleteLocalRef(arr); env->DeleteLocalRef(peerInfoCls); env->DeleteLocalRef(p2pClass);
}
"""

files["cpp/src/jni_helpers.cpp"] = r"""
#include "jni_helpers.h"
#include <android/log.h>

JavaVM* g_vm = nullptr;

JNIEnv* getJNIEnv() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint res = g_vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (res == JNI_EDETACHED) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return nullptr;
    }
    return env;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}
"""

files["cpp/src/logger.cpp"] = r"""
#include "logger.h"
#include "jni_helpers.h"
#include <mutex>
#include <android/log.h>

static jobject g_loggerTarget = nullptr;
static jmethodID g_onNativeLog = nullptr;
static std::mutex g_mutex;

void loggerSetJavaVM(JavaVM* vm) { (void)vm; }

void setLoggerTarget(JNIEnv* env, jobject activityObj) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_loggerTarget) env->DeleteGlobalRef(g_loggerTarget);
    g_loggerTarget = env->NewGlobalRef(activityObj);
    jclass cls = env->GetObjectClass(activityObj);
    g_onNativeLog = env->GetMethodID(cls, "onNativeLog", "(Ljava/lang/String;)V");
}

void nativeLog(const std::string& msg) {
    __android_log_print(ANDROID_LOG_DEBUG, "LiteP2P", "%s", msg.c_str());
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_loggerTarget || !g_onNativeLog) return;
    JNIEnv* env = getJNIEnv();
    if (!env) return;
    jstring jmsg = env->NewStringUTF(msg.c_str());
    env->CallVoidMethod(g_loggerTarget, g_onNativeLog, jmsg);
    env->DeleteLocalRef(jmsg);
}
"""

def create_zip():
    zip_name = "litep2p_clean_structure.zip"
    with zipfile.ZipFile(zip_name, 'w') as zf:
        for path, content in files.items():
            zf.writestr(path, content)
            print(f"Added: {path}")
    print(f"\nSuccessfully created {zip_name}")

if __name__ == "__main__":
    create_zip()
