#include "discovery.h"
#include "logger.h"

#include <thread>
#include <atomic>
#include <vector>
#include <chrono>
#include <sstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#include "discovery.h"

// Global instance definition
Discovery g_discovery;

class DiscoveryImpl {
public:
    DiscoveryImpl() : m_running(false), m_sock(-1) {}
    ~DiscoveryImpl() { stop(); }

    bool start(int listenPort) {
        if (m_running.load()) return false;

        m_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) return false;

        int on = 1;
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(listenPort);

        if (::bind(m_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            ::close(m_sock);
            m_sock = -1;
            return false;
        }

        m_running.store(true);

        m_thread = std::thread([this, listenPort]() {
            run(listenPort);
        });

        std::thread([listenPort]() {
            broadcastOnce(listenPort);
        }).detach();

        nativeLog("Discovery started");
        return true;
    }

    void stop() {
        if (!m_running.load()) return;

        m_running.store(false);
        if (m_sock >= 0) {
            ::shutdown(m_sock, SHUT_RDWR);
            ::close(m_sock);
            m_sock = -1;
        }

        if (m_thread.joinable()) m_thread.join();
    }

    void setCb(DiscoveryCb cb) {
        m_cb = std::move(cb);
    }

private:
    int m_sock;
    std::atomic<bool> m_running;
    std::thread m_thread;
    DiscoveryCb m_cb;

    static void broadcastOnce(int port) {
        int s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return;

        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));

        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = htons(port);
        to.sin_addr.s_addr = inet_addr("255.255.255.255");

        std::ostringstream ss;
        ss << "node-" << std::chrono::system_clock::now().time_since_epoch().count();
        std::string id = ss.str();

        std::string msg = "LITEP2P_DISCOVER:" + id + ":" + std::to_string(port);
        sendto(s, msg.c_str(), msg.size(), 0, (sockaddr*)&to, sizeof(to));

        ::close(s);
    }

    void run(int listenPort) {
        constexpr size_t BUFSZ = 1024;
        char buf[BUFSZ];

        while (m_running.load()) {
            sockaddr_in from{};
            socklen_t fromlen = sizeof(from);
            ssize_t r = recvfrom(m_sock, buf, BUFSZ - 1, 0, (sockaddr*)&from, &fromlen);

            if (r < 0) continue;
            buf[r] = '\0';
            std::string s(buf);

            if (s.rfind("LITEP2P_DISCOVER:", 0) == 0) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from.sin_addr, ipstr, sizeof(ipstr));
                int theirPort = ntohs(from.sin_port);

                std::ostringstream resp;
                resp << "LITEP2P_RESPONSE:node:" << ipstr << ":" << theirPort;
                std::string out = resp.str();

                sendto(m_sock, out.c_str(), out.size(), 0, (sockaddr*)&from, fromlen);
                continue;
            }

            if (s.rfind("LITEP2P_RESPONSE:", 0) == 0) {
                std::string payload = s.substr(strlen("LITEP2P_RESPONSE:"));
                auto parts = split(payload, ':');
                if (parts.size() < 3) continue;

                Peer p;
                p.id = parts[0];
                p.ip = parts[1];
                p.port = std::stoi(parts[2]);
                p.latency = -1;
                p.connected = false;
                p.lastSeenMs = nowMs();

                if (m_cb) m_cb(p);
            }
        }
    }

    static std::vector<std::string> split(const std::string& s, char delim) {
        std::vector<std::string> out;
        size_t start = 0;
        while (start < s.size()) {
            size_t pos = s.find(delim, start);
            if (pos == std::string::npos) {
                out.push_back(s.substr(start));
                break;
            }
            out.push_back(s.substr(start, pos - start));
            start = pos + 1;
        }
        return out;
    }

    static long long nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// Internal engine objects
static DiscoveryImpl* g_impl = nullptr;
static Discovery      g_instance;

// API exposed to outer modules
Discovery* getGlobalDiscoveryInstance() {
    return &g_instance;
}

Discovery::Discovery() {
    if (!g_impl) g_impl = new DiscoveryImpl();
}

Discovery::~Discovery() {}

bool Discovery::start(int port) {
    if (!g_impl) g_impl = new DiscoveryImpl();
    return g_impl->start(port);
}

void Discovery::stop() {
    if (g_impl) g_impl->stop();
}

void Discovery::setCallback(DiscoveryCb cb) {
    if (g_impl) g_impl->setCb(cb);
}