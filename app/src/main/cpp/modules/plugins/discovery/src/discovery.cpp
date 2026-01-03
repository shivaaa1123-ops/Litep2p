#include "discovery.h"
#include "logger.h"
#include "constants.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <atomic>
#include <cstring>
#include <condition_variable>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <ifaddrs.h>
#include <net/if.h>

namespace {
    std::vector<sockaddr_in> get_ipv4_broadcast_targets(uint16_t port) {
        std::vector<sockaddr_in> targets;

        auto add_target = [&](in_addr addr) {
            // Skip invalid/loopback-ish targets
            const uint32_t host = ntohl(addr.s_addr);
            if (host == 0) return;
            if ((host & 0xFF000000u) == 0x7F000000u) return; // 127.0.0.0/8

            for (const auto& existing : targets) {
                if (existing.sin_addr.s_addr == addr.s_addr) {
                    return;
                }
            }

            sockaddr_in dst{};
            dst.sin_family = AF_INET;
            dst.sin_port = htons(port);
            dst.sin_addr = addr;
            targets.push_back(dst);
        };

        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == 0 && ifaddr) {
            for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) {
                    continue;
                }
                if ((ifa->ifa_flags & IFF_UP) == 0) {
                    continue;
                }
                if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
                    continue;
                }
                if ((ifa->ifa_flags & IFF_BROADCAST) == 0) {
                    continue;
                }
                if (ifa->ifa_addr->sa_family != AF_INET) {
                    continue;
                }

                // Prefer kernel-provided broadcast address
                if (ifa->ifa_broadaddr && ifa->ifa_broadaddr->sa_family == AF_INET) {
                    auto* b = reinterpret_cast<sockaddr_in*>(ifa->ifa_broadaddr);
                    add_target(b->sin_addr);
                    continue;
                }

                // Fallback: compute broadcast = (ip & mask) | ~mask
                if (ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET) {
                    auto* a = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
                    auto* m = reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask);
                    const uint32_t ip_h = ntohl(a->sin_addr.s_addr);
                    const uint32_t mask_h = ntohl(m->sin_addr.s_addr);
                    const uint32_t bcast_h = (ip_h & mask_h) | (~mask_h);
                    in_addr bcast{};
                    bcast.s_addr = htonl(bcast_h);
                    add_target(bcast);
                }
            }
            freeifaddrs(ifaddr);
        }

        // Always include limited broadcast as a fallback.
        in_addr limited{};
        limited.s_addr = inet_addr("255.255.255.255");
        add_target(limited);

        return targets;
    }
}

class DiscoveryImpl : public Discovery {
public:
    DiscoveryImpl() : m_running(false), m_sock(-1), m_connection_port(30001), m_use_central_discovery(true), m_event_loop_mode(false) {}
    ~DiscoveryImpl() override { stop(); }

    void start(int port, const std::string& peer_id) override {
        // Always ensure we're in a clean state before starting
        if (m_running) {
            stop();
        }

        m_peer_id = peer_id;
        m_connection_port = port;

        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) {
            nativeLog("Discovery Error: Failed to create socket.");
            return;
        }

        int broadcast = 1;
        int reuse = 1;
        setsockopt(m_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = htons(DISCOVERY_PORT);
        
        int bind_attempts = 0;
        const int max_bind_attempts = 5;
        while (bind_attempts < max_bind_attempts) {
            if (bind(m_sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) == 0) {
                break;
            }
            bind_attempts++;
            if (bind_attempts >= max_bind_attempts) {
                nativeLog("Discovery Error: Failed to bind socket after " + std::to_string(max_bind_attempts) + " attempts.");
                close(m_sock);
                m_sock = -1;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        m_running = true;
        m_event_loop_mode = false;
        m_broadcastThread = std::thread(&DiscoveryImpl::broadcastLoop, this);
        m_listenThread = std::thread(&DiscoveryImpl::listenLoop, this);
        nativeLog("Discovery services started.");
    }
    
    int startEventLoop(int port, const std::string& peer_id) override {
        if (m_running) {
            stop();
        }

        m_peer_id = peer_id;
        m_connection_port = port;

        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) {
            nativeLog("Discovery Error: Failed to create socket.");
            return -1;
        }

        int broadcast = 1;
        int reuse = 1;
        setsockopt(m_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

        // Set non-blocking for event loop mode
        fcntl(m_sock, F_SETFL, O_NONBLOCK);

        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = htons(DISCOVERY_PORT);
        
        if (bind(m_sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
            nativeLog("Discovery Error: Failed to bind socket in event-loop mode.");
            close(m_sock);
            m_sock = -1;
            return -1;
        }

        m_running = true;
        m_event_loop_mode = true;
        // No threads spawned - caller polls and calls sendBroadcast()/processIncoming()
        
        nativeLog("Discovery started in event-loop mode.");
        return m_sock;
    }

    void stop() override {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (!m_running) {
                return;
            }
            m_running = false;
        }
        
        m_cv.notify_all();

        if (m_sock >= 0) {
            shutdown(m_sock, SHUT_RDWR);
            close(m_sock);
            m_sock = -1;
        }
        
        if (!m_event_loop_mode) {
            try {
                if (m_broadcastThread.joinable()) {
                    m_broadcastThread.join();
                }
                if (m_listenThread.joinable()) {
                    m_listenThread.join();
                }
            } catch (const std::exception& e) {
                nativeLog("Discovery Error: Exception while joining threads: " + std::string(e.what()));
            }
        }
        
        nativeLog("Discovery services stopped.");
    }

    void setCallback(std::function<void(const std::string&, const std::string&)> cb) override {
        m_callback = cb;
    }
    
    void sendBroadcast() override {
        if (m_sock < 0 || !m_running) return;

        std::string msg = std::string(DISCOVERY_MESSAGE_PREFIX) + ":" + m_peer_id + ":" + std::to_string(m_connection_port);
        const auto targets = get_ipv4_broadcast_targets(static_cast<uint16_t>(DISCOVERY_PORT));

        bool any_sent = false;
        for (const auto& dst : targets) {
            const ssize_t sent = sendto(m_sock, msg.c_str(), msg.length(), 0,
                                        reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
            if (sent >= 0) {
                any_sent = true;
            }
        }

        if (!any_sent) {
            nativeLog("Discovery Warning: Failed to send broadcast on all interfaces");
        }
    }
    
    void processIncoming() override {
        if (m_sock < 0 || !m_running) return;
        
        char buf[DISCOVERY_MSG_MAX];
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        ssize_t n = recvfrom(m_sock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from_addr, &from_len);
        
        if (n > 0) {
            buf[n] = 0;
            std::string msg(buf);
            if (msg.rfind(DISCOVERY_MESSAGE_PREFIX, 0) == 0) {
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
                
                std::string msg_without_prefix = msg.substr(strlen(DISCOVERY_MESSAGE_PREFIX) + 1);
                size_t colon_pos = msg_without_prefix.find(':');
                
                std::string peer_id;
                int connection_port = ntohs(from_addr.sin_port);
                
                if (colon_pos != std::string::npos) {
                    peer_id = msg_without_prefix.substr(0, colon_pos);
                    try {
                        connection_port = std::stoi(msg_without_prefix.substr(colon_pos + 1));
                    } catch (...) {
                        connection_port = ntohs(from_addr.sin_port);
                    }
                } else {
                    peer_id = msg_without_prefix;
                }

                if (!m_peer_id.empty() && peer_id == m_peer_id) {
                    return; // Skip self-discovery
                }

                // Drop duplicates that can occur when peers broadcast to multiple targets
                // (e.g., per-interface broadcast + limited broadcast).
                if (is_recent_duplicate(sender_ip, connection_port, peer_id)) {
                    return;
                }
                
                if (m_callback) {
                    std::string network_id = std::string(sender_ip) + ":" + std::to_string(connection_port);
                    m_callback(network_id, peer_id);
                }
            }
        }
    }
    
    int getSocketFd() const override {
        return m_sock;
    }

    void enableCentralDiscovery(bool enable) {
        m_use_central_discovery = enable;
    }

private:
    void broadcastLoop() {
        while (m_running) {
            // Include connection port in the discovery message
            // Format: "DISCOVER:<peer_id>:<connection_port>"
            std::string msg = std::string(DISCOVERY_MESSAGE_PREFIX) + ":" + m_peer_id + ":" + std::to_string(m_connection_port);
            const auto targets = get_ipv4_broadcast_targets(static_cast<uint16_t>(DISCOVERY_PORT));

            bool any_sent = false;
            for (const auto& dst : targets) {
                const ssize_t sent = sendto(m_sock, msg.c_str(), msg.length(), 0,
                                            reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
                if (sent >= 0) {
                    any_sent = true;
                }
            }

            if (!any_sent) {
                nativeLog("Discovery Warning: Failed to send broadcast on all interfaces (threaded)");
            }
            
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(DISCOVERY_BROADCAST_INTERVAL_SEC), [this] { return !m_running; });
        }
    }

    void listenLoop() {
        char buf[DISCOVERY_MSG_MAX];
        while (m_running) {
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(m_sock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from_addr, &from_len);
            if (n > 0) {
                buf[n] = 0;
                std::string msg(buf);
                if (msg.rfind(DISCOVERY_MESSAGE_PREFIX, 0) == 0) {
                    char sender_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
                    
                    // Parse message format: "DISCOVER:<peer_id>:<connection_port>"
                    std::string msg_without_prefix = msg.substr(strlen(DISCOVERY_MESSAGE_PREFIX) + 1);
                    size_t colon_pos = msg_without_prefix.find(':');
                    
                    std::string peer_id;
                    int connection_port = ntohs(from_addr.sin_port);  // Default to sender's UDP port if not specified
                    
                    if (colon_pos != std::string::npos) {
                        peer_id = msg_without_prefix.substr(0, colon_pos);
                        try {
                            connection_port = std::stoi(msg_without_prefix.substr(colon_pos + 1));
                        } catch (...) {
                            nativeLog("Discovery Warning: Failed to parse connection port from message");
                            connection_port = ntohs(from_addr.sin_port);
                        }
                    } else {
                        peer_id = msg_without_prefix;
                    }

                    // Avoid self-discovery (we hear our own broadcast on some networks).
                    if (!m_peer_id.empty() && peer_id == m_peer_id) {
                        continue;
                    }

                    // Drop duplicates that can occur when peers broadcast to multiple targets.
                    if (is_recent_duplicate(sender_ip, connection_port, peer_id)) {
                        continue;
                    }
                    
                    if (m_callback) {
                        // Use the advertised connection port, not the UDP discovery port
                        std::string network_id = std::string(sender_ip) + ":" + std::to_string(connection_port);
                        nativeLog("Discovery: Found peer " + peer_id + " at " + network_id);
                        m_callback(network_id, peer_id);
                    }
                }
            } else if (!m_running) {
                break;
            }
        }
    }

    bool is_recent_duplicate(const char* sender_ip, int connection_port, const std::string& peer_id) {
        const auto now = std::chrono::steady_clock::now();
        const std::string key = std::string(sender_ip) + ":" + std::to_string(connection_port) + ":" + peer_id;

        // 500ms window is enough to collapse immediate duplicates while still allowing rapid
        // rediscovery after port changes.
        constexpr auto kWindow = std::chrono::milliseconds(500);

        auto it = m_recent_discoveries.find(key);
        if (it != m_recent_discoveries.end()) {
            if (now - it->second < kWindow) {
                return true;
            }
            it->second = now;
        } else {
            m_recent_discoveries.emplace(key, now);
        }

        // Bound the cache size (best-effort cleanup).
        if (m_recent_discoveries.size() > 2048) {
            for (auto iter = m_recent_discoveries.begin(); iter != m_recent_discoveries.end();) {
                if (now - iter->second > std::chrono::seconds(10)) {
                    iter = m_recent_discoveries.erase(iter);
                } else {
                    ++iter;
                }
            }
        }

        return false;
    }

    std::atomic<bool> m_running;
    int m_sock;
    std::string m_peer_id;
    int m_connection_port;
    std::thread m_broadcastThread;
    std::thread m_listenThread;
    std::function<void(const std::string&, const std::string&)> m_callback;
    bool m_use_central_discovery;
    bool m_event_loop_mode;

    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_recent_discoveries;
    
    std::mutex m_mutex;
    std::condition_variable m_cv;
};

static DiscoveryImpl g_discovery_instance;
Discovery* getGlobalDiscoveryInstance() {
    return &g_discovery_instance;
}
