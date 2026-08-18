#include "discovery.h"
#include "logger.h"
#include "constants.h"
#include "config_manager.h"
#include "anomaly_reporter.h"
#include <sodium.h>
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
} // namespace

// ------------------------------------------------------------------
// Censorship-resistant discovery packet parsing (v0.4)
// ------------------------------------------------------------------
// Legacy format:      <magic>:<peer_id>:<port>          (plaintext)
// Obfuscated format:  <magic> || nonce(12) || AEAD_ct   (when a shared
//                     key is configured).
// The magic is config-driven (network.discovery_magic). Legacy interop:
// default-magic peers are still accepted when our magic differs.
// Declared in discovery.h so the parser can be fuzzed/unit-tested.
bool parse_discovery_announcement(const std::string& raw,
                                  std::string& out_peer_id, int& out_port) {
        const std::string magic = ConfigManager::getInstance().getDiscoveryMagic();
        std::vector<uint8_t> key;
        const bool encrypted = ConfigManager::getInstance().getDiscoverySharedKey(key);

        std::string body;
        if (encrypted && key.size() == 32 &&
            raw.size() > magic.size() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                                    crypto_aead_xchacha20poly1305_ietf_ABYTES &&
            raw.compare(0, magic.size(), magic) == 0) {
            const size_t off = magic.size();
            std::vector<uint8_t> nonce(raw.begin() + off,
                                       raw.begin() + off + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            std::vector<uint8_t> ct(raw.begin() + off + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                                    raw.end());
            std::vector<uint8_t> pt(ct.size());
            unsigned long long plen = 0;
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    pt.data(), &plen, nullptr,
                    ct.data(), ct.size(), nullptr, 0, nonce.data(), key.data()) != 0) {
                return false;  // not encrypted by our key -> drop
            }
            pt.resize(plen);
            body.assign(reinterpret_cast<const char*>(pt.data()), pt.size());
            while (!body.empty() && body.back() == ' ') body.pop_back();
        } else if (raw.compare(0, magic.size(), magic) == 0) {
            body = raw.substr(magic.size());
            if (!body.empty() && body[0] == ':') body = body.substr(1);
        } else {
            // Legacy interop: default-magic peers.
            const std::string legacy = DISCOVERY_MESSAGE_PREFIX;
            if (raw.compare(0, legacy.size(), legacy) != 0) return false;
            body = raw.substr(legacy.size());
            if (!body.empty() && body[0] == ':') body = body.substr(1);
        }

        const size_t colon = body.find(':');
        if (colon == std::string::npos) return false;
        out_peer_id = body.substr(0, colon);
        try {
            out_port = std::stoi(body.substr(colon + 1));
        } catch (...) {
            return false;
        }
        return !out_peer_id.empty() && out_port > 0 && out_port <= 65535;
    }

class DiscoveryImpl : public Discovery {
public:
    DiscoveryImpl()
        : m_running(false), m_sock(-1), m_connection_port(30001),
          m_discovery_port(30000), m_use_central_discovery(true), m_event_loop_mode(false) {}
    ~DiscoveryImpl() override { stop(); }

    void start(int port, const std::string& peer_id) override {
        // Always ensure we're in a clean state before starting
        if (m_running) {
            stop();
        }

        m_peer_id = peer_id;
        m_connection_port = port;
        // The discovery listener/broadcast port is config-driven
        // (network.discovery_port) so deployments and hermetic tests can use a
        // distinct port instead of the historic hardcoded 30000.
        m_discovery_port = ConfigManager::getInstance().getDiscoveryPort();

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
        bind_addr.sin_port = htons(static_cast<uint16_t>(m_discovery_port));
        
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
                {
                    AnomalyReporter::Event ev;
                    ev.type = "runtime_error";
                    ev.severity = "critical";
                    ev.reason = "The LAN discovery socket could not bind after retries; peers will not be discovered on the LAN";
                    ev.detail = "Discovery bind failed (port " +
                                std::to_string(m_discovery_port) + ")";
                    ev.extras.emplace_back("subsystem", "discovery");
                    AnomalyReporter::getInstance().report(ev);
                }
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
        m_discovery_port = ConfigManager::getInstance().getDiscoveryPort();

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
        bind_addr.sin_port = htons(static_cast<uint16_t>(m_discovery_port));
        
        if (bind(m_sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
            nativeLog("Discovery Error: Failed to bind socket in event-loop mode.");
            close(m_sock);
            m_sock = -1;
            {
                AnomalyReporter::Event ev;
                ev.type = "runtime_error";
                ev.severity = "critical";
                ev.reason = "The LAN discovery socket could not bind in event-loop mode; peers will not be discovered on the LAN";
                ev.detail = "Discovery bind failed (event-loop, port " +
                            std::to_string(m_discovery_port) + ")";
                ev.extras.emplace_back("subsystem", "discovery");
                AnomalyReporter::getInstance().report(ev);
            }
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

        std::string msg = buildAnnouncement();
        const auto targets = get_ipv4_broadcast_targets(static_cast<uint16_t>(m_discovery_port));

        bool any_sent = false;
        int sent_count = 0;
        for (const auto& dst : targets) {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dst.sin_addr, addr_str, sizeof(addr_str));
            
            const ssize_t sent = sendto(m_sock, msg.c_str(), msg.length(), 0,
                                        reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
            if (sent >= 0) {
                any_sent = true;
                sent_count++;
                nativeLog("Discovery: Sent broadcast to " + std::string(addr_str) + ":" + std::to_string(ntohs(dst.sin_port)) + " (" + std::to_string(sent) + " bytes)");
            } else {
                nativeLog("Discovery Warning: Failed to send broadcast to " + std::string(addr_str) + ":" + std::to_string(ntohs(dst.sin_port)) + " (errno=" + std::to_string(errno) + ")");
            }
        }

        if (!any_sent) {
            nativeLog("Discovery Warning: Failed to send broadcast on all interfaces");
        } else {
            nativeLog("Discovery: Broadcast sent to " + std::to_string(sent_count) + " target(s), msg_len=" + std::to_string(msg.length()));
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

            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));

            std::string peer_id;
            int connection_port = 0;
            if (!parseAnnouncement(msg, peer_id, connection_port)) {
                return;  // not a valid discovery announcement (or wrong key)
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
    
    int getSocketFd() const override {
        return m_sock;
    }

    void sendDirectProbe(const std::string& ip, int port) override {
        if (m_sock < 0 || !m_running) {
            nativeLog("Discovery: sendDirectProbe skipped - not running");
            return;
        }
        
        // Send discovery message directly to the specified IP:port on the discovery port
        // This bypasses AP isolation that may block broadcasts
        std::string msg = buildAnnouncement();
        
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(static_cast<uint16_t>(m_discovery_port));  // Send to discovery port
        
        if (inet_pton(AF_INET, ip.c_str(), &dst.sin_addr) <= 0) {
            nativeLog("Discovery: sendDirectProbe - invalid IP: " + ip);
            return;
        }
        
        const ssize_t sent = sendto(m_sock, msg.c_str(), msg.length(), 0,
                                    reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
        
        if (sent >= 0) {
            nativeLog("Discovery: Sent direct probe to " + ip + ":" + std::to_string(m_discovery_port) + " (" + std::to_string(sent) + " bytes)");
        } else {
            nativeLog("Discovery: Failed to send direct probe to " + ip + " errno=" + std::to_string(errno));
        }
    }

    std::string getLocalLanIP() const override {
        // Find the first private (LAN) IP address on a non-loopback interface
        struct ifaddrs* ifaddr = nullptr;
        std::string result;
        
        if (getifaddrs(&ifaddr) != 0 || !ifaddr) {
            return result;
        }
        
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
            if (ifa->ifa_addr->sa_family != AF_INET) continue;
            
            auto* addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str)) == nullptr) continue;
            
            std::string ip(ip_str);
            
            // Check if this is a private IP (RFC1918)
            bool is_private = false;
            if (ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0) {
                is_private = true;
            } else if (ip.rfind("172.", 0) == 0) {
                auto dot = ip.find('.', 4);
                if (dot != std::string::npos) {
                    try {
                        int second = std::stoi(ip.substr(4, dot - 4));
                        if (second >= 16 && second <= 31) {
                            is_private = true;
                        }
                    } catch (...) {}
                }
            }
            
            if (is_private) {
                result = ip;
                break;  // Return first private IP found
            }
        }
        freeifaddrs(ifaddr);
        
        return result;
    }

    void enableCentralDiscovery(bool enable) {
        m_use_central_discovery = enable;
    }

    void setConnectionPort(int port) override {
        m_connection_port = port;
    }

    // ------------------------------------------------------------------
    // Censorship-resistant discovery packets (v0.4)
    // ------------------------------------------------------------------
    // Legacy format:      <magic>:<peer_id>:<port>          (plaintext)
    // Obfuscated format:  <magic> || nonce(12) || AEAD_ct   (when a shared
    //                     key is configured; plaintext is padded to a fixed
    //                     size so datagram length doesn't leak peer info).
    // The magic is config-driven (network.discovery_magic), so a deployment
    // can use an arbitrary random prefix that is NOT recognizable as
    // "LITEP2P_DISCOVERY" by a DPI box. Defaults preserve legacy behavior.
    std::string buildAnnouncement() const {
        const std::string magic = ConfigManager::getInstance().getDiscoveryMagic();
        std::vector<uint8_t> key;
        const bool encrypted = ConfigManager::getInstance().getDiscoverySharedKey(key);
        std::string plain = m_peer_id + ":" + std::to_string(m_connection_port);
        if (encrypted && key.size() == 32) {
            static constexpr size_t kPadLen = 96;
            std::string padded = plain;
            if (padded.size() > kPadLen) padded.resize(kPadLen);
            padded.resize(kPadLen, ' ');

            std::vector<uint8_t> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            randombytes_buf(nonce.data(), nonce.size());
            std::vector<uint8_t> ct(padded.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
            unsigned long long clen = 0;
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ct.data(), &clen,
                reinterpret_cast<const uint8_t*>(padded.data()), padded.size(),
                nullptr, 0, nullptr, nonce.data(), key.data());
            ct.resize(clen);

            std::string out = magic;
            out.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
            out.append(reinterpret_cast<const char*>(ct.data()), ct.size());
            return out;
        }
        return magic + ":" + plain;
    }

    bool parseAnnouncement(const std::string& raw,
                           std::string& out_peer_id, int& out_port) const {
        // Delegates to the free function (see discovery.h) so the exact parser
        // is fuzz-tested and unit-tested without a live socket.
        return ::parse_discovery_announcement(raw, out_peer_id, out_port);
    }

private:
    void broadcastLoop() {
        while (m_running) {
            // Include connection port in the discovery message
            // Format: obfuscated (see buildAnnouncement)
            std::string msg = buildAnnouncement();
            const auto targets = get_ipv4_broadcast_targets(static_cast<uint16_t>(m_discovery_port));

            nativeLog("Discovery broadcastLoop: Sending to " + std::to_string(targets.size()) + " broadcast targets");

            bool any_sent = false;
            int success_count = 0;
            for (const auto& dst : targets) {
                char target_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &dst.sin_addr, target_ip, sizeof(target_ip));
                
                const ssize_t sent = sendto(m_sock, msg.c_str(), msg.length(), 0,
                                            reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
                if (sent >= 0) {
                    any_sent = true;
                    success_count++;
                    nativeLog("Discovery broadcastLoop: Sent to " + std::string(target_ip) + ":" + std::to_string(ntohs(dst.sin_port)));
                } else {
                    nativeLog("Discovery broadcastLoop: FAILED to send to " + std::string(target_ip) + " errno=" + std::to_string(errno));
                }
            }

            if (!any_sent) {
                nativeLog("Discovery Warning: Failed to send broadcast on all interfaces (threaded)");
            } else {
                nativeLog("Discovery broadcastLoop: Sent " + std::to_string(success_count) + "/" + std::to_string(targets.size()) + " broadcasts OK");
            }
            
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(DISCOVERY_BROADCAST_INTERVAL_SEC), [this] { return !m_running; });
        }
    }

    void listenLoop() {
        nativeLog("Discovery listenLoop: Started listening on UDP port " + std::to_string(m_discovery_port));
        char buf[DISCOVERY_MSG_MAX];
        while (m_running) {
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(m_sock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from_addr, &from_len);
            if (n > 0) {
                buf[n] = 0;
                std::string msg(buf);
                
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
                nativeLog("Discovery listenLoop: Received " + std::to_string(n) + " bytes from " + std::string(sender_ip) + " msg=" + msg.substr(0, 50));

                std::string peer_id;
                int connection_port = 0;
                if (parseAnnouncement(msg, peer_id, connection_port)) {
                    // Avoid self-discovery (we hear our own broadcast on some networks).
                    if (!m_peer_id.empty() && peer_id == m_peer_id) {
                        nativeLog("Discovery listenLoop: Ignoring self-discovery for peer_id=" + peer_id);
                        continue;
                    }

                    // Drop duplicates that can occur when peers broadcast to multiple targets.
                    if (is_recent_duplicate(sender_ip, connection_port, peer_id)) {
                        nativeLog("Discovery listenLoop: Ignoring duplicate from " + std::string(sender_ip));
                        continue;
                    }
                    
                    if (m_callback) {
                        // Use the advertised connection port, not the UDP discovery port
                        std::string network_id = std::string(sender_ip) + ":" + std::to_string(connection_port);
                        nativeLog("Discovery: Found peer " + peer_id + " at " + network_id);
                        m_callback(network_id, peer_id);
                    } else {
                        nativeLog("Discovery listenLoop: No callback registered!");
                    }
                } else {
                    nativeLog("Discovery listenLoop: Ignoring non-discovery message: " + msg.substr(0, 30));
                }
            } else if (!m_running) {
                break;
            }
        }
        nativeLog("Discovery listenLoop: Stopped");
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
    int m_discovery_port;  // network.discovery_port (config-driven, default 30000)
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
