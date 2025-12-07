#include "discovery.h"
#include "logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <cstring>

static const int DISCOVERY_PORT = 30000;
static const char* DISCOVERY_MSG = "LITEP2P_DISCOVERY";

class DiscoveryImpl : public Discovery {
public:
    DiscoveryImpl() : m_running(false), m_sock(-1) {}
    ~DiscoveryImpl() override { stop(); }

    void start(int port, const std::string& peer_id) override {
        if (m_running) return;

        m_peer_id = peer_id;

        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) {
            nativeLog("Discovery Error: Failed to create socket.");
            return;
        }

        int broadcast = 1;
        setsockopt(m_sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
        
        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = htons(DISCOVERY_PORT);
        if (bind(m_sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
            nativeLog("Discovery Error: Failed to bind socket.");
            close(m_sock);
            return;
        }

        m_running = true;
        m_broadcastThread = std::thread(&DiscoveryImpl::broadcastLoop, this);
        m_listenThread = std::thread(&DiscoveryImpl::listenLoop, this);
        nativeLog("Discovery services started.");
    }

    void stop() override {
        m_running = false;
        if (m_sock >= 0) {
            shutdown(m_sock, SHUT_RDWR);
            close(m_sock);
            m_sock = -1;
        }
        if (m_broadcastThread.joinable()) m_broadcastThread.join();
        if (m_listenThread.joinable()) m_listenThread.join();
        nativeLog("Discovery services stopped.");
    }

    void setCallback(std::function<void(const std::string&, const std::string&)> cb) override {
        m_callback = cb;
    }

private:
    void broadcastLoop() {
        while (m_running) {
            sockaddr_in broadcast_addr{};
            broadcast_addr.sin_family = AF_INET;
            broadcast_addr.sin_port = htons(DISCOVERY_PORT);
            broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

            std::string msg = std::string(DISCOVERY_MSG) + ":" + m_peer_id;
            sendto(m_sock, msg.c_str(), msg.length(), 0, (sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
            nativeLog("Discovery: Sent discovery packet.");
            
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    void listenLoop() {
        char buf[1024];
        while (m_running) {
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(m_sock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from_addr, &from_len);
            if (n > 0) {
                buf[n] = 0;
                std::string msg(buf);
                if (msg.rfind(DISCOVERY_MSG, 0) == 0) {
                    char sender_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
                    std::string peer_id = msg.substr(strlen(DISCOVERY_MSG) + 1);
                    if (m_callback) {
                        nativeLog("Discovery: Received discovery packet from " + peer_id);
                        m_callback(std::string(sender_ip), peer_id);
                    }
                }
            }
        }
    }

    std::atomic<bool> m_running;
    int m_sock;
    std::string m_peer_id;
    std::thread m_broadcastThread;
    std::thread m_listenThread;
    std::function<void(const std::string&, const std::string&)> m_callback;
};

static DiscoveryImpl g_discovery_instance;
Discovery* getGlobalDiscoveryInstance() {
    return &g_discovery_instance;
}
