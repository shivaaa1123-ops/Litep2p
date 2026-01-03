#include "udp_connection_manager.h"
#include "udp_message.h"
#include "logger.h"
#include "crypto_utils.h"
#include "constants.h"

#include <thread>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <mutex>
#include <map>
#include <vector>

class UdpConnectionManager::UdpImpl {
public:
    UdpImpl() : m_running(false), m_sock(-1), m_bound_port(-1), m_event_loop_recv_buf(UDP_BUFFER_SIZE) {}
    ~UdpImpl() { stop(); }

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
        if (m_running) return false;
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        m_on_data = on_data;
        m_on_disconnect = on_disconnect;
        m_bound_port = port;

        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) {
            nativeLog("UDP Error: Failed to create socket: " + std::string(strerror(errno)));
            return false;
        }

        int opt = 1;
        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            nativeLog("UDP Error: setsockopt(SO_REUSEADDR) failed: " + std::string(strerror(errno)));
            close(m_sock);
            m_sock = -1;
            return false;
        }

        // Increase socket buffers to 1MB to reduce packet loss during bursts/churn
        int buf_size = 1048576; // 1MB
        if (setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size))) {
             nativeLog("UDP Warning: Failed to set SO_RCVBUF: " + std::string(strerror(errno)));
        }
        if (setsockopt(m_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size))) {
             nativeLog("UDP Warning: Failed to set SO_SNDBUF: " + std::string(strerror(errno)));
        }
        
        if (fcntl(m_sock, F_SETFL, O_NONBLOCK) < 0) {
            nativeLog("UDP Error: fcntl(O_NONBLOCK) failed: " + std::string(strerror(errno)));
            close(m_sock);
            m_sock = -1;
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(m_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            nativeLog("UDP Error: Failed to bind socket: " + std::string(strerror(errno)));
            close(m_sock);
            m_sock = -1;
            return false;
        }

        m_running = true;
        m_event_loop_mode = false;
        m_listenThread = std::thread(&UdpImpl::listenLoop, this);

        nativeLog("UDP server started successfully on port " + std::to_string(port) + " (sock_fd=" + std::to_string(m_sock) + ")");
        return true;
    }
    
    // Event-loop mode: start without spawning a thread
    bool startServerEventLoop(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
        if (m_running) return false;
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        m_on_data = on_data;
        m_on_disconnect = on_disconnect;
        m_bound_port = port;

        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) {
            nativeLog("UDP Error: Failed to create socket: " + std::string(strerror(errno)));
            return false;
        }

        int opt = 1;
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(m_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

        int buf_size = 1048576;
        setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        setsockopt(m_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        
        if (fcntl(m_sock, F_SETFL, O_NONBLOCK) < 0) {
            nativeLog("UDP Error: fcntl(O_NONBLOCK) failed");
            close(m_sock);
            m_sock = -1;
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(m_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            nativeLog("UDP Error: Failed to bind socket on port " + std::to_string(port) + ": " + std::string(strerror(errno)));
            close(m_sock);
            m_sock = -1;
            return false;
        }

        m_running = true;
        m_event_loop_mode = true;
        // No thread spawned - caller will poll getSocket() and call processOnePacket()
        
        nativeLog("UDP server started in event-loop mode on port " + std::to_string(port));
        return true;
    }

    void stop() {
        m_running = false;
        {
            std::lock_guard<std::mutex> lock(m_sock_mutex);
            if (m_sock >= 0) {
                close(m_sock);
                m_sock = -1;
            }
        }
        if (!m_event_loop_mode && m_listenThread.joinable()) m_listenThread.join();
        m_bound_port = -1;
        nativeLog("UDP server stopped.");
    }

    void sendMessageToPeer(const std::string& peer_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        if (m_sock < 0) {
            nativeLog("UDP Error: sendMessageToPeer called with invalid socket (fd=" + std::to_string(m_sock) + ")");
            return;
        }
        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        size_t colon_pos = peer_id.find(':');
        if (colon_pos == std::string::npos) {
            nativeLog("UDP Error: Invalid peer ID format for sending message.");
            return;
        }
        std::string ip = peer_id.substr(0, colon_pos);
        int port = std::stoi(peer_id.substr(colon_pos + 1));
        LOG_INFO("UDP_SEND_ATTEMPT: Attempting to send to IP: " + ip + " Port: " + std::to_string(port));

        LOG_INFO("UDP_DEBUG: Calling encrypt_message_udp");
        std::string encrypted_msg = encrypt_message_udp(message);
        LOG_INFO("UDP_DEBUG: Encrypted message length: " + std::to_string(encrypted_msg.length()));

        if (UdpMessage::send(m_sock, ip, port, encrypted_msg)) {
            // Don't log raw payload here: it can be binary (e.g., Noise handshake) and will corrupt stdout/log parsing.
            LOG_INFO("UDP_SEND_SUCCESS: Sent message to peer " + peer_id + " (IP:Port), payload_len=" + std::to_string(message.size()) + ", encrypted_len=" + std::to_string(encrypted_msg.size()));
        } else {
            LOG_INFO("UDP_SEND_ERROR: Failed to send message to " + peer_id);
        }
    }

    void sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(m_sock_mutex);
        if (m_sock < 0) {
            nativeLog("UDP Error: sendRawPacket called with invalid socket (fd=" + std::to_string(m_sock) + ")");
            return;
        }
        UdpMessage::sendRaw(m_sock, ip, port, data);
    }

    bool connectToPeer(const std::string& ip, int port) {
        if (!m_running || m_sock < 0) {
            nativeLog("UDP Error: connectToPeer called while server not running");
            return false;
        }
        if (port <= 0 || port > 65535) {
            nativeLog("UDP Error: connectToPeer invalid port: " + std::to_string(port));
            return false;
        }
        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr) <= 0) {
            nativeLog("UDP Error: connectToPeer invalid IP address: " + ip);
            return false;
        }

        // NOTE: We intentionally do NOT call ::connect() on the UDP socket.
        // Doing so would restrict receives to a single peer, which breaks multi-peer scenarios.
        return true;
    }

    void setStunPacketCallback(OnStunPacketCallback callback) {
        m_stun_callback = callback;
    }
    
    int getSocket() const { return m_sock; }
    
    // Single-threaded mode: process one incoming packet
    void processOnePacket() {
        if (m_sock < 0 || !m_running) return;

        auto& buf = m_event_loop_recv_buf;
        sockaddr_in from_addr{};
        socklen_t from_len = sizeof(from_addr);
        ssize_t n = recvfrom(m_sock, buf.data(), buf.size(), 0, (sockaddr*)&from_addr, &from_len);
        
        if (n > 0) {
            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
            int sender_port = ntohs(from_addr.sin_port);
            std::string peer_id = std::string(sender_ip) + ":" + std::to_string(sender_port);

            nativeLog("UDP_ST_DEBUG: recvfrom received " + std::to_string(n) + " bytes from " + peer_id);
            
            // Check for STUN packet
            if (UdpMessage::isStunPacket(buf.data(), n)) {
                nativeLog("UDP_ST_DEBUG: STUN packet detected from " + peer_id + ", len=" + std::to_string(n));
                if (m_stun_callback) {
                    std::vector<uint8_t> packet_data(buf.data(), buf.data() + n);
                    m_stun_callback(sender_ip, sender_port, packet_data);
                } else {
                    nativeLog("UDP_ST_DEBUG: STUN callback is null; dropping STUN packet from " + peer_id);
                }
                return;
            }

            // Check for discovery packets (plain text) that might arrive on the wrong port
            if (isDiscoveryPacket(buf.data(), static_cast<size_t>(n))) {
                return;
            }

            std::string encrypted_data(buf.data(), n);
            std::string decrypted_data = decrypt_message_udp(encrypted_data);

            if (decrypted_data.empty()) {
                std::string hex_preview;
                for (int i = 0; i < std::min((int)n, 32); i++) {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%02x ", (unsigned char)buf[i]);
                    hex_preview += hex;
                }
                nativeLog("UDP_ST_RECEIVE_ERROR: Decryption returned empty for message from " + peer_id +
                          ", len=" + std::to_string(n) + ", first_bytes=" + hex_preview);
                return;
            }

            if (m_on_data) {
                m_on_data(peer_id, decrypted_data);
            } else {
                nativeLog("UDP_ST_DEBUG: on_data callback is null; dropping decrypted UDP message from " + peer_id + ", len=" + std::to_string(decrypted_data.size()));
            }
        } else if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                nativeLog("UDP_ST_ERROR: recvfrom() failed in processOnePacket: " + std::string(strerror(errno)));
            }
        }
    }

private:
    static bool isDiscoveryPacket(const char* data, size_t len) {
        // Discovery format is plain text and begins with: "LITEP2P_DISCOVERY:".
        // Use a strict prefix+delimiter match to avoid accidental collisions with binary payloads.
        const size_t prefix_len = std::strlen(DISCOVERY_MESSAGE_PREFIX);
        if (len < prefix_len + 1) return false;
        if (std::memcmp(data, DISCOVERY_MESSAGE_PREFIX, prefix_len) != 0) return false;
        return data[prefix_len] == ':';
    }

    void listenLoop() {
        nativeLog("UDP_DEBUG: listenLoop started (sock_fd=" + std::to_string(m_sock) + ", bound_port=" + std::to_string(m_bound_port) + ", has_on_data=" + std::string(m_on_data ? "true" : "false") + ")");
        std::vector<char> buf(UDP_BUFFER_SIZE);
        while (m_running) {
            int sock_fd;
            {
                std::lock_guard<std::mutex> lock(m_sock_mutex);
                sock_fd = m_sock;
            }
            if (sock_fd < 0) break;

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(sock_fd, &read_fds);
            timeval timeout = {UDP_SELECT_TIMEOUT_SEC, 0}; 

            int select_res = select(sock_fd + 1, &read_fds, nullptr, nullptr, &timeout);
            if (select_res < 0) {
                if (errno != EINTR && m_running) {
                    if (errno == EBADF) break;
                    nativeLog("UDP Error: select() failed in listenLoop: " + std::string(strerror(errno)));
                }
                break;
            } else if (select_res == 0) {
                continue;
            }

            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(sock_fd, buf.data(), buf.size(), 0, (sockaddr*)&from_addr, &from_len);
            
            if (n > 0) {
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
                int sender_port = ntohs(from_addr.sin_port);
                std::string peer_id = std::string(sender_ip) + ":" + std::to_string(sender_port);
                
                nativeLog("UDP_DEBUG: recvfrom received " + std::to_string(n) + " bytes from " + peer_id);

                // Check for STUN packet
                if (UdpMessage::isStunPacket(buf.data(), n)) {
                    nativeLog("UDP_DEBUG: STUN packet detected from " + peer_id + ", len=" + std::to_string(n));
                    if (m_stun_callback) {
                        std::vector<uint8_t> packet_data(buf.data(), buf.data() + n);
                        m_stun_callback(sender_ip, sender_port, packet_data);
                    }
                    continue; // Skip decryption for STUN packets
                }

                // Check for discovery packets that might arrive on the wrong port
                // Discovery format: "LITEP2P_DISCOVERY:..." (plain text)
                if (isDiscoveryPacket(buf.data(), static_cast<size_t>(n))) {
                    LOG_INFO("UDP_DEBUG: Discovery packet received on connection port from " + peer_id + " - ignoring");
                    continue;
                }

                std::string encrypted_data(buf.data(), n);
                std::string decrypted_data = decrypt_message_udp(encrypted_data);

                if (decrypted_data.empty()) {
                    // Add hex dump of first 32 bytes for debugging
                    std::string hex_preview;
                    for (int i = 0; i < std::min((int)n, 32); i++) {
                        char hex[4];
                        snprintf(hex, sizeof(hex), "%02x ", (unsigned char)buf[i]);
                        hex_preview += hex;
                    }
                    LOG_INFO("UDP_RECEIVE_ERROR: Decryption returned empty for message from " + peer_id + 
                             ", len=" + std::to_string(n) + ", first_bytes=" + hex_preview);
                    continue;
                }

                if (!m_on_data) {
                    nativeLog("UDP Error: on_data callback is null; dropping decrypted UDP message from " + peer_id + ", len=" + std::to_string(decrypted_data.length()));
                    continue;
                }

                {
                    // Don't log raw payload here: it can be binary (e.g., Noise handshake) and will corrupt stdout/log parsing.
                    LOG_INFO("UDP_RECEIVE: Received message from peer " + peer_id + " (IP:Port), payload_len=" + std::to_string(decrypted_data.size()));
                    // Acknowledge UDP connection when data is received
                    if (decrypted_data.find("ACK") != std::string::npos || 
                        decrypted_data.find("PONG") != std::string::npos ||
                        decrypted_data.find("HEARTBEAT") != std::string::npos) {
                        nativeLog("UDP: Connection acknowledged from " + peer_id);
                    }
                    m_on_data(peer_id, decrypted_data);
                }
            } else if (n < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    nativeLog("UDP Error: recvfrom() failed in listenLoop: " + std::string(strerror(errno)));
                }
            }
        }
    }

    std::atomic<bool> m_running;
    int m_sock;
    std::mutex m_sock_mutex;
    int m_bound_port;
    std::thread m_listenThread;
    OnDataCallback m_on_data;
    OnDisconnectCallback m_on_disconnect;
    OnStunPacketCallback m_stun_callback;
    bool m_event_loop_mode{false};
    std::vector<char> m_event_loop_recv_buf;
};

UdpConnectionManager::UdpConnectionManager() : m_impl(std::make_unique<UdpImpl>()) {}
UdpConnectionManager::~UdpConnectionManager() = default;
bool UdpConnectionManager::startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) { return m_impl->startServer(port, on_data, on_disconnect); }
bool UdpConnectionManager::startServerEventLoop(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) { return m_impl->startServerEventLoop(port, on_data, on_disconnect); }
void UdpConnectionManager::stop() { m_impl->stop(); }
bool UdpConnectionManager::connectToPeer(const std::string& ip, int port) { return m_impl->connectToPeer(ip, port); }
void UdpConnectionManager::sendMessageToPeer(const std::string& peer_id, const std::string& message) { m_impl->sendMessageToPeer(peer_id, message); }
void UdpConnectionManager::sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) { m_impl->sendRawPacket(ip, port, data); }
void UdpConnectionManager::setStunPacketCallback(OnStunPacketCallback callback) { m_impl->setStunPacketCallback(callback); }
int UdpConnectionManager::getSocketFd() const { return m_impl->getSocket(); }
void UdpConnectionManager::processIncomingData() { m_impl->processOnePacket(); }
