#include "udp_connection_manager.h"
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

class UdpConnectionManager::UdpImpl {
public:
    UdpImpl() : m_running(false), m_sock(-1) {}
    ~UdpImpl() { stop(); }

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
        if (m_running) return false;
        m_on_data = on_data;
        m_on_disconnect = on_disconnect;

        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) {
            nativeLog("UDP Error: Failed to create socket: " + std::string(strerror(errno)));
            return false;
        }

        int opt = 1;
        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            nativeLog("UDP Error: setsockopt(SO_REUSEADDR) failed: " + std::string(strerror(errno)));
            close(m_sock);
            return false;
        }
        
        if (fcntl(m_sock, F_SETFL, O_NONBLOCK) < 0) {
            nativeLog("UDP Error: fcntl(O_NONBLOCK) failed: " + std::string(strerror(errno)));
            close(m_sock);
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(m_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            nativeLog("UDP Error: Failed to bind socket: " + std::string(strerror(errno)));
            close(m_sock);
            return false;
        }

        m_running = true;
        m_listenThread = std::thread(&UdpImpl::listenLoop, this);

        nativeLog("UDP server started successfully on port " + std::to_string(port));
        return true;
    }

    void stop() {
        m_running = false;
        if (m_sock >= 0) {
            shutdown(m_sock, SHUT_RDWR);
            close(m_sock);
            m_sock = -1;
        }
        if (m_listenThread.joinable()) m_listenThread.join();
        nativeLog("UDP server stopped.");
    }

    void sendMessageToPeer(const std::string& peer_id, const std::string& message) {
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

        dest_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

        std::string encrypted_msg = encrypt_message_udp(message);
        ssize_t bytes_sent = sendto(m_sock, encrypted_msg.c_str(), encrypted_msg.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
        if (bytes_sent < 0) {
            LOG_INFO("UDP_SEND_ERROR: Failed to send message to " + peer_id + " (" + strerror(errno) + ")");
        } else {
            LOG_INFO("UDP_SEND_SUCCESS: Sent message to peer " + peer_id + " (IP:Port) with payload: " + message);
        }
    }

private:
    void listenLoop() {
        std::vector<char> buf(UDP_BUFFER_SIZE);
        while (m_running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(m_sock, &read_fds);
            timeval timeout = {UDP_SELECT_TIMEOUT_SEC, 0}; 

            int select_res = select(m_sock + 1, &read_fds, nullptr, nullptr, &timeout);
            if (select_res < 0) {
                if (errno != EINTR && m_running) {
                    nativeLog("UDP Error: select() failed in listenLoop: " + std::string(strerror(errno)));
                }
                break;
            } else if (select_res == 0) {
                continue;
            }

            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(m_sock, buf.data(), buf.size(), 0, (sockaddr*)&from_addr, &from_len);

            if (n > 0) {
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
                int sender_port = ntohs(from_addr.sin_port);
                std::string peer_id = std::string(sender_ip) + ":" + std::to_string(sender_port);

                std::string encrypted_data(buf.data(), n);
                std::string decrypted_data = decrypt_message_udp(encrypted_data);

                if (!decrypted_data.empty() && m_on_data) {
                    // Enhanced logging: show IP and port for received UDP connections
                    LOG_INFO("UDP_RECEIVE: Received message from peer " + peer_id + " (IP:Port) with payload: " + decrypted_data);
                    // Acknowledge UDP connection when data is received
                    if (decrypted_data.find("ACK") != std::string::npos || 
                        decrypted_data.find("PONG") != std::string::npos ||
                        decrypted_data.find("HEARTBEAT") != std::string::npos) {
                        nativeLog("UDP: Connection acknowledged from " + peer_id);
                    }
                    m_on_data(peer_id, decrypted_data);
                } else if (decrypted_data.empty()){
                     LOG_INFO("UDP_RECEIVE_ERROR: Decryption failed for message from " + peer_id);
                }
            }
        }
    }

    std::atomic<bool> m_running;
    int m_sock;
    std::thread m_listenThread;
    OnDataCallback m_on_data;
    OnDisconnectCallback m_on_disconnect;
};

UdpConnectionManager::UdpConnectionManager() : m_impl(std::make_unique<UdpImpl>()) {}
UdpConnectionManager::~UdpConnectionManager() = default;
bool UdpConnectionManager::startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) { return m_impl->startServer(port, on_data, on_disconnect); }
void UdpConnectionManager::stop() { m_impl->stop(); }
void UdpConnectionManager::sendMessageToPeer(const std::string& peer_id, const std::string& message) { m_impl->sendMessageToPeer(peer_id, message); }
