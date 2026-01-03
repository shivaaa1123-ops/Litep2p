#include "quic_connection_manager.h"
#include "quic_message.h"
#include "udp_message.h" // For STUN check
#include "logger.h"
#include "crypto_utils.h"
#include "constants.h"

#include <iostream>
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
#include <random>

class QuicConnectionManager::QuicImpl {
public:
    QuicImpl() : m_running(false), m_sock(-1) {}
    ~QuicImpl() { stop(); }

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
        std::cout << "DEBUG: QuicImpl::startServer called on port " << port << std::endl;
        if (m_running) {
            std::cout << "DEBUG: QuicImpl::startServer - already running" << std::endl;
            return false;
        }
        m_on_data = on_data;
        m_on_disconnect = on_disconnect;

        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) {
            std::string err = "QUIC Error: Failed to create socket: " + std::string(strerror(errno));
            nativeLog(err);
            std::cout << "DEBUG: " << err << std::endl;
            return false;
        }

        int opt = 1;
        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            std::string err = "QUIC Error: setsockopt(SO_REUSEADDR) failed: " + std::string(strerror(errno));
            nativeLog(err);
            std::cout << "DEBUG: " << err << std::endl;
            close(m_sock);
            m_sock = -1;
            return false;
        }

        // Large buffers for QUIC (4MB)
        int buf_size = 4 * 1048576; 
        if (setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
            std::string err = "QUIC Warning: Failed to set SO_RCVBUF: " + std::string(strerror(errno));
            nativeLog(err);
            std::cout << "DEBUG: " << err << std::endl;
        }
        if (setsockopt(m_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
            std::string err = "QUIC Warning: Failed to set SO_SNDBUF: " + std::string(strerror(errno));
            nativeLog(err);
            std::cout << "DEBUG: " << err << std::endl;
        }
        
        if (fcntl(m_sock, F_SETFL, O_NONBLOCK) < 0) {
            std::string err = "QUIC Error: fcntl(O_NONBLOCK) failed: " + std::string(strerror(errno));
            nativeLog(err);
            std::cout << "DEBUG: " << err << std::endl;
            close(m_sock);
            m_sock = -1;
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(m_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::string err = "QUIC Error: Failed to bind socket: " + std::string(strerror(errno));
            nativeLog(err);
            std::cout << "DEBUG: " << err << std::endl;
            close(m_sock);
            m_sock = -1;
            return false;
        }

        m_running = true;
        m_listenThread = std::thread(&QuicImpl::listenLoop, this);

        nativeLog("QUIC server started successfully on port " + std::to_string(port));
        std::cout << "DEBUG: QUIC server started successfully on port " << port << std::endl;
        return true;
    }

    void stop() {
        m_running = false;
        std::lock_guard<std::mutex> lock(m_mutex); // Reuse m_mutex for socket protection
        if (m_sock >= 0) {
            shutdown(m_sock, SHUT_RDWR);
            close(m_sock);
            m_sock = -1;
        }
        if (m_listenThread.joinable()) m_listenThread.join();
        nativeLog("QUIC server stopped.");
    }

    void sendMessageToPeer(const std::string& peer_id, const std::string& message) {
        std::cout << "DEBUG: QuicImpl::sendMessageToPeer called for " << peer_id << std::endl;
        size_t colon_pos = peer_id.find(':');
        if (colon_pos == std::string::npos) {
            nativeLog("QUIC Error: Invalid peer ID format.");
            return;
        }
        std::string ip = peer_id.substr(0, colon_pos);
        int port = std::stoi(peer_id.substr(colon_pos + 1));

        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_sock < 0) {
            nativeLog("QUIC Error: Socket closed, cannot send to " + peer_id);
            return;
        }

        uint32_t& pkt_num = m_peer_packet_numbers[peer_id];
        pkt_num++;
        
        // Generate a pseudo connection ID based on peer hash for now
        uint64_t conn_id = std::hash<std::string>{}(peer_id);

        std::string encrypted_msg = encrypt_message_udp(message);
        
        if (QuicMessage::send(m_sock, ip, port, conn_id, pkt_num, encrypted_msg)) {
            LOG_INFO("QUIC_SEND_SUCCESS: Sent packet #" + std::to_string(pkt_num) + " to " + peer_id);
            std::cout << "DEBUG: QUIC_SEND_SUCCESS" << std::endl;
        } else {
            LOG_INFO("QUIC_SEND_ERROR: Failed to send to " + peer_id);
            std::cout << "DEBUG: QUIC_SEND_ERROR" << std::endl;
        }
    }

    // Add connectToPeer implementation to QuicImpl
    bool connectToPeer(const std::string& ip, int port) {
        std::cout << "DEBUG: QuicImpl::connectToPeer called for " << ip << ":" << port << std::endl;
        // For QUIC/UDP, "connecting" is just ensuring we can send to the address.
        // We could send a dummy packet or handshake here if needed.
        // For now, we just return true to satisfy the interface.
        return true;
    }

    void sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) {
        // Use standard UDP for raw packets (STUN)
        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);
        
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_sock < 0) {
            // Socket closed, ignore packet
            return;
        }

        sendto(m_sock, data.data(), data.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
    }

    void setStunPacketCallback(OnStunPacketCallback callback) {
        m_stun_callback = callback;
    }

private:
    void listenLoop() {
        std::vector<uint8_t> buf(65535);
        while (m_running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(m_sock, &read_fds);
            timeval timeout = {1, 0}; 

            int select_res = select(m_sock + 1, &read_fds, nullptr, nullptr, &timeout);
            if (select_res <= 0) continue;

            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(m_sock, buf.data(), buf.size(), 0, (sockaddr*)&from_addr, &from_len);

            if (n > 0) {
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &from_addr.sin_addr, sender_ip, sizeof(sender_ip));
                int sender_port = ntohs(from_addr.sin_port);
                std::string peer_id = std::string(sender_ip) + ":" + std::to_string(sender_port);

                // Check for STUN first (raw UDP)
                if (UdpMessage::isStunPacket(reinterpret_cast<const char*>(buf.data()), n)) {
                    if (m_stun_callback) {
                        std::vector<uint8_t> packet_data(buf.data(), buf.data() + n);
                        m_stun_callback(sender_ip, sender_port, packet_data);
                    }
                    continue;
                }

                // Try to parse as QUIC
                std::vector<uint8_t> packet_data(buf.data(), buf.data() + n);
                QuicMessage::Header header;
                std::string payload;
                
                if (QuicMessage::parsePacket(packet_data, header, payload)) {
                    std::string decrypted_data = decrypt_message_udp(payload);
                    if (!decrypted_data.empty() && m_on_data) {
                        LOG_INFO("QUIC_RECEIVE: Pkt#" + std::to_string(header.packet_number) + " from " + peer_id);
                        m_on_data(peer_id, decrypted_data);
                    }
                } else {
                    // Fallback: Try to treat as plain UDP if QUIC parse fails (backward compatibility?)
                    // Or just log error
                    // LOG_INFO("QUIC_RECEIVE_ERROR: Invalid packet format from " + peer_id);
                }
            }
        }
    }

    std::atomic<bool> m_running;
    int m_sock;
    std::thread m_listenThread;
    OnDataCallback m_on_data;
    OnDisconnectCallback m_on_disconnect;
    OnStunPacketCallback m_stun_callback;
    
    std::mutex m_mutex;
    std::map<std::string, uint32_t> m_peer_packet_numbers;
};

QuicConnectionManager::QuicConnectionManager() : m_impl(std::make_unique<QuicImpl>()) {
    std::cout << "DEBUG: QuicConnectionManager constructor called" << std::endl;
}
QuicConnectionManager::~QuicConnectionManager() = default;
bool QuicConnectionManager::startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) { 
    std::cout << "DEBUG: QuicConnectionManager::startServer called" << std::endl;
    return m_impl->startServer(port, on_data, on_disconnect); 
}
void QuicConnectionManager::stop() { m_impl->stop(); }
bool QuicConnectionManager::connectToPeer(const std::string& ip, int port) { 
    std::cout << "DEBUG: QuicConnectionManager::connectToPeer called for " << ip << ":" << port << std::endl;
    return m_impl->connectToPeer(ip, port); 
}
void QuicConnectionManager::sendMessageToPeer(const std::string& peer_id, const std::string& message) { m_impl->sendMessageToPeer(peer_id, message); }
void QuicConnectionManager::sendRawPacket(const std::string& ip, int port, const std::vector<uint8_t>& data) { m_impl->sendRawPacket(ip, port, data); }
void QuicConnectionManager::setStunPacketCallback(OnStunPacketCallback callback) { m_impl->setStunPacketCallback(callback); }
