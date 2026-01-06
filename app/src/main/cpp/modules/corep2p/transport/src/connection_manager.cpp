#include "connection_manager.h"
#include "logger.h"
#include "config_manager.h"
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
#include <map>
#include <vector>
#include <mutex>
#include <algorithm>
#include <condition_variable>
#include <sys/select.h>
#include <errno.h>
#include <netinet/tcp.h>

#include "tcp_message.h"

// ============================================================================
// BufferPool - Zero-Allocation Buffer Reuse
// ============================================================================
// Moved to tcp_message.h/cpp

class ConnectionManager::Impl {
public:
    Impl() : m_running(false), m_server_sock(-1), m_buffer_pool(std::make_unique<BufferPool>()) {}
    ~Impl() { 
        nativeLog("TCP_DEBUG: Impl destructor called for " + std::to_string((uintptr_t)this));
        stop(); 
    }

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
        std::cout << "TCP_DEBUG_RAW: startServer called on Impl " << (uintptr_t)this << std::endl;
        if (isRunning()) {
            std::cout << "TCP_DEBUG_RAW: startServer returning false because isRunning() is true" << std::endl;
            return false;
        }
        m_on_data = on_data;
        m_on_disconnect = on_disconnect;

        m_server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (m_server_sock < 0) {
            std::cout << "TCP_DEBUG_RAW: socket() failed: " << strerror(errno) << std::endl;
            nativeLog("TCP Error: Failed to create server socket.");
            return false;
        }

#ifdef __APPLE__
        int nosigpipe = 1;
        setsockopt(m_server_sock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

        int opt = 1;
        if (setsockopt(m_server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            std::cout << "TCP_DEBUG_RAW: setsockopt() failed: " << strerror(errno) << std::endl;
            nativeLog("TCP Error: setsockopt(SO_REUSEADDR) failed: " + std::string(strerror(errno)));
            close(m_server_sock);
            m_server_sock = -1;
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(m_server_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cout << "TCP_DEBUG_RAW: bind() failed: " << strerror(errno) << std::endl;
            nativeLog("TCP Error: Failed to bind server socket to port " + std::to_string(port) + ": " + std::string(strerror(errno)));
            close(m_server_sock);
            m_server_sock = -1;
            return false;
        }

        if (listen(m_server_sock, DEFAULT_LISTEN_BACKLOG) < 0) {
            std::cout << "TCP_DEBUG_RAW: listen() failed: " << strerror(errno) << std::endl;
            nativeLog("TCP Error: Failed to listen on server socket: " + std::string(strerror(errno)));
            close(m_server_sock);
            m_server_sock = -1;
            return false;
        }

        setRunning(true);
        m_acceptThread = std::thread(&Impl::acceptLoop, this);

        std::cout << "TCP_DEBUG_RAW: startServer success" << std::endl;
        nativeLog("TCP server started successfully on port " + std::to_string(port));
        return true;
    }

    void stop() {
        nativeLog("TCP_DEBUG: stop() called on Impl " + std::to_string((uintptr_t)this));
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!isRunning()) {
                return;
            }
            setRunning(false);
        }
        
        m_cv.notify_all();

        if (m_server_sock >= 0) {
            shutdown(m_server_sock, SHUT_RDWR);
            close(m_server_sock);
            m_server_sock = -1;
        }

        if (m_acceptThread.joinable()) m_acceptThread.join();

        std::map<std::string, int> clients_copy;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            clients_copy = m_clients;
            m_clients.clear();
        }

        for (auto const& [network_id, sock] : clients_copy) {
            shutdown(sock, SHUT_RDWR);
            close(sock);
        }

        for (auto& t : m_clientThreads) {
            if (t.joinable()) {
                // Add a timeout to prevent hanging
                // In a real implementation, we might want to use std::future or similar
                // For now, we'll just join with a note that this could hang
                nativeLog("TCP: Joining client thread (this may hang if thread is blocked)");
                t.join();
            }
        }
        m_clientThreads.clear();

        nativeLog("TCP server stopped.");
    }

    bool connectToPeer(const std::string& ip, int port) {
        std::string network_id = ip + ":" + std::to_string(port);
        LOG_INFO("TCP_CONNECT_ATTEMPT: Attempting to connect to IP: " + ip + " Port: " + std::to_string(port));
        bool already_connected = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            already_connected = (m_clients.count(network_id) != 0);
        }

        if (already_connected) {
            nativeLog("TCP: Already connected to " + network_id);
            // IMPORTANT: Never invoke callbacks while holding m_mutex.
            // The callback may synchronously call back into the transport (e.g. send),
            // which would deadlock if m_mutex is held.
            if (m_on_data) {
                m_on_data(network_id, "CONNECT_ACK");
            }
            return true;
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            nativeLog("TCP Error: Failed to create client socket: " + std::string(strerror(errno)));
            return false;
        }
        
        LOG_DEBUG("TCP_CONNECT: Socket created successfully, fd=" + std::to_string(sock));

#ifdef __APPLE__
        int nosigpipe = 1;
        setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

        // Configure Nagle's algorithm based on config
        int nodelay_flag = ConfigManager::getInstance().isTCPNoDelayEnabled() ? 1 : 0;
        if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay_flag, sizeof(int)) < 0) {
             nativeLog("TCP Warning: Failed to set TCP_NODELAY: " + std::string(strerror(errno)));
        } else {
             LOG_DEBUG("TCP_CONNECT: TCP_NODELAY set to " + std::to_string(nodelay_flag));
        }

        // Set socket to non-blocking mode for timeout handling
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        LOG_DEBUG("TCP_CONNECT: Socket set to non-blocking mode");

        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);
        LOG_DEBUG("TCP_CONNECT: Address structure prepared");

        // Attempt to connect (non-blocking)
        int result = ::connect(sock, (sockaddr*)&dest_addr, sizeof(dest_addr));
        LOG_DEBUG("TCP_CONNECT: connect() returned, result=" + std::to_string(result) + ", errno=" + std::to_string(errno));
        
        if (result < 0) {
            if (errno == EINPROGRESS) {
                LOG_DEBUG("TCP_CONNECT: Connection in progress, waiting with timeout");
                // Connection in progress, wait with timeout
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(sock, &write_fds);
                
                timeval timeout;
                timeout.tv_sec = ConfigManager::getInstance().getTCPConnectTimeout();
                timeout.tv_usec = 0;
                
                result = select(sock + 1, NULL, &write_fds, NULL, &timeout);
                LOG_DEBUG("TCP_CONNECT: select() returned, result=" + std::to_string(result));
                
                if (result <= 0) {
                    // Timeout or error
                    nativeLog("TCP Error: Connection timeout to " + network_id + ": " + (result == 0 ? "Timeout" : std::string(strerror(errno))));
                    close(sock);
                    return false;
                }
                
                // Check if connection was successful
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                    nativeLog("TCP Error: Failed to connect to " + network_id + ": " + (error ? std::string(strerror(error)) : "Unknown error"));
                    close(sock);
                    return false;
                }
                LOG_DEBUG("TCP_CONNECT: Connection established successfully");
            } else {
                nativeLog("TCP Error: Failed to connect to " + network_id + ": " + std::string(strerror(errno)));
                close(sock);
                return false;
            }
        } else {
            LOG_DEBUG("TCP_CONNECT: Connection established immediately");
        }

        // Keep socket in non-blocking mode for select() loop in handleClient
        // fcntl(sock, F_SETFL, flags);
        // LOG_DEBUG("TCP_CONNECT: Socket set back to blocking mode");

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_clients[network_id] = sock;
            m_clientThreads.emplace_back(&Impl::handleClient, this, sock, network_id);
        }
        LOG_INFO("TCP_CONNECT_SUCCESS: Successfully connected to IP: " + ip + " Port: " + std::to_string(port) + " - connection acknowledged");
        
        if (m_on_data) {
            m_on_data(network_id, "CONNECT_ACK");
        }
        
        return true;
    }

    void sendMessageToPeer(const std::string& network_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_mutex);
           if (m_clients.count(network_id)) {
              int sock = m_clients[network_id];
              std::string encrypted_msg = encrypt_message(message);
              std::string framed_msg = TcpMessage::frameMessage(encrypted_msg);

              if (TcpMessage::send(sock, framed_msg, network_id)) {
                  LOG_INFO("TCP_SEND_SUCCESS: Sent message to peer " + network_id + " (IP:Port) with payload: " + message);
              }
           } else {
              LOG_INFO("TCP_SEND_ERROR: Could not send message, peer " + network_id + " not found or not connected.");
           }
    }

private:
    void acceptLoop() {
        while (isRunning()) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            if(m_server_sock >= 0) {
                FD_SET(m_server_sock, &read_fds);
            }
            timeval timeout = {1, 0}; 

            int select_res = select(m_server_sock + 1, &read_fds, nullptr, nullptr, &timeout);

            if (select_res < 0) {
                if (errno != EINTR && isRunning()) {
                    nativeLog("TCP Error: select() failed in acceptLoop: " + std::string(strerror(errno)));
                }
                if (!isRunning()) break;
                else continue;
            } else if (select_res == 0) {
                continue; 
            }

            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_sock = accept(m_server_sock, (sockaddr*)&client_addr, &client_len);

            if (client_sock < 0) {
                if(isRunning()) nativeLog("TCP Error: accept() failed: " + std::string(strerror(errno)));
                continue;
            }

#ifdef __APPLE__
            int nosigpipe = 1;
            setsockopt(client_sock, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
#endif

            // Configure Nagle's algorithm based on config
            int nodelay_flag = ConfigManager::getInstance().isTCPNoDelayEnabled() ? 1 : 0;
            if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay_flag, sizeof(int)) < 0) {
                 nativeLog("TCP Warning: Failed to set TCP_NODELAY on accepted socket: " + std::string(strerror(errno)));
            }

            // Set socket to non-blocking mode for select() loop
            int flags = fcntl(client_sock, F_GETFL, 0);
            fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            int client_port = ntohs(client_addr.sin_port);
            std::string network_id = std::string(client_ip) + ":" + std::to_string(client_port);
            
            nativeLog("TCP: Accepted new connection from " + network_id);
            
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_clients[network_id] = client_sock;
                m_clientThreads.emplace_back(&Impl::handleClient, this, client_sock, network_id);
            }

            // DO NOT send CONNECT_ACK here - wait for CONTROL_CONNECT message to identify the peer
            // The message_handler will respond with CONTROL_CONNECT_ACK after peer identification
            // This allows Device B to properly identify Device A from the CONTROL_CONNECT payload
        }
    }

    void handleClient(int client_sock, std::string network_id) {
        auto buf = m_buffer_pool->acquire();
        std::vector<uint8_t> receive_buffer; // Buffer for partial reads/framing
        nativeLog("TCP_DEBUG: handleClient started for " + network_id + " on Impl " + std::to_string((uintptr_t)this) + ", m_running=" + (isRunning() ? "true" : "false"));
        
        while (isRunning()) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_sock, &read_fds);
            timeval timeout = {1, 0};

            int select_res = select(client_sock + 1, &read_fds, nullptr, nullptr, &timeout);

            if (select_res < 0) {
                 if (errno != EINTR && isRunning()) {
                    nativeLog("TCP Error: select() failed for client " + network_id + ": " + std::string(strerror(errno)));
                } else {
                    nativeLog("TCP_DEBUG: select() returned < 0, errno=" + std::to_string(errno));
                }
                break;
            }

            if (select_res == 0) {
                // nativeLog("TCP_DEBUG: select() timed out for " + network_id);
                continue;
            }
            
            if (FD_ISSET(client_sock, &read_fds)) {
                // nativeLog("TCP_DEBUG: Calling recv for " + network_id);
                ssize_t n = recv(client_sock, buf->data(), buf->size(), 0);
                // nativeLog("TCP_DEBUG: recv returned " + std::to_string(n) + " for " + network_id);
                
                if (n > 0) {
                    // LOG_DEBUG("TCP: Received " + std::to_string(n) + " bytes from " + network_id);
                    
                    // Append to buffer
                    receive_buffer.insert(receive_buffer.end(), buf->data(), buf->data() + n);
                    
                    // Process messages in buffer
                    auto messages = TcpMessage::extractMessages(receive_buffer);
                    for (const auto& encrypted_data : messages) {
                        // Decrypt and process
                        std::string decrypted_data = decrypt_message(encrypted_data);
                        if (m_on_data) {
                            m_on_data(network_id, decrypted_data);
                        }
                    }
                } else if (n == 0) {
                    nativeLog("TCP: Peer " + network_id + " gracefully disconnected.");
                    break;
                } else {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                         nativeLog("TCP Error: recv() failed for " + network_id + ": " + std::string(strerror(errno)));
                         break;
                    }
                }
            } else {
                nativeLog("TCP_DEBUG: select > 0 but FD_ISSET false");
            }
        }
        
        nativeLog("TCP_DEBUG: handleClient exiting for " + network_id);
        m_buffer_pool->release(buf);

        bool was_connected = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_clients.count(network_id)) {
                close(m_clients[network_id]);
                m_clients.erase(network_id);
                was_connected = true;
            }
        }
        if (was_connected && m_on_disconnect) m_on_disconnect(network_id);
    }

    void setRunning(bool val) {
        nativeLog("TCP_DEBUG: setRunning(" + std::string(val ? "true" : "false") + ") called on Impl " + std::to_string((uintptr_t)this));
        m_running = val;
    }

    bool isRunning() const {
        return m_running;
    }

private:
    std::atomic<bool> m_running;
public:
    int m_server_sock;
    std::thread m_acceptThread;
    std::map<std::string, int> m_clients;
    std::map<std::string, std::vector<uint8_t>> m_receiveBuffers; // Buffer for partial reads
    std::vector<std::thread> m_clientThreads; 
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::unique_ptr<BufferPool> m_buffer_pool;

    OnDataCallback m_on_data;
    OnDisconnectCallback m_on_disconnect;
};

ConnectionManager::ConnectionManager() : m_impl(std::make_unique<Impl>()) {}
ConnectionManager::~ConnectionManager() = default;
bool ConnectionManager::startServer(int p, OnDataCallback d, OnDisconnectCallback c) { return m_impl->startServer(p, d, c); }
void ConnectionManager::stop() { m_impl->stop(); }
bool ConnectionManager::connectToPeer(const std::string& ip, int port) { return m_impl->connectToPeer(ip, port); }
void ConnectionManager::sendMessageToPeer(const std::string& nid, const std::string& msg) { m_impl->sendMessageToPeer(nid, msg); }
