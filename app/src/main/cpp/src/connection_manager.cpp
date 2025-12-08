#include "connection_manager.h"
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
#include <map>
#include <vector>
#include <mutex>
#include <algorithm>

class ConnectionManager::Impl {
public:
    Impl() : m_running(false), m_server_sock(-1) {}
    ~Impl() { stop(); }

    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
        if (m_running) return false;
        m_on_data = on_data;
        m_on_disconnect = on_disconnect;

        m_server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (m_server_sock < 0) {
            nativeLog("TCP Error: Failed to create server socket.");
            return false;
        }

        int opt = 1;
        if (setsockopt(m_server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            nativeLog("TCP Error: setsockopt(SO_REUSEADDR) failed: " + std::string(strerror(errno)));
            close(m_server_sock);
            m_server_sock = -1;
            return false;
        }

        if (fcntl(m_server_sock, F_SETFL, O_NONBLOCK) < 0) {
            nativeLog("TCP Error: fcntl(O_NONBLOCK) failed for server socket: " + std::string(strerror(errno)));
            close(m_server_sock);
            m_server_sock = -1;
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(m_server_sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            nativeLog("TCP Error: Failed to bind server socket to port " + std::to_string(port) + ": " + std::string(strerror(errno)));
            close(m_server_sock);
            m_server_sock = -1;
            return false;
        }

        if (listen(m_server_sock, DEFAULT_LISTEN_BACKLOG) < 0) {
            nativeLog("TCP Error: Failed to listen on server socket: " + std::string(strerror(errno)));
            close(m_server_sock);
            m_server_sock = -1;
            return false;
        }

        m_running = true;
        m_acceptThread = std::thread(&Impl::acceptLoop, this);

        nativeLog("TCP server started successfully on port " + std::to_string(port));
        return true;
    }

    void stop() {
        m_running = false;
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
            nativeLog("TCP: Shutting down client socket for " + network_id);
            shutdown(sock, SHUT_RDWR);
            close(sock);
        }

        for (auto& t : m_clientThreads) {
            if (t.joinable()) {
                t.join();
            }
        }
        m_clientThreads.clear();

        nativeLog("TCP server stopped.");
    }

    bool connectToPeer(const std::string& ip, int port) {
        std::string network_id = ip + ":" + std::to_string(port);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_clients.count(network_id)) {
                nativeLog("TCP: Already connected to " + network_id);
                return true;
            }
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            nativeLog("TCP Error: Failed to create client socket: " + std::string(strerror(errno)));
            return false;
        }

        if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
            nativeLog("TCP Error: fcntl(O_NONBLOCK) failed for client socket: " + std::string(strerror(errno)));
            close(sock);
            return false;
        }

        sockaddr_in dest_addr{};
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

        int connect_res = ::connect(sock, (sockaddr*)&dest_addr, sizeof(dest_addr));
        if (connect_res < 0 && errno != EINPROGRESS) {
            nativeLog("TCP Error: Failed to connect to " + network_id + ": " + std::string(strerror(errno)));
            close(sock);
            return false;
        }

        if (connect_res < 0) { 
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);
            timeval timeout = {TCP_CONNECT_TIMEOUT_SEC, 0}; 

            int select_res = select(sock + 1, nullptr, &write_fds, nullptr, &timeout);
            if (select_res <= 0) {
                nativeLog("TCP Error: Connect timeout or error for " + network_id + ": " + std::string(strerror(errno)));
                close(sock);
                return false;
            }

            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error != 0) {
                nativeLog("TCP Error: Connect failed for " + network_id + ": " + std::string(strerror(so_error)));
                close(sock);
                return false;
            }
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        m_clients[network_id] = sock;
        m_clientThreads.emplace_back(&Impl::handleClient, this, sock, network_id);
        nativeLog("TCP: Successfully connected to " + network_id);
        return true;
    }

    void sendMessageToPeer(const std::string& network_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_clients.count(network_id)) {
            int sock = m_clients[network_id];
            std::string encrypted_msg = encrypt_message(message);
            ssize_t bytes_sent = ::send(sock, encrypted_msg.c_str(), encrypted_msg.size(), 0);
            if (bytes_sent < 0) {
                 nativeLog("TCP Error: Failed to send message to " + network_id + ": " + std::string(strerror(errno)));
            } else if (bytes_sent < encrypted_msg.size()) {
                 nativeLog("TCP Warning: Partial send to " + network_id + ": " + std::to_string(bytes_sent) + " of " + std::to_string(encrypted_msg.size()) + " bytes.");
            }
        } else {
            nativeLog("TCP Error: Could not send message, peer " + network_id + " not found or not connected.");
        }
    }

private:
    void acceptLoop() {
        while (m_running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(m_server_sock, &read_fds);
            timeval timeout = {TCP_SELECT_TIMEOUT_SEC, 0}; 

            int select_res = select(m_server_sock + 1, &read_fds, nullptr, nullptr, &timeout);

            if (select_res < 0) {
                if (errno != EINTR && m_running) {
                    nativeLog("TCP Error: select() failed in acceptLoop: " + std::string(strerror(errno)));
                }
                break; 
            } else if (select_res == 0) {
                continue; 
            }

            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_sock = accept(m_server_sock, (sockaddr*)&client_addr, &client_len);

            if (client_sock < 0) {
                if(m_running) nativeLog("TCP Error: accept() failed: " + std::string(strerror(errno)));
                break;
            }

            if (fcntl(client_sock, F_SETFL, O_NONBLOCK) < 0) {
                nativeLog("TCP Error: fcntl(O_NONBLOCK) failed for client_sock: " + std::string(strerror(errno)));
                close(client_sock);
                continue;
            }

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            int client_port = ntohs(client_addr.sin_port);
            std::string network_id = std::string(client_ip) + ":" + std::to_string(client_port);
            
            nativeLog("TCP: Accepted new connection from " + network_id);

            std::lock_guard<std::mutex> lock(m_mutex);
            m_clients[network_id] = client_sock;
            m_clientThreads.emplace_back(&Impl::handleClient, this, client_sock, network_id);
        }
    }

    void handleClient(int client_sock, std::string network_id) {
        std::vector<char> buf(TCP_BUFFER_SIZE); 
        while (m_running) {
            ssize_t n = recv(client_sock, buf.data(), buf.size(), 0);
            if (n > 0) {
                std::string encrypted_data(buf.data(), n);
                std::string decrypted_data = decrypt_message(encrypted_data);
                if (!decrypted_data.empty() && m_on_data) {
                    m_on_data(network_id, decrypted_data);
                } else if (decrypted_data.empty()) {
                    nativeLog("TCP Error: Decryption failed for message from " + network_id);
                }
            } else if (n == 0) {
                nativeLog("TCP: Peer " + network_id + " gracefully disconnected.");
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) { 
                nativeLog("TCP Error: recv() failed for " + network_id + ": " + std::string(strerror(errno)));
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); 
        }

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

    std::atomic<bool> m_running;
    int m_server_sock;
    std::thread m_acceptThread;
    std::map<std::string, int> m_clients;
    std::vector<std::thread> m_clientThreads; 
    std::mutex m_mutex; 

    OnDataCallback m_on_data;
    OnDisconnectCallback m_on_disconnect;
};

ConnectionManager::ConnectionManager() : m_impl(std::make_unique<Impl>()) {}
ConnectionManager::~ConnectionManager() = default;
bool ConnectionManager::startServer(int p, OnDataCallback d, OnDisconnectCallback c) { return m_impl->startServer(p, d, c); }
void ConnectionManager::stop() { m_impl->stop(); }
bool ConnectionManager::connectToPeer(const std::string& ip, int port) { return m_impl->connectToPeer(ip, port); }
void ConnectionManager::sendMessageToPeer(const std::string& nid, const std::string& msg) { m_impl->sendMessageToPeer(nid, msg); }
