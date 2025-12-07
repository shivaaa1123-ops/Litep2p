#include "connection_manager.h"
#include "logger.h"
#include "aes_wrapper.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <vector>

void ConnectionManager::startServer(int port, 
                                    std::function<void(const std::string&, const std::string&)> on_data, 
                                    std::function<void(const std::string&)> on_disconnect) {
    m_on_data_cb = on_data;
    m_on_disconnect_cb = on_disconnect;
    m_running = true;
    m_serverThread = std::thread(&ConnectionManager::serverLoop, this, port);
    nativeLog("CM: TCP Server started on port " + std::to_string(port));
}

void ConnectionManager::stop() {
    m_running = false;
    if (m_server_sock >= 0) {
        shutdown(m_server_sock, SHUT_RDWR);
        close(m_server_sock);
        m_server_sock = -1;
    }

    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        for (auto const& [key, val] : m_clients) {
            close(val);
        }
        m_clients.clear();
    }

    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }
    nativeLog("CM: TCP Server stopped.");
}

bool ConnectionManager::connectToPeer(const std::string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        nativeLog("CM Error: Failed to create socket for peer connection.");
        return false;
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
        nativeLog("CM Error: Invalid address for peer " + ip);
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        nativeLog("CM Error: Connection failed to peer " + ip);
        close(sock);
        return false;
    }
    
    std::string network_id = ip + ":" + std::to_string(port);
    
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        m_clients[network_id] = sock;
    }

    std::thread clientThread(&ConnectionManager::readLoop, this, sock, network_id);
    clientThread.detach();
    nativeLog("CM: Successfully connected to peer " + network_id);
    return true;
}

void ConnectionManager::sendMessageToPeer(const std::string& network_id, const std::string& message) {
    int client_sock = -1;
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        if (m_clients.count(network_id)) {
            client_sock = m_clients[network_id];
        }
    }

    if (client_sock != -1) {
        std::string encrypted_msg = encrypt_message(message);
        uint32_t msg_len = encrypted_msg.length();
        uint32_t net_msg_len = htonl(msg_len);

        std::vector<char> buffer;
        buffer.resize(sizeof(net_msg_len) + msg_len);
        memcpy(buffer.data(), &net_msg_len, sizeof(net_msg_len));
        memcpy(buffer.data() + sizeof(net_msg_len), encrypted_msg.data(), msg_len);

        ssize_t n = write(client_sock, buffer.data(), buffer.size());
        
        if (n < 0) {
            nativeLog("CM: Write failed for peer " + network_id + ". Disconnecting.");
            {
                std::lock_guard<std::mutex> lock(m_clients_mutex);
                m_clients.erase(network_id);
                close(client_sock);
            }
            m_on_disconnect_cb(network_id);
        } else {
             nativeLog("CM: Sent " + std::to_string(n) + " bytes to " + network_id);
        }
    } else {
        nativeLog("CM Error: Could not find socket for peer " + network_id);
    }
}

void ConnectionManager::serverLoop(int port) {
    m_server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (m_server_sock < 0) {
        nativeLog("CM Error: Failed to create server socket.");
        return;
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(m_server_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        nativeLog("CM Error: Failed to bind server socket.");
        return;
    }

    listen(m_server_sock, 5);

    while (m_running) {
        sockaddr_in cli_addr{};
        socklen_t clilen = sizeof(cli_addr);
        int client_sock = accept(m_server_sock, (struct sockaddr*)&cli_addr, &clilen);
        if (client_sock < 0) {
            if (!m_running) break;
            nativeLog("CM Error: Accept failed.");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
        std::string network_id = std::string(client_ip) + ":" + std::to_string(ntohs(cli_addr.sin_port));
        
        nativeLog("CM: Accepted new connection from " + network_id);

        {
            std::lock_guard<std::mutex> lock(m_clients_mutex);
            m_clients[network_id] = client_sock;
        }

        std::thread clientThread(&ConnectionManager::readLoop, this, client_sock, network_id);
        clientThread.detach();
    }
}

void ConnectionManager::readLoop(int client_sock, std::string network_id) {
    while (m_running) {
        uint32_t net_msg_len;
        ssize_t n = read(client_sock, &net_msg_len, sizeof(net_msg_len));

        if (n <= 0) {
            break; 
        }

        uint32_t msg_len = ntohl(net_msg_len);
        std::vector<char> buffer(msg_len);
        n = read(client_sock, buffer.data(), msg_len);
        if (n != msg_len) {
            break;
        }

        std::string encrypted_msg(buffer.begin(), buffer.end());
        std::string plain_msg = decrypt_message(encrypted_msg);
        m_on_data_cb(network_id, plain_msg);
    }
    
    nativeLog("CM: Peer " + network_id + " disconnected.");
    {
        std::lock_guard<std::mutex> lock(m_clients_mutex);
        m_clients.erase(network_id);
        close(client_sock);
    }
    m_on_disconnect_cb(network_id);
}
