#include "multi_socket_manager.h"
#include <algorithm>
#include <thread>

MultiSocketManager::MultiSocketManager(const Config& config)
    : m_config(config) {}

MultiSocketManager::~MultiSocketManager() {
    stop();
}

bool MultiSocketManager::startServer(int base_port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_running) return false;
    
    m_on_data_cb = on_data;
    m_on_disconnect_cb = on_disconnect;
    m_running = true;
    
    // Create socket handlers
    for (int i = 0; i < m_config.num_sockets; ++i) {
        if (!create_socket_handler(i, base_port + i)) {
            return false;
        }
    }
    
    return true;
}

void MultiSocketManager::stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_running) return;
        m_running = false;
    }
    
    for (size_t i = 0; i < m_sockets.size(); ++i) {
        cleanup_socket(i);
    }
    
    // Wait for listener threads
    for (auto& thread : m_listener_threads) {
        if (thread && thread->joinable()) {
            thread->join();
        }
    }
}

bool MultiSocketManager::add_peer(const std::string& peer_id, const std::string& ip, int port) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int socket_id = get_socket_id_for_peer(peer_id);
    
    if (socket_id < 0 || socket_id >= static_cast<int>(m_sockets.size())) {
        return false;
    }
    
    auto& socket_handler = m_sockets[socket_id];
    
    // Add peer to this socket's list
    auto it = std::find(socket_handler->peers.begin(), socket_handler->peers.end(), peer_id);
    if (it == socket_handler->peers.end()) {
        socket_handler->peers.push_back(peer_id);
        m_peer_to_socket[peer_id] = socket_id;
        return true;
    }
    
    return false;
}

bool MultiSocketManager::remove_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peer_to_socket.find(peer_id);
    if (it == m_peer_to_socket.end()) {
        return false;
    }
    
    int socket_id = it->second;
    auto& socket_handler = m_sockets[socket_id];
    
    auto peer_it = std::find(socket_handler->peers.begin(), socket_handler->peers.end(), peer_id);
    if (peer_it != socket_handler->peers.end()) {
        socket_handler->peers.erase(peer_it);
    }
    
    m_peer_to_socket.erase(it);
    return true;
}

void MultiSocketManager::sendMessageToPeer(const std::string& peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peer_to_socket.find(peer_id);
    if (it == m_peer_to_socket.end()) {
        return;
    }
    
    int socket_id = it->second;
    if (socket_id < 0 || socket_id >= static_cast<int>(m_sockets.size())) {
        return;
    }
    
    auto& socket_handler = m_sockets[socket_id];
    socket_handler->messages_sent++;
    socket_handler->bytes_sent += message.length();
    
    // In real implementation, would send via socket_handler->socket_fd
}

void MultiSocketManager::sendBatchToMultiplePeers(const std::vector<std::pair<std::string, std::string>>& messages) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Group messages by socket
    std::map<int, std::vector<std::pair<std::string, std::string>>> messages_by_socket;
    
    for (const auto& msg : messages) {
        auto it = m_peer_to_socket.find(msg.first);
        if (it != m_peer_to_socket.end()) {
            int socket_id = it->second;
            messages_by_socket[socket_id].push_back(msg);
        }
    }
    
    // Send via appropriate sockets
    for (auto& pair : messages_by_socket) {
        int socket_id = pair.first;
        auto& batch = pair.second;
        
        if (socket_id < 0 || socket_id >= static_cast<int>(m_sockets.size())) {
            continue;
        }
        
        auto& socket_handler = m_sockets[socket_id];
        for (const auto& msg : batch) {
            socket_handler->messages_sent++;
            socket_handler->bytes_sent += msg.second.length();
        }
    }
}

std::vector<MultiSocketManager::SocketStats> MultiSocketManager::get_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<SocketStats> stats;
    for (const auto& socket : m_sockets) {
        SocketStats s;
        s.socket_id = socket->socket_id;
        s.peer_count = socket->peers.size();
        s.messages_sent = socket->messages_sent;
        s.bytes_sent = socket->bytes_sent;
        s.messages_received = socket->messages_received;
        s.bytes_received = socket->bytes_received;
        stats.push_back(s);
    }
    return stats;
}

void MultiSocketManager::reconfigure(const Config& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
    // In real implementation, would resize sockets array
}

int MultiSocketManager::get_socket_id_for_peer(const std::string& peer_id) const {
    std::hash<std::string> hash_fn;
    return hash_fn(peer_id) % m_config.num_sockets;
}

bool MultiSocketManager::create_socket_handler(int socket_id, int base_port) {
    auto handler = std::make_shared<SocketHandler>();
    handler->socket_id = socket_id;
    handler->listen_port = base_port;
    handler->socket_fd = -1;  // Placeholder
    
    m_sockets.push_back(handler);
    return true;
}

void MultiSocketManager::cleanup_socket(int socket_id) {
    if (socket_id < 0 || socket_id >= static_cast<int>(m_sockets.size())) {
        return;
    }
    
    auto& socket_handler = m_sockets[socket_id];
    if (socket_handler && socket_handler->socket_fd >= 0) {
        // Close socket
        socket_handler->socket_fd = -1;
    }
}
