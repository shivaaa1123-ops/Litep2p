#include "batch_connection_manager.h"
#include "logger.h"
#include <chrono>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

BatchConnectionManager::BatchConnectionManager(const BatchConfig& config)
    : m_config(config), m_running(false) {}

BatchConnectionManager::~BatchConnectionManager() {
    stop();
}

bool BatchConnectionManager::startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_running) return false;
    
    m_listen_port = port;
    m_on_data_cb = on_data;
    m_on_disconnect_cb = on_disconnect;
    m_running = true;
    
    nativeLog("BatchConnectionManager: Starting on port " + std::to_string(port));
    
    // Start cleanup thread
    m_cleanup_thread = std::thread([this] {
        while (m_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            cleanup_expired_batches();
        }
    });
    
    return true;
}

void BatchConnectionManager::stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_running) return;
        m_running = false;
    }
    
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }
    
    if (m_server_socket_fd >= 0) {
        ::close(m_server_socket_fd);
        m_server_socket_fd = -1;
    }
}

bool BatchConnectionManager::add_peer_to_batch(const std::string& peer_id, const std::string& ip, int port) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check if peer already in a batch
    if (m_peer_to_batch.find(peer_id) != m_peer_to_batch.end()) {
        return false;  // Already batched
    }
    
    // Find or create batch for this peer
    std::string batch_id = allocate_batch(peer_id, ip, port);
    m_peer_to_batch[peer_id] = batch_id;
    
    nativeLog("BatchConnectionManager: Added peer " + peer_id + " to batch " + batch_id);
    return true;
}

bool BatchConnectionManager::remove_peer_from_batch(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peer_to_batch.find(peer_id);
    if (it == m_peer_to_batch.end()) return false;
    
    std::string batch_id = it->second;
    m_peer_to_batch.erase(it);
    
    // Remove from batch
    auto batch_it = m_batches.find(batch_id);
    if (batch_it != m_batches.end()) {
        auto& batch = batch_it->second;
        auto peer_it = std::find(batch->peer_ids.begin(), batch->peer_ids.end(), peer_id);
        if (peer_it != batch->peer_ids.end()) {
            batch->peer_ids.erase(peer_it);
        }
        
        // If batch empty, remove it
        if (batch->peer_ids.empty() && batch->socket_fd >= 0) {
            ::close(batch->socket_fd);
            m_batches.erase(batch_it);
        }
    }
    
    return true;
}

void BatchConnectionManager::sendMessageToPeer(const std::string& peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto batch_it = m_peer_to_batch.find(peer_id);
    if (batch_it == m_peer_to_batch.end()) return;
    
    auto batch_ptr_it = m_batches.find(batch_it->second);
    if (batch_ptr_it == m_batches.end()) return;
    
    auto& batch = batch_ptr_it->second;
    
    // Format: BATCH_MSG|peer_id|message_length|message
    std::string formatted = "BATCH_MSG|" + peer_id + "|" + 
                           std::to_string(message.length()) + "|" + message;
    
    // In real implementation, would send via batch socket
    // For now, just queue
}

void BatchConnectionManager::sendBatch(const std::vector<std::pair<std::string, std::string>>& messages) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string batch_data;
    serialize_batch_message(messages, batch_data);
    
    // Send batch_data to all active sockets
    for (auto& pair : m_batches) {
        if (pair.second->socket_fd >= 0) {
            ::send(pair.second->socket_fd, batch_data.c_str(), batch_data.length(), 0);
        }
    }
}

BatchConnectionManager::Stats BatchConnectionManager::get_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Stats stats;
    stats.active_batches = m_batches.size();
    
    for (const auto& pair : m_batches) {
        stats.total_peers += pair.second->peer_ids.size();
    }
    
    if (!m_batches.empty()) {
        stats.avg_batch_utilization = static_cast<float>(stats.total_peers) / 
                                     (stats.active_batches * m_config.max_peers_per_batch) * 100.0f;
    }
    
    return stats;
}

void BatchConnectionManager::reconfigure(const BatchConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
}

void BatchConnectionManager::cleanup_expired_batches() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::steady_clock::now();
    
    auto it = m_batches.begin();
    while (it != m_batches.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second->last_activity
        ).count();
        
        if (elapsed > m_config.batch_timeout_sec && it->second->peer_ids.empty()) {
            if (it->second->socket_fd >= 0) {
                ::close(it->second->socket_fd);
            }
            it = m_batches.erase(it);
        } else {
            ++it;
        }
    }
}

std::string BatchConnectionManager::allocate_batch(const std::string& peer_id, 
                                                   const std::string& ip, int port) {
    // Round-robin allocation to balance load
    if (m_batch_queue.size() >= static_cast<size_t>(m_config.max_batches)) {
        // Use existing batch with available slots
        for (auto& batch : m_batch_queue) {
            if (batch->peer_ids.size() < static_cast<size_t>(m_config.max_peers_per_batch)) {
                batch->peer_ids.push_back(peer_id);
                batch->last_activity = std::chrono::steady_clock::now();
                return batch->batch_id;
            }
        }
    }
    
    // Create new batch
    std::string batch_id = "batch_" + std::to_string(m_batches.size());
    auto batch = std::make_shared<Batch>();
    batch->batch_id = batch_id;
    batch->peer_ids.push_back(peer_id);
    batch->primary_ip = ip;
    batch->primary_port = port;
    batch->last_activity = std::chrono::steady_clock::now();
    batch->socket_fd = -1;  // Created on-demand
    
    m_batches[batch_id] = batch;
    m_batch_queue.push_back(batch);
    
    return batch_id;
}

std::string BatchConnectionManager::get_batch_for_peer(const std::string& peer_id) {
    auto it = m_peer_to_batch.find(peer_id);
    return it != m_peer_to_batch.end() ? it->second : "";
}

void BatchConnectionManager::serialize_batch_message(const std::vector<std::pair<std::string, std::string>>& messages,
                                                    std::string& output) {
    output = "BATCH|";
    output += std::to_string(messages.size()) + "|";
    
    for (const auto& msg : messages) {
        output += msg.first + "|" + std::to_string(msg.second.length()) + "|" + msg.second + "|";
    }
}
