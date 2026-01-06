#include "tcp_message.h"
#include "logger.h"
#include "config_manager.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <algorithm>

// ============================================================================
// BufferPool Implementation
// ============================================================================

BufferPool::BufferPool() {
    size_t buffer_size = ConfigManager::getInstance().getTCPBufferSize();
    for (size_t i = 0; i < POOL_SIZE; i++) {
        m_available.push(std::make_shared<std::vector<char>>(buffer_size));
    }
    nativeLog("BufferPool: Initialized with " + std::to_string(POOL_SIZE) + " buffers (" +
              std::to_string(POOL_SIZE * buffer_size / 1024) + " KB)");
}

std::shared_ptr<std::vector<char>> BufferPool::acquire() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_available.empty()) {
        auto buf = m_available.front();
        m_available.pop();
        return buf;
    }
    nativeLog("BufferPool: Warning - pool exhausted, allocating new buffer");
    return std::make_shared<std::vector<char>>(ConfigManager::getInstance().getTCPBufferSize());
}

void BufferPool::release(std::shared_ptr<std::vector<char>> buf) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_available.size() < POOL_SIZE) {
        m_available.push(buf);
    }
}

size_t BufferPool::get_available_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_available.size();
}

// ============================================================================
// TcpMessage Implementation
// ============================================================================

std::string TcpMessage::frameMessage(const std::string& payload) {
    uint32_t msg_len = htonl(static_cast<uint32_t>(payload.size()));
    std::string framed_msg;
    framed_msg.reserve(4 + payload.size());
    framed_msg.append(reinterpret_cast<const char*>(&msg_len), 4);
    framed_msg.append(payload);
    return framed_msg;
}

bool TcpMessage::send(int sock, const std::string& framed_msg, const std::string& network_id) {
    // Sanity check
    if (sock < 0) {
        nativeLog("TCP Error: Invalid socket " + std::to_string(sock));
        return false;
    }

    nativeLog("TCP_DEBUG: Sending framed message, total size=" + std::to_string(framed_msg.size()));
    errno = 0;
    size_t total_sent = 0;
    size_t msg_len = framed_msg.size();
    const char* data_ptr = framed_msg.c_str();

    while (total_sent < msg_len) {
#ifdef __APPLE__
        ssize_t bytes_sent = ::send(sock, data_ptr + total_sent, msg_len - total_sent, 0);
#else
        ssize_t bytes_sent = ::send(sock, data_ptr + total_sent, msg_len - total_sent, MSG_NOSIGNAL);
#endif
    
        if (bytes_sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_INFO("TCP_SEND_ERROR: Send buffer full (EAGAIN) for " + network_id);
                // In a real non-blocking scenario, we should buffer the rest.
                // For now, we fail to avoid partial packet corruption on the wire.
                return false;
            } else {
                LOG_INFO("TCP_SEND_ERROR: Failed to send message to " + network_id + ": " + std::string(strerror(errno)));
                return false;
            }
        }
        
        total_sent += bytes_sent;
    }
    
    if (total_sent < msg_len) {
        nativeLog("TCP Warning: Partial send to " + network_id + ": " + std::to_string(total_sent) + " of " + std::to_string(msg_len) + " bytes.");
        return false;
    }
    return true;
}

std::vector<std::string> TcpMessage::extractMessages(std::vector<uint8_t>& buffer) {
    std::vector<std::string> messages;
    
    while (buffer.size() >= 4) {
        // Read length
        uint32_t msg_len;
        std::memcpy(&msg_len, buffer.data(), 4);
        msg_len = ntohl(msg_len);
        
        if (buffer.size() < 4 + msg_len) {
            // Wait for more data
            break;
        }
        
        // Extract message
        messages.emplace_back(reinterpret_cast<char*>(buffer.data() + 4), msg_len);
        
        // Remove from buffer
        buffer.erase(buffer.begin(), buffer.begin() + 4 + msg_len);
    }
    
    return messages;
}
