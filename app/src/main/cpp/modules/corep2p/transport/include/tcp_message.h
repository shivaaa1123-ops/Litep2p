#pragma once

#include <vector>
#include <string>
#include <memory>
#include <queue>
#include <mutex>
#include <cstdint>

// BufferPool - Zero-Allocation Buffer Reuse
class BufferPool {
public:
    static constexpr size_t POOL_SIZE = 16;

    BufferPool();
    ~BufferPool() = default;

    std::shared_ptr<std::vector<char>> acquire();
    void release(std::shared_ptr<std::vector<char>> buf);
    size_t get_available_count() const;

private:
    mutable std::mutex m_mutex;
    std::queue<std::shared_ptr<std::vector<char>>> m_available;
};

class TcpMessage {
public:
    // Frames a message with a 4-byte length prefix (network byte order)
    static std::string frameMessage(const std::string& payload);

    // Sends a framed message over a socket
    // Returns true on success, false on error
    static bool send(int socket, const std::string& framed_msg, const std::string& network_id);

    // Extracts complete messages from a buffer
    // Returns a vector of payloads (without length prefix)
    // Modifies the buffer to remove processed data
    static std::vector<std::string> extractMessages(std::vector<uint8_t>& buffer);
};
