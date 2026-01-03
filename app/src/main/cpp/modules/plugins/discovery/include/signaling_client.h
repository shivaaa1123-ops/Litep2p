#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <queue>

class SignalingClient {
public:
    using MessageCallback = std::function<void(const std::string&)>;

    SignalingClient();
    ~SignalingClient();

    bool connect(const std::string& url);
    
    // Single-threaded mode: connect without spawning receive thread
    // Returns socket fd for polling, or -1 on failure
    int connectEventLoop(const std::string& url);
    
    void disconnect();
    
    void sendRegister(const std::string& peer_id);
    void sendRegister(const std::string& peer_id, const std::string& network_id);
    void sendSignal(const std::string& target_peer_id, const std::string& payload);

    void sendListPeers();
    void sendUpdateNetworkId(const std::string& network_id);
    
    void setMessageCallback(MessageCallback callback);
    bool isConnected() const;
    
    // Single-threaded mode: process incoming data (call when socket is readable)
    void processIncoming();
    
    // Get socket fd for event loop
    int getSocketFd() const { return m_socket; }

private:
    void receiveLoop();
    bool performHandshake(const std::string& host, int port, const std::string& path);
    bool sendFrame(const std::string& data, uint8_t opcode = 0x1); // 0x1 = Text
    bool readOneFrame(std::string& out_message);
    
    // Helpers
    std::string generateWebSocketKey();
    std::string base64Encode(const std::vector<uint8_t>& data);

    int m_socket{-1};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_event_loop_mode{false};
    std::thread m_thread;
    MessageCallback m_callback;
    std::mutex m_mutex;
    
    std::string m_host;
    int m_port;
};
