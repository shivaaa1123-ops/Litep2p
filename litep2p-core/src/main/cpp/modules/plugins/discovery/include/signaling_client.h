#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <queue>

#if defined(HAVE_OPENSSL)
#include <openssl/ssl.h>
#endif

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
    
    // Relay a message through the signaling server to a peer
    // Used when direct UDP path is failing (NAT/firewall issues)
    void sendRelayMessage(const std::string& target_peer_id, const std::string& message);

    void sendListPeers();
    void sendUpdateNetworkId(const std::string& network_id);

    // v0.4: send an arbitrary pre-built JSON frame (alias/lookup/invite/store/
    // fetch/presence protocol messages). Returns false when not connected.
    bool sendRawJson(const std::string& json_payload);

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

    // TLS-aware I/O (wss://). These dispatch to OpenSSL when m_tls is set,
    // otherwise to the plain-socket helpers.
    bool ioSendAll(const void* buf, size_t len);
    bool ioRecvExact(void* out, size_t len, bool* would_block = nullptr);
    bool ioRecvExactWithSelect(void* out, size_t len);

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

    // wss:// TLS state (only used when compiled with HAVE_OPENSSL).
    bool m_tls{false};
#if defined(HAVE_OPENSSL)
    SSL_CTX* m_ssl_ctx{nullptr};
    SSL* m_ssl{nullptr};
#endif
};
