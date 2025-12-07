
#include "network.h"
#include "logger.h"
#include "aes.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <algorithm>

using DataCb = std::function<void(const std::string&, const std::string&)>;
using DisconnectCb = std::function<void(const std::string&)>;

static const uint8_t g_aes_key[] = { 
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

std::string encrypt_message(const std::string& plain_text) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, g_aes_key);
    std::string encrypted_text = plain_text;
    int padding = AES_BLOCKLEN - (encrypted_text.length() % AES_BLOCKLEN);
    encrypted_text.append(padding, (char)padding);
    AES_CBC_encrypt_buffer(&ctx, (uint8_t*)encrypted_text.data(), encrypted_text.length());
    return encrypted_text;
}

std::string decrypt_message(const std::string& encrypted_text) {
    if (encrypted_text.length() % AES_BLOCKLEN != 0) {
        nativeLog("Network Error: Received malformed (non-padded) encrypted message.");
        return "";
    }
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, g_aes_key);
    std::string decrypted_text = encrypted_text;
    AES_CBC_decrypt_buffer(&ctx, (uint8_t*)decrypted_text.data(), decrypted_text.length());
    int padding = decrypted_text.back();
    if (padding > 0 && padding <= AES_BLOCKLEN) {
        decrypted_text.resize(decrypted_text.length() - padding);
    }
    return decrypted_text;
}

class NetworkImpl {
public:
    void send(const std::string& peer_id, const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_clients.count(peer_id)) {
            int sock = m_clients[peer_id];
            std::string encrypted_msg = encrypt_message(msg);
            nativeLog("Network: Sending " + std::to_string(encrypted_msg.size()) + " bytes to " + peer_id);
            ssize_t bytes_sent = ::send(sock, encrypted_msg.c_str(), encrypted_msg.size(), 0);
            if (bytes_sent < 0) {
                nativeLog("Network Error: Failed to send message to " + peer_id + " (" + strerror(errno) + ")");
            }
        } else {
            nativeLog("Network Error: Could not send message. No connection to " + peer_id);
        }
    }

private:
    void on_data(const std::string& peer_id, const char* data, int len) {
        nativeLog("Network: Received " + std::to_string(len) + " encrypted bytes from " + peer_id);
        std::string decrypted_data = decrypt_message(std::string(data, len));
        
        if (m_data_cb && !decrypted_data.empty()) {
            m_data_cb(peer_id, decrypted_data);
        } else if (decrypted_data.empty()) {
            nativeLog("Network Error: Decryption failed for message from " + peer_id);
        }
    }

public:
    NetworkImpl() : m_running(false), m_listen_sock(-1) {}
    ~NetworkImpl() { stop(); }
    void setCallbacks(DataCb dcb, DisconnectCb discb) { m_data_cb = dcb; m_disconnect_cb = discb; }
    bool startServer(int port) {
        if (m_running) return false;
        m_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (m_listen_sock < 0) return false;
        int on = 1;
        setsockopt(m_listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        fcntl(m_listen_sock, F_SETFL, O_NONBLOCK);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (bind(m_listen_sock, (sockaddr*)&addr, sizeof(addr)) < 0) { close(m_listen_sock); return false; }
        if (listen(m_listen_sock, 5) < 0) { close(m_listen_sock); return false; }
        m_running = true;
        m_listen_thread = std::thread([this]() {
            while (m_running) {
                sockaddr_in client_addr{};
                socklen_t len = sizeof(client_addr);
                int client_sock = accept(m_listen_sock, (sockaddr*)&client_addr, &len);
                if (client_sock >= 0) {
                    char client_ip[64];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                    int client_port = ntohs(client_addr.sin_port);
                    // --- THIS IS THE FIX ---
                    // Correctly use the client_ip variable.
                    std::string peer_id = std::string(client_ip) + ":" + std::to_string(client_port);
                    fcntl(client_sock, F_SETFL, O_NONBLOCK);
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_clients[peer_id] = client_sock;
                    m_client_threads.emplace_back([this, client_sock, peer_id]() { handle_client(client_sock, peer_id); });
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
        return true;
    }
    bool connect(const std::string& ip, int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        if (::connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return false; }
        fcntl(sock, F_SETFL, O_NONBLOCK);
        std::string peer_id = ip + ":" + std::to_string(port);
        std::lock_guard<std::mutex> lock(m_mutex);
        m_clients[peer_id] = sock;
        m_client_threads.emplace_back([this, sock, peer_id]() { handle_client(sock, peer_id); });
        return true;
    }
    void stop() {
        m_running = false;
        if (m_listen_sock >= 0) { shutdown(m_listen_sock, SHUT_RDWR); close(m_listen_sock); m_listen_sock = -1; }
        if (m_listen_thread.joinable()) m_listen_thread.join();
        std::lock_guard<std::mutex> lock(m_mutex);
        for(auto const& [key, val] : m_clients) { shutdown(val, SHUT_RDWR); close(val); }
        m_clients.clear();
        for (auto& t : m_client_threads) { if (t.joinable()) t.join(); }
        m_client_threads.clear();
    }
private:
    void handle_client(int sock, std::string peer_id) {
        char buf[1024];
        while (m_running) {
            ssize_t n = recv(sock, buf, sizeof(buf), 0);
            if (n > 0) {
                on_data(peer_id, buf, n);
            } else if (n == 0 || (n < 0 && errno != EAGAIN)) {
                if (m_disconnect_cb) m_disconnect_cb(peer_id);
                std::lock_guard<std::mutex> lock(m_mutex);
                m_clients.erase(peer_id);
                close(sock);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    std::atomic<bool> m_running;
    int m_listen_sock;
    std::thread m_listen_thread;
    std::map<std::string, int> m_clients;
    std::vector<std::thread> m_client_threads;
    std::mutex m_mutex;
    DataCb m_data_cb;
    DisconnectCb m_disconnect_cb;
};

Network::Network() : m_impl(new NetworkImpl()) {}
Network::~Network() = default;
void Network::setCallbacks(DataCb dcb, DisconnectCb discb) { m_impl->setCallbacks(dcb, discb); }
bool Network::startServer(int p) { return m_impl->startServer(p); }
bool Network::connect(const std::string& ip, int p) { return m_impl->connect(ip, p); }
void Network::send(const std::string& pid, const std::string& m) { m_impl->send(pid, m); }
void Network::stop() { m_impl->stop(); }
