#ifndef MULTI_SOCKET_MANAGER_H
#define MULTI_SOCKET_MANAGER_H

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <thread>

/**
 * Multi-socket connection manager for extreme scale (50,000+ peers)
 * Uses socket striping to parallelize I/O across multiple sockets
 * Each socket handles subset of peers, avoiding single socket bottleneck
 */
class MultiSocketManager {
public:
    using OnDataCallback = std::function<void(const std::string&, const std::string&)>;
    using OnDisconnectCallback = std::function<void(const std::string&)>;

    struct Config {
        int num_sockets = 4;
        int peers_per_socket = 5000;
        int socket_buffer_size = 65536;
        bool enable_zero_copy = false;
    };

    explicit MultiSocketManager(const Config& config);
    ~MultiSocketManager();

    bool startServer(int base_port, OnDataCallback on_data, OnDisconnectCallback on_disconnect);
    void stop();

    // Add peer to appropriate socket based on hash
    bool add_peer(const std::string& peer_id, const std::string& ip, int port);

    // Remove peer
    bool remove_peer(const std::string& peer_id);

    // Send message (automatically routes to correct socket)
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);

    // Send batch across multiple sockets
    void sendBatchToMultiplePeers(const std::vector<std::pair<std::string, std::string>>& messages);

    // Get statistics
    struct SocketStats {
        int socket_id = 0;
        int peer_count = 0;
        long messages_sent = 0;
        long bytes_sent = 0;
        long messages_received = 0;
        long bytes_received = 0;
    };
    std::vector<SocketStats> get_stats() const;

    // Reconfigure socket count
    void reconfigure(const Config& config);

private:
    struct SocketHandler {
        int socket_id = 0;
        int socket_fd = -1;
        int listen_port = 0;
        std::vector<std::string> peers;  // Peers assigned to this socket
        long messages_sent = 0;
        long bytes_sent = 0;
        long messages_received = 0;
        long bytes_received = 0;
    };

    int get_socket_id_for_peer(const std::string& peer_id) const;
    bool create_socket_handler(int socket_id, int base_port);
    void cleanup_socket(int socket_id);

    Config m_config;
    mutable std::mutex m_mutex;
    std::vector<std::shared_ptr<SocketHandler>> m_sockets;
    std::map<std::string, int> m_peer_to_socket;  // peer_id -> socket_id
    
    OnDataCallback m_on_data_cb;
    OnDisconnectCallback m_on_disconnect_cb;
    
    bool m_running = false;
    std::vector<std::shared_ptr<std::thread>> m_listener_threads;
};

#endif // MULTI_SOCKET_MANAGER_H
