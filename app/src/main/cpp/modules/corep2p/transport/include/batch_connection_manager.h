#ifndef BATCH_CONNECTION_MANAGER_H
#define BATCH_CONNECTION_MANAGER_H

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>
#include <unordered_map>
#include <mutex>
#include <thread>

/**
 * Connection batching for UDP mode
 * Reduces socket overhead by reusing connections
 * Each batch can handle multiple peers (fan-out)
 * Optimized for 10,000+ concurrent peers
 */
class BatchConnectionManager {
public:
    struct BatchConfig {
        int max_peers_per_batch = 100;
        int batch_timeout_sec = 60;
        int max_batches = 100;
        bool enable_compression = false;
    };

    using OnDataCallback = std::function<void(const std::string&, const std::string&)>;
    using OnDisconnectCallback = std::function<void(const std::string&)>;

    explicit BatchConnectionManager(const BatchConfig& config);
    ~BatchConnectionManager();

    // Start batch server
    bool startServer(int port, OnDataCallback on_data, OnDisconnectCallback on_disconnect);
    void stop();

    // Add peer to a batch
    bool add_peer_to_batch(const std::string& peer_id, const std::string& ip, int port);

    // Remove peer from batch
    bool remove_peer_from_batch(const std::string& peer_id);

    // Send message to peer
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);

    // Send batch of messages
    void sendBatch(const std::vector<std::pair<std::string, std::string>>& messages);

    // Get batch statistics
    struct Stats {
        int active_batches = 0;
        int total_peers = 0;
        int messages_sent = 0;
        int bytes_sent = 0;
        float avg_batch_utilization = 0.0f;
    };
    Stats get_stats() const;

    // Reconfigure batch parameters
    void reconfigure(const BatchConfig& config);

private:
    struct Batch {
        std::string batch_id;
        std::vector<std::string> peer_ids;  // Peer IDs in this batch
        std::string primary_ip;             // Primary peer's IP for route
        int primary_port;
        std::chrono::steady_clock::time_point last_activity;
        int socket_fd;
    };

    void cleanup_expired_batches();
    std::string allocate_batch(const std::string& peer_id, const std::string& ip, int port);
    std::string get_batch_for_peer(const std::string& peer_id);
    void serialize_batch_message(const std::vector<std::pair<std::string, std::string>>& messages, 
                                  std::string& output);

    BatchConfig m_config;
    mutable std::mutex m_mutex;
    
    std::unordered_map<std::string, std::shared_ptr<Batch>> m_batches;        // batch_id -> Batch
    std::unordered_map<std::string, std::string> m_peer_to_batch;             // peer_id -> batch_id
    std::vector<std::shared_ptr<Batch>> m_batch_queue;  // For round-robin allocation
    
    int m_server_socket_fd = -1;
    int m_listen_port = 0;
    
    OnDataCallback m_on_data_cb;
    OnDisconnectCallback m_on_disconnect_cb;

    bool m_running = false;
    std::thread m_listener_thread;
    std::thread m_cleanup_thread;
};

#endif // BATCH_CONNECTION_MANAGER_H
