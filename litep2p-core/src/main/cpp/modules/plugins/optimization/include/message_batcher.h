#ifndef MESSAGE_BATCHER_H
#define MESSAGE_BATCHER_H

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <mutex>
#include <chrono>
#include <functional>

// Message batching to reduce radio on-time
// Delays message send by Xms to allow multiple messages in one packet
// Can reduce radio on-time by 50-80% on typical traffic

struct PendingMessage {
    std::string peer_id;
    std::string message;
    std::chrono::steady_clock::time_point enqueued_at;
    bool is_high_priority;  // PING, PONG - send immediately
};

class MessageBatcher {
public:
    MessageBatcher(int batch_delay_ms = 50, int max_batch_size = 10);
    ~MessageBatcher();

    // Enqueue a message for batching
    // Returns: batch_id if message queued, or -1 if should send immediately
    // high_priority: true for PING/PONG/control (send immediately)
    int enqueue_message(const std::string& peer_id, 
                        const std::string& message,
                        bool high_priority = false);

    // Get messages ready to send (batch delay expired)
    std::vector<PendingMessage> get_ready_batch();

    // Manually flush pending messages for a peer
    std::vector<PendingMessage> flush_peer(const std::string& peer_id);

    // Flush all pending messages
    std::vector<PendingMessage> flush_all();

    // Get batching statistics
    struct Stats {
        int messages_batched = 0;      // Messages waiting in batch
        int batches_sent = 0;          // Completed batches
        int radio_savings_percent = 0; // Estimated radio on-time saved
    };
    Stats get_stats() const;

    // Set configuration
    void set_batch_delay_ms(int delay);
    void set_max_batch_size(int size);

private:
    std::vector<PendingMessage> m_pending_messages;
    mutable std::mutex m_mutex;  // mutable for const getter methods
    
    int m_batch_delay_ms;
    int m_max_batch_size;
    int m_batches_sent = 0;
    int m_total_messages_batched = 0;
};

#endif // MESSAGE_BATCHER_H
