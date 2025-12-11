#include "message_batcher.h"
#include "logger.h"

MessageBatcher::MessageBatcher(int batch_delay_ms, int max_batch_size)
    : m_batch_delay_ms(batch_delay_ms),
      m_max_batch_size(max_batch_size) {
    nativeLog("MessageBatcher: Initialized with " + std::to_string(batch_delay_ms) + 
              "ms delay, max " + std::to_string(max_batch_size) + " messages/batch");
}

MessageBatcher::~MessageBatcher() = default;

int MessageBatcher::enqueue_message(const std::string& peer_id,
                                     const std::string& message,
                                     bool high_priority) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Control messages (PING, PONG) send immediately
    if (high_priority) {
        return -1;  // Signal to send immediately
    }
    
    // Batch is full - need to flush first
    if (m_pending_messages.size() >= m_max_batch_size) {
        return -1;  // Signal to send immediately
    }
    
    PendingMessage pending;
    pending.peer_id = peer_id;
    pending.message = message;
    pending.enqueued_at = std::chrono::steady_clock::now();
    pending.is_high_priority = false;
    
    m_pending_messages.push_back(pending);
    m_total_messages_batched++;
    
    int batch_id = m_pending_messages.size() - 1;
    nativeLog("MessageBatcher: Enqueued message #" + std::to_string(batch_id) + 
              " for " + peer_id + " (batch size: " + std::to_string(m_pending_messages.size()) + ")");
    
    return batch_id;
}

std::vector<PendingMessage> MessageBatcher::get_ready_batch() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<PendingMessage> ready;
    
    if (m_pending_messages.empty()) {
        return ready;
    }
    
    auto now = std::chrono::steady_clock::now();
    
    // Check if batch delay has elapsed
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_pending_messages[0].enqueued_at
    ).count();
    
    if (elapsed_ms < m_batch_delay_ms && m_pending_messages.size() < m_max_batch_size) {
        // Not ready yet, unless we're at max capacity
        return ready;
    }
    
    // Batch is ready!
    ready = std::move(m_pending_messages);
    m_pending_messages.clear();
    m_batches_sent++;
    
    nativeLog("MessageBatcher: Sending batch of " + std::to_string(ready.size()) + 
              " messages (delay: " + std::to_string(elapsed_ms) + "ms)");
    
    return ready;
}

std::vector<PendingMessage> MessageBatcher::flush_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<PendingMessage> flushed;
    
    auto it = m_pending_messages.begin();
    while (it != m_pending_messages.end()) {
        if (it->peer_id == peer_id) {
            flushed.push_back(*it);
            it = m_pending_messages.erase(it);
        } else {
            ++it;
        }
    }
    
    if (!flushed.empty()) {
        nativeLog("MessageBatcher: Flushed " + std::to_string(flushed.size()) + 
                  " messages for peer " + peer_id);
    }
    
    return flushed;
}

std::vector<PendingMessage> MessageBatcher::flush_all() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto all = std::move(m_pending_messages);
    m_pending_messages.clear();
    
    if (!all.empty()) {
        nativeLog("MessageBatcher: Flushed all " + std::to_string(all.size()) + " pending messages");
    }
    
    return all;
}

MessageBatcher::Stats MessageBatcher::get_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Stats stats;
    stats.messages_batched = m_pending_messages.size();
    stats.batches_sent = m_batches_sent;
    
    // Estimate: each batch saves ~1 radio on-time
    // Typical: 50-80% savings with batching
    if (m_total_messages_batched > 0) {
        int avg_batch_size = m_total_messages_batched / (m_batches_sent + 1);
        stats.radio_savings_percent = std::min(80, (avg_batch_size - 1) * 10);
    }
    
    return stats;
}

void MessageBatcher::set_batch_delay_ms(int delay) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_batch_delay_ms = delay;
    nativeLog("MessageBatcher: Updated batch delay to " + std::to_string(delay) + "ms");
}

void MessageBatcher::set_max_batch_size(int size) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_max_batch_size = size;
    nativeLog("MessageBatcher: Updated max batch size to " + std::to_string(size));
}
