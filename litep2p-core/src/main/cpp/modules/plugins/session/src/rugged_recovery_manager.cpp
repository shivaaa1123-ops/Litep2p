#include "rugged_recovery_manager.h"
#include "logger.h"
#include "wire_codec.h"
#include "message_types.h"

#include <sstream>
#include <iomanip>
#include <random>
#include <thread>
#include <algorithm>

namespace recovery {

// =============================================================================
// CONSTRUCTION / DESTRUCTION
// =============================================================================

RuggedRecoveryManager::RuggedRecoveryManager() = default;

RuggedRecoveryManager::~RuggedRecoveryManager() {
    shutdown();
}

void RuggedRecoveryManager::initialize(
    SendCallback send_direct,
    RelayCallback send_relay,
    RestartSocketCallback restart_socket,
    ReconnectPeerCallback reconnect_peer,
    GetPeerNetworkIdCallback get_network_id
) {
    if (m_initialized.load(std::memory_order_acquire)) {
        LOG_WARN("RuggedRecoveryManager: Already initialized");
        return;
    }
    
    m_send_direct = std::move(send_direct);
    m_send_relay = std::move(send_relay);
    m_restart_socket = std::move(restart_socket);
    m_reconnect_peer = std::move(reconnect_peer);
    m_get_network_id = std::move(get_network_id);
    
    // Initialize socket health
    m_socket_health.is_healthy.store(true, std::memory_order_release);
    m_socket_health.last_send_success_ms.store(steady_now_ms(), std::memory_order_release);
    m_socket_health.last_recv_success_ms.store(steady_now_ms(), std::memory_order_release);
    
    m_initialized.store(true, std::memory_order_release);
    LOG_INFO("RuggedRecoveryManager: Initialized with rugged recovery enabled");
}

void RuggedRecoveryManager::shutdown() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    m_shutting_down.store(true, std::memory_order_release);
    
    // Fail all pending messages
    {
        std::lock_guard<std::mutex> lock(m_messages_mutex);
        for (auto& kv : m_pending_messages) {
            if (kv.second.on_complete) {
                kv.second.on_complete(DeliveryStatus::FAILED_PEER_GONE, kv.second.current_path);
            }
        }
        m_pending_messages.clear();
    }
    
    m_initialized.store(false, std::memory_order_release);
    LOG_INFO("RuggedRecoveryManager: Shutdown complete");
}

// =============================================================================
// RELIABLE MESSAGE DELIVERY
// =============================================================================

std::string RuggedRecoveryManager::generate_message_id() {
    static std::atomic<uint64_t> counter{0};
    uint64_t id = counter.fetch_add(1, std::memory_order_relaxed);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    uint32_t random_part = dist(gen);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << id
       << std::setw(8) << random_part;
    return ss.str();
}

std::string RuggedRecoveryManager::send_reliable(
    const std::string& peer_id,
    const std::string& message,
    bool require_ack,
    std::function<void(DeliveryStatus, DeliveryPath)> on_complete
) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        LOG_WARN("RuggedRecoveryManager: Not initialized, cannot send reliable message");
        if (on_complete) {
            on_complete(DeliveryStatus::FAILED_PEER_GONE, DeliveryPath::DIRECT_UDP);
        }
        return "";
    }
    
    std::string message_id = generate_message_id();
    
    MessageDeliveryRecord record;
    record.message_id = message_id;
    record.peer_id = peer_id;
    record.message_content = message;
    record.first_sent = std::chrono::steady_clock::now();
    record.last_attempt = record.first_sent;
    record.attempt_count = 1;
    record.current_timeout_ms = MESSAGE_ACK_TIMEOUT_MS;
    record.current_path = get_best_path(peer_id);
    record.status = DeliveryStatus::PENDING;
    record.requires_ack = require_ack;
    record.on_complete = std::move(on_complete);
    
    // Wrap message with reliability header if ACK required
    std::string wrapped_message;
    if (require_ack) {
        // Format: RELIABLE_MSG|<message_id>|<payload>
        wrapped_message = "RELIABLE_MSG|" + message_id + "|" + message;
    } else {
        wrapped_message = message;
    }
    record.message_content = wrapped_message;
    
    // Add to pending
    if (require_ack) {
        std::lock_guard<std::mutex> lock(m_messages_mutex);
        m_pending_messages[message_id] = record;
    }
    
    // Send via appropriate path
    send_via_path(record);
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats.messages_sent_total++;
    }
    
    LOG_INFO("RuggedRecoveryManager: Sent reliable message " + message_id + 
             " to peer " + peer_id + " via " + 
             (record.current_path == DeliveryPath::SIGNALING_RELAY ? "relay" : "direct"));
    
    return message_id;
}

void RuggedRecoveryManager::send_via_path(MessageDeliveryRecord& record) {
    std::string network_id;
    
    switch (record.current_path) {
        case DeliveryPath::DIRECT_UDP:
        case DeliveryPath::HOLE_PUNCH:
            if (m_get_network_id) {
                network_id = m_get_network_id(record.peer_id);
            }
            if (!network_id.empty() && m_send_direct) {
                m_send_direct(network_id, record.message_content);
            } else {
                // Fall through to relay - just update path and send via relay
                record.current_path = DeliveryPath::SIGNALING_RELAY;
                if (m_send_relay) {
                    m_send_relay(record.peer_id, record.message_content);
                }
            }
            break;
            
        case DeliveryPath::SIGNALING_RELAY:
            if (m_send_relay) {
                m_send_relay(record.peer_id, record.message_content);
            }
            break;
            
        case DeliveryPath::TCP_FALLBACK:
            // TODO: Implement TCP fallback
            LOG_WARN("RuggedRecoveryManager: TCP fallback not yet implemented");
            break;
    }
}

bool RuggedRecoveryManager::process_ack(const std::string& message_id) {
    std::lock_guard<std::mutex> lock(m_messages_mutex);
    
    auto it = m_pending_messages.find(message_id);
    if (it == m_pending_messages.end()) {
        return false;
    }
    
    MessageDeliveryRecord& record = it->second;
    record.status = (record.current_path == DeliveryPath::SIGNALING_RELAY) 
                    ? DeliveryStatus::RELAYED 
                    : DeliveryStatus::DELIVERED;
    
    // Update peer stats
    {
        std::lock_guard<std::mutex> peer_lock(m_peers_mutex);
        auto& peer_state = get_or_create_peer_state(record.peer_id);
        peer_state.record_success(record.current_path == DeliveryPath::SIGNALING_RELAY);
    }
    
    // Callback
    if (record.on_complete) {
        record.on_complete(record.status, record.current_path);
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
        m_stats.messages_delivered_total++;
        if (record.current_path == DeliveryPath::SIGNALING_RELAY) {
            m_stats.messages_relayed_total++;
        }
    }
    
    LOG_INFO("RuggedRecoveryManager: ACK received for message " + message_id + 
             " after " + std::to_string(record.attempt_count) + " attempts");
    
    m_pending_messages.erase(it);
    return true;
}

std::string RuggedRecoveryManager::process_incoming_reliable(
    const std::string& peer_id,
    const std::string& wrapped_message
) {
    // Check if this is a reliable message
    if (wrapped_message.rfind("RELIABLE_MSG|", 0) != 0) {
        return wrapped_message;  // Not a reliable message, return as-is
    }
    
    // Parse: RELIABLE_MSG|<message_id>|<payload>
    size_t first_pipe = wrapped_message.find('|', 13);
    if (first_pipe == std::string::npos) {
        LOG_WARN("RuggedRecoveryManager: Invalid reliable message format");
        return "";
    }
    
    std::string message_id = wrapped_message.substr(13, first_pipe - 13);
    std::string payload = wrapped_message.substr(first_pipe + 1);
    
    // Deduplicate
    {
        std::lock_guard<std::mutex> lock(m_messages_mutex);
        if (m_seen_message_ids.count(message_id)) {
            LOG_INFO("RuggedRecoveryManager: Duplicate message " + message_id + " - sending ACK only");
            send_ack(peer_id, message_id);
            return "";  // Already processed
        }
        m_seen_message_ids.insert(message_id);
        
        // Limit seen set size (LRU would be better, but simple cap works)
        if (m_seen_message_ids.size() > 10000) {
            m_seen_message_ids.clear();  // Simple reset (rare case)
        }
    }
    
    // Send ACK
    send_ack(peer_id, message_id);
    
    // Update peer receive timestamp
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto& peer_state = get_or_create_peer_state(peer_id);
        peer_state.last_successful_recv = std::chrono::steady_clock::now();
    }
    
    return payload;
}

void RuggedRecoveryManager::send_ack(const std::string& peer_id, const std::string& message_id) {
    // Format: RELIABLE_ACK|<message_id>
    std::string ack = "RELIABLE_ACK|" + message_id;
    
    // Use best available path for ACK (typically relay if that's how we received the message)
    std::string network_id;
    if (m_get_network_id) {
        network_id = m_get_network_id(peer_id);
    }
    
    if (!network_id.empty() && m_send_direct) {
        m_send_direct(network_id, ack);
    } else if (m_send_relay) {
        m_send_relay(peer_id, ack);
    }
    
    LOG_INFO("RuggedRecoveryManager: Sent ACK for message " + message_id + " to peer " + peer_id);
}

// =============================================================================
// SOCKET RECOVERY
// =============================================================================

void RuggedRecoveryManager::handle_network_change(bool is_wifi, bool is_available) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    
    // Prevent concurrent recovery
    bool expected = false;
    if (!m_network_recovery_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        LOG_INFO("RuggedRecoveryManager: Network recovery already in progress");
        return;
    }
    
    m_last_network_change_ms.store(steady_now_ms(), std::memory_order_release);
    
    LOG_INFO("RuggedRecoveryManager: Network change detected - WiFi=" + 
             std::string(is_wifi ? "true" : "false") + 
             ", Available=" + std::string(is_available ? "true" : "false"));
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats.network_changes_handled++;
    }
    
    if (!is_available) {
        // Network gone - mark socket unhealthy
        m_socket_health.is_healthy.store(false, std::memory_order_release);
        m_network_recovery_in_progress.store(false, std::memory_order_release);
        return;
    }
    
    // Network available - start recovery sequence
    // Step 1: Wait for interface to stabilize
    std::this_thread::sleep_for(std::chrono::milliseconds(POST_NETWORK_CHANGE_SETTLE_MS));
    
    // Step 2: Restart socket with verification
    bool socket_ok = restart_socket_verified();
    if (!socket_ok) {
        LOG_WARN("RuggedRecoveryManager: Socket restart failed after network change");
    }
    
    // Step 3: Reset all peer recovery states (allow immediate reconnects)
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        for (auto& kv : m_peer_states) {
            kv.second.direct_failures = 0;
            kv.second.prefer_relay = false;
        }
    }
    
    // Step 4: Re-send all pending reliable messages via relay (guaranteed path)
    {
        std::lock_guard<std::mutex> lock(m_messages_mutex);
        for (auto& kv : m_pending_messages) {
            MessageDeliveryRecord& record = kv.second;
            if (record.status == DeliveryStatus::PENDING) {
                record.current_path = DeliveryPath::SIGNALING_RELAY;
                record.last_attempt = std::chrono::steady_clock::now();
                send_via_path(record);
                LOG_INFO("RuggedRecoveryManager: Re-sent pending message " + record.message_id + " via relay");
            }
        }
    }
    
    m_network_recovery_in_progress.store(false, std::memory_order_release);
    LOG_INFO("RuggedRecoveryManager: Network change recovery complete");
}

bool RuggedRecoveryManager::restart_socket_verified() {
    if (!m_restart_socket) {
        LOG_WARN("RuggedRecoveryManager: No socket restart callback configured");
        return false;
    }
    
    LOG_INFO("RuggedRecoveryManager: Attempting verified socket restart");
    
    for (int attempt = 0; attempt < SOCKET_RESTART_MAX_RETRIES; attempt++) {
        // Attempt restart
        bool restart_ok = m_restart_socket();
        
        if (!restart_ok) {
            LOG_WARN("RuggedRecoveryManager: Socket restart attempt " + 
                     std::to_string(attempt + 1) + "/" + 
                     std::to_string(SOCKET_RESTART_MAX_RETRIES) + " failed");
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
            continue;
        }
        
        // Verify socket is working by waiting for any successful operation
        int64_t start_ms = steady_now_ms();
        while (steady_now_ms() - start_ms < SOCKET_RESTART_VERIFY_TIMEOUT_MS) {
            std::this_thread::sleep_for(std::chrono::milliseconds(SOCKET_RESTART_VERIFY_INTERVAL_MS));
            
            // Check if we've had any successful sends/receives since restart
            int64_t restart_time = m_socket_health.last_restart_ms.load(std::memory_order_acquire);
            int64_t last_send = m_socket_health.last_send_success_ms.load(std::memory_order_acquire);
            int64_t last_recv = m_socket_health.last_recv_success_ms.load(std::memory_order_acquire);
            
            if (last_send > restart_time || last_recv > restart_time) {
                // Socket verified working
                m_socket_health.is_healthy.store(true, std::memory_order_release);
                m_socket_health.consecutive_send_failures.store(0, std::memory_order_release);
                
                {
                    std::lock_guard<std::mutex> lock(m_stats_mutex);
                    m_stats.socket_restarts_total++;
                }
                
                LOG_INFO("RuggedRecoveryManager: Socket restart verified successfully");
                return true;
            }
        }
        
        LOG_WARN("RuggedRecoveryManager: Socket restart verification timeout (attempt " + 
                 std::to_string(attempt + 1) + ")");
    }
    
    // All attempts failed
    m_socket_health.is_healthy.store(false, std::memory_order_release);
    
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats.socket_restart_failures++;
    }
    
    LOG_WARN("RuggedRecoveryManager: All socket restart attempts failed");
    return false;
}

void RuggedRecoveryManager::report_socket_send(bool success) {
    if (success) {
        m_socket_health.last_send_success_ms.store(steady_now_ms(), std::memory_order_release);
        m_socket_health.consecutive_send_failures.store(0, std::memory_order_release);
        m_socket_health.is_healthy.store(true, std::memory_order_release);
    } else {
        int failures = m_socket_health.consecutive_send_failures.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (failures >= 3) {
            m_socket_health.is_healthy.store(false, std::memory_order_release);
            LOG_WARN("RuggedRecoveryManager: Socket marked unhealthy after " + 
                     std::to_string(failures) + " consecutive send failures");
        }
    }
}

void RuggedRecoveryManager::report_socket_recv(bool success) {
    if (success) {
        m_socket_health.last_recv_success_ms.store(steady_now_ms(), std::memory_order_release);
        m_socket_health.is_healthy.store(true, std::memory_order_release);
    }
}

// =============================================================================
// PEER RECOVERY
// =============================================================================

void RuggedRecoveryManager::schedule_peer_recovery(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    m_recovery_queue.push(peer_id);
    
    {
        std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
        m_stats.peer_recoveries_triggered++;
    }
    
    LOG_INFO("RuggedRecoveryManager: Scheduled recovery for peer " + peer_id);
}

DeliveryPath RuggedRecoveryManager::get_best_path(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    
    auto it = m_peer_states.find(peer_id);
    if (it != m_peer_states.end()) {
        if (it->second.prefer_relay) {
            return DeliveryPath::SIGNALING_RELAY;
        }
        if (it->second.direct_failures >= PATH_ESCALATION_FAILURE_THRESHOLD) {
            return DeliveryPath::HOLE_PUNCH;
        }
    }
    
    // Check socket health
    if (!m_socket_health.is_healthy.load(std::memory_order_acquire)) {
        return DeliveryPath::SIGNALING_RELAY;
    }
    
    return DeliveryPath::DIRECT_UDP;
}

void RuggedRecoveryManager::tick() {
    if (!m_initialized.load(std::memory_order_acquire) ||
        m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    
    process_pending_retries();
    process_recovery_queue();
}

void RuggedRecoveryManager::process_pending_retries() {
    std::vector<MessageDeliveryRecord> records_to_retry;
    std::vector<std::string> records_to_remove;
    
    auto now_time = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(m_messages_mutex);
        
        for (auto& kv : m_pending_messages) {
            MessageDeliveryRecord& record = kv.second;
            
            if (record.status != DeliveryStatus::PENDING) {
                continue;
            }
            
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now_time - record.last_attempt
            ).count();
            
            if (elapsed_ms < record.current_timeout_ms) {
                continue;  // Not yet timed out
            }
            
            // Timeout - need to retry or escalate
            if (record.attempt_count >= MESSAGE_ACK_MAX_RETRIES) {
                // All retries exhausted
                record.status = DeliveryStatus::FAILED_TIMEOUT;
                
                if (record.on_complete) {
                    record.on_complete(record.status, record.current_path);
                }
                
                // Update peer stats
                {
                    std::lock_guard<std::mutex> peer_lock(m_peers_mutex);
                    auto& peer_state = get_or_create_peer_state(record.peer_id);
                    peer_state.record_direct_failure();
                }
                
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.messages_failed_total++;
                }
                
                records_to_remove.push_back(record.message_id);
                LOG_WARN("RuggedRecoveryManager: Message " + record.message_id + 
                         " failed after " + std::to_string(record.attempt_count) + " attempts");
            } else {
                // Prepare retry with escalation
                escalate_path(record);
                record.attempt_count++;
                record.current_timeout_ms = std::min(
                    static_cast<int>(record.current_timeout_ms * MESSAGE_ACK_BACKOFF_MULTIPLIER),
                    MESSAGE_ACK_MAX_TIMEOUT_MS
                );
                record.last_attempt = std::chrono::steady_clock::now();
                
                records_to_retry.push_back(record);
            }
        }
        
        // Remove failed records
        for (const auto& id : records_to_remove) {
            m_pending_messages.erase(id);
        }
    }
    
    // Send retries (outside lock)
    for (auto& record : records_to_retry) {
        LOG_INFO("RuggedRecoveryManager: Retrying message " + record.message_id + 
                 " (attempt " + std::to_string(record.attempt_count) + 
                 ", path=" + std::to_string(static_cast<int>(record.current_path)) + 
                 ", timeout=" + std::to_string(record.current_timeout_ms) + "ms)");
        send_via_path(record);
        
        // Update the record in the map
        {
            std::lock_guard<std::mutex> lock(m_messages_mutex);
            auto it = m_pending_messages.find(record.message_id);
            if (it != m_pending_messages.end()) {
                it->second = record;
            }
        }
    }
}

void RuggedRecoveryManager::escalate_path(MessageDeliveryRecord& record) {
    DeliveryPath old_path = record.current_path;
    
    switch (record.current_path) {
        case DeliveryPath::DIRECT_UDP:
            if (record.attempt_count >= PATH_ESCALATION_FAILURE_THRESHOLD) {
                record.current_path = DeliveryPath::HOLE_PUNCH;
            }
            break;
            
        case DeliveryPath::HOLE_PUNCH:
            if (record.attempt_count >= PATH_ESCALATION_FAILURE_THRESHOLD + 1) {
                record.current_path = DeliveryPath::SIGNALING_RELAY;
            }
            break;
            
        case DeliveryPath::SIGNALING_RELAY:
            // Already on relay - no further escalation
            break;
            
        case DeliveryPath::TCP_FALLBACK:
            // Already on TCP - no further escalation
            break;
    }
    
    if (record.current_path != old_path) {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats.path_escalations_total++;
        LOG_INFO("RuggedRecoveryManager: Escalated path for message " + record.message_id + 
                 " from " + std::to_string(static_cast<int>(old_path)) + 
                 " to " + std::to_string(static_cast<int>(record.current_path)));
    }
}

void RuggedRecoveryManager::process_recovery_queue() {
    if (!m_reconnect_peer) {
        return;
    }
    
    std::vector<std::string> peers_to_recover;
    
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        int count = 0;
        while (!m_recovery_queue.empty() && count < PARALLEL_RECONNECT_LIMIT) {
            peers_to_recover.push_back(m_recovery_queue.front());
            m_recovery_queue.pop();
            count++;
        }
    }
    
    for (const auto& peer_id : peers_to_recover) {
        LOG_INFO("RuggedRecoveryManager: Processing recovery for peer " + peer_id);
        m_reconnect_peer(peer_id);
        
        // Small delay between reconnects to avoid storming
        std::this_thread::sleep_for(std::chrono::milliseconds(RECONNECT_BURST_INTERVAL_MS));
    }
}

PeerRecoveryState& RuggedRecoveryManager::get_or_create_peer_state(const std::string& peer_id) {
    auto it = m_peer_states.find(peer_id);
    if (it == m_peer_states.end()) {
        PeerRecoveryState state;
        state.peer_id = peer_id;
        state.last_recovery_attempt = std::chrono::steady_clock::now();
        m_peer_states[peer_id] = state;
        return m_peer_states[peer_id];
    }
    return it->second;
}

// =============================================================================
// STATISTICS & DEBUGGING
// =============================================================================

RuggedRecoveryManager::Stats RuggedRecoveryManager::get_stats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    return m_stats;
}

std::string RuggedRecoveryManager::get_status_json() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    
    std::stringstream ss;
    ss << "{"
       << "\"messages_sent_total\":" << m_stats.messages_sent_total << ","
       << "\"messages_delivered_total\":" << m_stats.messages_delivered_total << ","
       << "\"messages_failed_total\":" << m_stats.messages_failed_total << ","
       << "\"messages_relayed_total\":" << m_stats.messages_relayed_total << ","
       << "\"socket_restarts_total\":" << m_stats.socket_restarts_total << ","
       << "\"socket_restart_failures\":" << m_stats.socket_restart_failures << ","
       << "\"path_escalations_total\":" << m_stats.path_escalations_total << ","
       << "\"network_changes_handled\":" << m_stats.network_changes_handled << ","
       << "\"peer_recoveries_triggered\":" << m_stats.peer_recoveries_triggered << ","
       << "\"socket_healthy\":" << (m_socket_health.is_healthy.load() ? "true" : "false") << ","
       << "\"pending_messages\":" << m_pending_messages.size()
       << "}";
    
    return ss.str();
}

int64_t RuggedRecoveryManager::steady_now_ms() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

} // namespace recovery
