#include "nat_traversal_manager.h"
#include "../../../corep2p/core/include/logger.h"
#include "peer_reconnect_policy.h"
#include <algorithm>

NATTraversalManager::NATTraversalManager()
    : m_initialized(false) {
}

NATTraversalManager::~NATTraversalManager() {
    cleanup();
}

void NATTraversalManager::initialize() {
    if (!m_initialized) {
        m_initialized = true;
        LOG_INFO("NTM: NAT Traversal Manager initialized");
    }
}

void NATTraversalManager::initiateAsyncNATTraversal(const std::string& peer_id,
                                                   std::function<void(SessionEvent)> event_callback,
                                                   std::vector<std::future<void>>& background_futures,
                                                   std::mutex& background_futures_mutex,
                                                   std::atomic<bool>& stopping,
                                                   std::atomic<bool>& force_stop) {
    LOG_INFO("NTM: Initiating async NAT traversal for peer: " + peer_id);
    
    // Check if we're stopping before starting NAT traversal
    if (stopping || force_stop) {
        LOG_WARN("NTM: Ignoring NAT traversal for " + peer_id + " - session manager is stopping");
        return;
    }
    
    // Launch NAT traversal in a background thread and track it with a future
    auto future = std::async(std::launch::async, [this, peer_id, event_callback, &stopping, &force_stop]() {
        LOG_INFO("NTM: [DIAG] NAT traversal operation started for peer: " + peer_id);
        
        // Check stopping flag at the beginning of the operation
        if (stopping || force_stop) {
            LOG_WARN("NTM: NAT traversal cancelled for " + peer_id + " - session manager is stopping");
            return;
        }
        
        try {
            // Get the singleton instance of NATTraversal
            NATTraversal& nat = NATTraversal::getInstance();
            
            // Perform NAT traversal (this can take several seconds)
            // Check stopping flag periodically during the operation
            NATInfo nat_info = nat.detectNATType();
            
            // Check stopping flag before pushing result
            if (stopping || force_stop) {
                LOG_WARN("NTM: NAT traversal result discarded for " + peer_id + " - session manager is stopping");
                return;
            }
            
            // Push result back to the event queue
            NATTraversalCompleteEvent result_event;
            result_event.peerId = peer_id;
            result_event.success = !nat_info.external_ip.empty();
            result_event.external_ip = nat_info.external_ip;
            result_event.external_port = nat_info.external_port;
            result_event.error_message = nat_info.external_ip.empty() ? "NAT traversal failed" : "";
            
            event_callback(result_event);
        } catch (const std::exception& e) {
            // Check stopping flag before pushing result
            if (stopping || force_stop) {
                LOG_WARN("NTM: NAT traversal exception discarded for " + peer_id + " - session manager is stopping");
                return;
            }
            
            LOG_WARN("NTM: Exception in NAT traversal for peer " + peer_id + ": " + std::string(e.what()));
            
            // Push failure result back to the event queue
            NATTraversalCompleteEvent result_event;
            result_event.peerId = peer_id;
            result_event.success = false;
            result_event.error_message = "Exception: " + std::string(e.what());
            
            event_callback(result_event);
        }
        LOG_INFO("NTM: [DIAG] NAT traversal operation finished for peer: " + peer_id);
    });
    
    // Track the background operation for proper shutdown
    {
        std::lock_guard<std::mutex> lock(background_futures_mutex);
        background_futures.push_back(std::move(future));
    }
    LOG_INFO("NTM: NAT traversal operation tracked for peer: " + peer_id);
}

void NATTraversalManager::handleNATTraversalCompleteEvent(const NATTraversalCompleteEvent& event,
                                                     const std::string& comms_mode,
                                                     std::function<void()> peer_update_callback,
                                                     std::function<void(const std::string&, const std::string&)> retry_scheduling_callback,
                                                     std::function<Peer*(const std::string&)> peer_lookup_callback,
                                                     std::function<void(const std::string&, const std::string&, uint16_t)> connection_initiation_callback,
                                                     std::mutex& scheduled_events_mutex,
                                                     std::atomic<bool>& stopping,
                                                     std::atomic<bool>& force_stop) {
    LOG_INFO("NTM: NAT traversal complete for peer: " + event.peerId + 
             ", success: " + (event.success ? "true" : "false"));
    
    // Check if we're stopping before processing the result
    if (stopping || force_stop) {
        LOG_WARN("NTM: NAT traversal result discarded for " + event.peerId + " - session manager is stopping");
        return;
    }
    
    if (!event.success) {
        LOG_WARN("NTM: NAT traversal failed for peer " + event.peerId + ": " + event.error_message);
        // Handle NAT traversal failure - notify UI and possibly retry
        Peer* peer = peer_lookup_callback(event.peerId);
        if (peer) {
            // Peer state is now managed by the FSM
            // Notify peer update without directly modifying the connected field
            peer_update_callback();
            
            // Schedule a retry
            PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
            policy.on_connection_failure(event.peerId, comms_mode);
            
            // Check if we're forcing stop before scheduling retry
            if (force_stop) {
                LOG_WARN("NTM: Skipping retry scheduling for " + event.peerId + " - force stop is active");
                return;
            }
            
            auto next_strategy = policy.get_retry_strategy(event.peerId);
            if (next_strategy.should_retry && next_strategy.backoff_ms > 0) {
                retry_scheduling_callback(event.peerId, std::to_string(next_strategy.backoff_ms));
            }
        }
        return;
    }
    
    // NAT traversal succeeded, now initiate connection attempt
    Peer* peer = peer_lookup_callback(event.peerId);
    if (!peer) {
        LOG_WARN("NTM: Peer not found for NAT traversal result: " + event.peerId);
        return;
    }
    
    // Update peer with external address information
    peer->ip = event.external_ip;
    peer->port = event.external_port;
    peer->network_id = event.external_ip + ":" + std::to_string(event.external_port);
    
    LOG_INFO("NTM: Updated peer " + event.peerId + " with external address " + 
             event.external_ip + ":" + std::to_string(event.external_port));
    
    // Initiate connection attempt
    connection_initiation_callback(event.peerId, event.external_ip, event.external_port);
}

void NATTraversalManager::cleanup() {
    if (m_initialized) {
        m_initialized = false;
        LOG_INFO("NTM: NAT Traversal Manager cleaned up");
    }
}