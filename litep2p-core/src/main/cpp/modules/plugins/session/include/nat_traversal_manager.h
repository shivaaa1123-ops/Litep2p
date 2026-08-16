#ifndef NAT_TRAVERSAL_MANAGER_H
#define NAT_TRAVERSAL_MANAGER_H

#include "nat_traversal.h"
#include "session_events.h"
#include "peer.h"
#include <string>
#include <memory>
#include <future>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <functional>

class NATTraversalManager {
public:
    NATTraversalManager();
    ~NATTraversalManager();
    
    // Initialize the NAT traversal manager
    void initialize();
    
    // Initiate asynchronous NAT traversal for a peer
    void initiateAsyncNATTraversal(const std::string& peer_id, 
                                   std::function<void(SessionEvent)> event_callback,
                                   std::vector<std::future<void>>& background_futures,
                                   std::mutex& background_futures_mutex,
                                   std::atomic<bool>& stopping,
                                   std::atomic<bool>& force_stop);
    
    // Handle NAT traversal complete event
    void handleNATTraversalCompleteEvent(const NATTraversalCompleteEvent& event,
                                         const std::string& comms_mode,
                                         std::function<void()> peer_update_callback,
                                         std::function<void(const std::string&, const std::string&)> retry_scheduling_callback,
                                         std::function<Peer*(const std::string&)> peer_lookup_callback,
                                         std::function<void(const std::string&, const std::string&, uint16_t)> connection_initiation_callback,
                                         std::mutex& scheduled_events_mutex,
                                         std::atomic<bool>& stopping,
                                         std::atomic<bool>& force_stop);
    
    // Cleanup resources
    void cleanup();

private:
    bool m_initialized;
};

#endif // NAT_TRAVERSAL_MANAGER_H