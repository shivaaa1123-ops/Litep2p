#ifndef TIER_MANAGER_H
#define TIER_MANAGER_H

#include "peer_tier_manager.h"
#include "peer.h"
#include <string>
#include <memory>
#include <mutex>

class TierManager {
public:
    TierManager();
    ~TierManager();
    
    // Initialize the tier manager
    void initialize();
    
    // Get peer tier for a given peer ID
    PeerTier getPeerTier(const std::string& peer_id);
    
    // Record latency for a peer
    void recordLatency(const std::string& peer_id, int latency_ms);
    
    // Handle peer tier assignment during discovery
    PeerTier handlePeerDiscoveryTierAssignment(const std::string& peer_id);
    
    // Cleanup resources
    void cleanup();

private:
    std::unique_ptr<PeerTierManager> m_peer_tier_manager;
    bool m_initialized;
};

#endif // TIER_MANAGER_H