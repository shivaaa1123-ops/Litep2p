#include "tier_manager.h"
#include "../../../corep2p/core/include/logger.h"

TierManager::TierManager()
    : m_initialized(false) {
}

TierManager::~TierManager() {
    cleanup();
}

void TierManager::initialize() {
    if (!m_initialized) {
        m_peer_tier_manager = std::make_unique<PeerTierManager>();
        m_initialized = true;
        LOG_INFO("TM: Tier Manager initialized");
    }
}

PeerTier TierManager::getPeerTier(const std::string& peer_id) {
    if (m_peer_tier_manager) {
        return m_peer_tier_manager->get_peer_tier(peer_id);
    }
    return PeerTier::TIER_1; // Default to TIER_1 if not initialized
}

void TierManager::recordLatency(const std::string& peer_id, int latency_ms) {
    if (m_peer_tier_manager) {
        m_peer_tier_manager->record_latency(peer_id, latency_ms);
    }
}

PeerTier TierManager::handlePeerDiscoveryTierAssignment(const std::string& peer_id) {
    if (m_peer_tier_manager) {
        return m_peer_tier_manager->get_peer_tier(peer_id);
    }
    return PeerTier::TIER_1; // Default to TIER_1 if not initialized
}

void TierManager::cleanup() {
    if (m_initialized) {
        m_peer_tier_manager.reset();
        m_initialized = false;
        LOG_INFO("TM: Tier Manager cleaned up");
    }
}