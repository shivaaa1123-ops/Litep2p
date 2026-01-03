#include "peer_tier_manager.h"
#include "logger.h"
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iostream>
#include <cmath>

// ==================== LATENCY STATS IMPLEMENTATION ====================

int LatencyStats::get_median() const {
    if (history_ms.empty()) return -1;
    
    auto sorted = std::vector<int>(history_ms.begin(), history_ms.end());
    std::sort(sorted.begin(), sorted.end());
    
    if (sorted.size() % 2 == 0) {
        return (sorted[sorted.size() / 2 - 1] + sorted[sorted.size() / 2]) / 2;
    } else {
        return sorted[sorted.size() / 2];
    }
}

bool LatencyStats::is_stable() const {
    if (history_ms.size() < 5) return false;  // Need at least 5 samples
    
    int avg = get_average();
    if (avg < 0) return false;
    
    // Calculate variance
    int variance_sum = 0;
    for (int lat : history_ms) {
        int diff = lat - avg;
        variance_sum += diff * diff;
    }
    float variance = static_cast<float>(variance_sum) / history_ms.size();
    float stddev = std::sqrt(variance);
    
    // Consider stable if stddev < 30% of average
    return stddev < (avg * 0.3f);
}

// ==================== PEER TIER MANAGER IMPLEMENTATION ====================

// ==================== LOCKED INTERNAL HELPERS ====================

ManagedPeer* PeerTierManager::get_peer_locked(const std::string& peer_id) {
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? it->second.get() : nullptr;
}

const ManagedPeer* PeerTierManager::get_peer_locked(const std::string& peer_id) const {
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? it->second.get() : nullptr;
}

bool PeerTierManager::tier_has_capacity_locked(PeerTier tier) const {
    int count = 0;
    auto it = m_tier_map.find(static_cast<int>(tier));
    if (it != m_tier_map.end()) {
        count = static_cast<int>(it->second.size());
    }

    switch (tier) {
        case PeerTier::TIER_1:
            return count < m_config.max_tier1_peers;
        case PeerTier::TIER_2:
            return count < m_config.max_tier2_peers;
        default:
            return true;
    }
}

std::string PeerTierManager::find_lru_peer_in_tier_locked(PeerTier tier) const {
    auto it = m_tier_map.find(static_cast<int>(tier));
    if (it == m_tier_map.end() || it->second.empty()) {
        return "";
    }

    std::string lru_peer;
    auto lru_time = std::chrono::steady_clock::now();
    bool initialized = false;

    for (const auto& peer_id : it->second) {
        auto peer_it = m_peers.find(peer_id);
        if (peer_it == m_peers.end() || !peer_it->second) {
            continue;
        }
        auto peer_time = peer_it->second->last_activity;
        if (!initialized || peer_time < lru_time) {
            initialized = true;
            lru_time = peer_time;
            lru_peer = peer_id;
        }
    }

    return lru_peer;
}

bool PeerTierManager::move_peer_to_tier_locked(const std::string& peer_id, PeerTier new_tier) {
    ManagedPeer* peer = get_peer_locked(peer_id);
    if (!peer) {
        m_last_error = "Peer not found";
        return false;
    }

    PeerTier old_tier = peer->current_tier;
    if (old_tier == new_tier) return true;

    try {
        // Remove from old tier
        auto& old_tier_peers = m_tier_map[static_cast<int>(old_tier)];
        old_tier_peers.erase(std::remove(old_tier_peers.begin(), old_tier_peers.end(), peer_id),
                        old_tier_peers.end());

        // Ensure capacity for the new tier (Tier 3 is unlimited)
        if (new_tier != PeerTier::TIER_3 && !tier_has_capacity_locked(new_tier)) {
            std::string lru = find_lru_peer_in_tier_locked(new_tier);
            if (!lru.empty()) {
                ManagedPeer* lru_peer = get_peer_locked(lru);
                if (lru_peer) {
                    PeerTier lru_old_tier = lru_peer->current_tier;

                    // Remove LRU from its tier list
                    auto& new_tier_peers = m_tier_map[static_cast<int>(new_tier)];
                    new_tier_peers.erase(std::remove(new_tier_peers.begin(), new_tier_peers.end(), lru),
                                    new_tier_peers.end());

                    // Demote to Tier 3
                    lru_peer->current_tier = PeerTier::TIER_3;
                    lru_peer->last_tier_change = std::chrono::steady_clock::now();
                    m_tier_map[static_cast<int>(PeerTier::TIER_3)].push_back(lru);

                    // Metrics for demotion
                    switch (lru_old_tier) {
                        case PeerTier::TIER_1: m_metrics.tier1_count--; break;
                        case PeerTier::TIER_2: m_metrics.tier2_count--; break;
                        case PeerTier::TIER_3: m_metrics.tier3_count--; break;
                        default: break;
                    }
                    m_metrics.tier3_count++;
                    m_metrics.total_demotions++;
                    LOG_INFO("PeerTierManager: Demoted " + lru + " to tier 3 to make room");
                }
            }
        }

        // Add to new tier
        m_tier_map[static_cast<int>(new_tier)].push_back(peer_id);
        peer->current_tier = new_tier;
        peer->last_tier_change = std::chrono::steady_clock::now();
        peer->promotion_pending = false;

        // Metrics update
        switch (old_tier) {
            case PeerTier::TIER_1: m_metrics.tier1_count--; break;
            case PeerTier::TIER_2: m_metrics.tier2_count--; break;
            case PeerTier::TIER_3: m_metrics.tier3_count--; break;
            default: break;
        }

        switch (new_tier) {
            case PeerTier::TIER_1: m_metrics.tier1_count++; m_metrics.total_promotions++; break;
            case PeerTier::TIER_2: m_metrics.tier2_count++; m_metrics.total_promotions++; break;
            case PeerTier::TIER_3: m_metrics.tier3_count++; m_metrics.total_demotions++; break;
            default: break;
        }

        LOG_INFO("PeerTierManager: Moved " + peer_id + " to tier " + std::to_string(static_cast<int>(new_tier)));
        return true;
    } catch (const std::exception& e) {
        m_last_error = std::string("Failed to move peer: ") + e.what();
        return false;
    }
}

bool PeerTierManager::should_promote_locked(const std::string& peer_id) const {
    const ManagedPeer* peer = get_peer_locked(peer_id);
    if (!peer) return false;

    if (peer->current_tier != PeerTier::TIER_2 && peer->current_tier != PeerTier::TIER_3) {
        return false;
    }

    int avg_latency = peer->latency_stats.get_average();
    if (avg_latency < 0 || avg_latency >= m_config.tier1_threshold_ms) {
        return false;
    }

    if (peer->activity_count < m_config.activity_threshold_for_promotion) {
        return false;
    }

    if (!peer->latency_stats.is_stable()) {
        return false;
    }

    return true;
}

int PeerTierManager::cleanup_idle_tier2_locked() {
    int cleaned = 0;
    auto tier2_it = m_tier_map.find(static_cast<int>(PeerTier::TIER_2));
    if (tier2_it == m_tier_map.end()) {
        return 0;
    }

    std::vector<std::string> peers_to_cleanup;
    peers_to_cleanup.reserve(tier2_it->second.size());

    const auto now = std::chrono::steady_clock::now();
    for (const auto& peer_id : tier2_it->second) {
        ManagedPeer* peer = get_peer_locked(peer_id);
        if (!peer) continue;
        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(now - peer->last_activity).count();
        if (idle_time >= m_config.tier2_idle_timeout_sec) {
            int avg_lat = peer->latency_stats.get_average();
            if (avg_lat < 0 || avg_lat > m_config.tier2_threshold_ms) {
                peers_to_cleanup.push_back(peer_id);
            }
        }
    }

    for (const auto& peer_id : peers_to_cleanup) {
        if (move_peer_to_tier_locked(peer_id, PeerTier::TIER_3)) {
            cleaned++;
            m_metrics.total_cleanups++;
        }
    }

    if (cleaned > 0) {
        LOG_INFO("PeerTierManager: Cleaned up " + std::to_string(cleaned) + " idle Tier2 peers");
    }
    return cleaned;
}

PeerTierManager::PeerTierManager(const PeerTierConfig& config)
    : m_config(config), m_running(false) {
    LOG_INFO("PeerTierManager: Initializing with Tier1=" + std::to_string(config.max_tier1_peers) +
             ", Tier2=" + std::to_string(config.max_tier2_peers));
    
    // Initialize tier maps
    m_tier_map[static_cast<int>(PeerTier::TIER_1)] = std::vector<std::string>();
    m_tier_map[static_cast<int>(PeerTier::TIER_2)] = std::vector<std::string>();
    m_tier_map[static_cast<int>(PeerTier::TIER_3)] = std::vector<std::string>();
}

PeerTierManager::~PeerTierManager() {
    shutdown();
}

bool PeerTierManager::initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_running) {
        m_last_error = "Already initialized";
        return false;
    }
    
    try {
        m_running = true;
        
        // Start background cleanup thread
        if (m_config.enable_auto_cleanup) {
            m_cleanup_thread = std::thread([this] { cleanup_loop(); });
        }
        
        // Start background promotion thread
        if (m_config.enable_auto_promotion) {
            m_promotion_thread = std::thread([this] { promotion_loop(); });
        }
        
        m_last_cleanup = std::chrono::steady_clock::now();
        
        LOG_INFO("PeerTierManager: Initialized successfully");
        return true;
    } catch (const std::exception& e) {
        m_running = false;
        m_last_error = std::string("Initialization failed: ") + e.what();
        LOG_WARN("PeerTierManager: " + m_last_error);
        return false;
    }
}

void PeerTierManager::shutdown() {
    LOG_DEBUG("PeerTierManager: Shutdown initiated");
    
    // Signal threads to stop using atomic flag
    LOG_DEBUG("PeerTierManager: Setting m_running to false");
    m_running = false;
    
    // Notify threads waiting on condition variable
    {
        std::lock_guard<std::mutex> lock(m_thread_mutex);
        LOG_DEBUG("PeerTierManager: Notifying all threads to wake up");
        m_thread_cv.notify_all();
        LOG_DEBUG("PeerTierManager: Notified all threads");
    }
    
    // Wake up any sleeping threads
    {
        LOG_DEBUG("PeerTierManager: About to acquire mutex to wake up threads");
        std::lock_guard<std::mutex> lock(m_mutex);
        LOG_DEBUG("PeerTierManager: Acquired mutex to wake up threads");
        // Just need to acquire the lock to wake up any waiting threads
    }
    LOG_DEBUG("PeerTierManager: Released mutex after waking up threads");
    
    // Wait for threads to finish
    LOG_DEBUG("PeerTierManager: Checking if cleanup thread is joinable");
    if (m_cleanup_thread.joinable()) {
        LOG_DEBUG("PeerTierManager: Cleanup thread is joinable, about to join");
        try {
            LOG_DEBUG("PeerTierManager: Calling join on cleanup thread");
            m_cleanup_thread.join();
            LOG_DEBUG("PeerTierManager: Cleanup thread joined");
        } catch (const std::exception& e) {
            LOG_WARN("PeerTierManager: Exception while joining cleanup thread: " + std::string(e.what()));
        }
    } else {
        LOG_DEBUG("PeerTierManager: Cleanup thread is not joinable");
    }
    
    LOG_DEBUG("PeerTierManager: Checking if promotion thread is joinable");
    if (m_promotion_thread.joinable()) {
        LOG_DEBUG("PeerTierManager: Promotion thread is joinable, about to join");
        try {
            LOG_DEBUG("PeerTierManager: Calling join on promotion thread");
            m_promotion_thread.join();
            LOG_DEBUG("PeerTierManager: Promotion thread joined");
        } catch (const std::exception& e) {
            LOG_WARN("PeerTierManager: Exception while joining promotion thread: " + std::string(e.what()));
        }
    } else {
        LOG_DEBUG("PeerTierManager: Promotion thread is not joinable");
    }
    
    // Clear data structures
    LOG_DEBUG("PeerTierManager: About to acquire mutex to clear data structures");
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        LOG_DEBUG("PeerTierManager: Acquired mutex to clear data structures");
        LOG_DEBUG("PeerTierManager: Clearing peers map, size before: " + std::to_string(m_peers.size()));
        m_peers.clear();
        LOG_DEBUG("PeerTierManager: Clearing tier map, size before: " + std::to_string(m_tier_map.size()));
        m_tier_map.clear();
        LOG_DEBUG("PeerTierManager: Clearing seen broadcasts map, size before: " + std::to_string(m_seen_broadcasts.size()));
        m_seen_broadcasts.clear();
    }
    LOG_DEBUG("PeerTierManager: Released mutex after clearing data structures");
    
    LOG_INFO("PeerTierManager: Shutdown complete");
}

bool PeerTierManager::is_running() const {
    return m_running;
}

// ==================== PEER MANAGEMENT ====================

bool PeerTierManager::add_peer(const std::string& peer_id, const std::string& ip, int port) {
    LOG_DEBUG("PeerTierManager: add_peer called for peer: " + peer_id + " IP: " + ip + " Port: " + std::to_string(port));
    // Validation
    if (!validate_peer_id(peer_id)) {
        m_last_error = "Invalid peer_id";
        LOG_DEBUG("PeerTierManager: add_peer failed - invalid peer_id");
        return false;
    }
    if (!validate_ip(ip)) {
        m_last_error = "Invalid IP address";
        LOG_DEBUG("PeerTierManager: add_peer failed - invalid IP");
        return false;
    }
    if (!validate_port(port)) {
        m_last_error = "Invalid port number";
        LOG_DEBUG("PeerTierManager: add_peer failed - invalid port");
        return false;
    }
    
    LOG_DEBUG("PeerTierManager: add_peer validation passed, about to acquire mutex");
    std::lock_guard<std::mutex> lock(m_mutex);
    LOG_DEBUG("PeerTierManager: add_peer acquired mutex");
    
    // Check if already exists
    if (m_peers.count(peer_id)) {
        m_last_error = "Peer already exists";
        LOG_DEBUG("PeerTierManager: add_peer failed - peer already exists");
        return false;
    }
    
    try {
        // Create new managed peer
        LOG_DEBUG("PeerTierManager: add_peer creating managed peer");
        auto managed_peer = std::make_unique<ManagedPeer>(peer_id, ip, port);
        managed_peer->current_tier = PeerTier::TIER_3;  // Start as unknown
        LOG_DEBUG("PeerTierManager: add_peer created managed peer");
        
        // Store peer
        m_peers[peer_id] = std::move(managed_peer);
        LOG_DEBUG("PeerTierManager: add_peer stored peer");
        
        // Add to tier map
        m_tier_map[static_cast<int>(PeerTier::TIER_3)].push_back(peer_id);
        LOG_DEBUG("PeerTierManager: add_peer added to tier map");
        
        m_metrics.tier3_count++;
        
        LOG_DEBUG("PeerTierManager: Added peer " + peer_id + " at " + ip + ":" + std::to_string(port));
        return true;
    } catch (const std::exception& e) {
        m_last_error = std::string("Failed to add peer: ") + e.what();
        LOG_DEBUG("PeerTierManager: add_peer failed with exception: " + std::string(e.what()));
        return false;
    }
}

ManagedPeer* PeerTierManager::get_peer(const std::string& peer_id) {
    LOG_DEBUG("PeerTierManager: get_peer called for peer: " + peer_id);
    LOG_DEBUG("PeerTierManager: get_peer about to acquire mutex");
    std::lock_guard<std::mutex> lock(m_mutex);
    LOG_DEBUG("PeerTierManager: get_peer acquired mutex");
    ManagedPeer* result = get_peer_locked(peer_id);
    LOG_DEBUG("PeerTierManager: get_peer returning: " + std::to_string(result != nullptr));
    LOG_DEBUG("PeerTierManager: get_peer releasing mutex");
    return result;
}

const ManagedPeer* PeerTierManager::get_peer_const(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return get_peer_locked(peer_id);
}

bool PeerTierManager::remove_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peers.find(peer_id);
    if (it == m_peers.end()) {
        m_last_error = "Peer not found";
        return false;
    }
    
    try {
        PeerTier tier = it->second->current_tier;
        
        // Remove from tier map
        auto& tier_peers = m_tier_map[static_cast<int>(tier)];
        tier_peers.erase(std::remove(tier_peers.begin(), tier_peers.end(), peer_id), tier_peers.end());
        
        // Remove peer
        m_peers.erase(it);
        
        LOG_DEBUG("PeerTierManager: Removed peer " + peer_id);
        return true;
    } catch (const std::exception& e) {
        m_last_error = std::string("Failed to remove peer: ") + e.what();
        return false;
    }
}

bool PeerTierManager::peer_exists(const std::string& peer_id) const {
    LOG_DEBUG("PeerTierManager: peer_exists called for peer: " + peer_id);
    LOG_DEBUG("PeerTierManager: About to acquire mutex for peer_exists");
    std::lock_guard<std::mutex> lock(m_mutex);
    LOG_DEBUG("PeerTierManager: Acquired mutex for peer_exists");
    bool result = m_peers.count(peer_id) > 0;
    LOG_DEBUG("PeerTierManager: peer_exists returning: " + std::to_string(result));
    LOG_DEBUG("PeerTierManager: Releasing mutex for peer_exists");
    return result;
}

int PeerTierManager::get_tier_count(PeerTier tier) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_tier_map.find(static_cast<int>(tier));
    return (it != m_tier_map.end()) ? it->second.size() : 0;
}

std::vector<ManagedPeer> PeerTierManager::get_peers_by_tier(PeerTier tier) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<ManagedPeer> result;
    auto it = m_tier_map.find(static_cast<int>(tier));
    if (it != m_tier_map.end()) {
        for (const auto& peer_id : it->second) {
            auto peer_it = m_peers.find(peer_id);
            if (peer_it != m_peers.end()) {
                result.push_back(*peer_it->second);
            }
        }
    }
    return result;
}

// ==================== LATENCY TRACKING ====================

bool PeerTierManager::record_latency(const std::string& peer_id, int latency_ms) {
    LOG_DEBUG("PeerTierManager: record_latency called for peer: " + peer_id + " latency: " + std::to_string(latency_ms));
    if (latency_ms < 0) {
        m_last_error = "Invalid latency value";
        LOG_DEBUG("PeerTierManager: record_latency failed - invalid latency value");
        return false;
    }
    
    LOG_DEBUG("PeerTierManager: record_latency validation passed, about to acquire mutex");
    std::lock_guard<std::mutex> lock(m_mutex);
    LOG_DEBUG("PeerTierManager: record_latency acquired mutex");
    
    // Direct map access to avoid recursive lock in get_peer()
    auto it = m_peers.find(peer_id);
    ManagedPeer* peer = (it != m_peers.end()) ? it->second.get() : nullptr;

    if (!peer) {
        m_last_error = "Peer not found";
        LOG_DEBUG("PeerTierManager: record_latency failed - peer not found");
        return false;
    }
    
    try {
        // Record latency
        LOG_DEBUG("PeerTierManager: record_latency recording latency");
        peer->latency_stats.record(latency_ms);
        LOG_DEBUG("PeerTierManager: record_latency recorded latency");
        peer->last_activity = std::chrono::steady_clock::now();
        LOG_DEBUG("PeerTierManager: record_latency updated last_activity");
        
        // Check for latency spikes
        if (m_config.enable_safety_checks) {
            LOG_DEBUG("PeerTierManager: record_latency checking for latency spikes");
            int avg = peer->latency_stats.get_average();
            if (avg > 0 && latency_ms > avg + m_config.max_latency_spike_threshold_ms) {
                m_metrics.latency_spikes_detected++;
                LOG_WARN("PeerTierManager: Latency spike for " + peer_id + 
                        ": " + std::to_string(latency_ms) + "ms (avg: " + 
                        std::to_string(avg) + "ms)");
            }
            LOG_DEBUG("PeerTierManager: record_latency finished checking for latency spikes");
        }
        
        LOG_DEBUG("PeerTierManager: record_latency returning true");
        return true;
    } catch (const std::exception& e) {
        m_last_error = std::string("Failed to record latency: ") + e.what();
        LOG_DEBUG("PeerTierManager: record_latency failed with exception: " + std::string(e.what()));
        return false;
    }
}

int PeerTierManager::get_latency(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto peer = get_peer_locked(peer_id);
    if (!peer) return -1;
    
    return peer->latency_stats.get_average();
}

LatencyStats PeerTierManager::get_latency_stats(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto peer = get_peer_locked(peer_id);
    if (!peer) return LatencyStats();
    
    return peer->latency_stats;
}

// ==================== TIER MANAGEMENT ====================

PeerTier PeerTierManager::classify_by_latency(int avg_latency_ms) const {
    if (avg_latency_ms < 0) return PeerTier::TIER_UNKNOWN;
    
    if (avg_latency_ms < m_config.tier1_threshold_ms) {
        return PeerTier::TIER_1;
    } else if (avg_latency_ms < m_config.tier2_threshold_ms) {
        return PeerTier::TIER_2;
    } else {
        return PeerTier::TIER_3;
    }
}

PeerTier PeerTierManager::classify_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Direct map access to avoid recursive lock in get_peer()
    auto it = m_peers.find(peer_id);
    ManagedPeer* peer = (it != m_peers.end()) ? it->second.get() : nullptr;

    if (!peer) {
        m_last_error = "Peer not found";
        return PeerTier::TIER_UNKNOWN;
    }
    
    try {
        int avg_latency = peer->latency_stats.get_average();
        PeerTier recommended = classify_by_latency(avg_latency);
        
        peer->recommended_tier = recommended;
        
        // Apply hysteresis to prevent flapping
        if (recommended != peer->current_tier) {
            int current_threshold = (recommended == PeerTier::TIER_1) ? 
                m_config.tier1_threshold_ms : m_config.tier2_threshold_ms;
            
            // Only change if difference is larger than hysteresis
            int latency_diff = std::abs(avg_latency - current_threshold);
            if (latency_diff >= m_config.tier_change_hysteresis_ms) {
                peer->promotion_pending = true;
            }
        }
        
        return recommended;
    } catch (const std::exception& e) {
        m_last_error = std::string("Classification failed: ") + e.what();
        return PeerTier::TIER_UNKNOWN;
    }
}

PeerTier PeerTierManager::get_peer_tier(const std::string& peer_id) const {
    LOG_DEBUG("PeerTierManager: get_peer_tier called for peer: " + peer_id);
    LOG_DEBUG("PeerTierManager: About to acquire mutex for get_peer_tier");
    std::lock_guard<std::mutex> lock(m_mutex);
    LOG_DEBUG("PeerTierManager: Acquired mutex for get_peer_tier");
    
    auto peer = get_peer_locked(peer_id);
    PeerTier result = peer ? peer->current_tier : PeerTier::TIER_UNKNOWN;
    LOG_DEBUG("PeerTierManager: get_peer_tier returning: " + std::to_string(static_cast<int>(result)));
    LOG_DEBUG("PeerTierManager: Releasing mutex for get_peer_tier");
    return result;
}

bool PeerTierManager::tier_has_capacity(PeerTier tier) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return tier_has_capacity_locked(tier);
}

std::string PeerTierManager::find_lru_peer_in_tier(PeerTier tier) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return find_lru_peer_in_tier_locked(tier);
}

bool PeerTierManager::move_peer_to_tier(const std::string& peer_id, PeerTier new_tier) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return move_peer_to_tier_locked(peer_id, new_tier);
}

bool PeerTierManager::set_peer_tier(const std::string& peer_id, PeerTier tier) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Validate
    if (tier == PeerTier::TIER_UNKNOWN) {
        m_last_error = "Cannot set tier to UNKNOWN";
        return false;
    }
    
    if (tier != PeerTier::TIER_3 && !tier_has_capacity_locked(tier)) {
        m_last_error = "Target tier is full";
        return false;
    }

    return move_peer_to_tier_locked(peer_id, tier);
}

bool PeerTierManager::record_activity(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto peer = get_peer_locked(peer_id);
    if (!peer) {
        m_last_error = "Peer not found";
        return false;
    }
    
    peer->last_activity = std::chrono::steady_clock::now();
    peer->activity_count++;
    
    return true;
}

bool PeerTierManager::should_promote(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return should_promote_locked(peer_id);
}

bool PeerTierManager::should_demote(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto peer = get_peer_locked(peer_id);
    if (!peer) return false;
    
    if (peer->current_tier == PeerTier::TIER_3) {
        return false;  // Already lowest tier
    }
    
    int avg_latency = peer->latency_stats.get_average();
    
    // Check if should move to lower tier
    if (peer->current_tier == PeerTier::TIER_1) {
        return avg_latency >= m_config.tier1_threshold_ms + m_config.tier_change_hysteresis_ms;
    } else if (peer->current_tier == PeerTier::TIER_2) {
        return avg_latency >= m_config.tier2_threshold_ms + m_config.tier_change_hysteresis_ms;
    }
    
    return false;
}

// ==================== DISCOVERY & BROADCAST ====================

bool PeerTierManager::initiate_discovery(const std::string& target_peer_id, const std::string& request_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!validate_peer_id(target_peer_id)) {
        m_last_error = "Invalid target peer_id";
        return false;
    }
    
    m_metrics.total_discoveries++;
    LOG_INFO("PeerTierManager: Initiating discovery for " + target_peer_id);
    return true;
}

bool PeerTierManager::process_broadcast(const std::string& request_id, const std::string& source_peer_id,
                                       const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (request_id.empty() || source_peer_id.empty()) {
        m_last_error = "Invalid parameters";
        return false;
    }
    
    return true;
}

bool PeerTierManager::should_relay_broadcast(const std::string& request_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check if duplicate
    if (m_seen_broadcasts.count(request_id)) {
        m_metrics.broadcasts_dropped_dedup++;
        return false;
    }
    
    m_seen_broadcasts[request_id] = std::chrono::steady_clock::now();
    m_metrics.broadcasts_relayed++;
    return true;
}

PeerTierManager::BroadcastStats PeerTierManager::get_broadcast_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    BroadcastStats stats;
    stats.total_broadcasts = m_metrics.broadcasts_sent + m_metrics.broadcasts_relayed;
    // Add more stats as needed
    return stats;
}

// ==================== IDLE CLEANUP & LIFECYCLE ====================

bool PeerTierManager::mark_active(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto peer = get_peer_locked(peer_id);
    if (!peer) return false;
    
    peer->last_activity = std::chrono::steady_clock::now();
    return true;
}

bool PeerTierManager::is_idle(const std::string& peer_id, int timeout_sec) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto peer = get_peer_locked(peer_id);
    if (!peer) return true;
    
    auto now = std::chrono::steady_clock::now();
    auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
        now - peer->last_activity
    ).count();
    
    return idle_time >= timeout_sec;
}

int PeerTierManager::get_idle_time(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto peer = get_peer_locked(peer_id);
    if (!peer) return -1;
    
    auto now = std::chrono::steady_clock::now();
    auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
        now - peer->last_activity
    ).count();
    
    return static_cast<int>(idle_time);
}

int PeerTierManager::cleanup_idle_tier2() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return cleanup_idle_tier2_locked();
}

bool PeerTierManager::force_cleanup_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);

    return move_peer_to_tier_locked(peer_id, PeerTier::TIER_3);
}

// ==================== MONITORING & METRICS ====================

PeerTierMetrics PeerTierManager::get_metrics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    PeerTierMetrics m = m_metrics;
    
    // Calculate averages
    int tier1_lat_sum = 0, tier1_count = 0;
    int tier2_lat_sum = 0, tier2_count = 0;
    
    auto tier1_it = m_tier_map.find(static_cast<int>(PeerTier::TIER_1));
    if (tier1_it != m_tier_map.end()) {
        for (const auto& peer_id : tier1_it->second) {
            int lat = m_peers.at(peer_id)->latency_stats.get_average();
            if (lat >= 0) {
                tier1_lat_sum += lat;
                tier1_count++;
            }
        }
    }
    
    auto tier2_it = m_tier_map.find(static_cast<int>(PeerTier::TIER_2));
    if (tier2_it != m_tier_map.end()) {
        for (const auto& peer_id : tier2_it->second) {
            int lat = m_peers.at(peer_id)->latency_stats.get_average();
            if (lat >= 0) {
                tier2_lat_sum += lat;
                tier2_count++;
            }
        }
    }
    
    m.avg_tier1_latency_ms = (tier1_count > 0) ? (tier1_lat_sum / tier1_count) : 0;
    m.avg_tier2_latency_ms = (tier2_count > 0) ? (tier2_lat_sum / tier2_count) : 0;
    m.is_healthy = m_running && m_last_error.empty();
    m.last_error = m_last_error;
    
    return m;
}

bool PeerTierManager::is_healthy() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_running && m_last_error.empty();
}

std::string PeerTierManager::get_last_error() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_last_error;
}

void PeerTierManager::reset_metrics() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_metrics = PeerTierMetrics();
    m_last_error.clear();
}

// ==================== CONFIGURATION ====================

bool PeerTierManager::update_config(const PeerTierConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Validate new config
    if (config.max_tier1_peers < 1 || config.max_tier2_peers < 1) {
        m_last_error = "Invalid tier limits";
        return false;
    }
    
    m_config = config;
    LOG_INFO("PeerTierManager: Configuration updated");
    return true;
}

PeerTierConfig PeerTierManager::get_config() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

// ==================== DEBUGGING & LOGGING ====================

std::string PeerTierManager::get_status_json() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::ostringstream json;
	const int tier1_count = static_cast<int>(m_tier_map.count(static_cast<int>(PeerTier::TIER_1)) ? m_tier_map.at(static_cast<int>(PeerTier::TIER_1)).size() : 0);
	const int tier2_count = static_cast<int>(m_tier_map.count(static_cast<int>(PeerTier::TIER_2)) ? m_tier_map.at(static_cast<int>(PeerTier::TIER_2)).size() : 0);
	const int tier3_count = static_cast<int>(m_tier_map.count(static_cast<int>(PeerTier::TIER_3)) ? m_tier_map.at(static_cast<int>(PeerTier::TIER_3)).size() : 0);
	const bool healthy = m_running && m_last_error.empty();

    json << "{"
         << "\"tier1_count\":" << tier1_count << "," 
         << "\"tier2_count\":" << tier2_count << "," 
         << "\"tier3_count\":" << tier3_count << "," 
         << "\"total_peers\":" << m_peers.size() << ","
         << "\"broadcasts_sent\":" << m_metrics.broadcasts_sent << ","
         << "\"broadcasts_relayed\":" << m_metrics.broadcasts_relayed << ","
         << "\"total_discoveries\":" << m_metrics.total_discoveries << ","
         << "\"total_promotions\":" << m_metrics.total_promotions << ","
         << "\"total_demotions\":" << m_metrics.total_demotions << ","
         << "\"is_healthy\":" << (healthy ? "true" : "false")
         << "}";
    
    return json.str();
}

std::string PeerTierManager::get_peer_status_json(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_locked(peer_id);
    if (!peer) return "{}";
    
    std::ostringstream json;
    json << "{"
         << "\"peer_id\":\"" << peer->peer_id << "\","
         << "\"ip\":\"" << peer->ip << "\","
         << "\"port\":" << peer->port << ","
         << "\"tier\":" << static_cast<int>(peer->current_tier) << ","
         << "\"latency_avg\":" << peer->latency_stats.get_average() << ","
         << "\"latency_min\":" << peer->latency_stats.min_latency_ms << ","
         << "\"latency_max\":" << peer->latency_stats.max_latency_ms << ","
         << "\"activity_count\":" << peer->activity_count << ","
         << "\"is_connected\":" << (peer->is_connected ? "true" : "false")
         << "}";
    
    return json.str();
}

// ==================== BACKGROUND THREADS ====================

void PeerTierManager::cleanup_loop() {
    LOG_DEBUG("PeerTierManager: Cleanup loop started");
    while (m_running) {
        LOG_DEBUG("PeerTierManager: Cleanup loop iteration, m_running=" + std::to_string(m_running));
        // Use condition variable for more responsive shutdown
        std::unique_lock<std::mutex> lock(m_thread_mutex);
        LOG_DEBUG("PeerTierManager: Cleanup loop waiting on condition variable");
        m_thread_cv.wait_for(lock, 
            std::chrono::seconds(m_config.tier2_cleanup_interval_sec),
            [this] { 
                LOG_DEBUG("PeerTierManager: Cleanup loop condition check, m_running=" + std::to_string(m_running));
                return !m_running; 
            });
        lock.unlock();
        LOG_DEBUG("PeerTierManager: Cleanup loop woke up from wait");
        
        // Check if still running after sleep
        LOG_DEBUG("PeerTierManager: Cleanup loop checking m_running after wait, m_running=" + std::to_string(m_running));
        if (!m_running) {
            LOG_DEBUG("PeerTierManager: Cleanup loop breaking because m_running is false");
            break;
        }
        
        LOG_DEBUG("PeerTierManager: Cleanup loop about to acquire mutex");
        std::lock_guard<std::mutex> lock2(m_mutex);
        LOG_DEBUG("PeerTierManager: Cleanup loop acquired mutex");
        
        // Double-check running flag while holding lock
        LOG_DEBUG("PeerTierManager: Cleanup loop checking m_running while holding lock, m_running=" + std::to_string(m_running));
        if (!m_running) {
            LOG_DEBUG("PeerTierManager: Cleanup loop breaking because m_running is false while holding lock");
            break;
        }
        
        LOG_DEBUG("PeerTierManager: Cleanup loop calling cleanup_idle_tier2_locked");
        cleanup_idle_tier2_locked();
        LOG_DEBUG("PeerTierManager: Cleanup loop releasing mutex");
    }
    
    LOG_DEBUG("PeerTierManager: Cleanup loop exiting");
}

void PeerTierManager::promotion_loop() {
    LOG_DEBUG("PeerTierManager: Promotion loop started");
    while (m_running) {
        LOG_DEBUG("PeerTierManager: Promotion loop iteration, m_running=" + std::to_string(m_running));
        // Use condition variable for more responsive shutdown
        std::unique_lock<std::mutex> lock(m_thread_mutex);
        LOG_DEBUG("PeerTierManager: Promotion loop waiting on condition variable");
        m_thread_cv.wait_for(lock, 
            std::chrono::seconds(5),  // Check every 5 seconds
            [this] { 
                LOG_DEBUG("PeerTierManager: Promotion loop condition check, m_running=" + std::to_string(m_running));
                return !m_running; 
            });
        lock.unlock();
        LOG_DEBUG("PeerTierManager: Promotion loop woke up from wait");
        
        // Check if still running after sleep
        LOG_DEBUG("PeerTierManager: Promotion loop checking m_running after wait, m_running=" + std::to_string(m_running));
        if (!m_running) {
            LOG_DEBUG("PeerTierManager: Promotion loop breaking because m_running is false");
            break;
        }
        
        LOG_DEBUG("PeerTierManager: Promotion loop about to acquire mutex");
        std::lock_guard<std::mutex> lock2(m_mutex);
        LOG_DEBUG("PeerTierManager: Promotion loop acquired mutex");
        
        // Double-check running flag while holding lock
        LOG_DEBUG("PeerTierManager: Promotion loop checking m_running while holding lock, m_running=" + std::to_string(m_running));
        if (!m_running) {
            LOG_DEBUG("PeerTierManager: Promotion loop breaking because m_running is false while holding lock");
            break;
        }
        
        // Check all Tier 2 and Tier 3 peers for promotion
        LOG_DEBUG("PeerTierManager: Promotion loop checking candidates for promotion");
        std::vector<std::string> candidates;
        
        for (auto& entry : m_tier_map) {
            if (entry.first == static_cast<int>(PeerTier::TIER_1)) {
                continue;
            }

            for (const auto& peer_id : entry.second) {
                if (should_promote_locked(peer_id)) {
                    candidates.push_back(peer_id);
                }
            }
        }
        
        // Promote candidates
        LOG_DEBUG("PeerTierManager: Promotion loop found " + std::to_string(candidates.size()) + " candidates for promotion");
        for (const auto& peer_id : candidates) {
            if (tier_has_capacity_locked(PeerTier::TIER_1)) {
                move_peer_to_tier_locked(peer_id, PeerTier::TIER_1);
            }
        }
        LOG_DEBUG("PeerTierManager: Promotion loop releasing mutex");
    }
    
    LOG_DEBUG("PeerTierManager: Promotion loop exiting");
}

// ==================== VALIDATION ====================

bool PeerTierManager::validate_peer_id(const std::string& peer_id) const {
    return !peer_id.empty() && peer_id.length() <= 256;
}

bool PeerTierManager::validate_ip(const std::string& ip) const {
    if (ip.empty() || ip.length() > 45) return false;  // IPv6 max length
    
    // Basic validation: should contain at least one dot (IPv4) or colon (IPv6)
    return (ip.find('.') != std::string::npos || ip.find(':') != std::string::npos);
}

bool PeerTierManager::validate_port(int port) const {
    return port > 0 && port < 65536;
}

void PeerTierManager::cleanup_broadcast_cache() {
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = m_seen_broadcasts.begin(); it != m_seen_broadcasts.end();) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
        if (age > m_config.dedup_cache_timeout_sec) {
            it = m_seen_broadcasts.erase(it);
        } else {
            ++it;
        }
    }
}
