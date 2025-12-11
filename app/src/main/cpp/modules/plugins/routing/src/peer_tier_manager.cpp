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
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_running = false;
    }
    
    // Wait for threads to finish
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }
    if (m_promotion_thread.joinable()) {
        m_promotion_thread.join();
    }
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_peers.clear();
        m_tier_map.clear();
        m_seen_broadcasts.clear();
    }
    
    LOG_INFO("PeerTierManager: Shutdown complete");
}

bool PeerTierManager::is_running() const {
    return m_running;
}

// ==================== PEER MANAGEMENT ====================

bool PeerTierManager::add_peer(const std::string& peer_id, const std::string& ip, int port) {
    // Validation
    if (!validate_peer_id(peer_id)) {
        m_last_error = "Invalid peer_id";
        return false;
    }
    if (!validate_ip(ip)) {
        m_last_error = "Invalid IP address";
        return false;
    }
    if (!validate_port(port)) {
        m_last_error = "Invalid port number";
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check if already exists
    if (m_peers.count(peer_id)) {
        m_last_error = "Peer already exists";
        return false;
    }
    
    try {
        // Create new managed peer
        auto managed_peer = std::make_unique<ManagedPeer>(peer_id, ip, port);
        managed_peer->current_tier = PeerTier::TIER_3;  // Start as unknown
        
        m_peers[peer_id] = std::move(managed_peer);
        m_tier_map[static_cast<int>(PeerTier::TIER_3)].push_back(peer_id);
        
        m_metrics.tier3_count++;
        
        LOG_DEBUG("PeerTierManager: Added peer " + peer_id + " at " + ip + ":" + std::to_string(port));
        return true;
    } catch (const std::exception& e) {
        m_last_error = std::string("Failed to add peer: ") + e.what();
        return false;
    }
}

ManagedPeer* PeerTierManager::get_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? it->second.get() : nullptr;
}

const ManagedPeer* PeerTierManager::get_peer_const(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? it->second.get() : nullptr;
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
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_peers.count(peer_id) > 0;
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
    if (latency_ms < 0) {
        m_last_error = "Invalid latency value";
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer(peer_id);
    if (!peer) {
        m_last_error = "Peer not found";
        return false;
    }
    
    try {
        // Record latency
        peer->latency_stats.record(latency_ms);
        peer->last_activity = std::chrono::steady_clock::now();
        
        // Check for latency spikes
        if (m_config.enable_safety_checks) {
            int avg = peer->latency_stats.get_average();
            if (avg > 0 && latency_ms > avg + m_config.max_latency_spike_threshold_ms) {
                m_metrics.latency_spikes_detected++;
                LOG_WARN("PeerTierManager: Latency spike for " + peer_id + 
                        ": " + std::to_string(latency_ms) + "ms (avg: " + 
                        std::to_string(avg) + "ms)");
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        m_last_error = std::string("Failed to record latency: ") + e.what();
        return false;
    }
}

int PeerTierManager::get_latency(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_const(peer_id);
    if (!peer) return -1;
    
    return peer->latency_stats.get_average();
}

LatencyStats PeerTierManager::get_latency_stats(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_const(peer_id);
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
    
    auto peer = get_peer(peer_id);
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
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_const(peer_id);
    return peer ? peer->current_tier : PeerTier::TIER_UNKNOWN;
}

bool PeerTierManager::tier_has_capacity(PeerTier tier) const {
    int count = 0;
    auto it = m_tier_map.find(static_cast<int>(tier));
    if (it != m_tier_map.end()) {
        count = it->second.size();
    }
    
    switch (tier) {
        case PeerTier::TIER_1:
            return count < m_config.max_tier1_peers;
        case PeerTier::TIER_2:
            return count < m_config.max_tier2_peers;
        default:
            return true;  // TIER_3 unlimited
    }
}

std::string PeerTierManager::find_lru_peer_in_tier(PeerTier tier) const {
    auto it = m_tier_map.find(static_cast<int>(tier));
    if (it == m_tier_map.end() || it->second.empty()) {
        return "";
    }
    
    std::string lru_peer = it->second[0];
    auto lru_time = m_peers.at(lru_peer)->last_activity;
    
    for (const auto& peer_id : it->second) {
        auto peer_time = m_peers.at(peer_id)->last_activity;
        if (peer_time < lru_time) {
            lru_time = peer_time;
            lru_peer = peer_id;
        }
    }
    
    return lru_peer;
}

bool PeerTierManager::move_peer_to_tier(const std::string& peer_id, PeerTier new_tier) {
    auto peer = get_peer(peer_id);
    if (!peer) return false;
    
    PeerTier old_tier = peer->current_tier;
    if (old_tier == new_tier) return true;  // Already there
    
    try {
        // Remove from old tier
        auto& old_tier_peers = m_tier_map[static_cast<int>(old_tier)];
        old_tier_peers.erase(std::remove(old_tier_peers.begin(), old_tier_peers.end(), peer_id),
                            old_tier_peers.end());
        
        // Check capacity for new tier
        if (!tier_has_capacity(new_tier)) {
            // If full, evict LRU peer
            std::string lru = find_lru_peer_in_tier(new_tier);
            if (!lru.empty()) {
                move_peer_to_tier(lru, PeerTier::TIER_3);
            }
        }
        
        // Add to new tier
        m_tier_map[static_cast<int>(new_tier)].push_back(peer_id);
        peer->current_tier = new_tier;
        peer->last_tier_change = std::chrono::steady_clock::now();
        
        // Update metrics
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
        
        LOG_INFO("PeerTierManager: Promoted " + peer_id + " to tier " + 
                std::to_string(static_cast<int>(new_tier)));
        return true;
    } catch (const std::exception& e) {
        m_last_error = std::string("Failed to move peer: ") + e.what();
        return false;
    }
}

bool PeerTierManager::set_peer_tier(const std::string& peer_id, PeerTier tier) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Validate
    if (tier == PeerTier::TIER_UNKNOWN) {
        m_last_error = "Cannot set tier to UNKNOWN";
        return false;
    }
    
    if (!tier_has_capacity(tier) && tier != PeerTier::TIER_3) {
        m_last_error = "Target tier is full";
        return false;
    }
    
    return move_peer_to_tier(peer_id, tier);
}

bool PeerTierManager::record_activity(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer(peer_id);
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
    
    auto peer = get_peer_const(peer_id);
    if (!peer) return false;
    
    // Only consider promotion from TIER_2 or TIER_3 to TIER_1
    if (peer->current_tier != PeerTier::TIER_2 && peer->current_tier != PeerTier::TIER_3) {
        return false;
    }
    
    // Check latency
    int avg_latency = peer->latency_stats.get_average();
    if (avg_latency >= m_config.tier1_threshold_ms) {
        return false;  // Latency too high
    }
    
    // Check activity
    if (peer->activity_count < m_config.activity_threshold_for_promotion) {
        return false;  // Not enough activity
    }
    
    // Check stability
    if (!peer->latency_stats.is_stable()) {
        return false;  // Latency unstable
    }
    
    return true;
}

bool PeerTierManager::should_demote(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_const(peer_id);
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
    
    auto peer = get_peer(peer_id);
    if (!peer) return false;
    
    peer->last_activity = std::chrono::steady_clock::now();
    return true;
}

bool PeerTierManager::is_idle(const std::string& peer_id, int timeout_sec) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_const(peer_id);
    if (!peer) return true;
    
    auto now = std::chrono::steady_clock::now();
    auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
        now - peer->last_activity
    ).count();
    
    return idle_time >= timeout_sec;
}

int PeerTierManager::get_idle_time(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_const(peer_id);
    if (!peer) return -1;
    
    auto now = std::chrono::steady_clock::now();
    auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
        now - peer->last_activity
    ).count();
    
    return static_cast<int>(idle_time);
}

int PeerTierManager::cleanup_idle_tier2() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int cleaned = 0;
    auto tier2_it = m_tier_map.find(static_cast<int>(PeerTier::TIER_2));
    
    if (tier2_it == m_tier_map.end()) {
        return 0;
    }
    
    auto peers_to_cleanup = std::vector<std::string>();
    
    for (const auto& peer_id : tier2_it->second) {
        auto peer = m_peers[peer_id].get();
        
        // Check if idle
        auto now = std::chrono::steady_clock::now();
        auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
            now - peer->last_activity
        ).count();
        
        if (idle_time >= m_config.tier2_idle_timeout_sec) {
            // Check latency
            int avg_lat = peer->latency_stats.get_average();
            if (avg_lat < 0 || avg_lat > m_config.tier2_threshold_ms) {
                peers_to_cleanup.push_back(peer_id);
            }
        }
    }
    
    // Remove idle peers
    for (const auto& peer_id : peers_to_cleanup) {
        move_peer_to_tier(peer_id, PeerTier::TIER_3);
        cleaned++;
        m_metrics.total_cleanups++;
    }
    
    LOG_INFO("PeerTierManager: Cleaned up " + std::to_string(cleaned) + " idle Tier2 peers");
    return cleaned;
}

bool PeerTierManager::force_cleanup_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    return move_peer_to_tier(peer_id, PeerTier::TIER_3);
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
    json << "{"
         << "\"tier1_count\":" << get_tier_count(PeerTier::TIER_1) << ","
         << "\"tier2_count\":" << get_tier_count(PeerTier::TIER_2) << ","
         << "\"tier3_count\":" << get_tier_count(PeerTier::TIER_3) << ","
         << "\"total_peers\":" << m_peers.size() << ","
         << "\"broadcasts_sent\":" << m_metrics.broadcasts_sent << ","
         << "\"broadcasts_relayed\":" << m_metrics.broadcasts_relayed << ","
         << "\"total_discoveries\":" << m_metrics.total_discoveries << ","
         << "\"total_promotions\":" << m_metrics.total_promotions << ","
         << "\"total_demotions\":" << m_metrics.total_demotions << ","
         << "\"is_healthy\":" << (is_healthy() ? "true" : "false")
         << "}";
    
    return json.str();
}

std::string PeerTierManager::get_peer_status_json(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer = get_peer_const(peer_id);
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
    while (m_running) {
        std::this_thread::sleep_for(
            std::chrono::seconds(m_config.tier2_cleanup_interval_sec)
        );
        
        if (m_running) {
            cleanup_idle_tier2();
        }
    }
}

void PeerTierManager::promotion_loop() {
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));  // Check every 5 seconds
        
        if (!m_running) break;
        
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Check all Tier 2 and Tier 3 peers for promotion
        std::vector<std::string> candidates;
        
        for (auto& entry : m_tier_map) {
            if (entry.first == static_cast<int>(PeerTier::TIER_1)) {
                continue;  // Skip Tier 1
            }
            
            for (const auto& peer_id : entry.second) {
                if (should_promote(peer_id)) {
                    candidates.push_back(peer_id);
                }
            }
        }
        
        // Promote candidates
        for (const auto& peer_id : candidates) {
            if (tier_has_capacity(PeerTier::TIER_1)) {
                move_peer_to_tier(peer_id, PeerTier::TIER_1);
            }
        }
    }
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
