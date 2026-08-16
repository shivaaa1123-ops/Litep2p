#include "peer_cache_lru.h"

PeerCacheLRU::PeerCacheLRU(size_t max_hot_peers)
    : m_max_hot_peers(max_hot_peers) {}

Peer* PeerCacheLRU::get_or_restore(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Check hot cache first
    auto hot_it = m_hot_cache.find(peer_id);
    if (hot_it != m_hot_cache.end()) {
        update_lru(peer_id);
        ++m_cache_hits;
        return hot_it->second.get();
    }
    
    // Check archive
    auto archive_it = m_archived.find(peer_id);
    if (archive_it != m_archived.end()) {
        // Restore from archive
        auto& archived = archive_it->second;
        Peer restored;
        restored.id = archived.id;
        restored.ip = archived.ip;
        restored.port = archived.port;
        
        // Add to hot cache
        auto peer_ptr = std::make_shared<Peer>(restored);
        m_hot_cache[peer_id] = peer_ptr;
        update_lru(peer_id);
        
        // Remove from archive
        m_archived.erase(archive_it);
        
        ++m_cache_hits;
        return peer_ptr.get();
    }
    
    ++m_cache_misses;
    return nullptr;
}

Peer* PeerCacheLRU::get_hot(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_hot_cache.find(peer_id);
    if (it != m_hot_cache.end()) {
        update_lru(peer_id);
        ++m_cache_hits;
        return it->second.get();
    }
    
    ++m_cache_misses;
    return nullptr;
}

bool PeerCacheLRU::add_hot(const Peer& peer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto peer_ptr = std::make_shared<Peer>(peer);
    m_hot_cache[peer.id] = peer_ptr;
    update_lru(peer.id);
    
    // If exceeded max, evict LRU
    while (m_hot_cache.size() > m_max_hot_peers) {
        evict_lru();
    }
    
    return true;
}

bool PeerCacheLRU::archive_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_hot_cache.find(peer_id);
    if (it == m_hot_cache.end()) {
        return false;
    }
    
    // Archive the peer
    ArchivedPeer archived;
    archived.id = it->second->id;
    archived.ip = it->second->ip;
    archived.port = it->second->port;
    
    m_archived[peer_id] = archived;
    
    // Remove from hot cache
    m_hot_cache.erase(it);
    
    // Remove from LRU
    auto lru_it = m_lru_map.find(peer_id);
    if (lru_it != m_lru_map.end()) {
        m_lru_list.erase(lru_it->second);
        m_lru_map.erase(lru_it);
    }
    
    return true;
}

bool PeerCacheLRU::evict_lru() {
    if (m_lru_list.empty()) {
        return false;
    }
    
    std::string lru_peer_id = m_lru_list.front();
    m_lru_list.pop_front();
    m_lru_map.erase(lru_peer_id);
    
    // Archive the evicted peer
    auto it = m_hot_cache.find(lru_peer_id);
    if (it != m_hot_cache.end()) {
        ArchivedPeer archived;
        archived.id = it->second->id;
        archived.ip = it->second->ip;
        archived.port = it->second->port;
        m_archived[lru_peer_id] = archived;
        m_hot_cache.erase(it);
    }
    
    return true;
}

PeerCacheLRU::Stats PeerCacheLRU::get_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Stats stats;
    stats.hot_count = m_hot_cache.size();
    stats.archived_count = m_archived.size();
    stats.cache_hits = m_cache_hits;
    stats.cache_misses = m_cache_misses;
    
    size_t total = m_cache_hits + m_cache_misses;
    if (total > 0) {
        stats.hit_rate_percent = (float)m_cache_hits / total * 100.0f;
    }
    
    return stats;
}

size_t PeerCacheLRU::hot_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_hot_cache.size();
}

void PeerCacheLRU::update_lru(const std::string& peer_id) {
    auto it = m_lru_map.find(peer_id);
    if (it != m_lru_map.end()) {
        // Move to end (most recent)
        m_lru_list.erase(it->second);
    }
    
    m_lru_list.push_back(peer_id);
    m_lru_map[peer_id] = std::prev(m_lru_list.end());
}
