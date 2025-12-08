#include "session_cache.h"
#include "logger.h"

SessionCache::SessionCache() = default;

SessionCache::~SessionCache() = default;

void SessionCache::cache_session(const std::string& peer_id,
                                  const std::vector<unsigned char>& session_key,
                                  const std::vector<unsigned char>& nonce) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (session_key.size() != 32) {
        nativeLog("ERROR: Invalid session key size: " + std::to_string(session_key.size()));
        return;
    }
    
    auto session = std::make_shared<CachedSession>();
    session->peer_id = peer_id;
    session->session_key = session_key;
    session->nonce = nonce;
    session->created_at = std::chrono::steady_clock::now();
    session->last_used = session->created_at;
    session->usage_count = 0;
    session->is_valid = true;
    
    m_cache[peer_id] = session;
    nativeLog("SessionCache: Cached session for " + peer_id + " (saves handshake on reconnect)");
}

std::shared_ptr<CachedSession> SessionCache::get_cached_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_cache.find(peer_id);
    if (it == m_cache.end()) {
        m_cache_misses++;
        return nullptr;
    }
    
    auto session = it->second;
    
    // Check if expired
    if (session->is_expired()) {
        nativeLog("SessionCache: Session expired for " + peer_id);
        m_cache.erase(it);
        m_cache_misses++;
        return nullptr;
    }
    
    // Update usage stats
    session->last_used = std::chrono::steady_clock::now();
    session->usage_count++;
    m_cache_hits++;
    
    nativeLog("SessionCache: Cache HIT for " + peer_id + " (avoided handshake!)");
    return session;
}

void SessionCache::invalidate_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_cache.find(peer_id);
    if (it != m_cache.end()) {
        nativeLog("SessionCache: Invalidated session for " + peer_id);
        m_cache.erase(it);
    }
}

void SessionCache::clear_all() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int count = m_cache.size();
    m_cache.clear();
    m_cache_hits = 0;
    m_cache_misses = 0;
    
    nativeLog("SessionCache: Cleared all " + std::to_string(count) + " cached sessions");
}

int SessionCache::get_cached_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cache.size();
}

int SessionCache::get_hit_rate() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    int total = m_cache_hits + m_cache_misses;
    if (total == 0) return 0;
    
    return (m_cache_hits * 100) / total;
}

void SessionCache::cleanup_expired() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_cache.begin();
    int removed = 0;
    
    while (it != m_cache.end()) {
        if (it->second->is_expired()) {
            nativeLog("SessionCache: Cleaning up expired session for " + it->first);
            it = m_cache.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    if (removed > 0) {
        nativeLog("SessionCache: Cleaned up " + std::to_string(removed) + " expired sessions");
    }
}
