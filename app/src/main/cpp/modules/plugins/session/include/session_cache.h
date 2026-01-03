#ifndef SESSION_CACHE_H
#define SESSION_CACHE_H

#include <string>
#include <memory>
#include <map>
#include <mutex>
#include <vector>
#include <chrono>

// Session cache to avoid expensive re-handshaking
// Stores encrypted session keys for quick resumption
// Significantly reduces battery drain on reconnects

struct CachedSession {
    std::string peer_id;
    std::vector<unsigned char> session_key;      // 32 bytes
    std::vector<unsigned char> nonce;            // 8 bytes
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_used;
    int usage_count = 0;
    bool is_valid = true;
    int session_lifetime_sec = 3600;  // Default, can be set from config
    
    bool is_expired() const {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - created_at
        ).count();
        return elapsed > session_lifetime_sec;
    }
};

class SessionCache {
public:
    SessionCache();
    ~SessionCache();

    // Cache a new session
    void cache_session(const std::string& peer_id, 
                       const std::vector<unsigned char>& session_key,
                       const std::vector<unsigned char>& nonce);

    // Retrieve cached session (returns nullptr if not found or expired)
    std::shared_ptr<CachedSession> get_cached_session(const std::string& peer_id);

    // Remove cached session
    void invalidate_session(const std::string& peer_id);

    // Clear all cached sessions
    void clear_all();

    // Get cache statistics
    int get_cached_count() const;
    int get_hit_rate() const;  // Percentage

    // Cleanup expired sessions (called periodically)
    void cleanup_expired();

private:
    std::map<std::string, std::shared_ptr<CachedSession>> m_cache;
    mutable std::mutex m_mutex;  // mutable for const getter methods
    
    int m_cache_hits = 0;
    int m_cache_misses = 0;
};

#endif // SESSION_CACHE_H
