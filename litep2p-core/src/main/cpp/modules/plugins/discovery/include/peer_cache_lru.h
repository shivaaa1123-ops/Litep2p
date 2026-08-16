#ifndef PEER_CACHE_LRU_H
#define PEER_CACHE_LRU_H

//#include "peer.h"
#include "../../session/include/peer.h"
#include <unordered_map>
#include <list>
#include <mutex>
#include <memory>

/**
 * LRU Cache for peer hot-set optimization
 * Keeps frequently accessed peers in fast cache, archives cold peers
 * Useful for 50,000+ peers where you can't keep all in memory
 * Trade-off: Some latency for archive/restore, massive memory savings
 */
class PeerCacheLRU {
public:
    explicit PeerCacheLRU(size_t max_hot_peers = 5000);
    ~PeerCacheLRU() = default;

    // Add or access peer (moves to hot if in archive)
    Peer* get_or_restore(const std::string& peer_id);

    // Get from hot cache only (fast, no restore)
    Peer* get_hot(const std::string& peer_id);

    // Add peer to hot cache
    bool add_hot(const Peer& peer);

    // Archive peer (move to disk/archive)
    bool archive_peer(const std::string& peer_id);

    // Evict least recently used peer from hot cache
    bool evict_lru();

    // Get hot cache statistics
    struct Stats {
        size_t hot_count = 0;
        size_t archived_count = 0;
        size_t cache_hits = 0;
        size_t cache_misses = 0;
        float hit_rate_percent = 0.0f;
    };
    Stats get_stats() const;

    // Get hot peer count
    size_t hot_count() const;

private:
    mutable std::mutex m_mutex;
    size_t m_max_hot_peers;
    
    // Hot cache: frequently accessed peers
    std::unordered_map<std::string, std::shared_ptr<Peer>> m_hot_cache;
    
    // LRU tracking list
    std::list<std::string> m_lru_list;
    std::unordered_map<std::string, std::list<std::string>::iterator> m_lru_map;
    
    // Archive: cold peers (stub data only)
    struct ArchivedPeer {
        std::string id;
        std::string ip;
        int port;
    };
    std::unordered_map<std::string, ArchivedPeer> m_archived;
    
    size_t m_cache_hits = 0;
    size_t m_cache_misses = 0;
    
    void update_lru(const std::string& peer_id);
};

#endif // PEER_CACHE_LRU_H
