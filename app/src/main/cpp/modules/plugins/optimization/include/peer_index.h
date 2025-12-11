#ifndef PEER_INDEX_H
#define PEER_INDEX_H

#include "peer.h"
#include <unordered_map>
#include <mutex>
#include <vector>
#include <memory>

/**
 * Fast peer lookup index using HashMap
 * Replaces O(n) vector searches with O(1) HashMap lookups
 * Supports lookup by peer_id or IP address
 * Thread-safe with read-write semantics
 */
class PeerIndex {
public:
    PeerIndex();
    ~PeerIndex() = default;

    // Add or update peer (returns true if new peer)
    bool add_or_update(const Peer& peer);

    // Lookup peer by ID
    Peer* get_by_id(const std::string& peer_id);
    const Peer* get_by_id_const(const std::string& peer_id) const;

    // Lookup peer by IP
    Peer* get_by_ip(const std::string& ip);

    // Lookup peer by network_id (ip:port)
    Peer* get_by_network_id(const std::string& network_id);

    // Remove peer
    bool remove(const std::string& peer_id);

    // Get all peers (snapshot)
    std::vector<Peer> get_all_peers() const;

    // Get connected peers only
    std::vector<Peer> get_connected_peers() const;

    // Get peer count
    size_t peer_count() const;

    // Check if peer exists
    bool exists(const std::string& peer_id) const;

    // Update peer status
    bool update_status(const std::string& peer_id, bool connected);

    // Batch update peers
    void batch_update(const std::vector<Peer>& peers);

    // Clear all peers
    void clear();

private:
    mutable std::mutex m_mutex;
    
    // Main index by peer_id
    std::unordered_map<std::string, std::shared_ptr<Peer>> m_peers_by_id;
    
    // Secondary index by IP
    std::unordered_map<std::string, std::string> m_ip_to_id;  // IP -> peer_id
    
    // Secondary index by network_id
    std::unordered_map<std::string, std::string> m_network_id_to_id;  // network_id -> peer_id
};

#endif // PEER_INDEX_H
