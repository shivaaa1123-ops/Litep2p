#include "peer_index.h"
#include <algorithm>

PeerIndex::PeerIndex() = default;

bool PeerIndex::add_or_update(const Peer& peer) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    bool is_new = m_peers_by_id.find(peer.id) == m_peers_by_id.end();
    
    auto peer_ptr = std::make_shared<Peer>(peer);
    m_peers_by_id[peer.id] = peer_ptr;
    
    // Update secondary indices
    if (!peer.ip.empty()) {
        m_ip_to_id[peer.ip] = peer.id;
    }
    if (!peer.network_id.empty()) {
        m_network_id_to_id[peer.network_id] = peer.id;
    }
    
    return is_new;
}

Peer* PeerIndex::get_by_id(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peers_by_id.find(peer_id);
    if (it == m_peers_by_id.end()) return nullptr;
    return it->second.get();
}

const Peer* PeerIndex::get_by_id_const(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peers_by_id.find(peer_id);
    if (it == m_peers_by_id.end()) return nullptr;
    return it->second.get();
}

Peer* PeerIndex::get_by_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_ip_to_id.find(ip);
    if (it == m_ip_to_id.end()) return nullptr;
    
    auto peer_it = m_peers_by_id.find(it->second);
    if (peer_it == m_peers_by_id.end()) return nullptr;
    return peer_it->second.get();
}

Peer* PeerIndex::get_by_network_id(const std::string& network_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_network_id_to_id.find(network_id);
    if (it == m_network_id_to_id.end()) return nullptr;
    
    auto peer_it = m_peers_by_id.find(it->second);
    if (peer_it == m_peers_by_id.end()) return nullptr;
    return peer_it->second.get();
}

bool PeerIndex::remove(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peers_by_id.find(peer_id);
    if (it == m_peers_by_id.end()) return false;
    
    const auto& peer = *it->second;
    
    // Remove from secondary indices
    if (!peer.ip.empty()) {
        m_ip_to_id.erase(peer.ip);
    }
    if (!peer.network_id.empty()) {
        m_network_id_to_id.erase(peer.network_id);
    }
    
    m_peers_by_id.erase(it);
    return true;
}

std::vector<Peer> PeerIndex::get_all_peers() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<Peer> result;
    result.reserve(m_peers_by_id.size());
    
    for (const auto& pair : m_peers_by_id) {
        result.push_back(*pair.second);
    }
    
    return result;
}

std::vector<Peer> PeerIndex::get_connected_peers() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<Peer> result;
    for (const auto& pair : m_peers_by_id) {
        // Peer state is now managed by the FSM, so we can't directly check the connected field
        // For now, we'll return all peers
        result.push_back(*pair.second);
    }
    
    return result;
}

size_t PeerIndex::peer_count() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_peers_by_id.size();
}

bool PeerIndex::exists(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_peers_by_id.find(peer_id) != m_peers_by_id.end();
}

bool PeerIndex::update_status(const std::string& peer_id, bool connected) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_peers_by_id.find(peer_id);
    if (it == m_peers_by_id.end()) return false;
    
    // Peer state is now managed by the FSM, so we don't directly modify the connected field
    // This method is kept for API compatibility but doesn't modify the peer directly
    return true;
}

void PeerIndex::batch_update(const std::vector<Peer>& peers) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& peer : peers) {
        auto peer_ptr = std::make_shared<Peer>(peer);
        m_peers_by_id[peer.id] = peer_ptr;
        
        if (!peer.ip.empty()) {
            m_ip_to_id[peer.ip] = peer.id;
        }
        if (!peer.network_id.empty()) {
            m_network_id_to_id[peer.network_id] = peer.id;
        }
    }
}

void PeerIndex::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_peers_by_id.clear();
    m_ip_to_id.clear();
    m_network_id_to_id.clear();
}
