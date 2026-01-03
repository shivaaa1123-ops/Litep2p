/**
 * local_peer_db.cpp
 * JSON file-based implementation of peer persistence.
 * Replaces SQLite to avoid dlopen issues on Android.
 */

#include "local_peer_db.h"
#include "../../../corep2p/core/include/logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <unordered_map>

using json = nlohmann::json;

// ============================================================================
// Helper: Check if IP is private (skip storing these)
// ============================================================================
static bool is_private_ip(const std::string& ip) {
    // IPv4 private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
    if (ip.find(':') != std::string::npos) {
        // IPv6 - simplified check for link-local and loopback
        if (ip.find("fe80") == 0 || ip.find("::1") == 0 || ip == "::1") {
            return true;
        }
        return false;
    }

    // IPv4
    unsigned int a, b, c, d;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return true;  // Invalid IP, treat as private
    }

    if (a == 10) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 127) return true;
    if (a == 0) return true;

    return false;
}

// ============================================================================
// Helper: Current time in milliseconds
// ============================================================================
static int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// Impl class
// ============================================================================
struct LocalPeerDb::Impl {
    Impl() = default;
    ~Impl() { close(); }

    bool open(const Options& opts);
    void close();
    bool is_open() const { return m_is_open; }
    const std::string& path() const { return m_path; }

    void upsert_peer(const std::string& peer_id,
                     const std::string& network_id,
                     const std::string& ip,
                     int port,
                     bool connectable,
                     int64_t last_seen_ms,
                     int64_t last_discovery_ms);

    void set_peer_connected(const std::string& peer_id, bool connected, int64_t now_ms);

    std::vector<PeerRecord> get_reconnect_candidates(int limit);
    bool has_any_peers();
    void prune_stale_peers(int prune_after_days);

private:
    bool load();
    bool save();
    bool save_atomic();

    std::string m_path;
    bool m_is_open = false;
    int m_default_limit = 50;
    mutable std::mutex m_mutex;

    // In-memory storage: key = "peer_id:network_id"
    struct PeerEntry {
        std::string peer_id;
        std::string network_id;
        std::string ip;
        int port = 0;
        bool connectable = false;
        int64_t first_seen_ms = 0;
        int64_t last_seen_ms = 0;
        int64_t last_discovery_ms = 0;
        int64_t last_connected_ms = 0;
        bool never_delete = false;
    };
    std::unordered_map<std::string, PeerEntry> m_peers;

    std::string make_key(const std::string& peer_id, const std::string& network_id) const {
        return peer_id + ":" + network_id;
    }
};

// ============================================================================
// Impl methods
// ============================================================================

bool LocalPeerDb::Impl::open(const Options& opts) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_is_open) {
        return true;
    }

    m_path = opts.path;
    m_default_limit = opts.default_candidate_limit > 0 ? opts.default_candidate_limit : 50;

    // Try to load existing data
    load();  // Ignore failure - file may not exist yet

    m_is_open = true;
    LOG_INFO("LocalPeerDb: Opened JSON peer database at " + m_path + 
             " (" + std::to_string(m_peers.size()) + " peers loaded)");
    return true;
}

void LocalPeerDb::Impl::close() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_open) {
        return;
    }

    save();  // Save any pending changes
    m_peers.clear();
    m_is_open = false;
    LOG_INFO("LocalPeerDb: Closed");
}

bool LocalPeerDb::Impl::load() {
    // Called with mutex held
    std::ifstream ifs(m_path);
    if (!ifs.is_open()) {
        LOG_DEBUG("LocalPeerDb: No existing file at " + m_path);
        return false;
    }

    try {
        json j;
        ifs >> j;

        if (!j.is_object() || !j.contains("peers")) {
            LOG_WARN("LocalPeerDb: Invalid JSON format");
            return false;
        }

        m_peers.clear();
        for (const auto& p : j["peers"]) {
            PeerEntry entry;
            entry.peer_id = p.value("peer_id", "");
            entry.network_id = p.value("network_id", "");
            entry.ip = p.value("ip", "");
            entry.port = p.value("port", 0);
            entry.connectable = p.value("connectable", false);
            entry.first_seen_ms = p.value("first_seen_ms", (int64_t)0);
            entry.last_seen_ms = p.value("last_seen_ms", (int64_t)0);
            entry.last_discovery_ms = p.value("last_discovery_ms", (int64_t)0);
            entry.last_connected_ms = p.value("last_connected_ms", (int64_t)0);
            entry.never_delete = p.value("never_delete", false);

            if (!entry.peer_id.empty() && !entry.network_id.empty()) {
                std::string key = make_key(entry.peer_id, entry.network_id);
                m_peers[key] = std::move(entry);
            }
        }

        LOG_DEBUG("LocalPeerDb: Loaded " + std::to_string(m_peers.size()) + " peers from JSON");
        return true;

    } catch (const std::exception& e) {
        LOG_WARN("LocalPeerDb: Failed to parse JSON: " + std::string(e.what()));
        return false;
    }
}

bool LocalPeerDb::Impl::save() {
    return save_atomic();
}

bool LocalPeerDb::Impl::save_atomic() {
    // Called with mutex held
    // Write to temp file then rename for atomicity

    std::string tmp_path = m_path + ".tmp";

    try {
        json j;
        j["version"] = 1;
        j["peers"] = json::array();

        for (const auto& kv : m_peers) {
            const PeerEntry& e = kv.second;
            json peer;
            peer["peer_id"] = e.peer_id;
            peer["network_id"] = e.network_id;
            peer["ip"] = e.ip;
            peer["port"] = e.port;
            peer["connectable"] = e.connectable;
            peer["first_seen_ms"] = e.first_seen_ms;
            peer["last_seen_ms"] = e.last_seen_ms;
            peer["last_discovery_ms"] = e.last_discovery_ms;
            peer["last_connected_ms"] = e.last_connected_ms;
            peer["never_delete"] = e.never_delete;
            j["peers"].push_back(peer);
        }

        std::ofstream ofs(tmp_path);
        if (!ofs.is_open()) {
            LOG_ERROR("LocalPeerDb: Cannot write temp file " + tmp_path);
            return false;
        }

        ofs << j.dump(2);
        ofs.close();

        if (ofs.fail()) {
            LOG_ERROR("LocalPeerDb: Failed to write temp file");
            std::remove(tmp_path.c_str());
            return false;
        }

        // Atomic rename
        if (std::rename(tmp_path.c_str(), m_path.c_str()) != 0) {
            LOG_ERROR("LocalPeerDb: Failed to rename temp file to " + m_path);
            std::remove(tmp_path.c_str());
            return false;
        }

        LOG_DEBUG("LocalPeerDb: Saved " + std::to_string(m_peers.size()) + " peers to JSON");
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("LocalPeerDb: Exception during save: " + std::string(e.what()));
        std::remove(tmp_path.c_str());
        return false;
    }
}

void LocalPeerDb::Impl::upsert_peer(const std::string& peer_id,
                                     const std::string& network_id,
                                     const std::string& ip,
                                     int port,
                                     bool connectable,
                                     int64_t last_seen_ms_param,
                                     int64_t last_discovery_ms_param) {
    // Skip private IPs
    if (is_private_ip(ip)) {
        LOG_DEBUG("LocalPeerDb: Skipping private IP " + ip + " for peer " + peer_id);
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_open) {
        return;
    }

    std::string key = make_key(peer_id, network_id);
    int64_t now = now_ms();

    auto it = m_peers.find(key);
    if (it != m_peers.end()) {
        // Update existing
        it->second.ip = ip;
        it->second.port = port;
        it->second.connectable = connectable;
        it->second.last_seen_ms = last_seen_ms_param > 0 ? last_seen_ms_param : now;
        it->second.last_discovery_ms = last_discovery_ms_param > 0 ? last_discovery_ms_param : now;
    } else {
        // Insert new
        PeerEntry entry;
        entry.peer_id = peer_id;
        entry.network_id = network_id;
        entry.ip = ip;
        entry.port = port;
        entry.connectable = connectable;
        entry.first_seen_ms = now;
        entry.last_seen_ms = last_seen_ms_param > 0 ? last_seen_ms_param : now;
        entry.last_discovery_ms = last_discovery_ms_param > 0 ? last_discovery_ms_param : now;
        entry.last_connected_ms = 0;
        entry.never_delete = false;
        m_peers[key] = std::move(entry);
    }

    // Save after each upsert (can be optimized with batching later)
    save();
}

void LocalPeerDb::Impl::set_peer_connected(const std::string& peer_id, 
                                            bool connected, 
                                            int64_t now_ms_param) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_open) {
        return;
    }

    // Find all entries for this peer_id (across all network_ids)
    for (auto& kv : m_peers) {
        if (kv.second.peer_id == peer_id) {
            if (connected) {
                kv.second.last_connected_ms = now_ms_param > 0 ? now_ms_param : now_ms();
                kv.second.last_seen_ms = kv.second.last_connected_ms;
            }
            // Note: if !connected, we just leave the last_connected_ms as is
        }
    }

    save();
}

std::vector<LocalPeerDb::PeerRecord> LocalPeerDb::Impl::get_reconnect_candidates(int limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_open) {
        return {};
    }

    int actual_limit = (limit > 0) ? limit : m_default_limit;

    // Collect all peers and sort by priority
    // Priority: recently connected > recently seen > older
    std::vector<std::pair<const std::string*, const PeerEntry*>> sorted;
    sorted.reserve(m_peers.size());

    for (const auto& kv : m_peers) {
        sorted.push_back({&kv.first, &kv.second});
    }

    // Sort: higher last_connected_ms first, then higher last_seen_ms
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) {
            // Prioritize connected peers
            if (a.second->last_connected_ms != b.second->last_connected_ms) {
                return a.second->last_connected_ms > b.second->last_connected_ms;
            }
            return a.second->last_seen_ms > b.second->last_seen_ms;
        });

    std::vector<PeerRecord> result;
    result.reserve(std::min<size_t>(actual_limit, sorted.size()));

    for (size_t i = 0; i < sorted.size() && (int)i < actual_limit; ++i) {
        const PeerEntry& e = *sorted[i].second;
        PeerRecord rec;
        rec.peer_id = e.peer_id;
        rec.network_id = e.network_id;
        rec.ip = e.ip;
        rec.port = e.port;
        rec.connectable = e.connectable;
        rec.last_seen_ms = e.last_seen_ms;
        rec.last_connected_ms = e.last_connected_ms;
        result.push_back(std::move(rec));
    }

    return result;
}

bool LocalPeerDb::Impl::has_any_peers() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_is_open && !m_peers.empty();
}

void LocalPeerDb::Impl::prune_stale_peers(int prune_after_days) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_is_open) {
        return;
    }

    int64_t now = now_ms();
    int64_t max_age_ms = static_cast<int64_t>(prune_after_days) * 24 * 60 * 60 * 1000;
    int64_t cutoff = now - max_age_ms;
    int pruned = 0;

    for (auto it = m_peers.begin(); it != m_peers.end(); ) {
        // Skip never_delete peers
        if (it->second.never_delete) {
            ++it;
            continue;
        }

        bool is_stale = false;

        if (it->second.last_connected_ms > 0) {
            // Peer was connected at some point - check last_connected_ms
            is_stale = (it->second.last_connected_ms < cutoff);
        } else {
            // Never connected - check first_seen_ms
            is_stale = (it->second.first_seen_ms < cutoff);
        }

        if (is_stale) {
            LOG_DEBUG("LocalPeerDb: Pruning stale peer " + it->second.peer_id);
            it = m_peers.erase(it);
            ++pruned;
        } else {
            ++it;
        }
    }

    if (pruned > 0) {
        save();
        LOG_INFO("LocalPeerDb: Pruned " + std::to_string(pruned) + " stale peers");
    }
}

// ============================================================================
// Public API (delegating to Impl)
// ============================================================================

LocalPeerDb::LocalPeerDb() : m(std::make_unique<Impl>()) {}
LocalPeerDb::~LocalPeerDb() = default;

bool LocalPeerDb::open(const Options& opts) {
    if (!opts.enable) {
        LOG_INFO("LocalPeerDb: Disabled by configuration");
        return false;
    }
    return m->open(opts);
}

void LocalPeerDb::close() {
    m->close();
}

bool LocalPeerDb::is_open() const {
    return m->is_open();
}

std::string LocalPeerDb::path() const {
    return m->path();
}

void LocalPeerDb::upsert_peer(const std::string& peer_id,
                              const std::string& network_id,
                              const std::string& ip,
                              int port,
                              bool connectable,
                              int64_t last_seen_ms,
                              int64_t last_discovery_ms) {
    m->upsert_peer(peer_id, network_id, ip, port, connectable, last_seen_ms, last_discovery_ms);
}

void LocalPeerDb::set_peer_connected(const std::string& peer_id,
                                     bool connected,
                                     int64_t now_ms) {
    m->set_peer_connected(peer_id, connected, now_ms);
}

std::vector<LocalPeerDb::PeerRecord> LocalPeerDb::get_reconnect_candidates(int limit) {
    return m->get_reconnect_candidates(limit);
}

bool LocalPeerDb::has_any_peers() {
    return m->has_any_peers();
}

void LocalPeerDb::prune_stale_peers(int prune_after_days) {
    m->prune_stale_peers(prune_after_days);
}
