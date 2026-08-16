#include "overlay_mailbox.h"
#include "logger.h"

#include <algorithm>

namespace overlay {

OverlayMailbox::OverlayMailbox() : OverlayMailbox(Config()) {}

OverlayMailbox::OverlayMailbox(const Config& cfg) : m_cfg(cfg) {}

bool OverlayMailbox::over_limits_locked_(size_t extra_entry, size_t extra_bytes) const {
    return m_total_entries + extra_entry > m_cfg.max_entries ||
           m_total_bytes + extra_bytes > m_cfg.max_total_bytes;
}

void OverlayMailbox::evict_locked_(size_t need_entries, size_t need_bytes) {
    // Evict least-recently-touched whole boxes/entries until the prospective
    // additions fit. Never evict the box we are about to insert into unless it
    // is itself the LRU (in which case its own oldest entries go first).
    while (over_limits_locked_(need_entries, need_bytes) && !m_lru.empty()) {
        auto it = m_lru.begin();
        const std::string key = it->first;

        auto box_it = m_boxes.find(key);
        if (box_it == m_boxes.end() || box_it->second.empty()) {
            m_lru.erase(it);
            m_lru_it.erase(key);
            if (box_it != m_boxes.end()) m_boxes.erase(box_it);
            continue;
        }

        Entry& e = box_it->second.front();
        m_total_entries -= 1;
        m_total_bytes -= e.blob.size();
        box_it->second.pop_front();
        if (box_it->second.empty()) {
            m_lru.erase(it);
            m_lru_it.erase(key);
            m_boxes.erase(box_it);
        }
    }
}

bool OverlayMailbox::store(const std::string& pickup_key, const std::string& origin,
                           std::string blob, uint64_t now_ms) {
    if (pickup_key.empty() || origin.empty()) return false;
    if (blob.empty() || blob.size() > m_cfg.max_entry_bytes) return false;

    std::lock_guard<std::mutex> lock(m_mu);

    auto& box = m_boxes[pickup_key];

    // Per-origin quota: evict that origin's oldest entries in this box first.
    size_t origin_count = 0;
    for (const auto& e : box) {
        if (e.origin == origin) ++origin_count;
    }
    while (origin_count >= m_cfg.per_origin_quota) {
        bool removed = false;
        for (auto it = box.begin(); it != box.end(); ++it) {
            if (it->origin == origin) {
                m_total_entries -= 1;
                m_total_bytes -= it->blob.size();
                box.erase(it);
                --origin_count;
                removed = true;
                break;
            }
        }
        if (!removed) break;
    }

    evict_locked_(1, blob.size());
    if (over_limits_locked_(1, blob.size())) {
        // Still no room — refuse rather than silently drop the box's owner.
        if (box.empty()) m_boxes.erase(pickup_key);
        LOG_WARN("OVL mailbox: store refused (capacity), key=" + pickup_key.substr(0, 8));
        return false;
    }

    Entry e;
    e.origin = origin;
    e.blob = std::move(blob);
    e.stored_at_ms = now_ms;
    e.expires_at_ms = now_ms + m_cfg.default_ttl_ms;
    box.push_back(std::move(e));
    m_total_entries += 1;
    m_total_bytes += box.back().blob.size();

    // Touch LRU for this box.
    auto lit = m_lru_it.find(pickup_key);
    if (lit != m_lru_it.end()) {
        m_lru.erase(lit->second);
    }
    m_lru.emplace_back(pickup_key, ++m_next_seq);
    m_lru_it[pickup_key] = std::prev(m_lru.end());
    return true;
}

std::vector<std::string> OverlayMailbox::pickup(const std::string& pickup_key,
                                                size_t max, uint64_t now_ms) {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lock(m_mu);

    auto box_it = m_boxes.find(pickup_key);
    if (box_it == m_boxes.end()) return out;

    auto& box = box_it->second;
    while (!box.empty() && out.size() < max) {
        Entry& e = box.front();
        // Capture the size BEFORE the move below: a moved-from std::string is
        // guaranteed empty, so reading e.blob.size() after the move would
        // subtract 0 and leak the accounting forever (store-refusal bug).
        const size_t blob_size = e.blob.size();
        if (e.expires_at_ms > now_ms) {
            out.push_back(std::move(e.blob));
        }
        // Expired entries are silently discarded on pickup.
        m_total_entries -= 1;
        m_total_bytes -= blob_size;
        box.pop_front();
    }

    if (box.empty()) {
        auto lit = m_lru_it.find(pickup_key);
        if (lit != m_lru_it.end()) {
            m_lru.erase(lit->second);
            m_lru_it.erase(lit);
        }
        m_boxes.erase(box_it);
    }
    return out;
}

void OverlayMailbox::purge(uint64_t now_ms) {
    std::lock_guard<std::mutex> lock(m_mu);
    std::vector<std::string> dead_keys;
    for (auto& kv : m_boxes) {
        auto& box = kv.second;
        while (!box.empty() && box.front().expires_at_ms <= now_ms) {
            m_total_entries -= 1;
            m_total_bytes -= box.front().blob.size();
            box.pop_front();
        }
        if (box.empty()) dead_keys.push_back(kv.first);
    }
    for (const auto& k : dead_keys) {
        auto lit = m_lru_it.find(k);
        if (lit != m_lru_it.end()) {
            m_lru.erase(lit->second);
            m_lru_it.erase(lit);
        }
        m_boxes.erase(k);
    }
}

size_t OverlayMailbox::size() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_total_entries;
}

size_t OverlayMailbox::total_bytes() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_total_bytes;
}

size_t OverlayMailbox::entries_for(const std::string& pickup_key) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_boxes.find(pickup_key);
    return it == m_boxes.end() ? 0 : it->second.size();
}

} // namespace overlay
