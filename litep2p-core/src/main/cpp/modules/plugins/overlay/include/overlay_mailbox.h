#ifndef OVERLAY_MAILBOX_H
#define OVERLAY_MAILBOX_H

/*
 * overlay_mailbox.h — store-and-forward mailboxes for offline peers.
 *
 * When a destination is unreachable (offline, behind a hard NAT, or the
 * network is partitioned), the origin can ask a relay to HOLD a sealed blob
 * until the destination picks it up. This is what lets protest-time messages
 * survive network shutdowns and mass arrests of relay nodes.
 *
 * Abuse resistance (a mailbox must not become a free disk for strangers):
 *   - Bounded total capacity (entry count + total bytes), LRU eviction.
 *   - Per-origin quota (max stored entries per sender).
 *   - TTL expiry (default 24h) enforced by a purge tick.
 *   - The relay CANNOT read stored blobs: they are sealed to the destination
 *     before they ever reach the mailbox. Keying is by blake2b-16 of the
 *     destination peer id — the relay learns only an opaque pickup key.
 */

#include <cstdint>
#include <deque>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace overlay {

class OverlayMailbox {
public:
    struct Config {
        size_t max_entries{1000};              // total entries across all boxes
        size_t max_total_bytes{16u * 1024u * 1024u};
        size_t max_entry_bytes{1000};          // one LPX2-sized sealed blob
        size_t per_origin_quota{64};           // max entries stored per sender
        uint64_t default_ttl_ms{24ull * 60 * 60 * 1000};  // 24 hours
    };

    OverlayMailbox();                            // Config{} defaults
    explicit OverlayMailbox(const Config& cfg);

    // Store `blob` (sealed to the destination, opaque to us) under `pickup_key`
    // on behalf of `origin`. Returns false when the blob is too large or the
    // origin is over its quota and nothing could be evicted.
    bool store(const std::string& pickup_key, const std::string& origin,
               std::string blob, uint64_t now_ms);

    // Remove and return up to `max` blobs for `pickup_key`, oldest first.
    std::vector<std::string> pickup(const std::string& pickup_key, size_t max,
                                    uint64_t now_ms);

    // Drop expired entries. Call periodically from the router tick.
    void purge(uint64_t now_ms);

    size_t size() const;
    size_t total_bytes() const;
    size_t entries_for(const std::string& pickup_key) const;

private:
    struct Entry {
        std::string origin;
        std::string blob;
        uint64_t stored_at_ms{0};
        uint64_t expires_at_ms{0};
    };

    void evict_locked_(size_t need_entries, size_t need_bytes);
    bool over_limits_locked_(size_t extra_entry, size_t extra_bytes) const;

    Config m_cfg;
    mutable std::mutex m_mu;

    // pickup_key -> FIFO of entries.
    std::unordered_map<std::string, std::deque<Entry>> m_boxes;
    // LRU of (pickup_key, seq) for global capacity eviction.
    std::list<std::pair<std::string, uint64_t>> m_lru;
    std::unordered_map<std::string, std::list<std::pair<std::string, uint64_t>>::iterator> m_lru_it;
    uint64_t m_next_seq{0};
    size_t m_total_entries{0};
    size_t m_total_bytes{0};
};

} // namespace overlay

#endif // OVERLAY_MAILBOX_H
