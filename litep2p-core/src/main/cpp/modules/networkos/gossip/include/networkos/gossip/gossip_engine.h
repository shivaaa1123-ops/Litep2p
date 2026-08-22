#pragma once

// Network OS Phase 13 — GossipEngine (signalling.md §1/§2).
//
// The persistent peer routing directory + delta gossip engine. Owns:
//   - the bounded PeerRecord table (version-gated merge, stale purge);
//   - delta production per connected peer (only records the peer has not
//     seen, capped per batch — cellular-friendly);
//   - the community signaling pool (gossiped HAS_SIGNALING addresses, ranked
//     round-robin, bad-node marking — signalling.md §2 fallback pool);
//   - FIND_PEER query/reply codec (neighborhood lookup, tier 2 of the
//     discovery cascade);
//   - atomic JSON persistence so the directory survives process death
//     ("durable state is the source of truth").
//
// Transport-agnostic: frames move via the injected SendFn (same pattern as
// DeliveryManager/HandoffManager), riding the encrypted session channel as
// PEER_RECORDS_DELTA / FIND_PEER_QUERY / FIND_PEER_REPLY.

#include "networkos/Runtime.h"
#include "networkos/gossip/peer_record.h"
#include "message_types.h"

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace networkos {
namespace gossip {

class GossipEngine {
public:
    struct Config {
        std::string local_peer_id;
        size_t max_records{512};          // bounded directory (§75-style cap)
        size_t delta_batch_max{32};       // records per PEER_RECORDS_DELTA
        uint64_t stale_after_s{7 * 24 * 3600};  // purge entries unseen this long
        std::string persist_path;         // empty = no persistence (tests)
        size_t signaling_pool_max{16};
    };

    // peer_id -> MessageType frame payload sender (injected by the runtime).
    using SendFn = std::function<bool(const std::string&, MessageType,
                                      const std::string&)>;
    // Optional hook: accepted record (new or newer) — the runtime feeds this
    // into DiscoveryManager::notePeerSeen / known-peer table.
    using AcceptedFn = std::function<void(const PeerRecord&)>;

    explicit GossipEngine(const Config& cfg);

    void setSendFn(SendFn fn);
    void setAcceptedFn(AcceptedFn fn);

    // ---- Local identity / push token ---------------------------------------
    // App forwarded a fresh FCM token: bumps the local token_version, marks
    // the local record dirty so the next delta carries HAS_NEW_TOKEN.
    void setLocalPushToken(const std::string& token, uint64_t now_utc);
    const PeerRecord& localRecord() const { return m_local; }

    // ---- Directory ----------------------------------------------------------
    // Version-gated ingest of one batch (decoded PEER_RECORDS_DELTA payload).
    // Returns the number of records accepted (new or strictly newer).
    size_t ingestDelta(const std::string& payload, uint64_t now_utc);
    // Build a bounded delta batch for one connected peer (records that peer
    // has not acknowledged yet), and remember what was sent.
    std::string buildDeltaFor(const std::string& peer_id, uint64_t now_utc);
    // Purge entries unseen for stale_after_s. Returns purged count.
    size_t purgeStale(uint64_t now_utc);
    size_t size() const;
    bool lookup(const std::string& peer_id, PeerRecord& out) const;

    // ---- Community signaling pool (§2) --------------------------------------
    void signalingPoolAdd(const std::string& url);
    // Ranked round-robin: least-recently-used of the best-scored entries.
    bool signalingPoolNext(std::string& out_url);
    void signalingPoolMarkBad(const std::string& url);

    // ---- FIND_PEER (cascade tier 2) -----------------------------------------
    static std::string encodeFindPeer(const std::string& target_peer_id,
                                      uint32_t nonce);
    static bool decodeFindPeer(const std::string& payload,
                               std::string& target_peer_id, uint32_t& nonce);
    // Reply carries the record when known (flagged), else an explicit miss.
    static std::string encodeFindReply(const PeerRecord* record /*nullable*/,
                                       uint32_t nonce);
    static bool decodeFindReply(const std::string& payload, PeerRecord& out,
                                bool& found, uint32_t& nonce);

    // ---- Frame entry points (wired by the runtime) ---------------------------
    void onFrame(const std::string& peer_id, MessageType type,
                 const std::string& payload, uint64_t now_utc);
    // Opportunistic tick: push a bounded delta to every connected peer.
    // Called from wakeup windows / connectivity events — never a timer.
    void tick(const std::vector<std::string>& connected_peers, uint64_t now_utc);

    // ---- Persistence (atomic tmp+rename, FileIdentityStore precedent) -------
    bool save(uint64_t now_utc);
    bool load();

    std::string telemetryJson() const;

private:
    void evictIfNeededLocked_();

    Config m_cfg;
    PeerRecord m_local;                                    // self record
    mutable std::mutex m_mu;
    std::unordered_map<std::string, PeerRecord> m_records; // routing directory
    std::map<std::string, uint64_t> m_sent_version;        // peer -> max version sent
    struct PoolEntry {
        std::string url;
        int failures{0};
        int64_t last_used_ms{0};
    };
    std::vector<PoolEntry> m_pool;                          // community signaling
    SendFn m_send;
    AcceptedFn m_accepted;
    // Unlocked helpers — callers must hold m_mu (prevents self-deadlock, cf.
    // the P3 open() audit fix).
    void poolAddLocked_(const std::string& url);
    // Counters (telemetry).
    uint64_t m_delta_sent{0}, m_delta_recv{0}, m_accepted_total{0};
    uint64_t m_find_hit{0}, m_find_miss{0};
    int64_t m_dirty_since_ms{0};
};

}  // namespace gossip
}  // namespace networkos