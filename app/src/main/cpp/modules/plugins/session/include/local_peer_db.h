#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct Peer;

class LocalPeerDb {
public:
    struct Options {
        std::string path;
        bool enable = true;
        int default_candidate_limit = 50;
    };

    struct PeerRecord {
        std::string peer_id;
        std::string network_id;
        std::string ip;
        int port = 0;
        bool connectable = false;
        int64_t last_seen_ms = 0;
        int64_t last_connected_ms = 0;
    };

    LocalPeerDb();
    ~LocalPeerDb();

    LocalPeerDb(const LocalPeerDb&) = delete;
    LocalPeerDb& operator=(const LocalPeerDb&) = delete;

    bool open(const Options& options);
    void close();

    bool is_open() const;
    std::string path() const;

    // Upsert peer endpoint and freshness timestamps.
    void upsert_peer(const std::string& peer_id,
                     const std::string& network_id,
                     const std::string& ip,
                     int port,
                     bool connectable,
                     int64_t last_seen_ms,
                     int64_t last_discovery_ms);

    // Record connection state transitions.
    void set_peer_connected(const std::string& peer_id, bool connected, int64_t now_ms);

    // Fetch candidates for DB-first reconnect.
    std::vector<PeerRecord> get_reconnect_candidates(int limit);

    // Returns true if the peers table contains at least one row.
    bool has_any_peers();

    // Delete stale peers (excluding never_delete=1).
    // A peer is stale if:
    //  - last_connected_ms > 0 and is older than now - prune_after_days
    //  - OR last_connected_ms == 0 and first_seen_ms is older than now - prune_after_days
    void prune_stale_peers(int prune_after_days);

private:
    struct Impl;
    std::unique_ptr<Impl> m;
};
