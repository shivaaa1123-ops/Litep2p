#pragma once

// Network OS Phase 13 — Discovery Cascade (signalling.md §1).
//
// The ordered fallback state machine used when the app requests a connection
// to a target PeerID:
//
//   1. LOCAL CACHE   — routing directory lookup (instant, free)
//   2. GOSSIP        — FIND_PEER query to active UDP neighbors
//   3. PUSH TRIGGER  — out-of-band FCM payload carrying NAT candidates
//   4. SIGNALING POOL— community/global signaling fallback (gossiped pool)
//
// Tiers are injectable functionals, so the cascade logic is fully testable
// without sockets; the runtime binds them to the real mechanisms (directory,
// session frames, push bridge, signaling client). First tier that produces a
// usable PeerRecord wins; exhaustion is reported honestly.

#include "networkos/gossip/gossip_engine.h"

#include <cstdint>
#include <functional>
#include <string>

namespace networkos {
namespace gossip {

enum class CascadeTier : uint8_t {
    kCache = 0,
    kGossip = 1,
    kPush = 2,
    kSignalingPool = 3,
    kExhausted = 0xFF,
};

const char* cascade_tier_name(CascadeTier t);

class DiscoveryCascade {
public:
    // Tier handler: returns true + fills `out` when this tier resolved.
    using TierFn = std::function<bool(const std::string& peer_id, PeerRecord& out)>;

    struct Counters {
        uint64_t hits{0}, exhausted{0};
        uint64_t tier_hits[4]{0, 0, 0, 0};
    };

    void setCacheHandler(TierFn fn);          // default: engine->lookup
    void setGossipHandler(TierFn fn);         // FIND_PEER over connected peers
    void setPushHandler(TierFn fn);           // FCM trigger dispatch
    void setSignalingPoolHandler(TierFn fn);  // community pool probe

    // Runs the cascade synchronously in tier order. Returns the winning tier;
    // kExhausted when every tier failed (`out` untouched then).
    CascadeTier resolve(const std::string& peer_id, PeerRecord& out);

    const Counters& counters() const { return m_counters; }

private:
    bool runTier_(const TierFn& fn, const std::string& peer_id, PeerRecord& out);

    TierFn m_cache, m_gossip, m_push, m_pool;
    Counters m_counters;
};

}  // namespace gossip
}  // namespace networkos