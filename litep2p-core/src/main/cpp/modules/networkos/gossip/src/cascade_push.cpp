// Network OS Phase 13 — cascade + push bridge implementations.

#include "networkos/gossip/discovery_cascade.h"
#include "networkos/gossip/push_bridge.h"

#include <mutex>
#include <vector>

namespace networkos {
namespace gossip {

const char* cascade_tier_name(CascadeTier t) {
    switch (t) {
        case CascadeTier::kCache: return "cache";
        case CascadeTier::kGossip: return "gossip";
        case CascadeTier::kPush: return "push";
        case CascadeTier::kSignalingPool: return "signaling_pool";
        case CascadeTier::kExhausted: return "exhausted";
    }
    return "unknown";
}

void DiscoveryCascade::setCacheHandler(TierFn fn) { m_cache = std::move(fn); }
void DiscoveryCascade::setGossipHandler(TierFn fn) { m_gossip = std::move(fn); }
void DiscoveryCascade::setPushHandler(TierFn fn) { m_push = std::move(fn); }
void DiscoveryCascade::setSignalingPoolHandler(TierFn fn) { m_pool = std::move(fn); }

bool DiscoveryCascade::runTier_(const TierFn& fn, const std::string& peer_id,
                                PeerRecord& out) {
    return fn && fn(peer_id, out) && !out.peer_id.empty();
}

CascadeTier DiscoveryCascade::resolve(const std::string& peer_id,
                                      PeerRecord& out) {
    if (runTier_(m_cache, peer_id, out)) {
        ++m_counters.hits;
        ++m_counters.tier_hits[0];
        return CascadeTier::kCache;
    }
    if (runTier_(m_gossip, peer_id, out)) {
        ++m_counters.hits;
        ++m_counters.tier_hits[1];
        return CascadeTier::kGossip;
    }
    if (runTier_(m_push, peer_id, out)) {
        ++m_counters.hits;
        ++m_counters.tier_hits[2];
        return CascadeTier::kPush;
    }
    if (runTier_(m_pool, peer_id, out)) {
        ++m_counters.hits;
        ++m_counters.tier_hits[3];
        return CascadeTier::kSignalingPool;
    }
    ++m_counters.exhausted;
    return CascadeTier::kExhausted;
}

// ---- push bridge ------------------------------------------------------------

namespace {
std::mutex g_push_mu;
PushTriggerFn g_push_bridge = nullptr;
}  // namespace

void setPushTriggerBridge(PushTriggerFn fn) {
    std::lock_guard<std::mutex> lock(g_push_mu);
    g_push_bridge = fn;
}

PushTriggerFn pushTriggerBridge() {
    std::lock_guard<std::mutex> lock(g_push_mu);
    return g_push_bridge;
}

bool parse_push_payload(const std::string& json, PushPayload& out) {
    // Strict minimal parser for the fixed schema; no nested objects.
    auto find_str = [&json](const std::string& key, size_t from,
                            std::string& v) -> bool {
        const std::string pat = "\"" + key + "\":\"";
        size_t p = json.find(pat, from);
        if (p == std::string::npos) return false;
        p += pat.size();
        size_t e = json.find('"', p);
        if (e == std::string::npos || e - p > 4096) return false;
        v.assign(json, p, e - p);
        return true;
    };
    if (json.find("\"type\":\"candidates\"") != std::string::npos) {
        out.type = PushPayload::Type::kCandidates;
    } else if (json.find("\"type\":\"wake\"") != std::string::npos) {
        out.type = PushPayload::Type::kWake;
    } else {
        return false;
    }
    if (!find_str("peer_id", 0, out.peer_id)) return false;

    // nonce (optional for wake).
    const std::string nonce_pat = "\"nonce\":";
    size_t np = json.find(nonce_pat);
    out.nonce = 0;
    if (np != std::string::npos) {
        out.nonce = static_cast<uint32_t>(
            std::strtoul(json.c_str() + np + nonce_pat.size(), nullptr, 10));
    }

    // candidates array (optional; only meaningful for kCandidates).
    out.candidates.clear();
    const std::string arr_pat = "\"candidates\":[";
    size_t ap = json.find(arr_pat);
    if (ap != std::string::npos) {
        ap += arr_pat.size();
        // Quote-aware scan for the array-closing ']' — a naive find(']')
        // would stop at ']' inside IPv6 literals like "[::1]:6".
        size_t arr_end = std::string::npos;
        bool in_str = false;
        for (size_t i = ap; i < json.size(); ++i) {
            const char c = json[i];
            if (in_str) {
                if (c == '\\') {
                    ++i;  // skip escaped char
                } else if (c == '"') {
                    in_str = false;
                }
            } else if (c == '"') {
                in_str = true;
            } else if (c == ']') {
                arr_end = i;
                break;
            }
        }
        if (arr_end == std::string::npos || arr_end - ap > 2048) return false;
        while (ap < arr_end && out.candidates.size() < 8) {
            size_t q1 = json.find('"', ap);
            if (q1 == std::string::npos || q1 >= arr_end) break;
            size_t q2 = json.find('"', q1 + 1);
            if (q2 == std::string::npos || q2 > arr_end) break;
            if (q2 - q1 - 1 <= 128) {
                out.candidates.emplace_back(json, q1 + 1, q2 - q1 - 1);
            }
            ap = q2 + 1;
        }
    }
    return !out.candidates.empty() || out.type == PushPayload::Type::kWake;
}

}  // namespace gossip
}  // namespace networkos