// DiscoveryManager.cpp — Network OS Phase 9 modular discovery core.

#include "networkos/discovery/DiscoveryManager.h"

#include <algorithm>
#include <sstream>

namespace networkos {
namespace discovery {

DiscoveryManager::DiscoveryManager(const Config& cfg) : m_cfg(cfg) {
    m_local.peer_id = cfg.local_peer_id;
    m_local.storage_carrier = true;
    m_local.ha_node = false;
    m_local.relay_capable = false;
}

DiscoveryManager::~DiscoveryManager() = default;

// ---- Backend registration / control ----------------------------------------
void DiscoveryManager::registerBackend(std::unique_ptr<IDiscoveryBackend> backend) {
    if (!backend) return;
    std::lock_guard<std::mutex> lock(m_mu);
    // Replace an existing backend of the same kind (idempotent re-register).
    for (auto& b : m_backends) {
        if (b->kind() == backend->kind()) {
            b = std::move(backend);
            return;
        }
    }
    m_backends.push_back(std::move(backend));
}

IDiscoveryBackend* DiscoveryManager::find_(BackendKind kind) const {
    for (auto& b : m_backends) {
        if (b->kind() == kind) return b.get();
    }
    return nullptr;
}

void DiscoveryManager::setBackendEnabled(BackendKind kind, bool enabled) {
    std::lock_guard<std::mutex> lock(m_mu);
    if (auto* b = find_(kind)) b->setEnabled(enabled);
}

bool DiscoveryManager::backendEnabled(BackendKind kind) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto* b = find_(kind);
    return b && b->enabled();
}

bool DiscoveryManager::backendAvailable(BackendKind kind) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto* b = find_(kind);
    return b && b->available();
}

size_t DiscoveryManager::backendCount() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_backends.size();
}

// ---- Intensity scaling (Phase 8 resource profile) ---------------------------
void DiscoveryManager::setIntensity(uint8_t intensity) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_cfg.intensity = intensity;
}

uint8_t DiscoveryManager::intensity() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_cfg.intensity;
}

// ---- Discovery across enabled backends (bounded) ----------------------------
std::vector<DiscoveredPeer> DiscoveryManager::discover() {
    std::lock_guard<std::mutex> lock(m_mu);
    std::vector<DiscoveredPeer> out;
    if (!m_cfg.enabled) return out;
    // Intensity scales how many peers we scan for per backend (§42/P8): at 0
    // discovery is effectively off-demand. Bounded by intensity and a cap.
    const int per_backend = m_cfg.intensity == 0
        ? 0
        : std::max<int>(1, static_cast<int>(m_cfg.intensity) / 10);
    for (auto& b : m_backends) {
        if (!b->enabled() || !b->available()) continue;
        auto found = b->discover(per_backend);
        for (auto& p : found) {
            if (p.peer_id.empty() || p.peer_id == m_cfg.local_peer_id) continue;
            // Dedup against what we already collected this scan.
            bool dup = false;
            for (const auto& q : out) if (q.peer_id == p.peer_id) { dup = true; break; }
            if (dup) continue;
            m_known[p.peer_id] = p;      // bounded known-peer cache (§75)
            out.push_back(p);
        }
    }
    return out;
}

// ---- Graceful degradation (§15, invariant 19) ------------------------------
size_t DiscoveryManager::coreBackendCountUnlocked_() const {
    size_t n = 0;
    for (auto& b : m_backends) {
        if (!b->optional() && b->enabled() && b->available()) ++n;
    }
    return n;
}

size_t DiscoveryManager::coreBackendCount() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return coreBackendCountUnlocked_();
}

bool DiscoveryManager::functionalWithoutOptional() const {
    // The network functions if at least one NON-optional backend is usable.
    return coreBackendCount() > 0;
}

// ---- NAT/internet reachability layering (§73) ------------------------------
ReachPath DiscoveryManager::choosePath(const DiscoveredPeer& peer) const {
    if (peer.direct_reachable) return ReachPath::kDirect;
    if (peer.nat_traversable) return ReachPath::kNatTraversal;
    if (peer.relay_capable) return ReachPath::kRelay;
    return ReachPath::kStoreAndForward;
}

const char* DiscoveryManager::pathName(ReachPath p) {
    switch (p) {
        case ReachPath::kDirect: return "direct";
        case ReachPath::kNatTraversal: return "nat_traversal";
        case ReachPath::kRelay: return "relay";
        case ReachPath::kStoreAndForward: return "store_and_forward";
    }
    return "store_and_forward";
}

// ---- Carrier willingness + HA capabilities (§52/§79) -----------------------
void DiscoveryManager::setLocalCapabilities(bool storage_carrier, bool ha, bool relay_capable) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_local.storage_carrier = storage_carrier;
    m_local.ha_node = ha;
    m_local.relay_capable = relay_capable;
}

DiscoveredPeer DiscoveryManager::localCapabilities() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_local;
}

// ---- Peer exchange (bounded, dedup) ----------------------------------------
std::vector<DiscoveredPeer> DiscoveryManager::peerExchange(
    const std::vector<DiscoveredPeer>& incoming) {
    std::lock_guard<std::mutex> lock(m_mu);
    std::vector<DiscoveredPeer> merged;
    if (!m_cfg.peer_exchange_enabled) return merged;
    // Bound the exchange: never accept more than peer_exchange_max (§50/§9).
    const size_t cap = m_cfg.peer_exchange_max;
    size_t taken = 0;
    for (const auto& p : incoming) {
        if (taken >= cap) break;
        if (p.peer_id.empty() || p.peer_id == m_cfg.local_peer_id) continue;
        // Dedup against our known table (no flooding, no duplicates).
        auto it = m_known.find(p.peer_id);
        if (it == m_known.end()) {
            m_known[p.peer_id] = p;
            merged.push_back(p);
            ++taken;
        } else if (p.last_seen_ms > it->second.last_seen_ms) {
            it->second = p;   // fresher info wins
            merged.push_back(p);
            ++taken;
        }
    }
    return merged;
}

// ---- Serverless presence + alias fallback (Step 5.7, decision 11) ----------
void DiscoveryManager::notePeerSeen(const std::string& peer_id, int64_t at_ms) {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_last_seen.find(peer_id);
    if (it == m_last_seen.end() || at_ms > it->second) m_last_seen[peer_id] = at_ms;
}

bool DiscoveryManager::isPeerPresent(const std::string& peer_id, int64_t now_ms) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_last_seen.find(peer_id);
    if (it == m_last_seen.end()) return false;
    return (now_ms - it->second) <= m_cfg.presence_window_ms;
}

void DiscoveryManager::setAlias(const std::string& alias, const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_alias[alias] = peer_id;
}

std::string DiscoveryManager::resolveAlias(const std::string& alias) const {
    std::lock_guard<std::mutex> lock(m_mu);
    // Resolution order (decision 11): server directory first (optional — not
    // modeled here as a separate source), then the decentralized peer/known
    // table fallback. Returns empty when unresolvable.
    auto it = m_alias.find(alias);
    if (it != m_alias.end()) return it->second;
    // Fallback: match by known-peer id prefix (peer-exchange-learned names).
    for (const auto& kv : m_known) {
        if (kv.first == alias) return kv.first;
    }
    return "";
}

// ---- Telemetry --------------------------------------------------------------
std::string DiscoveryManager::telemetryJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream os;
    os << "{\"enabled\":" << (m_cfg.enabled ? "true" : "false")
       << ",\"intensity\":" << static_cast<int>(m_cfg.intensity)
       << ",\"backends\":" << m_backends.size()
       << ",\"core_backends\":" << coreBackendCountUnlocked_()
       << ",\"known_peers\":" << m_known.size()
       << ",\"aliases\":" << m_alias.size()
       << ",\"functional_without_optional\":"
       << (coreBackendCountUnlocked_() > 0 ? "true" : "false")
       << "}";
    return os.str();
}

std::unique_ptr<DiscoveryManager> createDiscoveryManager(
    const DiscoveryManager::Config& cfg) {
    return std::make_unique<DiscoveryManager>(cfg);
}

} // namespace discovery
} // namespace networkos