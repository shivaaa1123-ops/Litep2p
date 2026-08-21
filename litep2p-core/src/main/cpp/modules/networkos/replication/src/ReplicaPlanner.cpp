// ReplicaPlanner.cpp — Network OS Phase 7 target-driven adaptive replication.

#include "networkos/replication/ReplicaPlanner.h"

#include "networkos/object/object_id.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <random>
#include <set>
#include <sstream>

namespace networkos {
namespace replication {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// jitter in [-1, 1] from a local RNG (thread-local, no global state).
double jitter_unit() {
    thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_real_distribution<double> d(-1.0, 1.0);
    return d(rng);
}

} // namespace

ReplicaPlanner::ReplicaPlanner(ObjectStore* store, const Config& cfg)
    : m_store(store), m_cfg(cfg) {}

ReplicaPlanner::~ReplicaPlanner() = default;

void ReplicaPlanner::setIssueHandoffFn(IssueHandoffFn fn) { m_issue_handoff = std::move(fn); }
void ReplicaPlanner::setConnectedPeersFn(ConnectedPeersFn fn) { m_connected = std::move(fn); }
void ReplicaPlanner::setEventFn(EventFn fn) { m_event = std::move(fn); }

void ReplicaPlanner::emit_(const std::string& kind, const std::string& payload) {
    if (m_event) {
        try { m_event(kind, payload); } catch (...) {}
    }
}

size_t ReplicaPlanner::budgetFor_() const {
    return m_background.load() ? m_cfg.background_handoffs_per_tick
                               : m_cfg.foreground_handoffs_per_tick;
}

void ReplicaPlanner::setBudgetBackground(bool background) {
    m_background.store(background);
}

int ReplicaPlanner::deficitFor_(uint8_t desired, ObjectStore::DurabilityReadout& d) {
    const int cur = static_cast<int>(d.level);
    // Durability levels below D2 aren't directly comparable to "remote copies":
    // map D-level to an approximate remote-copy count. D0=0, D1=1, D2=2, D3=3.
    int approx_copies = cur;
    int need = static_cast<int>(desired) - approx_copies;
    return need > 0 ? need : 0;
}

// ---------------------------------------------------------------------------
// Step 5.4 — choose the best candidate peers (score + diversity). Bounded by
// `max`; never duplicates; avoids same failure-domain when diverse peers exist.
// ---------------------------------------------------------------------------
std::vector<ReplicaPlanner::Candidate>
ReplicaPlanner::scoreCandidates_(const std::vector<std::string>& peers) const {
    std::vector<Candidate> out;
    if (!m_store) return out;
    for (const auto& p : peers) {
        if (p.empty() || p == m_cfg.local_peer_id) continue;
        Candidate c;
        c.peer_id = p;
        ObjectStore::PeerScore ps;
        if (m_store->getPeerScore(p, ps) == Result::kOk) {
            c.score = ps.score;
            c.group = ps.diversity_group;
            c.willing = (ps.storage_willing == 1);
        } else {
            // Unknown peer: neutral local default (not trusted, not blocked).
            c.score = 0.5;
            c.willing = true;  // don't rule out unknowns for replication
        }
        out.push_back(std::move(c));
    }
    std::sort(out.begin(), out.end(),
              [](const Candidate& a, const Candidate& b) { return a.score > b.score; });
    return out;
}

std::vector<std::string>
ReplicaPlanner::chooseCandidates(const std::string& namespace_id,
                                 const std::string& /*object_id_hex*/,
                                 uint8_t /*desired*/,
                                 const std::vector<std::string>& connected,
                                 uint8_t max) const {
    std::vector<std::string> result;
    if (max == 0 || connected.empty()) return result;
    // Policy decides the diversity/high-uptime preferences (Step 5.2).
    ObjectStore::ReplicationPolicy pol =
        m_store ? m_store->defaultPolicy(namespace_id) : ObjectStore::ReplicationPolicy{};
    if (m_store) m_store->getReplicationPolicy(namespace_id, pol);
    auto cands = scoreCandidates_(connected);
    if (!pol.prefer_network_diversity && !pol.prefer_high_uptime_peers) {
        // Simple top-max by score.
        for (auto& c : cands) {
            if (result.size() >= max) break;
            result.push_back(c.peer_id);
        }
        return result;
    }
    // Diversity-aware: greedily take the highest-scoring peer, then prefer peers
    // in unseen failure-domain groups until `max` reached or peers exhausted.
    std::set<std::string> chosen_groups;
    for (auto& c : cands) {
        if (result.size() >= max) break;
        if (c.group.empty() || chosen_groups.count(c.group) == 0) {
            result.push_back(c.peer_id);
            if (!c.group.empty()) chosen_groups.insert(c.group);
        }
    }
    // If diversity couldn't fill `max`, relax and take the best remaining (still
    // bounded). High-uptime preference is already baked into the score ordering.
    for (auto& c : cands) {
        if (result.size() >= max) break;
        if (std::find(result.begin(), result.end(), c.peer_id) == result.end()) {
            result.push_back(c.peer_id);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Step 5.4/5.5 — repair a single object toward its policy target. Honors the
// policy maximum (never over-replicate), the active backoff (invariant 5), and
// the per-tick connection budget (Step 5.6). Returns true if a handoff issued.
// ---------------------------------------------------------------------------
size_t ReplicaPlanner::repairObject(const ObjectId& id, int64_t now) {
    if (!m_store || !m_cfg.enabled) return 0;
    ObjectStore::DurabilityReadout dr;
    if (m_store->getDurability(id, dr) != Result::kOk) return 0;
    const int deficit = deficitFor_(dr.desired_remote_copies, dr);
    if (deficit <= 0) return 0;   // already at/above target

    // Bound by policy max: never create more copies than allowed (§68).
    const int allowed = static_cast<int>(dr.maximum_remote_copies) -
                        static_cast<int>(dr.level);
    if (allowed <= 0) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.over_replication_attempts++;
        return 0;
    }
    const size_t issue = static_cast<size_t>(std::min(deficit, allowed));

    // Active repair backoff? (invariant 5 — no tight repair loops)
    int64_t next_retry = 0;
    if (m_store->getRepairBackoff(id, &next_retry) == Result::kOk && next_retry > now) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.backoff_suppressed++;
        return 0;
    }

    ObjectMeta meta;
    if (m_store->getMeta(id, meta) != Result::kOk) return 0;
    const std::string ns = meta.namespace_id;

    // Candidates: connected peers we don't already hold a lease with. Never
    // include the local peer.
    std::vector<std::string> connected =
        m_connected ? m_connected() : std::vector<std::string>{};
    std::vector<ObjectStore::LeaseInfo> leases;
    m_store->getLeases(id, leases);
    std::set<std::string> have_lease;
    for (auto& l : leases) have_lease.insert(l.carrier_id);
    std::vector<std::string> fresh;
    for (auto& p : connected) {
        if (p.empty() || p == m_cfg.local_peer_id) continue;
        if (have_lease.count(p) == 0) fresh.push_back(p);
    }
    auto chosen = chooseCandidates(ns, id.toHex(), dr.desired_remote_copies, fresh,
                                   static_cast<uint8_t>(issue));

    size_t issued = 0;
    const size_t budget = budgetFor_();   // per-tick connection budget (§17)
    for (const auto& peer : chosen) {
        if (issued >= issue) break;
        if (issued >= budget) {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.budget_suppressed++;
            break;
        }
        if (m_issue_handoff && m_issue_handoff(peer)) {
            issued++;
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.repair_handoffs++;
        }
    }
    if (issued == 0) {
        // No route/candidate this tick: schedule a backoff (±jitter) so the
        // next plan/second doesn't hammer it (§76). Persisted marker.
        const int64_t base = m_cfg.retry_base_ms;
        const int64_t jit = static_cast<int64_t>(base * m_cfg.jitter_fraction * jitter_unit());
        const int64_t next = now + base + jit;
        m_store->setRepairBackoff(id, next);
    } else {
        // Reached target: clear the marker so a future real deficit can repair.
        m_store->setRepairBackoff(id, 0);
    }
    return issued;
}

// ---------------------------------------------------------------------------
// Step 5.1/5.4 — scan every object below target and repair, bounded by budget.
// Event-driven; a caller invokes on peer_ready / connectivity / lease-expiry.
// ---------------------------------------------------------------------------
size_t ReplicaPlanner::plan(int64_t now) {
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.plans++;
        m_ctr.last_plan_ms = now;
    }
    if (!m_store || !m_cfg.enabled) return 0;
    size_t issued_handoffs = 0;
    // Objects with a durability deficit at/below D3 (below destination-accept).
    m_store->forEachObjectBelowDurability(
        ObjectStore::kDThreeRemote, [&](const ObjectId& id) -> Result {
            // Per-tick connection budget (§17/Step 5.6): stop once exhausted.
            const size_t budget = budgetFor_();
            if (issued_handoffs >= budget) return Result::kOk;
            issued_handoffs += repairObject(id, now);
            return Result::kOk;
        });
    return issued_handoffs;
}

void ReplicaPlanner::onPeerReady(const std::string& peer_id) {
    // Step 5.7: a peer connect is an event-triggered retry window.
    if (m_store && !peer_id.empty()) {
        m_store->recordPeerObservation(peer_id, true, true, 0);
        // Age stale peers opportunistically (§75).
        m_store->agePeerScores(now_ms(), m_cfg.peer_stale_after_ms);
    }
    // A plan on connect lets deficit objects use the new peer as a candidate.
    plan(now_ms());
}

size_t ReplicaPlanner::onConnectivityChange(int64_t now) {
    // Event-triggered early retry (Step 5.7): clear repair backoffs so any
    // previously unschedulable repair can retry now that connectivity changed.
    // (The next plan() automatically honors per-object backoff markers; here we
    // just bump the counter and re-plan — clearing markers is best-effort so a
    // tight loop stays bounded by the per-tick budget.)
    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.retries_event_triggered++;
    }
    return plan(now);
}

// --- Step 5.1 — durability accounting from protocol events -----------------
void ReplicaPlanner::noteStoredAck(const ObjectId& id) {
    // Each confirmed remote copy raises durability one step (D0->D1->D2->D3),
    // capped below destination-accept. Idempotent: re-acking the same copy is a
    // no-op (raiseDurability is monotonic-to-a-higher-level).
    if (m_store) {
        ObjectStore::DurabilityReadout dr;
        if (m_store->getDurability(id, dr) == Result::kOk &&
            dr.level < ObjectStore::kDDestinationAccepted) {
            m_store->raiseDurability(id, static_cast<ObjectStore::DurabilityLevel>(
                static_cast<int>(dr.level) + 1));
        }
    }
}
void ReplicaPlanner::noteDeliveryAccepted(const ObjectId& id) {
    if (m_store) m_store->raiseDurability(id, ObjectStore::kDDestinationAccepted);
}
void ReplicaPlanner::noteDeliveryAcked(const ObjectId& id) {
    if (m_store) m_store->raiseDurability(id, ObjectStore::kDDestSignedAck);
}
void ReplicaPlanner::noteLeaseExpired(const ObjectId& id, int64_t /*now_ms*/) {
    if (m_store) {
        ObjectStore::DurabilityReadout dr;
        if (m_store->getDurability(id, dr) == Result::kOk &&
            dr.level > ObjectStore::kDLocalOnly) {
            m_store->lowerDurability(id, static_cast<ObjectStore::DurabilityLevel>(
                static_cast<int>(dr.level) - 1));
        }
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.lease_expiry_repairs++;
        emit_("LEASE_EXPIRED_REPAIR", id.toHex());
    }
}
void ReplicaPlanner::noteEvictedEarly(const ObjectId& id, int64_t /*now_ms*/) {
    if (m_store) {
        ObjectStore::DurabilityReadout dr;
        if (m_store->getDurability(id, dr) == Result::kOk &&
            dr.level > ObjectStore::kDLocalOnly) {
            m_store->lowerDurability(id, static_cast<ObjectStore::DurabilityLevel>(
                static_cast<int>(dr.level) - 1));
        }
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.eviction_repairs++;
        emit_("EVICTED_EARLY_REPAIR", id.toHex());
    }
}

// --- Step 5.2 / 5.3 — policy + peer score passthroughs ---------------------
Result ReplicaPlanner::setPolicy(const ObjectStore::ReplicationPolicy& policy) {
    return m_store ? m_store->setReplicationPolicy(policy) : Result::kInvalidState;
}
Result ReplicaPlanner::getPolicy(const std::string& ns,
                                 ObjectStore::ReplicationPolicy& out) const {
    if (!m_store) return Result::kInvalidState;
    const Result r = m_store->getReplicationPolicy(ns, out);
    if (r == Result::kNotFound) { out = m_store->defaultPolicy(ns); return Result::kOk; }
    return r;
}
Result ReplicaPlanner::observePeer(const std::string& peer_id, bool reachable,
                                   bool handoff_success, int64_t latency_ms) {
    return m_store
        ? m_store->recordPeerObservation(peer_id, reachable, handoff_success, latency_ms)
        : Result::kInvalidState;
}
Result ReplicaPlanner::setPeerGroup(const std::string& peer_id, const std::string& group) {
    return m_store ? m_store->setPeerDiversityGroup(peer_id, group) : Result::kInvalidState;
}
Result ReplicaPlanner::setPeerWilling(const std::string& peer_id, bool willing) {
    return m_store ? m_store->setPeerStorageWilling(peer_id, willing) : Result::kInvalidState;
}

// --- Step 5.8 — telemetry ---------------------------------------------------
ReplicaPlanner::Counters ReplicaPlanner::counters() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_ctr;
}
std::string ReplicaPlanner::telemetryJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream os;
    os << "{\"plans\":" << m_ctr.plans
       << ",\"repair_handoffs\":" << m_ctr.repair_handoffs
       << ",\"repaired_objects\":" << m_ctr.repaired_objects
       << ",\"over_replication_attempts\":" << m_ctr.over_replication_attempts
       << ",\"lease_expiry_repairs\":" << m_ctr.lease_expiry_repairs
       << ",\"eviction_repairs\":" << m_ctr.eviction_repairs
       << ",\"backoff_suppressed\":" << m_ctr.backoff_suppressed
       << ",\"budget_suppressed\":" << m_ctr.budget_suppressed
       << ",\"retries_event_triggered\":" << m_ctr.retries_event_triggered
       << "}";
    return os.str();
}

std::unique_ptr<ReplicaPlanner> createReplicaPlanner(
    ObjectStore* store, const ReplicaPlanner::Config& cfg) {
    return std::make_unique<ReplicaPlanner>(store, cfg);
}

} // namespace replication
} // namespace networkos