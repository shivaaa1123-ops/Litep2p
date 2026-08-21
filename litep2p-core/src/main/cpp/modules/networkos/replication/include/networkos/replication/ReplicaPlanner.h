#pragma once

// Network OS Phase 7 — ReplicaPlanner (master doc §10 durability ladder,
// §11 leases + repair, §13 peer scoring, §17 connection budgets, §55
// replication policy, §61 failure semantics, §76 retry, §80 diversity,
// §89 Phase 7).
//
// Replaces fixed gossip/flooding with target-driven replication: the runtime
// continuously knows approximate durability (D0..D5, persisted per object) and
// repairs toward the policy target using local peer scores + failure-domain
// diversity — never over-replicating past the policy maximum.
//
// Orchestration only; it reuses the Phase 4 handoff (storeAndOffer via a
// wiring callback) and Phase 6 reconciliation as the delivery mechanism. The
// planner decides WHAT to replicate WHERE (peer scoring + diversity) and WHEN
// (event-triggered + bounded retry with backoff + jitter).

#include "networkos/Runtime.h"
#include "networkos/IPlatformAdapter.h"
#include "networkos/objectstore/ObjectStore.h"

#include "message_types.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace networkos {
namespace replication {

class ReplicaPlanner {
public:
    struct Config {
        bool enabled{true};
        // Connection budgets (§17) by resource state. Background/restricted
        // sessions get a small budget; foreground is generous.
        size_t foreground_handoffs_per_tick{8};
        size_t background_handoffs_per_tick{1};
        // Retry (§76): exponential backoff base + max + jitter fraction.
        int64_t retry_base_ms{2000};
        int64_t retry_max_ms{5LL * 60 * 1000};
        double jitter_fraction{0.3};
        // Repair cooldown: an object already scheduled for repair is not
        // re-repaired until its backoff expires (invariant 5 — no repair storm).
        int64_t default_repair_cooldown_ms{10 * 1000};
        // Lease-expiry lead time: start a repair handoff before a live lease
        // actually expires (Step 5.5), so there is never a zero-remote window
        // when the policy demands >= 1.
        int64_t lease_takeover_lead_ms{5 * 60 * 1000};
        // Peer aging (§75).
        int64_t peer_stale_after_ms{14LL * 24LL * 3600 * 1000};
        // Retry-jitter RNG seed. 0 (default) = non-deterministic thread-local
        // RNG (production). Non-zero = fully deterministic backoff jitter
        // (required by the Phase 11 simulator/chaos lab for reproducible runs).
        uint64_t jitter_seed{0};
        std::string local_peer_id;
    };

    // Wiring callbacks. IssueHandoffFn triggers a Phase 4 storeAndOffer for a
    // target peer; Returns true if a handoff was dispatched.
    using IssueHandoffFn = std::function<bool(const std::string& peer_id)>;
    using ConnectedPeersFn = std::function<std::vector<std::string>()>;
    using EventFn = std::function<void(const std::string& kind, const std::string& payload)>;

    explicit ReplicaPlanner(ObjectStore* store, const Config& cfg);
    ~ReplicaPlanner();
    ReplicaPlanner(const ReplicaPlanner&) = delete;
    ReplicaPlanner& operator=(const ReplicaPlanner&) = delete;

    void setIssueHandoffFn(IssueHandoffFn fn);
    void setConnectedPeersFn(ConnectedPeersFn fn);
    void setEventFn(EventFn fn);

    // Step 5.1/5.4 — scan all objects with a durability deficit and repair
    // toward the policy target, honoring connection budget + backoff. Returns
    // the number of handoffs issued this tick. Event-driven; never polled.
    size_t plan(int64_t now_ms);

    // Step 5.4 — repair one specific object's deficit (used on peer loss /
    // eviction / lease expiry). Honors policy target + backoff + budget.
    // Returns the number of handoffs issued (0 if no candidate/route/backoff).
    size_t repairObject(const ObjectId& id, int64_t now_ms);

    // Peer-connect event (Step 5.5/5.7): a peer became available — snapshot its
    // score + treat as an event-triggered retry opportunity.
    void onPeerReady(const std::string& peer_id);

    // Connectivity/network-change event (Step 5.7): triggers early retry of any
    // backed-off objects (bounded). Returns handoffs issued.
    size_t onConnectivityChange(int64_t now_ms);

    // Step 5.1 — durability accounting from protocol events.
    void noteStoredAck(const ObjectId& id);            // D0 -> D1 (monotonic up)
    void noteDeliveryAccepted(const ObjectId& id);     // -> D4
    void noteDeliveryAcked(const ObjectId& id);        // -> D5
    void noteLeaseExpired(const ObjectId& id, int64_t now_ms);  // lose a copy
    void noteEvictedEarly(const ObjectId& id, int64_t now_ms);  // lose a copy

    // Step 5.6 — resource/budget hint from the platform/resource manager.
    void setBudgetBackground(bool background);

    // Repair preferences per namespace (Step 5.2) — convenience passthroughs.
    Result setPolicy(const ObjectStore::ReplicationPolicy& policy);
    Result getPolicy(const std::string& ns, ObjectStore::ReplicationPolicy& out) const;

    // Peer scoring inputs (Step 5.3).
    Result observePeer(const std::string& peer_id, bool reachable,
                       bool handoff_success, int64_t latency_ms);
    Result setPeerGroup(const std::string& peer_id, const std::string& group);
    Result setPeerWilling(const std::string& peer_id, bool willing);

    // Telemetry (Step 5.8).
    struct Counters {
        uint64_t plans{0};
        uint64_t repair_handoffs{0};
        uint64_t repaired_objects{0};              // reached target
        uint64_t over_replication_attempts{0};     // throttled past max
        uint64_t lease_expiry_repairs{0};
        uint64_t eviction_repairs{0};
        uint64_t retries_event_triggered{0};
        uint64_t backoff_suppressed{0};            // skipped due to backoff
        uint64_t budget_suppressed{0};             // skipped due to budget
        int64_t last_plan_ms{0};
    };
    Counters counters() const;
    std::string telemetryJson() const;

    // Exposed for tests: pick the best candidate peers for an object given its
    // policy (diversity + score aware). Pure function over the store.
    std::vector<std::string> chooseCandidates(const std::string& namespace_id,
                                              const std::string& object_id_hex,
                                              uint8_t desired,
                                              const std::vector<std::string>& connected,
                                              uint8_t max) const;

private:
    // Deficit = how many more remote copies are needed to hit desired.
    static int deficitFor_(uint8_t desired, ObjectStore::DurabilityReadout& d);
    // Candidate model for scoring.
    struct Candidate {
        std::string peer_id;
        std::string group;
        double score{0.0};
        bool willing{false};
    };
    std::vector<Candidate> scoreCandidates_(const std::vector<std::string>& peers) const;

    void emit_(const std::string& kind, const std::string& payload);
    size_t budgetFor_() const;

    ObjectStore* m_store{nullptr};
    Config m_cfg;
    std::atomic<bool> m_background{false};
    // Deterministic-jitter state (used only when m_cfg.jitter_seed != 0).
    uint64_t m_jitter_state{0};
    bool m_jitter_seeded{false};

    IssueHandoffFn m_issue_handoff;
    ConnectedPeersFn m_connected;
    EventFn m_event;

    mutable std::mutex m_mu;
    Counters m_ctr;
};

std::unique_ptr<ReplicaPlanner> createReplicaPlanner(
    ObjectStore* store, const ReplicaPlanner::Config& cfg);

} // namespace replication
} // namespace networkos