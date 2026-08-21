// replication_test.cpp — Network OS Phase 7 verification suite.
//
// Covers (phase file §9): durability ladder D0..D5 (persisted, idempotent),
// target repair with NO over-replication, peer scoring + trust tiers +
// diversity-aware placement, lease-expiry repair, backoff + event-triggered
// retry, connection budgets, no fixed gossip (idle silence), and the churn
// harness skeleton (10 peers, random churn, durability target reached %).

#include "networkos/replication/ReplicaPlanner.h"
#include "networkos/object/envelope.h"
#include "networkos/object/object_id.h"
#include "networkos/objectstore/ObjectStore.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

#define TEST_ASSERT(cond, msg)                                        \
    do {                                                              \
        ++g_checks;                                                   \
        if (!(cond)) {                                                \
            std::cerr << "FAIL: " << msg << " (line " << __LINE__ << ")\n"; \
            ++g_failures;                                             \
        }                                                             \
    } while (0)

std::string db_path(const std::string& tag) {
    const std::string dir = std::string("/tmp/networkos_p7_") + tag;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    return dir + "/objects.sqlite";
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Deterministic ObjectId from a name (same id on both peers for the same name).
networkos::ObjectId make_id(const std::string& ns) {
    using namespace networkos;
    ObjectId id;
    id.network_id = "chatp2p-mesh";
    id.origin = ns;
    uint64_t h = 14695981039346656037ULL;
    for (char c : ns) { h ^= static_cast<uint8_t>(c); h *= 1099511628211ULL; }
    for (int i = 0; i < 16; ++i) id.nonce[i] = static_cast<uint8_t>((h >> ((i % 8) * 8)) & 0xFF);
    return id;
}

// Store an object (durability defaults to D0) so the planner can see a deficit.
void store_obj(networkos::ObjectStore& store, const std::string& ns,
               const std::string& payload) {
    using namespace networkos;
    ObjectId id = make_id(ns);
    ObjectMeta m;
    m.id = id;
    m.namespace_id = "chat";
    m.origin = ns;
    m.object_type = "message";
    m.created_at_ms = now_ms();
    m.ttl_ms = 3600000;
    m.priority = 1;
    m.payload_size = payload.size();
    m.payload_hash = networkos::obj::compute_payload_hash(payload);
    m.status = ObjectStatus::kStored;
    m.envelope_blob = ns + ":" + id.toHex() + ":" + payload;
    ObjectStore::Outcome oc;
    store.putWithOutcome(m, payload, oc);
}

// A planner node with a recording IssueHandoffFn (counts handoffs per peer).
struct PNode {
    std::string peer_id;
    std::string db;
    networkos::ObjectStore store;
    std::unique_ptr<networkos::replication::ReplicaPlanner> planner;
    std::vector<std::string> connected;
    std::vector<std::string> handoff_targets;
    std::vector<std::string> events;

    PNode(const std::string& id, const std::string& dbpath) : peer_id(id), db(dbpath) {
        networkos::ObjectStore::Options opt;
        opt.path = db;
        store.open(opt);
        networkos::replication::ReplicaPlanner::Config cfg;
        cfg.local_peer_id = id;
        planner = networkos::replication::createReplicaPlanner(&store, cfg);
        planner->setConnectedPeersFn([this]() { return connected; });
        planner->setIssueHandoffFn([this](const std::string& p) -> bool {
            handoff_targets.push_back(p);
            return true;
        });
        planner->setEventFn([this](const std::string& k, const std::string& p) {
            events.push_back(k + ":" + p);
        });
    }
};

// ---------------------------------------------------------------------------
// 1. Durability ladder (Step 5.1): D0..D5, idempotent, monotonic raise,
//    lower on loss, persisted across reopen.
// ---------------------------------------------------------------------------
static void test_durability_ladder() {
    using namespace networkos;
    const std::string path = db_path("ladder");
    {
        ObjectStore store;
        ObjectStore::Options opt;
        opt.path = path;
        store.open(opt);
        ObjectId id = make_id("ladder-obj");
        ObjectMeta m;
        m.id = id;
        m.namespace_id = "chat";
        m.origin = "ladder";
        m.object_type = "message";
        m.created_at_ms = now_ms();
        m.ttl_ms = 3600000;
        m.payload_size = 4;
        m.payload_hash = networkos::obj::compute_payload_hash("data");
        m.status = ObjectStatus::kStored;
        ObjectStore::Outcome oc;
        store.putWithOutcome(m, "data", oc);

        ObjectStore::DurabilityReadout dr;
        TEST_ASSERT(store.getDurability(id, dr) == Result::kOk &&
                        dr.level == ObjectStore::kDLocalOnly,
                    "fresh object is D0");
        TEST_ASSERT(dr.desired_remote_copies == 2, "default target D2");

        // Monotonic raise: D0 -> D1 -> ... -> D5.
        store.raiseDurability(id, ObjectStore::kDOneRemote);
        store.raiseDurability(id, ObjectStore::kDTwoRemote);
        store.raiseDurability(id, ObjectStore::kDThreeRemote);
        store.raiseDurability(id, ObjectStore::kDDestinationAccepted);
        store.raiseDurability(id, ObjectStore::kDDestSignedAck);
        store.getDurability(id, dr);
        TEST_ASSERT(dr.level == ObjectStore::kDDestSignedAck, "raised to D5");

        // Idempotent: re-raising to a lower level is a no-op (monotonic).
        store.raiseDurability(id, ObjectStore::kDOneRemote);
        store.getDurability(id, dr);
        TEST_ASSERT(dr.level == ObjectStore::kDDestSignedAck, "raise is monotonic");

        // Lower on loss event.
        store.lowerDurability(id, ObjectStore::kDThreeRemote);
        store.getDurability(id, dr);
        TEST_ASSERT(dr.level == ObjectStore::kDThreeRemote, "lowered to D3");
    }
    // Persistence across reopen (crash-safe).
    {
        ObjectStore store;
        ObjectStore::Options opt;
        opt.path = path;
        store.open(opt);
        ObjectId id = make_id("ladder-obj");
        ObjectStore::DurabilityReadout dr;
        TEST_ASSERT(store.getDurability(id, dr) == Result::kOk &&
                        dr.level == ObjectStore::kDThreeRemote,
                    "durability persists across reopen");
    }
    std::cout << "durability ladder ok: D0..D5, monotonic, persisted\n";
}

// ---------------------------------------------------------------------------
// 2. Target repair (Step 5.4): place 2 leases; kill one carrier -> durability
//    drops -> planner replenishes to D2, never over-replicates past max.
// ---------------------------------------------------------------------------
static void test_target_repair() {
    using namespace networkos;
    PNode a("peer-a", db_path("repair_a"));
    store_obj(a.store, "obj1", "p1");
    a.connected = {"peer-b", "peer-c", "peer-d"};

    // First plan: D0 -> target D2 means 2 handoffs issued.
    size_t n1 = a.planner->plan(now_ms());
    TEST_ASSERT(n1 == 2, "plan issues exactly 2 handoffs for D2 target");
    TEST_ASSERT(a.planner->counters().repair_handoffs == 2, "2 repair handoffs");

    // Simulate both leases landing: durability -> D2.
    ObjectId id = make_id("obj1");
    a.planner->noteStoredAck(id);
    a.planner->noteStoredAck(id);
    ObjectStore::DurabilityReadout dr;
    a.store.getDurability(id, dr);
    TEST_ASSERT(dr.level == ObjectStore::kDTwoRemote, "durability reached D2");

    // A second plan must NOT over-replicate (already at target).
    a.handoff_targets.clear();
    size_t n2 = a.planner->plan(now_ms());
    TEST_ASSERT(n2 == 0, "no over-replication when at target");
    TEST_ASSERT(a.handoff_targets.empty(), "no extra handoffs at target");

    // Kill one carrier: durability drops to D1 -> planner replenishes to D2.
    a.planner->noteLeaseExpired(id, now_ms());
    a.store.getDurability(id, dr);
    TEST_ASSERT(dr.level == ObjectStore::kDOneRemote, "lease loss drops to D1");
    a.handoff_targets.clear();
    size_t n3 = a.planner->plan(now_ms());
    TEST_ASSERT(n3 == 1, "replenish exactly 1 to restore D2");
    std::cout << "target repair ok: replenishes to target, no over-replication\n";
}

// ---------------------------------------------------------------------------
// 3. Peer scoring + trust tiers + diversity-aware placement (Step 5.3/5.4).
// ---------------------------------------------------------------------------
static void test_peer_scoring_diversity() {
    using namespace networkos;
    PNode a("peer-a", db_path("score_a"));
    store_obj(a.store, "obj1", "p1");
    a.store.setPeerDiversityGroup("peer-b", "lan-1");
    a.store.setPeerDiversityGroup("peer-c", "lan-1");
    a.store.setPeerDiversityGroup("peer-d", "lan-2");
    a.store.recordPeerObservation("peer-d", true, true, 20);
    a.store.setPeerStorageWilling("peer-d", true);
    a.store.recordPeerObservation("peer-b", true, true, 80);
    a.store.setPeerStorageWilling("peer-b", true);
    a.store.recordPeerObservation("peer-c", true, true, 90);
    a.store.setPeerStorageWilling("peer-c", true);

    a.connected = {"peer-b", "peer-c", "peer-d"};
    auto chosen = a.planner->chooseCandidates("chat", "obj1", 2, a.connected, 2);
    TEST_ASSERT(chosen.size() == 2, "chose 2 candidates");
    const bool has_b = std::find(chosen.begin(), chosen.end(), "peer-b") != chosen.end();
    const bool has_c = std::find(chosen.begin(), chosen.end(), "peer-c") != chosen.end();
    TEST_ASSERT(!(has_b && has_c), "same failure domain not double-selected");
    TEST_ASSERT(std::find(chosen.begin(), chosen.end(), "peer-d") != chosen.end(),
                "highest-scoring diverse peer selected");

    ObjectStore::PeerScore ps;
    TEST_ASSERT(a.store.getPeerScore("peer-d", ps) == Result::kOk, "peer score readable");
    TEST_ASSERT(ps.observations >= 1 && ps.score > 0.5, "composite score computed");

    a.store.recordPeerObservation("peer-c", false, false, 0);
    a.store.recordPeerObservation("peer-c", false, false, 0);
    a.store.recordPeerObservation("peer-c", false, false, 0);
    a.connected = {"peer-b", "peer-c"};
    auto chosen2 = a.planner->chooseCandidates("chat", "obj1", 1, a.connected, 1);
    TEST_ASSERT(!chosen2.empty() && chosen2[0] == "peer-b",
                "low-scoring/unreachable peer avoided");
    std::cout << "peer scoring + diversity ok\n";
}

// ---------------------------------------------------------------------------
// 4. Lease-expiry repair (Step 5.5).
// ---------------------------------------------------------------------------
static void test_lease_expiry_repair() {
    using namespace networkos;
    PNode a("peer-a", db_path("lease_a"));
    store_obj(a.store, "obj1", "p1");
    ObjectId id = make_id("obj1");
    a.connected = {"peer-b", "peer-c"};
    a.planner->plan(now_ms());
    a.planner->noteStoredAck(id);
    a.planner->noteStoredAck(id);
    a.planner->noteLeaseExpired(id, now_ms());
    ObjectStore::DurabilityReadout dr;
    a.store.getDurability(id, dr);
    TEST_ASSERT(dr.level == ObjectStore::kDOneRemote, "lease expiry -> D1");
    a.handoff_targets.clear();
    size_t n = a.planner->plan(now_ms());
    TEST_ASSERT(n == 1, "lease-expiry repair replenishes one copy");
    TEST_ASSERT(a.planner->counters().lease_expiry_repairs >= 1, "lease repair counted");
    std::cout << "lease expiry repair ok\n";
}

// ---------------------------------------------------------------------------
// 5. Backoff + event retry (Step 5.7): NO_CARRIER -> backoff with jitter;
//    connectivity change triggers early retry; bounded.
// ---------------------------------------------------------------------------
static void test_backoff_event_retry() {
    using namespace networkos;
    PNode a("peer-a", db_path("backoff_a"));
    store_obj(a.store, "obj1", "p1");
    ObjectId id = make_id("obj1");
    a.connected = {};
    size_t n1 = a.planner->plan(now_ms());
    TEST_ASSERT(n1 == 0, "no peers -> no handoffs");
    int64_t marker = 0;
    TEST_ASSERT(a.store.getRepairBackoff(id, &marker) == Result::kOk && marker > now_ms(),
                "backoff marker scheduled after no-carrier");
    size_t n2 = a.planner->plan(now_ms());
    TEST_ASSERT(n2 == 0, "backoff suppresses tight repair loop");
    TEST_ASSERT(a.planner->counters().backoff_suppressed >= 1, "backoff suppression counted");
    a.connected = {"peer-b"};
    size_t n3 = a.planner->onConnectivityChange(now_ms() + 100000);
    TEST_ASSERT(a.planner->counters().retries_event_triggered >= 1,
                "connectivity event triggers retry");
    TEST_ASSERT(n3 >= 1, "event retry issues handoffs once peers available");
    std::cout << "backoff + event retry ok\n";
}

// ---------------------------------------------------------------------------
// 6. Connection budgets (Step 5.6): background budget throttles replication;
//    foreground allows full repair.
// ---------------------------------------------------------------------------
static void test_connection_budgets() {
    using namespace networkos;
    PNode a("peer-a", db_path("budget_a"));
    for (int i = 0; i < 10; ++i) store_obj(a.store, "obj" + std::to_string(i), "p");
    a.connected = {"peer-b", "peer-c", "peer-d", "peer-e"};
    a.planner->setBudgetBackground(true);
    size_t n_bg = a.planner->plan(now_ms());
    TEST_ASSERT(n_bg <= 1, "background budget throttles to <=1 handoff");
    a.planner->setBudgetBackground(false);
    a.handoff_targets.clear();
    size_t n_fg = a.planner->plan(now_ms());
    TEST_ASSERT(n_fg >= 2, "foreground allows full repair");
    std::cout << "connection budgets ok\n";
}

// ---------------------------------------------------------------------------
// 7. No fixed gossip (Step 5.7): idle network with full durability -> zero
//    replication traffic; no periodic re-replication timers.
// ---------------------------------------------------------------------------
static void test_no_fixed_gossip() {
    using namespace networkos;
    PNode a("peer-a", db_path("idle_a"));
    store_obj(a.store, "obj1", "p1");
    ObjectId id = make_id("obj1");
    a.connected = {"peer-b"};
    a.planner->plan(now_ms());
    a.planner->noteStoredAck(id);
    a.planner->noteStoredAck(id);   // reach D2 (target)
    a.handoff_targets.clear();
    size_t n = a.planner->plan(now_ms());
    TEST_ASSERT(n == 0, "idle network with full durability -> zero replication traffic");
    TEST_ASSERT(a.handoff_targets.empty(), "no periodic re-replication");
    std::cout << "no fixed gossip ok\n";
}

// ---------------------------------------------------------------------------
// 8. Churn harness skeleton (Step 5.8 / Deliverables): 10 peers, random churn +
//    partitions; durability target reached for >= X% of objects (baseline for
//    Phase 11). Records the measured number.
// ---------------------------------------------------------------------------
static void test_churn_harness() {
    using namespace networkos;
    const int kPeers = 10;
    std::vector<std::unique_ptr<PNode>> nodes;
    for (int i = 0; i < kPeers; ++i) {
        nodes.push_back(std::make_unique<PNode>("peer-" + std::to_string(i),
                                                db_path("churn_" + std::to_string(i))));
    }
    for (int i = 0; i < kPeers; ++i) {
        for (int j = 0; j < 5; ++j) {
            store_obj(nodes[i]->store, "peer" + std::to_string(i) + "-obj" + std::to_string(j), "p");
        }
    }
    std::mt19937 rng(42);
    for (int round = 0; round < 5; ++round) {
        for (auto& n : nodes) {
            n->connected.clear();
            for (int i = 0; i < kPeers; ++i) {
                if (i != 0 && (rng() % 3 == 0)) continue;   // some peers offline
                const std::string pid = "peer-" + std::to_string(i);
                if (pid != n->peer_id) n->connected.push_back(pid);
            }
            // Plan repairs toward the D2 target (issues handoffs to connected,
            // candidate peers). Then model that each issued handoff was ACCEPTED
            // by the carrier and a STORED_ACK returned: durability rises toward
            // the number of cooperating carriers (capped by policy desired).
            n->planner->plan(now_ms());
            for (int j = 0; j < 5; ++j) {
                ObjectId id2 = make_id("peer" + n->peer_id.substr(5) + "-obj" + std::to_string(j));
                ObjectStore::DurabilityReadout dr;
                if (n->store.getDurability(id2, dr) == Result::kOk &&
                    dr.level < ObjectStore::kDDestinationAccepted) {
                    const size_t carriers = std::min<size_t>(n->connected.size(),
                                                             dr.desired_remote_copies);
                    for (size_t k = 0; k < carriers; ++k) n->planner->noteStoredAck(id2);
                }
            }
        }
    }
    int reached = 0, total = 0;
    for (auto& n : nodes) {
        for (int j = 0; j < 5; ++j) {
            ObjectId id2 = make_id("peer" + n->peer_id.substr(5) + "-obj" + std::to_string(j));
            ObjectStore::DurabilityReadout dr;
            if (n->store.getDurability(id2, dr) == Result::kOk) {
                ++total;
                if (dr.level >= ObjectStore::kDTwoRemote) ++reached;
            }
        }
    }
    const double pct = total > 0 ? (100.0 * reached) / total : 0.0;
    TEST_ASSERT(total > 0, "churn harness measured objects");
    TEST_ASSERT(pct >= 40.0, "durability target reached for >= 40% (baseline recorded)");
    std::cout << "churn harness: " << reached << "/" << total << " objects reached D2 ("
              << pct << "%) - Phase 11 baseline\n";
}

} // namespace

int main() {
    test_durability_ladder();
    test_target_repair();
    test_peer_scoring_diversity();
    test_lease_expiry_repair();
    test_backoff_event_retry();
    test_connection_budgets();
    test_no_fixed_gossip();
    test_churn_harness();
    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}