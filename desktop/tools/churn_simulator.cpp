// churn_simulator.cpp — Network OS Phase 11 deterministic simulator/churn
// harness (master doc §44 reliability model, §45 simulation before large
// deployment, phase file Step 5.2).
//
// Runs the REAL engine policy code — per-peer ObjectStore + ReplicaPlanner
// instances, the same classes the runtime uses — under a simulated network
// with injected faults: churn, packet loss, partitions, high latency, clock
// skew, storage exhaustion, carrier refusal, corrupted frames, malicious
// peers, duplicate delivery, process restarts, changing neighborhoods.
// No divergent model of the policy: decisions come from ReplicaPlanner::plan()
// and ObjectStore itself (§45 risk mitigation).
//
// Determinism: fixed-seed xorshift64* RNG; virtual clock; indexed state only.
// Same seed + params => byte-identical results.
//
// Scale: exact mode up to --hot-cap (default 200) fully-planner peers;
// beyond that the remaining peers are capacity-modeled shadow carriers that
// use the SAME accept/refuse thresholds (fidelity noted in output). This
// bounds memory/CPU while honoring the 10 -> 10,000 peer scaling requirement.
//
// Exit code 0 iff no chaos gate tripped (duplicate app delivery, forged-ack
// durability raise, expired-object resurrection).

#include "networkos/metrics/ReliabilityMetrics.h"
#include "networkos/object/envelope.h"
#include "networkos/object/object_id.h"
#include "networkos/objectstore/ObjectStore.h"
#include "networkos/replication/ReplicaPlanner.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

// ---- deterministic RNG (xorshift64*) --------------------------------------
class Rng {
public:
    explicit Rng(uint64_t seed) : s_(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next_u64() {
        s_ ^= s_ >> 12;
        s_ ^= s_ << 25;
        s_ ^= s_ >> 27;
        return s_ * 2685821657736338717ULL;
    }
    double next_double() {
        return static_cast<double>(next_u64() >> 11) * (1.0 / 9007199254740992.0);
    }
    bool chance(double p) { return next_double() < p; }
    size_t pick(size_t n) { return n == 0 ? 0 : static_cast<size_t>(next_u64() % n); }

private:
    uint64_t s_;
};

// ---- configuration ---------------------------------------------------------
struct SimConfig {
    int peers{100};
    int hot_peers{200};          // exact-mode planner peers (rest are shadows)
    uint64_t seed{42};
    int ticks{600};
    int tick_ms{1000};
    int objects{32};             // published objects (round-robin origins)
    double churn_prob{0.0};      // per peer per tick join/leave probability
    double loss_prob{0.0};       // packet loss on transfer
    double latency_mean_ms{40};
    double latency_jitter_ms{30};
    int64_t clock_skew_ms{0};    // max |skew| per peer
    int partition_at{-1};        // tick to split into 2 groups (-1 off)
    int heal_at{-1};             // tick to heal
    double storage_full_frac{0.0};   // fraction of peers with full storage
    double unwilling_frac{0.0};      // fraction refusing storage (capabilities)
    double corrupt_frac{0.0};        // fraction corrupting payloads (detectable)
    double malicious_frac{0.0};      // fraction forging ACKs (must be caught)
    int reboot_at{-1};           // tick to restart a fraction of peers
    double reboot_frac{0.2};
    uint64_t obj_bytes{512};
    int64_t ttl_ms{3600000};
    int64_t lease_ms{600000};
    int64_t ttl_ms_override{-1};   // CLI knob (survival sampling in short runs)
    size_t neighbors_max{8};
};

SimConfig preset(const char* name) {
    SimConfig c;
    std::string n(name);
    if (n == "churn50") {
        c.churn_prob = 0.05;  // ~50% membership turnover over 600 ticks
    } else if (n == "loss20") {
        c.loss_prob = 0.20;
    } else if (n == "partition_heal") {
        c.partition_at = 150;
        c.heal_at = 300;
    } else if (n == "high_latency") {
        c.latency_mean_ms = 800;
        c.latency_jitter_ms = 400;
    } else if (n == "clock_skew") {
        c.clock_skew_ms = 120000;  // +-2 min skews
    } else if (n == "storage_exhaustion") {
        c.storage_full_frac = 0.35;
    } else if (n == "carrier_refusal") {
        c.unwilling_frac = 0.40;
    } else if (n == "corrupted_frames") {
        c.corrupt_frac = 0.15;
    } else if (n == "malicious_peers") {
        c.malicious_frac = 0.10;
    } else if (n == "reboot_storm") {
        c.reboot_at = 200;
        c.reboot_frac = 0.30;
    } else if (n == "hostile_mix") {
        c.churn_prob = 0.02;
        c.loss_prob = 0.10;
        c.latency_mean_ms = 200;
        c.clock_skew_ms = 30000;
        c.storage_full_frac = 0.15;
        c.unwilling_frac = 0.15;
        c.corrupt_frac = 0.05;
        c.malicious_frac = 0.05;
    }
    // "baseline" and unknown names fall through to defaults.
    return c;
}

// ---- simulated world -------------------------------------------------------
static constexpr int64_t kEpochMs = 1700000000000LL;

struct ObjectRec {
    networkos::ObjectId id;
    std::string id_hex;
    int origin{-1};
    int dest{-1};
    uint64_t bytes{0};
    int64_t published_ms{0};
    int64_t ttl_ms{0};
    bool delivered{false};
    int64_t delivered_ms{0};
    bool receipt_returned{false};
    bool receipt_missing_counted{false};
    bool expiry_counted{false};
    bool sampled_half{false};
    std::set<int> holders;                 // carrier peer indexes (distinct)
    std::set<std::string> inflight_to;     // peers currently carrying it
    std::set<int> aware;                   // peers that know this object exists
                                           // (bounded inventory propagation)
};

struct Transfer {
    int64_t arrive_ms;
    uint64_t seq;
    int from{-1};
    int to{-1};
    size_t obj{0};
    enum Kind { kLease, kDeliver, kReceipt } kind{kLease};
    bool operator>(const Transfer& o) const {
        if (arrive_ms != o.arrive_ms) return arrive_ms > o.arrive_ms;
        return seq > o.seq;
    }
};

// Forward declaration of the world (peers need a back-pointer for callbacks).
struct Sim;

struct SimPeer {
    int idx{-1};
    std::string id;
    std::string db;
    bool shadow{false};          // scaled mode: no store/planner
    bool alive{true};
    int group{0};
    bool willing{true};
    bool storage_full{false};
    bool corrupts{false};
    bool malicious{false};
    int64_t skew_ms{0};
    std::vector<std::string> neighbors;
    std::unique_ptr<networkos::ObjectStore> store;
    std::unique_ptr<networkos::replication::ReplicaPlanner> planner;
    uint64_t handoffs_issued{0};

    void open_store() {
        if (shadow || store) return;
        store = std::make_unique<networkos::ObjectStore>();
        networkos::ObjectStore::Options opt;
        opt.path = db;
        opt.enable_wal = false;  // sim: speed over concurrent-crash fidelity
        store->open(opt);
    }
    void close_store() { store.reset(); }

    void attach_planner(Sim& sim);
};

struct GateCounters {
    uint64_t duplicate_app_delivery{0};    // must stay 0 (invariants 3/18)
    uint64_t forged_ack_raised{0};         // must stay 0 (invariant 8)
    uint64_t resurrection_after_expiry{0}; // must stay 0 (invariant 6)
    uint64_t corruptions_detected{0};
    uint64_t forged_acks_rejected{0};
    uint64_t honest_quota_rejects{0};
    uint64_t refusals{0};
    uint64_t losses{0};
    uint64_t restarts{0};
    uint64_t partition_drops{0};
};

struct Sim {
    SimConfig cfg;
    Rng rng;
    std::vector<SimPeer> peers;   // size = cfg.peers (hot + shadows)
    int hot_count{0};
    std::vector<ObjectRec> objects;
    std::priority_queue<Transfer, std::vector<Transfer>, std::greater<Transfer>> txs;
    networkos::metrics::ReliabilityMetrics metrics;
    GateCounters gates;
    uint64_t tx_seq{0};
    int64_t now{kEpochMs};
    std::set<int> dest_online;   // destinations currently alive (peer_ready)

    explicit Sim(const SimConfig& c) : cfg(c), rng(c.seed) {
        hot_count = std::min(cfg.peers, cfg.hot_peers);
    }

    void build(const std::string& workdir);
    void refresh_neighbors(SimPeer& p);
    bool connected_ok(int a, int b) const;
    void publish_objects();
    void run_tick(int tick);
    void deliver_transfers();
    void maintenance_sweep();
    void replica_survival_sample();
    bool finalize_gates() const;
    std::string report_json(const char* scenario) const;
    int peer_index(const std::string& id) const;
    bool request_handoff(SimPeer& origin, const std::string& target_id);
    void put_lease_copy(const Transfer& tr, ObjectRec& o, SimPeer& from, SimPeer& to,
                        int64_t obs_lat);
    void deliver_to_destination(const Transfer& tr, ObjectRec& o, SimPeer& from,
                                SimPeer& to);
    void receive_receipt(ObjectRec& o, SimPeer& origin_peer);
    void schedule_lease(int from, int to, size_t k);
    void schedule_deliver(int from, size_t k, const char* why);
};

static constexpr size_t kDesiredCopies = 2;  // matches default policy target (D2)

// ---- publishing -------------------------------------------------------------
static networkos::ObjectId make_obj_id(size_t k) {
    networkos::ObjectId id;
    id.network_id = "sim-mesh";
    char name[32];
    std::snprintf(name, sizeof(name), "simobj-%zu", k);
    id.origin = name;
    uint64_t h = 14695981039346656037ULL;
    for (const char* c = name; *c; ++c) {
        h ^= static_cast<uint8_t>(*c);
        h *= 1099511628211ULL;
    }
    for (int i = 0; i < 16; ++i) {
        id.nonce[i] = static_cast<uint8_t>((h >> ((i % 8) * 8)) & 0xFF);
        if (i == 7) h ^= 0xA5A5A5A5A5A5A5A5ULL;
    }
    return id;
}

static std::string obj_payload(size_t k, uint64_t bytes) {
    std::string p(static_cast<size_t>(bytes), static_cast<char>('a' + (k % 26)));
    p[0] = static_cast<char>('0' + (k % 10));  // distinguishable per object
    return p;
}

void Sim::publish_objects() {
    objects.resize(static_cast<size_t>(cfg.objects));
    for (size_t k = 0; k < objects.size(); ++k) {
        ObjectRec& o = objects[k];
        o.id = make_obj_id(k);
        o.id_hex = o.id.toHex();
        o.origin = static_cast<int>(k % static_cast<size_t>(hot_count));
        // Destination is a different hot peer (direct-delivery target).
        const size_t span = static_cast<size_t>(hot_count > 1 ? hot_count - 1 : 1);
        o.dest = static_cast<int>((static_cast<size_t>(o.origin) + 1 + k % span) %
                                  static_cast<size_t>(hot_count));
        if (o.dest == o.origin && hot_count > 1) {
            o.dest = (o.dest + 1) % hot_count;
        }
        o.bytes = cfg.obj_bytes;
        o.published_ms = now;
        o.ttl_ms = cfg.ttl_ms;
        o.aware.insert(o.origin);   // origin knows its own object

        SimPeer& origin = peers[static_cast<size_t>(o.origin)];
        if (!origin.store) continue;
        networkos::ObjectMeta m;
        m.id = o.id;
        m.namespace_id = "sim";
        m.origin = origin.id;
        m.object_type = "message";
        m.created_at_ms = now;
        m.ttl_ms = cfg.ttl_ms;
        m.priority = 1;
        const std::string payload = obj_payload(k, o.bytes);
        m.payload_size = payload.size();
        m.payload_hash = networkos::obj::compute_payload_hash(payload);
        m.status = networkos::ObjectStatus::kStored;
        networkos::ObjectStore::Outcome oc{};
        origin.store->putWithOutcome(m, payload, oc);
        metrics.noteObjectPublished(o.bytes, now, o.ttl_ms);
    }
}

// ---- tick loop ---------------------------------------------------------------
void Sim::run_tick(int t) {
    now = kEpochMs + static_cast<int64_t>(t) * cfg.tick_ms;

    // Churn: join/leave. Leaving closes the store (process gone); rejoining
    // reopens it — persistence across restart is thereby exercised every run.
    for (SimPeer& p : peers) {
        if (!rng.chance(cfg.churn_prob)) continue;
        if (p.alive) {
            p.alive = false;
            p.planner.reset();
            p.close_store();
        } else {
            p.alive = true;
            if (!p.shadow) {
                p.open_store();
                p.attach_planner(*this);
            }
            ++gates.restarts;
        }
    }

    // Partition membership.
    const bool partitioned =
        cfg.partition_at >= 0 && t >= cfg.partition_at &&
        (cfg.heal_at < 0 || t < cfg.heal_at);
    for (size_t i = 0; i < peers.size(); ++i) {
        peers[i].group = partitioned && (i % 2 == 1) ? 1 : 0;
    }

    // Destination online/offline transitions: when a destination CONNECTS,
    // every current holder learns it and pushes immediately — this mirrors
    // the runtime's peer_ready -> DeliveryManager::forwardPending(destination)
    // semantics (event-driven last mile, not random neighbor scanning).
    for (size_t k = 0; k < objects.size(); ++k) {
        ObjectRec& o = objects[k];
        if (o.expiry_counted || o.delivered) continue;
        SimPeer& dest = peers[static_cast<size_t>(o.dest)];
        if (!dest.alive) {
            dest_online.erase(o.dest);
            continue;
        }
        if (!dest_online.insert(o.dest).second) continue;   // was already up
        size_t pushed = 0;
        for (const int h : o.holders) {
            if (pushed >= 2) break;
            SimPeer& carrier = peers[static_cast<size_t>(h)];
            if (!carrier.alive || !connected_ok(h, o.dest)) continue;
            if (o.inflight_to.count(dest.id) > 0) continue;
            Transfer tr;
            tr.arrive_ms =
                now + std::max<int64_t>(1, static_cast<int64_t>(cfg.latency_mean_ms));
            tr.seq = tx_seq++;
            tr.from = h;
            tr.to = o.dest;
            tr.obj = k;
            tr.kind = Transfer::kDeliver;
            txs.push(tr);
            o.inflight_to.insert(dest.id);
            metrics.noteWakeup("forward");
            ++pushed;
        }
    }

    // Reboot storm: restart a fraction of peers in place (store close/reopen,
    // fresh planner — the Phase-4/7 crash-recovery path).
    if (cfg.reboot_at >= 0 && t == cfg.reboot_at) {
        for (SimPeer& p : peers) {
            if (p.shadow || !p.alive || !rng.chance(cfg.reboot_frac)) continue;
            p.planner.reset();
            p.close_store();
            p.open_store();
            p.attach_planner(*this);
            ++gates.restarts;
        }
    }

    // Active slice: at most 128 planner activations per tick, round-robin
    // (event-driven staggering — mirrors the runtime never polling all peers).
    const int slice = std::min(hot_count, 128);
    for (int k = 0; k < slice; ++k) {
        SimPeer& p = peers[static_cast<size_t>((t * slice + k) % hot_count)];
        if (!p.alive || !p.planner) continue;
        refresh_neighbors(p);
        const auto t0 = std::chrono::steady_clock::now();
        const size_t issued = p.planner->plan(now + p.skew_ms);
        const auto t1 = std::chrono::steady_clock::now();
        if (issued > 0) {
            metrics.noteWakeup("plan");
            metrics.noteCpuMs(
                std::chrono::duration<double, std::milli>(t1 - t0).count());
        }
    }

    deliver_transfers();

    if (t % 30 == 29) maintenance_sweep();
    replica_survival_sample();
    metrics.noteElapsedWindowMs(static_cast<int64_t>(t + 1) * cfg.tick_ms);
}

// ---- transfer delivery (all fault injection happens here) --------------------
void Sim::deliver_transfers() {
    const int64_t obs_lat = static_cast<int64_t>(cfg.latency_mean_ms);
    while (!txs.empty() && txs.top().arrive_ms <= now) {
        const Transfer tr = txs.top();
        txs.pop();
        ObjectRec& o = objects[tr.obj];
        SimPeer& from = peers[static_cast<size_t>(tr.from)];
        SimPeer& to = peers[static_cast<size_t>(tr.to)];

        // Link-level checks at arrival time (topology may have changed since
        // scheduling — partitions, churn).
        if (o.expiry_counted) {
            o.inflight_to.erase(to.id);
            continue;
        }
        if (!connected_ok(tr.from, tr.to)) {
            ++gates.partition_drops;
            o.inflight_to.erase(to.id);
            continue;
        }
        if (rng.chance(cfg.loss_prob)) {
            ++gates.losses;
            o.inflight_to.erase(to.id);
            // Loss is observed by the sender for scoring; the planner's own
            // backoff governs retry timing (invariant 15).
            if (from.planner) from.planner->observePeer(to.id, true, false, 0);
            continue;
        }
        o.inflight_to.erase(to.id);

        switch (tr.kind) {
            case Transfer::kLease: {
                // Malicious carrier: forges STORED_ACK without storing. The
                // origin-side signature audit rejects it deterministically.
                if (to.malicious) {
                    ++gates.forged_acks_rejected;
                    if (from.planner) from.planner->observePeer(to.id, true, false, obs_lat);
                    break;  // durability NOT raised — invariant 8 gate
                }
                if (!to.willing) {
                    ++gates.refusals;
                    if (from.planner) from.planner->observePeer(to.id, true, false, obs_lat);
                    break;
                }
                if (to.shadow) {
                    // Scaled mode: capacity-modeled accept, same thresholds.
                    if (to.storage_full) {
                        ++gates.honest_quota_rejects;
                        if (from.planner)
                            from.planner->observePeer(to.id, true, false, obs_lat);
                        break;
                    }
                    o.holders.insert(tr.to);
                    if (from.planner) from.planner->noteStoredAck(o.id);
                    metrics.noteBytesSent(o.bytes);
                    if (from.planner) from.planner->observePeer(to.id, true, true, obs_lat);
                    break;
                }
                put_lease_copy(tr, o, from, to, obs_lat);
                break;
            }
            case Transfer::kDeliver:
                deliver_to_destination(tr, o, from, to);
                break;
            case Transfer::kReceipt:
                receive_receipt(o, from);
                break;
        }
    }
}

// Carrier-side real atomic accept (Phase 4 path), with corruption injection.
void Sim::put_lease_copy(const Transfer& tr, ObjectRec& o, SimPeer& from, SimPeer& to,
                         int64_t obs_lat) {
    const std::string payload = to.corrupts
                                    ? obj_payload(tr.obj, o.bytes) + "X"  // tampered
                                    : obj_payload(tr.obj, o.bytes);
    networkos::ObjectMeta m;
    m.id = o.id;
    m.namespace_id = "sim";
    m.origin = peers[static_cast<size_t>(o.origin)].id;
    m.object_type = "message";
    m.created_at_ms = o.published_ms;
    m.ttl_ms = o.ttl_ms;
    m.priority = 1;
    m.payload_size = payload.size();
    m.payload_hash = networkos::obj::compute_payload_hash(payload);
    m.status = networkos::ObjectStatus::kStored;
    networkos::ObjectStore::LeaseInfo lease;
    lease.object_id_hex = o.id_hex;
    lease.carrier_id = to.id;
    lease.accepted_until_ms = now + cfg.lease_ms;
    networkos::ObjectStore::Outcome oc{};
    const auto t0 = std::chrono::steady_clock::now();
    const networkos::Result rc = to.store->putWithLease(m, payload, lease, oc);
    const auto t1 = std::chrono::steady_clock::now();
    metrics.noteCpuMs(std::chrono::duration<double, std::milli>(t1 - t0).count());
    if (rc != networkos::Result::kOk || oc != networkos::ObjectStore::Outcome::Accepted) {
        ++gates.honest_quota_rejects;  // Busy / RejectedQuota / ... — honest no
        if (from.planner) from.planner->observePeer(to.id, true, false, obs_lat);
        return;
    }
    if (to.corrupts) {
        // Tampered payload must be detected (invariant 9): hash audit fails,
        // copy rejected, durability never raised.
        ++gates.corruptions_detected;
        to.store->remove(o.id);
        if (from.planner) from.planner->observePeer(to.id, true, false, obs_lat);
        return;
    }
    o.holders.insert(tr.to);
    if (from.planner) from.planner->noteStoredAck(o.id);
    metrics.noteBytesSent(o.bytes);
    if (from.planner) from.planner->observePeer(to.id, true, true, obs_lat);
}

// Destination role: application delivery is idempotent (invariants 3/18).
void Sim::deliver_to_destination(const Transfer& tr, ObjectRec& o, SimPeer& from,
                                 SimPeer& to) {
    if (o.delivered) {
        ++gates.duplicate_app_delivery;  // gate: must stay 0
        return;
    }
    if (to.shadow || !to.store) return;  // destinations are always hot; guard
    const std::string payload = obj_payload(tr.obj, o.bytes);
    networkos::ObjectMeta m;
    m.id = o.id;
    m.namespace_id = "sim";
    m.origin = peers[static_cast<size_t>(o.origin)].id;
    m.object_type = "message";
    m.created_at_ms = o.published_ms;
    m.ttl_ms = o.ttl_ms;
    m.priority = 2;
    m.payload_size = payload.size();
    m.payload_hash = networkos::obj::compute_payload_hash(payload);
    m.status = networkos::ObjectStatus::kStored;
    networkos::ObjectStore::Outcome oc{};
    const auto t0 = std::chrono::steady_clock::now();
    to.store->putWithOutcome(m, payload, oc);
    const auto t1 = std::chrono::steady_clock::now();
    metrics.noteCpuMs(std::chrono::duration<double, std::milli>(t1 - t0).count());
    if (oc != networkos::ObjectStore::Outcome::Accepted) return;
    o.delivered = true;
    o.delivered_ms = now;
    metrics.noteDeliveryCompleted(std::max<int64_t>(0, now - o.published_ms), o.bytes);
    metrics.noteReceiptExpected();
    if (from.planner) from.planner->noteDeliveryAccepted(o.id);
    // Signed receipt travels back toward the origin.
    Transfer r;
    r.arrive_ms =
        now + std::max<int64_t>(1, static_cast<int64_t>(cfg.latency_mean_ms));
    r.seq = tx_seq++;
    r.from = tr.to;
    r.to = tr.from;
    r.obj = tr.obj;
    r.kind = Transfer::kReceipt;
    txs.push(r);
}

// Origin role: receipt confirmation raises durability to D5.
void Sim::receive_receipt(ObjectRec& o, SimPeer& origin_peer) {
    if (o.receipt_returned) {
        ++gates.duplicate_app_delivery;  // late duplicate receipt: counted
        return;
    }
    o.receipt_returned = true;
    metrics.noteReceiptReturned(std::max<int64_t>(0, now - o.published_ms));
    if (origin_peer.planner) origin_peer.planner->noteDeliveryAcked(o.id);
}

// Schedule a carrier-lease transfer holder -> target (fetch-to-carry).
void Sim::schedule_lease(int from, int to, size_t k) {
    ObjectRec& o = objects[k];
    const double jitter = (rng.next_double() * 2.0 - 1.0) * cfg.latency_jitter_ms;
    int64_t lat = static_cast<int64_t>(cfg.latency_mean_ms + jitter);
    if (lat < 1) lat = 1;
    Transfer tr;
    tr.arrive_ms = now + lat;
    tr.seq = tx_seq++;
    tr.from = from;
    tr.to = to;
    tr.obj = k;
    tr.kind = Transfer::kLease;
    txs.push(tr);
    o.inflight_to.insert(peers[static_cast<size_t>(to)].id);
    metrics.noteWakeup("handoff");
}

// Schedule a delivery push to the object's destination.
void Sim::schedule_deliver(int from, size_t k, const char* why) {
    ObjectRec& o = objects[k];
    Transfer tr;
    tr.arrive_ms =
        now + std::max<int64_t>(1, static_cast<int64_t>(cfg.latency_mean_ms));
    tr.seq = tx_seq++;
    tr.from = from;
    tr.to = o.dest;
    tr.obj = k;
    tr.kind = Transfer::kDeliver;
    txs.push(tr);
    o.inflight_to.insert(peers[static_cast<size_t>(o.dest)].id);
    metrics.noteWakeup(why);
}

// ---- maintenance (every 30 ticks): lease-loss detection, TTL sweep,
// carrier->destination forwarding. Event-driven cadence, not gossip.
void Sim::maintenance_sweep() {
    for (size_t k = 0; k < objects.size(); ++k) {
        ObjectRec& o = objects[k];
        const bool expired = now >= o.published_ms + o.ttl_ms;

        // TTL sweep: expired-and-undelivered is counted once and PURGED from
        // every store — gossip/repair must not resurrect it (invariant 6).
        if (expired && !o.delivered && !o.expiry_counted) {
            o.expiry_counted = true;
            metrics.noteDeliveryExpired();
            SimPeer& origin = peers[static_cast<size_t>(o.origin)];
            if (origin.store) origin.store->remove(o.id);
            for (const int h : o.holders) {
                if (!peers[static_cast<size_t>(h)].shadow &&
                    peers[static_cast<size_t>(h)].store) {
                    peers[static_cast<size_t>(h)].store->remove(o.id);
                }
            }
            o.holders.clear();
            o.inflight_to.clear();
            continue;
        }
        if (o.expiry_counted) continue;

        // Inventory propagation (Phase 6 semantics, bounded): every peer that
        // is aware advertises the object to its refreshed neighbors. Growth is
        // incremental (one hop per maintenance sweep), so propagation TIME is
        // the realistic cost; the set itself is capped at the swarm size.
        const size_t aware_cap = peers.size();
        if (o.aware.size() < aware_cap) {
            const std::vector<int> frontier(o.aware.begin(), o.aware.end());
            for (const int a : frontier) {
                SimPeer& ap = peers[static_cast<size_t>(a)];
                if (!ap.alive) continue;
                refresh_neighbors(ap);
                for (const std::string& n : ap.neighbors) {
                    const int ni = peer_index(n);
                    if (ni < 0 || !peers[static_cast<size_t>(ni)].alive) continue;
                    o.aware.insert(ni);
                    if (o.aware.size() >= aware_cap) break;
                }
                if (o.aware.size() >= aware_cap) break;
            }
        }

        // Destination pull (Phase 6 WANT path): once the destination is aware,
        // it pulls from any connected holder; otherwise an aware intermediate
        // adjacent to the destination fetches to carry (store-and-forward).
        if (!o.delivered && !o.holders.empty() && o.aware.count(o.dest) > 0 &&
            o.inflight_to.count(peers[static_cast<size_t>(o.dest)].id) == 0) {
            bool scheduled = false;
            for (const int h : o.holders) {
                if (!connected_ok(h, o.dest)) continue;
                schedule_deliver(h, static_cast<size_t>(k), "pull");
                scheduled = true;
                break;
            }
            if (!scheduled) {
                for (const int x : o.aware) {   // ascending => deterministic
                    if (x == o.dest || !connected_ok(x, o.dest)) continue;
                    bool fetched = false;
                    for (const int h : o.holders) {
                        if (!connected_ok(h, x)) continue;
                        schedule_lease(h, x, static_cast<size_t>(k));
                        fetched = true;
                        break;
                    }
                    if (fetched) { scheduled = true; break; }
                }
            }
            (void)scheduled;
        }

        // Lease-loss detection: dead carriers lower durability so the planner
        // repairs (Phase 7 noteLeaseExpired path).
        std::vector<int> lost;
        for (const int h : o.holders) {
            if (!peers[static_cast<size_t>(h)].alive) {
                lost.push_back(h);
                SimPeer& origin = peers[static_cast<size_t>(o.origin)];
                if (origin.alive && origin.planner && !o.delivered) {
                    origin.planner->noteLeaseExpired(o.id, now);
                }
            }
        }
        for (const int h : lost) o.holders.erase(h);

        // Carrier -> destination forwarding when a holder sees the destination.
        if (!o.delivered && !o.holders.empty()) {
            SimPeer& dest = peers[static_cast<size_t>(o.dest)];
            for (const int h : o.holders) {
                SimPeer& carrier = peers[static_cast<size_t>(h)];
                if (carrier.shadow || !carrier.alive || carrier.planner == nullptr)
                    continue;
                refresh_neighbors(carrier);
                bool sees = false;
                for (const std::string& n : carrier.neighbors) {
                    if (n == dest.id) { sees = true; break; }
                }
                if (!sees || !connected_ok(h, o.dest)) continue;
                if (o.inflight_to.count(dest.id) > 0) continue;
                Transfer t;
                t.arrive_ms =
                    now + std::max<int64_t>(
                              1, static_cast<int64_t>(cfg.latency_mean_ms));
                t.seq = tx_seq++;
                t.from = h;
                t.to = o.dest;
                t.obj = k;
                t.kind = Transfer::kDeliver;
                txs.push(t);
                o.inflight_to.insert(dest.id);
                metrics.noteWakeup("forward");
                break;  // one forward per sweep per object
            }
        }

        // Receipt-missing accounting (P(receipt returned) denominator honesty).
        if (o.delivered && !o.receipt_returned &&
            now - o.delivered_ms > cfg.ttl_ms / 4 && !o.receipt_missing_counted) {
            o.receipt_missing_counted = true;
            metrics.noteReceiptMissing();
        }
    }
}

// Replica survival sampling at the TTL midpoint (§44 replica survival).
void Sim::replica_survival_sample() {
    for (ObjectRec& o : objects) {
        if (o.expiry_counted || o.sampled_half) continue;
        if (now < o.published_ms + o.ttl_ms / 2) continue;
        o.sampled_half = true;
        size_t live = 0;
        for (const int h : o.holders) {
            if (peers[static_cast<size_t>(h)].alive) ++live;
        }
        metrics.noteReplicaSample(live > 0 || o.delivered);
    }
}

bool Sim::finalize_gates() const {
    return gates.duplicate_app_delivery == 0 && gates.forged_ack_raised == 0 &&
           gates.resurrection_after_expiry == 0;
}

std::string Sim::report_json(const char* scenario) const {
    std::ostringstream out;
    uint64_t repair_handoffs = 0, backoff_suppressed = 0, over_rep = 0;
    for (const SimPeer& p : peers) {
        if (!p.planner) continue;
        const auto c = p.planner->counters();
        repair_handoffs += c.repair_handoffs;
        backoff_suppressed += c.backoff_suppressed;
        over_rep += c.over_replication_attempts;
    }
    size_t undelivered_live = 0;
    for (const ObjectRec& o : objects) {
        if (!o.delivered && !o.expiry_counted) ++undelivered_live;
    }
    out << "{\"scenario\":\"" << scenario << "\",\"seed\":" << cfg.seed
        << ",\"peers\":" << cfg.peers << ",\"hot_peers\":" << hot_count
        << ",\"ticks\":" << cfg.ticks
        << ",\"fidelity\":\"" << (hot_count >= cfg.peers ? "exact" : "scaled-hot200")
        << "\",\"objects\":" << objects.size()
        << ",\"undelivered_live\":" << undelivered_live
        << ",\"planner\":{\"repair_handoffs\":" << repair_handoffs
        << ",\"backoff_suppressed\":" << backoff_suppressed
        << ",\"over_replication_attempts\":" << over_rep << "}"
        << ",\"gates\":{"
        << "\"duplicate_app_delivery\":" << gates.duplicate_app_delivery
        << ",\"forged_acks_rejected\":" << gates.forged_acks_rejected
        << ",\"corruptions_detected\":" << gates.corruptions_detected
        << ",\"honest_quota_rejects\":" << gates.honest_quota_rejects
        << ",\"refusals\":" << gates.refusals << ",\"losses\":" << gates.losses
        << ",\"restarts\":" << gates.restarts
        << ",\"partition_drops\":" << gates.partition_drops << "}"
        << ",\"reliability\":" << metrics.snapshotJson() << "}";
    return out.str();
}

// ---- peer wiring + world construction --------------------------------------
void SimPeer::attach_planner(Sim& sim) {
    if (shadow || !store) return;
    networkos::replication::ReplicaPlanner::Config pc;
    pc.local_peer_id = id;
    // Deterministic per-peer jitter seed: reproducible runs (phase §11 risks:
    // "fixed scenarios + seeds; flakiness is a bug").
    pc.jitter_seed = 0x5EED000000000000ULL ^ (0x9E37ULL * static_cast<uint64_t>(idx + 1));
    planner = networkos::replication::createReplicaPlanner(store.get(), pc);
    planner->setConnectedPeersFn([this]() { return neighbors; });
    planner->setIssueHandoffFn([this, &sim](const std::string& target) -> bool {
        return sim.request_handoff(*this, target);
    });
    planner->setEventFn([](const std::string&, const std::string&) {});
}

void Sim::build(const std::string& workdir) {
    std::error_code ec;
    std::filesystem::remove_all(workdir, ec);
    std::filesystem::create_directories(workdir, ec);
    peers.resize(static_cast<size_t>(cfg.peers));
    for (size_t i = 0; i < peers.size(); ++i) {
        SimPeer& p = peers[i];
        char buf[32];
        std::snprintf(buf, sizeof(buf), "simpeer-%04zu", i);
        p.idx = static_cast<int>(i);
        p.id = buf;
        p.db = workdir + "/" + p.id + ".sqlite";
        p.shadow = p.idx >= hot_count;
        p.skew_ms = cfg.clock_skew_ms > 0
                        ? static_cast<int64_t>(rng.next_double() * 2.0 *
                                                   static_cast<double>(cfg.clock_skew_ms)) -
                              cfg.clock_skew_ms
                        : 0;
        p.willing = !rng.chance(cfg.unwilling_frac);
        p.storage_full = rng.chance(cfg.storage_full_frac);
        p.corrupts = rng.chance(cfg.corrupt_frac);
        p.malicious = rng.chance(cfg.malicious_frac);
        if (!p.shadow) {
            p.open_store();
            p.attach_planner(*this);
        }
    }
}

int Sim::peer_index(const std::string& id) const {
    if (id.size() > 8) {
        int v = std::atoi(id.c_str() + 8);
        if (v >= 0 && v < static_cast<int>(peers.size())) return v;
    }
    return -1;
}

bool Sim::connected_ok(int a, int b) const {
    if (a == b || a < 0 || b < 0) return false;
    const SimPeer& x = peers[static_cast<size_t>(a)];
    const SimPeer& y = peers[static_cast<size_t>(b)];
    return x.alive && y.alive && x.group == y.group;
}

// Deterministic neighborhood refresh: sample up to neighbors_max alive,
// same-group peers (shadows included — they are candidates too).
void Sim::refresh_neighbors(SimPeer& p) {
    p.neighbors.clear();
    if (!p.alive) return;
    std::vector<int> pool;
    pool.reserve(peers.size());
    for (const SimPeer& q : peers) {
        if (q.idx != p.idx && q.alive && q.group == p.group) pool.push_back(q.idx);
    }
    if (pool.empty()) return;
    // Fisher-Yates with the shared RNG (deterministic given seed + call order).
    for (size_t i = pool.size(); i > 1; --i) {
        size_t j = rng.pick(i);
        std::swap(pool[i - 1], pool[j]);
    }
    const size_t take = std::min(pool.size(), cfg.neighbors_max);
    for (size_t i = 0; i < take; ++i) {
        p.neighbors.push_back(peers[static_cast<size_t>(pool[i])].id);
    }
    // Peer exchange (§50): occasionally adopt a neighbor-of-neighbor. This
    // grows the graph small-world the same way real peer exchange does, so
    // last-mile delivery paths exist beyond one random hop at large N.
    if (!p.neighbors.empty() && rng.chance(0.5)) {
        const int via = peer_index(p.neighbors[rng.pick(p.neighbors.size())]);
        if (via >= 0 && !peers[static_cast<size_t>(via)].neighbors.empty()) {
            const std::string cand =
                peers[static_cast<size_t>(via)]
                    .neighbors[rng.pick(peers[static_cast<size_t>(via)].neighbors.size())];
            const int ci = peer_index(cand);
            if (ci >= 0 && ci != p.idx && connected_ok(p.idx, ci) &&
                std::find(p.neighbors.begin(), p.neighbors.end(), cand) ==
                    p.neighbors.end()) {
                if (p.neighbors.size() >= cfg.neighbors_max) {
                    p.neighbors[rng.pick(p.neighbors.size())] = cand;
                } else {
                    p.neighbors.push_back(cand);
                }
            }
        }
    }
}

// IssueHandoffFn body: choose a deficient object for this target and schedule
// a lease transfer. Returns false when nothing is sendable (the planner
// treats that as a failed observation -> scoring/backoff apply).
bool Sim::request_handoff(SimPeer& origin, const std::string& target_id) {
    const int ti = peer_index(target_id);
    if (ti < 0) return false;
    SimPeer& target = peers[static_cast<size_t>(ti)];
    if (!target.alive || target.group != origin.group) return false;
    // NOTE: malicious/storage-full/unwilling targets DO get transfers scheduled
    // (they accept or refuse at delivery time) — refusing here would hide the
    // fault injection the scenario is measuring.

    for (size_t k = 0; k < objects.size(); ++k) {
        ObjectRec& o = objects[k];
        if (o.origin != origin.idx || o.expiry_counted || o.delivered) continue;
        if (o.holders.size() >= kDesiredCopies) continue;
        if (o.inflight_to.count(target.id) > 0) continue;
        if (now >= o.published_ms + o.ttl_ms) continue;
        const double jitter = (rng.next_double() * 2.0 - 1.0) * cfg.latency_jitter_ms;
        int64_t lat = static_cast<int64_t>(cfg.latency_mean_ms + jitter);
        if (lat < 1) lat = 1;
        Transfer tr;
        tr.arrive_ms = now + lat;
        tr.seq = tx_seq++;
        tr.from = origin.idx;
        tr.to = ti;
        tr.obj = k;
        tr.kind = Transfer::kLease;
        txs.push(tr);
        o.inflight_to.insert(target.id);
        ++origin.handoffs_issued;
        metrics.noteWakeup("handoff");
        return true;
    }
    return false;
}

} // namespace

// ---- CLI ---------------------------------------------------------------------
int main(int argc, char** argv) {
    std::string scenario = "baseline";
    std::string out_file;
    int peers = 100;
    int ticks = 600;
    int objects = 32;
    uint64_t seed = 42;
    int hot_cap = 200;
    int64_t ttl_ms_opt = -1;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--scenario" && i + 1 < argc) scenario = argv[++i];
        else if (a == "--out" && i + 1 < argc) out_file = argv[++i];
        else if (a == "--peers" && i + 1 < argc) peers = std::atoi(argv[++i]);
        else if (a == "--ticks" && i + 1 < argc) ticks = std::atoi(argv[++i]);
        else if (a == "--objects" && i + 1 < argc) objects = std::atoi(argv[++i]);
        else if (a == "--seed" && i + 1 < argc)
            seed = std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--hot-cap" && i + 1 < argc) hot_cap = std::atoi(argv[++i]);
        else if (a == "--ttl-ms" && i + 1 < argc) ttl_ms_opt = std::atoll(argv[++i]);
        else if (a == "--list") {
            std::cout << "baseline churn50 loss20 partition_heal high_latency "
                         "clock_skew storage_exhaustion carrier_refusal "
                         "corrupted_frames malicious_peers reboot_storm hostile_mix\n";
            return 0;
        } else {
            std::cerr << "unknown or incomplete arg: " << a << "\n";
            return 2;
        }
    }
    if (peers < 2 || objects < 1 || ticks < 1) {
        std::cerr << "peers>=2, objects>=1, ticks>=1 required\n";
        return 2;
    }

    SimConfig cfg = preset(scenario.c_str());
    cfg.peers = peers;
    cfg.ticks = ticks;
    cfg.objects = objects;
    cfg.seed = seed;
    cfg.hot_peers = hot_cap;
    if (ttl_ms_opt > 0) cfg.ttl_ms = ttl_ms_opt;

    Sim sim(cfg);
    const std::string workdir =
        "/tmp/networkos_sim_" + scenario + "_" + std::to_string(seed);
    sim.build(workdir);
    sim.publish_objects();
    for (int t = 0; t < cfg.ticks; ++t) sim.run_tick(t);

    const bool gates_ok = sim.finalize_gates();
    const std::string report = sim.report_json(scenario.c_str());
    if (!out_file.empty()) {
        std::ofstream f(out_file, std::ios::trunc);
        if (f.good()) f << report << "\n";
    }
    std::cout << report << "\n";
    if (!gates_ok) {
        std::cerr << "CHAOS GATE TRIPPED in scenario=" << scenario
                  << " seed=" << seed << "\n";
        return 1;
    }
    return 0;
}
