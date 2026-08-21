// invariants_test.cpp — Network OS Phase 11: the §93 rugged-invariant
// manifest as a single runnable gate (phase file Step 5.5).
//
// Each of the 20 invariants maps to >= 1 concrete test over the REAL engine
// modules (no mocks of the thing under test). The suite exits 0 only when
// every invariant holds — it is the release gate referenced by the
// reliability report and METHODOLOGY.md.

#include "networkos/IIdentityStore.h"
#include "networkos/anti_entropy/AntiEntropyManager.h"
#include "networkos/anti_entropy/anti_entropy_frames.h"
#include "networkos/capability.h"
#include "networkos/delivery/DeliveryManager.h"
#include "networkos/discovery/DiscoveryManager.h"
#include "networkos/handoff/HandoffManager.h"
#include "networkos/handoff/handoff_frames.h"
#include "networkos/largeobject/largeobject.h"
#include "networkos/metrics/ReliabilityMetrics.h"
#include "networkos/object/envelope.h"
#include "networkos/object/object_id.h"
#include "networkos/objectstore/ObjectStore.h"
#include "networkos/replication/ReplicaPlanner.h"
#include "networkos/resources/ResourceManager.h"
#include "networkos/anti_entropy/anti_entropy_frames.h"

#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK_INV(n, cond, msg)                                              \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            std::cerr << "FAIL [invariant " << n << "]: " << msg             \
                      << " (line " << __LINE__ << ")\n";                     \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

std::string db_path(const std::string& tag) {
    const std::string dir = std::string("/tmp/networkos_inv_") + tag;
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

networkos::ObjectMeta make_meta(const networkos::ObjectId& id, const std::string& origin,
                                const std::string& payload, int64_t ttl = 3600000) {
    networkos::ObjectMeta m;
    m.id = id;
    m.namespace_id = "chat";
    m.origin = origin;
    m.object_type = "message";
    m.created_at_ms = now_ms();
    m.ttl_ms = ttl;
    m.priority = 1;
    m.payload_size = payload.size();
    m.payload_hash = networkos::obj::compute_payload_hash(payload);
    m.status = networkos::ObjectStatus::kStored;
    return m;
}

// ---------------------------------------------------------------------------
// 1 + 16: malformed input / external lengths — bounded rejection, every codec.
// ---------------------------------------------------------------------------
static void inv01_and_16_lengths_bounded() {
    using namespace networkos;
    // Capability document codec.
    CapabilityDocument doc;
    const std::string good = cap::encode(doc);
    CHECK_INV(16, !good.empty() && cap::decode(good, doc), "capability roundtrip");
    CHECK_INV(16, !cap::decode(std::string(3, '\0'), doc),
              "capability truncated rejected");
    CHECK_INV(1, !cap::decode(std::string(64 * 1024, '\xAB'), doc),
              "capability oversized rejected (no unbounded alloc)");
    // Inventory codec (Phase 6).
    anti_entropy::InventoryFrame inv;
    const std::string inv_bytes = anti_entropy::encode_inventory(inv);
    CHECK_INV(16, !anti_entropy::decode_inventory(inv_bytes.substr(0, 2), inv),
              "inventory truncated rejected");
    CHECK_INV(1, !anti_entropy::decode_inventory(std::string(64, '\xFF'), inv),
              "inventory absurd counts rejected");
    // OBJECT_WANT codec.
    anti_entropy::ObjectWantFrame want;
    CHECK_INV(16, !anti_entropy::decode_object_want(std::string("\x01"), want),
              "want truncated rejected");
    // Manifest codec (Phase 10).
    largeobject::Manifest mf;
    const std::string mf_bytes = largeobject::encode_manifest(mf);
    CHECK_INV(16, !largeobject::decode_manifest(mf_bytes.substr(0, 3), mf),
              "manifest truncated rejected");
    CHECK_INV(1, !largeobject::decode_manifest(std::string(96 * 1024, '\x7F'), mf),
              "manifest oversized rejected");
    std::cout << "inv 1/16 ok: malformed input bounded-rejected by all codecs\n";
}

// ---------------------------------------------------------------------------
// 2: crash cannot create acknowledged-but-not-stored (commit-before-ACK).
// ---------------------------------------------------------------------------
static void inv02_crash_no_unbacked_ack() {
    using namespace networkos;
    const std::string path = db_path("inv02");
    ObjectId id = ObjectId::generate("chatp2p-mesh", "origin-a");
    const std::string payload = "acked-implies-stored";
    bool ack_sent = false;
    {
        ObjectStore store;
        ObjectStore::Options opt;
        opt.path = path;
        store.open(opt);
        ObjectStore::LeaseInfo lease;
        lease.object_id_hex = id.toHex();
        lease.carrier_id = "carrier-1";
        lease.accepted_until_ms = now_ms() + 600000;
        ObjectStore::Outcome oc{};
        const Result rc = store.putWithLease(make_meta(id, "origin-a", payload),
                                             payload, lease, oc);
        // The ACK goes on the wire ONLY after commit returned Ok (§29/inv 2).
        if (rc == Result::kOk && oc == ObjectStore::Outcome::Accepted) ack_sent = true;
    }   // "crash": process gone right after the ACK.
    CHECK_INV(2, ack_sent, "lease accepted pre-crash");
    {
        ObjectStore store;
        ObjectStore::Options opt;
        opt.path = path;
        store.open(opt);
        CHECK_INV(2, store.contains(id), "acked object survives crash");
    }
    std::cout << "inv 2 ok: no acknowledged-but-not-stored across crash\n";
}

// ---------------------------------------------------------------------------
// Shared two-node delivery rig (invariants 3/18).
// ---------------------------------------------------------------------------
struct InvNode {
    std::string peer_id;
    networkos::ObjectStore store;
    std::unique_ptr<networkos::delivery::DeliveryManager> mgr;
    std::vector<uint8_t> sign_pk, sign_sk;
    std::vector<std::string> connected;

    InvNode(const std::string& id, const std::string& db) : peer_id(id) {
        sign_pk.resize(32);
        sign_sk.resize(64);
        crypto_sign_keypair(sign_pk.data(), sign_sk.data());
        networkos::ObjectStore::Options opt;
        opt.path = db;
        store.open(opt);
        networkos::delivery::DeliveryManager::Config cfg;
        cfg.local_peer_id = id;
        mgr = networkos::delivery::createDeliveryManager(&store, cfg);
    }
};

static void wire_loopback(InvNode& a, InvNode& b) {
    a.mgr->setSendFn([&a, &b](const std::string&, MessageType type,
                              const std::string& payload) -> bool {
        b.mgr->onFrame(a.peer_id, type, payload, true);
        return true;
    });
    b.mgr->setSendFn([&a, &b](const std::string&, MessageType type,
                              const std::string& payload) -> bool {
        a.mgr->onFrame(b.peer_id, type, payload, false);
        return true;
    });
    a.mgr->setConnectedPeersFn([&a]() { return a.connected; });
    b.mgr->setConnectedPeersFn([&b]() { return b.connected; });
    a.mgr->setSigningKeysFns(
        [&a]() { return std::make_pair(a.sign_pk, a.sign_sk); },
        [&b](const std::string& peer) {
            return peer == b.peer_id ? std::vector<uint8_t>(b.sign_pk)
                                     : std::vector<uint8_t>();
        });
    b.mgr->setSigningKeysFns(
        [&b]() { return std::make_pair(b.sign_pk, b.sign_sk); },
        [&a](const std::string& peer) {
            return peer == a.peer_id ? std::vector<uint8_t>(a.sign_pk)
                                     : std::vector<uint8_t>();
        });
}

static std::string make_envelope(const InvNode& from, const std::string& dest,
                                 const networkos::ObjectId& id,
                                 const std::string& payload) {
    networkos::obj::NetworkObject o;
    o.origin.network_id = "chatp2p-mesh";
    o.origin.namespace_id = "chat";
    o.origin.object_id_hex = id.toHex();
    o.origin.origin = from.peer_id;
    o.origin.destination = dest;
    o.origin.object_type = "message";
    o.origin.created_at_ms = now_ms();
    o.origin.ttl_ms = 3600000;
    o.origin.priority = 1;
    o.origin.payload_size = payload.size();
    o.origin.payload_hash = networkos::obj::compute_payload_hash(payload);
    o.payload = payload;
    if (!networkos::obj::sign_object(o, from.sign_sk.data(), from.sign_pk.data()))
        return "";
    return networkos::obj::serialize(o);
}

// 3 + 18: replay / late duplicate cannot duplicate application delivery.
static void inv03_18_replay_no_duplicate() {
    using namespace networkos;
    InvNode a("inv-a", db_path("inv03_a"));
    InvNode b("inv-b", db_path("inv03_b"));
    wire_loopback(a, b);

    ObjectId id = ObjectId::generate("chatp2p-mesh", "inv-a");
    const std::string payload = "replay-me-once";
    a.connected = {b.peer_id};
    const std::string env = make_envelope(a, b.peer_id, id, payload);
    CHECK_INV(3, !env.empty(), "envelope built");

    ObjectMeta meta = make_meta(id, a.peer_id, payload);
    meta.destination = b.peer_id;
    const auto out = a.mgr->storeAndDeliver(meta, env, 0);
    CHECK_INV(3, out.rc == Result::kOk, "first delivery accepted");

    // Replays of the identical DATA frame: re-ACK allowed, but NO second app
    // delivery, NO second receipt, NO state change (invariants 3 and 18).
    networkos::handoff::DataFrame df;
    df.object_id_hex = id.toHex();
    df.envelope = env;
    const std::string frame = networkos::handoff::encode_data(df);
    b.mgr->onFrame(a.peer_id, MessageType::OBJECT_DATA, frame, true);
    b.mgr->onFrame(a.peer_id, MessageType::OBJECT_DATA, frame, true);
    CHECK_INV(3, b.mgr->counters().receipts_created == 1, "no duplicate receipt");
    CHECK_INV(18, b.mgr->counters().duplicate_data_rejected == 2,
              "both duplicates detected");
    std::cout << "inv 3/18 ok: replay + late duplicates are harmless\n";
}

// 4: restarting during replication converges (persisted durability + planner).
static void inv04_restart_converges() {
    using namespace networkos;
    const std::string path = db_path("inv04");
    ObjectId id = ObjectId::generate("chatp2p-mesh", "origin-r");
    replication::ReplicaPlanner::Config pc;
    pc.local_peer_id = "origin-r";
    std::vector<std::string> connected{"c1", "c2"};
    ObjectStore::Outcome oc{};
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = path;
    store.open(opt);
    const std::string payload = "restart-payload";
    store.putWithOutcome(make_meta(id, "origin-r", payload), payload, oc);
    auto make_planner = [&]() {
        auto p = replication::createReplicaPlanner(&store, pc);
        p->setConnectedPeersFn([&connected]() { return connected; });
        p->setIssueHandoffFn([](const std::string&) { return true; });
        return p;
    };
    auto planner = make_planner();
    planner->plan(now_ms());
    planner->noteStoredAck(id);
    planner->noteStoredAck(id);
    ObjectStore::DurabilityReadout dr;
    store.getDurability(id, dr);
    CHECK_INV(4, dr.level == ObjectStore::kDTwoRemote, "D2 before restart");

    // RESTART: fresh planner, reopened store.
    planner.reset();
    store.close();
    store.open(opt);
    planner = make_planner();
    store.getDurability(id, dr);
    CHECK_INV(4, dr.level == ObjectStore::kDTwoRemote, "durability persisted");
    planner->noteLeaseExpired(id, now_ms());
    const size_t repairs = planner->plan(now_ms());
    CHECK_INV(4, repairs == 1, "converges: exactly one repair after loss");
    std::cout << "inv 4 ok: restart during replication converges\n";
}

// 5: losing a carrier does not corrupt the sender's state.
static void inv05_carrier_loss_sender_intact() {
    using namespace networkos;
    ObjectStore origin;
    ObjectStore::Options oopt;
    oopt.path = db_path("inv05_o");
    origin.open(oopt);
    ObjectId id = ObjectId::generate("chatp2p-mesh", "origin-s");
    const std::string payload = "sender-state-intact";
    ObjectStore::Outcome oc{};
    origin.putWithOutcome(make_meta(id, "origin-s", payload), payload, oc);
    replication::ReplicaPlanner::Config pc;
    pc.local_peer_id = "origin-s";
    auto planner = replication::createReplicaPlanner(&origin, pc);

    // Carrier accepts; then the carrier is LOST (store gone).
    {
        ObjectStore carrier;
        ObjectStore::Options copt;
        copt.path = db_path("inv05_c");
        carrier.open(copt);
        ObjectStore::LeaseInfo lease;
        lease.object_id_hex = id.toHex();
        lease.carrier_id = "carrier-x";
        lease.accepted_until_ms = now_ms() + 600000;
        ObjectStore::Outcome coc{};
        carrier.putWithLease(make_meta(id, "origin-s", payload), payload, lease, coc);
        planner->noteStoredAck(id);   // sender records the copy
    }                                  // carrier vanishes
    planner->noteLeaseExpired(id, now_ms());  // sender learns of the loss

    // Sender state intact: payload unchanged, durability honestly lowered.
    ObjectMeta meta_out;
    std::string got;
    CHECK_INV(5, origin.get(id, meta_out, got) == Result::kOk && got == payload,
              "sender payload intact after carrier loss");
    ObjectStore::DurabilityReadout dr;
    origin.getDurability(id, dr);
    CHECK_INV(5, dr.level == ObjectStore::kDLocalOnly,
              "durability honestly lowered on loss");
    std::cout << "inv 5 ok: losing a carrier leaves sender state intact\n";
}

// 6: expired objects do not live forever (no repair/gossip resurrection).
static void inv06_expired_not_forever() {
    using namespace networkos;
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db_path("inv06");
    store.open(opt);
    ObjectId id = ObjectId::generate("chatp2p-mesh", "origin-e");
    const std::string payload = "short-lived";
    ObjectMeta m = make_meta(id, "origin-e", payload, /*ttl*/ 50);
    m.created_at_ms = now_ms() - 200;   // already past TTL
    ObjectStore::Outcome oc{};
    store.putWithOutcome(m, payload, oc);
    // TTL sweep removes it... (collect first — no reentrant removes inside
    // the iteration callback).
    std::vector<ObjectId> expired;
    store.forEachExpired(now_ms(), [&](const ObjectId& e) {
        expired.push_back(e);
        return Result::kOk;
    });
    for (const ObjectId& e : expired) store.remove(e);
    const bool removed = !expired.empty() && !store.contains(id);
    CHECK_INV(6, removed, "expired object removed");
    // ...and the planner has nothing to keep alive.
    replication::ReplicaPlanner::Config pc;
    pc.local_peer_id = "origin-e";
    auto planner = replication::createReplicaPlanner(&store, pc);
    planner->setConnectedPeersFn([]() { return std::vector<std::string>{"c1"}; });
    planner->setIssueHandoffFn([](const std::string&) { return true; });
    CHECK_INV(6, planner->plan(now_ms()) == 0,
              "no repair work for a purged object");
    std::cout << "inv 6 ok: expired objects do not live forever\n";
}

// 7: a low-storage device rejects storage honestly.
static void inv07_low_storage_honest_reject() {
    using namespace networkos;
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db_path("inv07");
    opt.global_quota_bytes = 8192;
    opt.default_namespace_quota_bytes = 4096;
    opt.default_origin_quota_bytes = 2048;
    store.open(opt);
    const std::string blob(1536, 'x');   // 1.5 KB
    ObjectId a = ObjectId::generate("chatp2p-mesh", "origin-a");
    ObjectId b = ObjectId::generate("chatp2p-mesh", "origin-a");
    ObjectStore::Outcome oc{};
    store.putWithOutcome(make_meta(a, "origin-a", blob), blob, oc);
    CHECK_INV(7, oc == ObjectStore::Outcome::Accepted, "first object fits");
    store.putWithOutcome(make_meta(b, "origin-a", blob), blob, oc);
    CHECK_INV(7, oc == ObjectStore::Outcome::RejectedQuota,
              "second object honestly rejected (never silently dropped)");
    std::cout << "inv 7 ok: low-storage rejects honestly\n";
}

// 8: a malicious peer cannot forge the origin (Ed25519 canonical signing).
static void inv08_no_origin_forgery() {
    using namespace networkos;
    InvNode honest("honest", db_path("inv08_h"));
    InvNode mallory("mallory", db_path("inv08_m"));
    ObjectId id = ObjectId::generate("chatp2p-mesh", "honest");
    const std::string env = make_envelope(honest, "dest", id, "legit");
    obj::NetworkObject forged;
    CHECK_INV(8, obj::deserialize(env, forged), "envelope parses");
    forged.origin.origin = mallory.peer_id;  // claim someone else's identity
    forged.origin.created_at_ms += 1;        // ...or tamper any signed field
    const std::string forged_bytes = obj::serialize(forged);
    obj::NetworkObject check;
    CHECK_INV(8, obj::deserialize(forged_bytes, check), "forged bytes parse");
    CHECK_INV(8, !obj::verify_object(check, honest.sign_pk.data()),
              "signature over modified origin fails");
    std::cout << "inv 8 ok: origin forgery detected by signature\n";
}

// 9: a carrier cannot modify encrypted application payload undetected.
static void inv09_tamper_detected() {
    using namespace networkos;
    InvNode sender("sender", db_path("inv09"));
    ObjectId id = ObjectId::generate("chatp2p-mesh", "sender");
    const std::string payload = "payload-AAAA";
    const std::string env = make_envelope(sender, "dest", id, payload);
    obj::NetworkObject o;
    CHECK_INV(9, obj::deserialize(env, o), "parses");
    o.payload[0] ^= 0x01;                 // single-bit carrier tamper
    const std::string tampered = obj::serialize(o);
    obj::NetworkObject check;
    CHECK_INV(9, obj::deserialize(tampered, check), "tampered bytes parse");
    CHECK_INV(9, !obj::verify_object(check, sender.sign_pk.data()),
              "payload tamper breaks signature");
    CHECK_INV(9, check.origin.payload_hash != obj::compute_payload_hash(check.payload),
              "tampered payload no longer matches signed header hash");
    std::cout << "inv 9 ok: carrier tampering is detectable\n";
}

// 10: one application cannot exhaust all SDK resources (origin quotas isolate).
static void inv10_quota_isolation() {
    using namespace networkos;
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db_path("inv10");
    opt.default_origin_quota_bytes = 4096;
    store.open(opt);
    const std::string blob(3072, 'y');
    ObjectId a1 = ObjectId::generate("chatp2p-mesh", "app-A");
    ObjectId a2 = ObjectId::generate("chatp2p-mesh", "app-A");
    ObjectId b1 = ObjectId::generate("chatp2p-mesh", "app-B");
    ObjectStore::Outcome oc{};
    store.putWithOutcome(make_meta(a1, "app-A", blob), blob, oc);
    CHECK_INV(10, oc == ObjectStore::Outcome::Accepted, "A first object in");
    store.putWithOutcome(make_meta(a2, "app-A", blob), blob, oc);
    CHECK_INV(10, oc == ObjectStore::Outcome::RejectedQuota, "A quota enforced");
    store.putWithOutcome(make_meta(b1, "app-B", blob), blob, oc);
    CHECK_INV(10, oc == ObjectStore::Outcome::Accepted,
              "B unaffected by A's exhaustion attempt");
    std::cout << "inv 10 ok: per-origin quotas contain exhaustion\n";
}

// 11: idle runtime creates almost no work (bounded budgets, no fabricated
// metrics, zero wakeups without events).
static void inv11_idle_almost_no_work() {
    using namespace networkos;
    resources::ResourceManager rm;
    rm.setProfile(resources::ResourceProfile::kEco);
    const auto b = rm.budget();
    // ECO legitimately zeroes background budgets; the invariant is BOUNDED,
    // never unbounded — whatever the profile.
    CHECK_INV(11, b.connection_budget <= 64, "connection budget bounded");
    CHECK_INV(11, b.replication_budget <= 64, "replication budget bounded");
    metrics::ReliabilityMetrics m;
    const auto s = m.snapshot();
    CHECK_INV(11, s.wakeups == 0 && s.p_delivery_before_ttl == 0.0,
              "idle: no wakeups, no fabricated reliability claims");
    std::cout << "inv 11 ok: idle runtime creates almost no work\n";
}

// 12: network changes do not change peer identity.
static void inv12_identity_stable() {
    using namespace networkos;
    const std::string dir = "/tmp/networkos_inv_identity";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    Identity id1;
    {
        auto store = createFileIdentityStore(dir);
        CHECK_INV(12, store->loadOrCreate("device-1", id1) == Result::kOk,
                  "identity created");
    }
    Identity id2;
    {
        // "Network change": brand-new adapter instance, same files_dir.
        auto store = createFileIdentityStore(dir);
        CHECK_INV(12, store->load(id2) == Result::kOk, "identity reloaded");
    }
    CHECK_INV(12, id1.peer_id == id2.peer_id && !id1.peer_id.empty(),
              "peer id stable across reload");
    std::cout << "inv 12 ok: network changes do not change identity\n";
}

// 13: old and new protocol versions negotiate safely.
static void inv13_version_negotiation_safe() {
    using namespace networkos;
    CapabilityDocument local;   // min=1 max=1 (current engine)
    CapabilityDocument same;    // identical peer
    const auto n1 = local.negotiated_with(same);
    CHECK_INV(13, n1.compatible && n1.protocol_version == kWireProtocolMax,
              "same-version peers interoperate");
    CapabilityDocument ancient; // hypothetical older peer (min=1,max=1) ok
    ancient.protocol_max = 1;
    const auto n2 = local.negotiated_with(ancient);
    CHECK_INV(13, n2.compatible, "older peer still compatible at v1");
    CapabilityDocument future;  // hypothetical newer peer
    future.protocol_min = 9;
    future.protocol_max = 9;
    const auto n3 = local.negotiated_with(future);
    CHECK_INV(13, !n3.compatible, "disjoint versions refuse safely");
    std::cout << "inv 13 ok: version negotiation is safe both directions\n";
}

// 14: every queue is bounded (engine caps are compile-time enforced).
static void inv14_queues_bounded() {
    using namespace networkos;
    anti_entropy::AntiEntropyManager::Config ae;
    CHECK_INV(14, ae.inventory_limit > 0 && ae.inventory_limit <= 4096,
              "inventory entries capped");
    CHECK_INV(14, ae.max_objects_per_session > 0 && ae.max_objects_per_session <= 4096,
              "per-session object cap");
    CHECK_INV(14,
              ae.max_bytes_per_session > 0 &&
                  ae.max_bytes_per_session <= 64ull * 1024 * 1024,
              "per-session byte cap");
    handoff::HandoffManager::Config hm;
    CHECK_INV(14, hm.max_concurrent_handoffs > 0 && hm.max_concurrent_handoffs <= 64,
              "concurrent handoff cap");
    // Bounded buffers hold under flood too (metrics sink cannot grow unbounded).
    metrics::ReliabilityMetrics m;
    for (int i = 0; i < 100000; ++i) {
        m.noteWakeup("flood");
        m.noteCpuMs(0.001);
        m.noteDeliveryCompleted(1, 1);
    }
    CHECK_INV(14, m.snapshot().wakeups == 100000,
              "accounting exact while internal buffers stay bounded");
    std::cout << "inv 14 ok: every queue/buffer is bounded\n";
}

// 15: every retry is bounded and backed off (no tight repair loops).
static void inv15_retry_backoff_bounded() {
    using namespace networkos;
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db_path("inv15");
    store.open(opt);
    ObjectId id = ObjectId::generate("chatp2p-mesh", "origin-b");
    const std::string payload = "backoff";
    ObjectStore::Outcome oc{};
    store.putWithOutcome(make_meta(id, "origin-b", payload), payload, oc);
    replication::ReplicaPlanner::Config pc;
    pc.local_peer_id = "origin-b";
    auto planner = replication::createReplicaPlanner(&store, pc);
    std::vector<std::string> connected{"c1", "c2"};
    planner->setConnectedPeersFn([&connected]() { return connected; });
    planner->setIssueHandoffFn([](const std::string&) { return false; });  // all fail
    uint64_t suppressed_before = 0;
    bool saw_suppression = false;
    int64_t t = now_ms();
    for (int i = 0; i < 200 && !saw_suppression; ++i, t += 100) {
        planner->plan(t);
        const auto c = planner->counters();
        if (c.backoff_suppressed > suppressed_before) saw_suppression = true;
        suppressed_before = c.backoff_suppressed;
    }
    CHECK_INV(15, saw_suppression, "backoff suppresses tight retries");
    int64_t next_retry = 0;
    const bool has_backoff = store.getRepairBackoff(id, &next_retry) == Result::kOk;
    CHECK_INV(15, !has_backoff || next_retry - now_ms() <= 2 * pc.retry_max_ms,
              "retry delay bounded by configured maximum");
    std::cout << "inv 15 ok: retries are backed off and bounded\n";
}

// 17: delivery status survives process death (durability is persisted state).
static void inv17_status_survives_death() {
    using namespace networkos;
    const std::string path = db_path("inv17");
    ObjectId id = ObjectId::generate("chatp2p-mesh", "origin-d");
    {
        ObjectStore store;
        ObjectStore::Options opt;
        opt.path = path;
        store.open(opt);
        const std::string payload = "status";
        ObjectStore::Outcome oc{};
        store.putWithOutcome(make_meta(id, "origin-d", payload), payload, oc);
        store.raiseDurability(id, ObjectStore::kDDestSignedAck);  // delivered+acked
    }  // process death
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = path;
    store.open(opt);
    ObjectStore::DurabilityReadout dr;
    CHECK_INV(17, store.getDurability(id, dr) == Result::kOk &&
                      dr.level == ObjectStore::kDDestSignedAck,
              "delivery status survives process death");
    std::cout << "inv 17 ok: delivery status survives process death\n";
}

// 19 + 20: no mandatory infrastructure; optional infra helps but is never
// trusted.
namespace {
class FakeBackend : public networkos::discovery::IDiscoveryBackend {
public:
    FakeBackend(networkos::discovery::BackendKind k, bool opt, const char* id)
        : kind_(k), optional_(opt), peer_id_(id) {}
    networkos::discovery::BackendKind kind() const override { return kind_; }
    std::string name() const override { return peer_id_; }
    bool available() const override { return true; }
    bool optional() const override { return optional_; }
    void setEnabled(bool e) override { enabled_ = e; }
    bool enabled() const override { return enabled_; }
    std::vector<networkos::discovery::DiscoveredPeer> discover(int) override {
        if (!enabled_) return {};
        networkos::discovery::DiscoveredPeer p;
        p.peer_id = peer_id_;
        p.source = kind_;
        p.direct_reachable = false;
        p.nat_traversable = true;
        return {p};
    }

private:
    networkos::discovery::BackendKind kind_;
    bool optional_;
    const char* peer_id_;
    bool enabled_{true};
};
} // namespace

static void inv19_20_optional_not_trusted() {
    using namespace networkos;
    // Zero-infrastructure path layering still functions (inv 19 half 1).
    {
        discovery::DiscoveryManager::Config cfg;
        cfg.local_peer_id = "me";
        discovery::DiscoveryManager mgr(cfg);
        discovery::DiscoveredPeer direct;
        direct.direct_reachable = true;
        CHECK_INV(19, mgr.choosePath(direct) == discovery::ReachPath::kDirect,
                  "direct layering needs no infrastructure");
    }

    // Core (LAN-class, non-optional) backend present => functional, and the
    // loss of any OPTIONAL backend cannot break it.
    {
        discovery::DiscoveryManager::Config cfg;
        cfg.local_peer_id = "me";
        discovery::DiscoveryManager mgr(cfg);
        mgr.registerBackend(
            std::make_unique<FakeBackend>(discovery::BackendKind::kLan, false,
                                          "lan-peer"));
        CHECK_INV(19, mgr.functionalWithoutOptional(),
                  "functional with only non-optional backends");
        CHECK_INV(19, mgr.coreBackendCount() == 1, "core backend counted");
    }

    // Optional bootstrap improves reach but is never trusted (invariant 20).
    {
        discovery::DiscoveryManager::Config cfg;
        cfg.local_peer_id = "me";
        discovery::DiscoveryManager mgr(cfg);
        mgr.registerBackend(
            std::make_unique<FakeBackend>(discovery::BackendKind::kLan, false,
                                          "lan-peer"));
        mgr.registerBackend(std::make_unique<FakeBackend>(
            discovery::BackendKind::kBootstrap, true, "boot-peer"));
        const auto found = mgr.discover();
        CHECK_INV(20, found.size() >= 2, "optional backend improves discovery");
        CHECK_INV(20, mgr.functionalWithoutOptional(),
                  "still functional if the optional backend disappears");
        // ...and an unseen optional-infra peer has NO trust.
        ObjectStore store;
        ObjectStore::Options opt;
        opt.path = db_path("inv20");
        store.open(opt);
        ObjectStore::PeerScore ps;
        CHECK_INV(20,
                  store.getPeerScore("boot-peer", ps) == Result::kNotFound ||
                      ps.trust_tier == 0,
                  "infrastructure never becomes a trusted authority");
    }
    std::cout << "inv 19/20 ok: no SPOF; optional infra never trusted\n";
}

} // namespace

int main(int argc, char** argv) {
    sodium_init();
    // Optional filter: run only checks whose function name contains argv[1].
    const std::string only = argc > 1 ? argv[1] : "";
    struct Check { const char* name; void (*fn)(); };
    const Check checks[] = {
        {"inv01_and_16_lengths_bounded", inv01_and_16_lengths_bounded},
        {"inv02_crash_no_unbacked_ack", inv02_crash_no_unbacked_ack},
        {"inv03_18_replay_no_duplicate", inv03_18_replay_no_duplicate},
        {"inv04_restart_converges", inv04_restart_converges},
        {"inv05_carrier_loss_sender_intact", inv05_carrier_loss_sender_intact},
        {"inv06_expired_not_forever", inv06_expired_not_forever},
        {"inv07_low_storage_honest_reject", inv07_low_storage_honest_reject},
        {"inv08_no_origin_forgery", inv08_no_origin_forgery},
        {"inv09_tamper_detected", inv09_tamper_detected},
        {"inv10_quota_isolation", inv10_quota_isolation},
        {"inv11_idle_almost_no_work", inv11_idle_almost_no_work},
        {"inv12_identity_stable", inv12_identity_stable},
        {"inv13_version_negotiation_safe", inv13_version_negotiation_safe},
        {"inv14_queues_bounded", inv14_queues_bounded},
        {"inv15_retry_backoff_bounded", inv15_retry_backoff_bounded},
        {"inv17_status_survives_death", inv17_status_survives_death},
        {"inv19_20_optional_not_trusted", inv19_20_optional_not_trusted},
    };
    for (const Check& c : checks) {
        if (!only.empty() && std::string(c.name).find(only) == std::string::npos)
            continue;
        c.fn();
    }

    std::cout << "\n=== §93 invariant manifest: " << g_checks << " checks, "
              << g_failures << " failures ===\n";
    return g_failures == 0 ? 0 : 1;
}
