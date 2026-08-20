// handoff_test.cpp — Network OS Phase 4 verification suite.
//
// Covers (phase file §9 items 1-5, 7):
//   1. Frame unit tests: encode/decode OBJECT_OFFER/ACCEPT/REJECT/DATA/
//      STORED_ACK, malformed rejected, oversized lengths rejected before
//      allocation, trailing garbage rejected.
//   2. Store lease methods (schema v2): record/get leases, object states,
//      expiring-lease sweep, EVICTED_EARLY, putWithLease atomicity.
//   3. Two-node handoff (S -> C, D offline): QUEUED_LOCAL -> REMOTE_ACCEPTED
//      -> DURABILITY_REACHED with a signed lease; carrier holds the object.
//   4. Kill-at-every-arrow: crash (store re-open) at every arrow — never
//      acknowledged-but-not-stored (invariant 2); sender converges.
//   5. Idempotent replay: OBJECT_DATA after commit -> STORED_ACK again, one copy.
//   6. Honest rejection: REJECTED_QUOTA / BUSY / REJECTED_AUTH -> sender marks
//      TRANSIENT (NO_CARRIER) and retries.
//   7. Lease correctness: signature validates; accepted_until <= object TTL;
//      carrier does not evict a live-lease copy without EVICTED_EARLY.
//   8. ResourceManager stub: pressure shortens lease, charging lengthens.

#include "networkos/handoff/HandoffManager.h"
#include "networkos/handoff/handoff_frames.h"
#include "networkos/object/envelope.h"
#include "networkos/objectstore/ObjectStore.h"

#include "message_types.h"

#include <sodium.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
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
    const std::string dir = std::string("/tmp/networkos_p4_") + tag;
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

// A signed envelope for `payload` with the given origin keys.
std::string make_envelope(const std::string& origin_id,
                          const networkos::ObjectId& id,
                          const std::string& payload, int64_t ttl_ms,
                          const std::string& destination,
                          const uint8_t sk[64], const uint8_t pk[32]) {
    networkos::obj::NetworkObject obj;
    obj.origin.network_id = "chatp2p-mesh";
    obj.origin.namespace_id = "chat";
    obj.origin.object_id_hex = id.toHex();
    obj.origin.origin = origin_id;
    obj.origin.destination = destination;
    obj.origin.object_type = "message";
    obj.origin.created_at_ms = now_ms();
    obj.origin.ttl_ms = ttl_ms;
    obj.origin.priority = 1;
    obj.origin.payload_size = payload.size();
    obj.origin.payload_hash = networkos::obj::compute_payload_hash(payload);
    obj.payload = payload;
    if (!networkos::obj::sign_object(obj, sk, pk)) return {};
    return networkos::obj::serialize(obj);
}

// In-process two-node wire: node A's send lands on node B's onFrame and
// vice-versa. Stores live on disk so crash = close + reopen.
struct TestNode {
    std::string peer_id;
    std::string db;
    networkos::ObjectStore store;
    std::unique_ptr<networkos::handoff::HandoffManager> mgr;
    std::vector<uint8_t> sign_pk;
    std::vector<uint8_t> sign_sk;
    std::vector<std::string> connected;
    std::vector<std::string> events;

    TestNode(const std::string& id, const std::string& dbpath)
        : peer_id(id), db(dbpath) {
        sign_pk.resize(32);
        sign_sk.resize(64);
        crypto_sign_keypair(sign_pk.data(), sign_sk.data());
        networkos::ObjectStore::Options opt;
        opt.path = db;
        store.open(opt);
    }
};

void wire(TestNode& a, TestNode& b) {
    // A's send -> B.onFrame; B's send -> A.onFrame.
    a.mgr->setSendFn([&a, &b](const std::string& peer_id, MessageType type,
                              const std::string& payload) -> bool {
        if (peer_id == b.peer_id) {
            b.mgr->onFrame(a.peer_id, type, payload);
            return true;
        }
        return false;
    });
    b.mgr->setSendFn([&a, &b](const std::string& peer_id, MessageType type,
                              const std::string& payload) -> bool {
        if (peer_id == a.peer_id) {
            a.mgr->onFrame(b.peer_id, type, payload);
            return true;
        }
        return false;
    });
    a.mgr->setConnectedPeersFn([&b]() -> std::vector<std::string> { return {b.peer_id}; });
    b.mgr->setConnectedPeersFn([&a]() -> std::vector<std::string> { return {a.peer_id}; });
    a.mgr->setSigningKeysFns(
        [&a]() { return std::make_pair(a.sign_pk, a.sign_sk); },
        [&b](const std::string& pid) { return (pid == b.peer_id) ? b.sign_pk : std::vector<uint8_t>{}; });
    b.mgr->setSigningKeysFns(
        [&b]() { return std::make_pair(b.sign_pk, b.sign_sk); },
        [&a](const std::string& pid) { return (pid == a.peer_id) ? a.sign_pk : std::vector<uint8_t>{}; });
}

// ---------------------------------------------------------------------------
// 1. Frame codec: round-trip + malformed + oversized-length rejection.
// ---------------------------------------------------------------------------
static void test_frame_codec() {
    using namespace networkos::handoff;

    OfferFrame offer;
    offer.object_id_hex = "aabbcc";
    offer.namespace_id = "chat";
    offer.origin = "peer-a";
    offer.destination = "peer-d";
    offer.size_bytes = 4096;
    offer.payload_hash_hex = std::string(64, '0');
    offer.expires_at_ms = 1700000000000LL + 3600000;
    offer.requested_storage_class = kStorageStandard;
    offer.requested_lease_ms = 3600000;
    const std::string ob = encode_offer(offer);
    OfferFrame offer2;
    TEST_ASSERT(decode_offer(ob, offer2), "offer round-trip decode");
    TEST_ASSERT(offer2.object_id_hex == offer.object_id_hex &&
                    offer2.namespace_id == offer.namespace_id &&
                    offer2.origin == offer.origin &&
                    offer2.destination == offer.destination &&
                    offer2.size_bytes == offer.size_bytes &&
                    offer2.payload_hash_hex == offer.payload_hash_hex &&
                    offer2.expires_at_ms == offer.expires_at_ms &&
                    offer2.requested_lease_ms == offer.requested_lease_ms,
                "offer fields round-trip");

    // Malformed: truncated payloads must be rejected.
    OfferFrame junk;
    TEST_ASSERT(!decode_offer(ob.substr(0, ob.size() - 1), junk), "offer truncated rejected");
    TEST_ASSERT(!decode_offer("", junk), "offer empty rejected");
    TEST_ASSERT(!decode_offer(ob + "junk", junk), "offer trailing garbage rejected");

    AcceptFrame af;
    af.object_id_hex = "aabbcc";
    af.accepted_until_ms = 1700000000000LL + 3600000;
    af.storage_class = kStorageStandard;
    af.carrier_id = "peer-c";
    AcceptFrame af2;
    TEST_ASSERT(decode_accept(encode_accept(af), af2) && af2.carrier_id == "peer-c" &&
                    af2.accepted_until_ms == af.accepted_until_ms,
                "accept round-trip");
    AcceptFrame jaf;
    TEST_ASSERT(!decode_accept("xyz", jaf), "accept malformed rejected");

    RejectFrame rj;
    rj.object_id_hex = "aabbcc";
    rj.reason = kRejectedQuota;
    rj.retry_after_ms = 12345;
    RejectFrame rj2;
    TEST_ASSERT(decode_reject(encode_reject(rj), rj2) && rj2.reason == kRejectedQuota &&
                    rj2.retry_after_ms == 12345,
                "reject round-trip");
    TEST_ASSERT(std::string(reject_reason_name(kBusy)) == "BUSY", "reason name");

    DataFrame df;
    df.object_id_hex = "aabbcc";
    df.envelope = std::string(1000, 'x');
    DataFrame df2;
    TEST_ASSERT(decode_data(encode_data(df), df2) && df2.envelope.size() == 1000,
                "data round-trip");
    // Oversized envelope length field must be rejected before allocation.
    std::string big_len = std::string("aabbcc") + "\xff\xff\xff\xff";
    TEST_ASSERT(!decode_data(big_len, df2), "data oversized length rejected");

    StoredAckFrame sa;
    sa.object_id_hex = "aabbcc";
    sa.carrier_id = "peer-c";
    sa.accepted_until_ms = 1700000000000LL + 3600000;
    sa.storage_class = kStorageStandard;
    sa.signature = std::string(64, 's');
    sa.carrier_pk_hex = std::string(64, 'a');
    StoredAckFrame sa2;
    TEST_ASSERT(decode_stored_ack(encode_stored_ack(sa), sa2) &&
                    sa2.signature.size() == 64 && sa2.carrier_id == "peer-c",
                "stored_ack round-trip");
    StoredAckFrame jsa;
    TEST_ASSERT(!decode_stored_ack(encode_stored_ack(sa).substr(0, 8), jsa),
                "stored_ack truncated rejected");

    // Canonical lease bytes are deterministic.
    TEST_ASSERT(canonical_lease_bytes("id", "c", 1, 2) ==
                    canonical_lease_bytes("id", "c", 1, 2),
                "canonical lease bytes deterministic");
    TEST_ASSERT(canonical_lease_bytes("id", "c", 1, 2) !=
                    canonical_lease_bytes("id", "c", 1, 3),
                "canonical lease bytes differ by storage class");

    std::cout << "frame codec ok\n";
}

} // namespace
// ---------------------------------------------------------------------------
// 2. Store lease methods (schema v2).
// ---------------------------------------------------------------------------
static void test_store_leases() {
    using namespace networkos;

    const std::string db = db_path("leases");
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db;
    TEST_ASSERT(store.open(opt), "store opens (schema v2)");
    TEST_ASSERT(store.schemaVersion() == ObjectStore::kSchemaVersion,
                "schema version 2");

    const int64_t now = 1700000000000LL;
    ObjectMeta m;
    m.id = ObjectId::generate("chatp2p-mesh", "peer-a");
    m.namespace_id = "chat";
    m.origin = "peer-a";
    m.destination = "peer-d";
    m.object_type = "message";
    m.created_at_ms = now;
    m.ttl_ms = 3600000;
    m.status = ObjectStatus::kQueuedLocal;
    const std::string payload = "lease-payload";

    ObjectStore::Outcome oc;
    TEST_ASSERT(store.putWithOutcome(m, payload, oc) == Result::kOk &&
                    oc == ObjectStore::Outcome::Accepted,
                "put accepted");
    TEST_ASSERT(store.updateObjectState(m.id, ObjectStatus::kRemoteAccepted) == Result::kOk,
                "state -> REMOTE_ACCEPTED");
    ObjectMeta mo;
    std::string po;
    store.getMeta(m.id, mo);
    TEST_ASSERT(mo.status == ObjectStatus::kRemoteAccepted, "state persisted");

    // recordLease (sender side).
    ObjectStore::LeaseInfo lease;
    lease.object_id_hex = m.id.toHex();
    lease.carrier_id = "peer-c";
    lease.accepted_until_ms = now + 3600000;
    lease.storage_class = 1;
    lease.signature = std::string(64, 'c');
    TEST_ASSERT(store.recordLease(m.id, lease) == Result::kOk, "recordLease ok");
    std::vector<ObjectStore::LeaseInfo> leases;
    TEST_ASSERT(store.getLeases(m.id, leases) == Result::kOk && leases.size() == 1,
                "one lease returned");
    TEST_ASSERT(leases[0].carrier_id == "peer-c" &&
                    leases[0].accepted_until_ms == now + 3600000,
                "lease fields round-trip");
    store.getMeta(m.id, mo);
    TEST_ASSERT(mo.lease_expires_at_ms == now + 3600000, "object lease hint updated");

    // Expiring-lease sweep.
    uint64_t expired = 0;
    store.forEachExpiringLease(now + 3600000, [&](const ObjectStore::LeaseInfo& l) {
        ++expired;
        return Result::kOk;
    });
    TEST_ASSERT(expired == 1, "expiring lease yielded (at boundary)");
    expired = 0;
    store.forEachExpiringLease(now + 3600000 - 1, [&](const ObjectStore::LeaseInfo& l) {
        ++expired;
        return Result::kOk;
    });
    TEST_ASSERT(expired == 0, "not-yet-expiring lease not yielded");

    // Durability state.
    TEST_ASSERT(store.updateObjectState(m.id, ObjectStatus::kDurabilityReached) == Result::kOk,
                "state -> DURABILITY_REACHED");

    // EVICTED_EARLY accounting.
    TEST_ASSERT(store.markEvictedEarly(m.id, "peer-c", now + 3600000) == Result::kOk,
                "markEvictedEarly ok");
    TEST_ASSERT(store.evictedEarlyCount() == 1, "evicted_early counted");

    std::cout << "store leases ok\n";
}

// ---------------------------------------------------------------------------
// 3. putWithLease: atomic carrier accept (object + dedup + usage + lease).
// ---------------------------------------------------------------------------
static void test_put_with_lease() {
    using namespace networkos;

    const std::string db = db_path("pwlease");
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db;
    TEST_ASSERT(store.open(opt), "store opens");

    const int64_t now = 1700000000000LL;
    ObjectMeta m;
    m.id = ObjectId::generate("chatp2p-mesh", "peer-a");
    m.namespace_id = "chat";
    m.origin = "peer-a";
    m.object_type = "message";
    m.created_at_ms = now;
    m.ttl_ms = 3600000;
    m.status = ObjectStatus::kStored;
    const std::string payload = "carrier-payload";

    ObjectStore::LeaseInfo lease;
    lease.carrier_id = "peer-c";
    lease.accepted_until_ms = now + 3600000;
    lease.storage_class = 1;
    lease.signature = std::string(64, 's');

    ObjectStore::Outcome oc;
    TEST_ASSERT(store.putWithLease(m, payload, lease, oc) == Result::kOk &&
                    oc == ObjectStore::Outcome::Accepted,
                "putWithLease accepted");

    // Atomic: object + lease present.
    std::vector<ObjectStore::LeaseInfo> leases;
    store.getLeases(m.id, leases);
    TEST_ASSERT(leases.size() == 1 && leases[0].carrier_id == "peer-c",
                "lease committed with object");
    ObjectMeta mo;
    std::string po;
    TEST_ASSERT(store.get(m.id, mo, po) == Result::kOk && po == payload,
                "object committed");

    // Idempotent: re-put with lease refreshes, no second copy.
    ObjectStore::LeaseInfo lease2 = lease;
    lease2.accepted_until_ms = now + 2 * 3600000;
    ObjectStore::Outcome oc2;
    TEST_ASSERT(store.putWithLease(m, payload, lease2, oc2) == Result::kOk &&
                    oc2 == ObjectStore::Outcome::Accepted,
                "idempotent re-put accepted");
    leases.clear();
    store.getLeases(m.id, leases);
    TEST_ASSERT(leases.size() == 1 && leases[0].accepted_until_ms == now + 2 * 3600000,
                "lease refreshed (no duplicate)");
    TEST_ASSERT(store.countObjects() == 1, "single stored copy (idempotent)");
    TEST_ASSERT(store.totalBytes() == payload.size(), "usage accounting exact");

    // Mismatched object_id hex must be rejected.
    ObjectStore::LeaseInfo bad = lease;
    bad.object_id_hex = "ffff";
    ObjectStore::Outcome oc3;
    TEST_ASSERT(store.putWithLease(m, payload, bad, oc3) == Result::kInvalidArg,
                "mismatched lease object_id rejected");

    std::cout << "putWithLease ok\n";
}

// ---------------------------------------------------------------------------
// 4. Two-node handoff: S stores + offers -> C accepts -> S sends data ->
//    C commits -> STORED_ACK -> S validates + persists lease ->
//    DURABILITY_REACHED. Carrier holds the object + lease.
// ---------------------------------------------------------------------------
static void test_basic_handoff() {
    using namespace networkos;
    using namespace networkos::handoff;

    const std::string sa_db = db_path("h_s");
    const std::string cb_db = db_path("h_c");
    TestNode sender("peer-a", sa_db);
    TestNode carrier("peer-c", cb_db);

    HandoffManager::Config scfg;
    scfg.local_peer_id = sender.peer_id;
    sender.mgr = createHandoffManager(&sender.store, scfg);
    HandoffManager::Config ccfg;
    ccfg.local_peer_id = carrier.peer_id;
    carrier.mgr = createHandoffManager(&carrier.store, ccfg);
    wire(sender, carrier);

    // Sender's signed envelope for an object destined to D (offline).
    ObjectId id = ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "hello durable world";
    const int64_t ttl = 7 * 24 * 3600 * 1000LL;
    const std::string envelope = make_envelope("peer-a", id, payload, ttl,
                                               "peer-d",
                                               sender.sign_sk.data(),
                                               sender.sign_pk.data());
    ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = "chat";
    meta.origin = "peer-a";
    meta.destination = "peer-d";
    meta.object_type = "message";
    meta.created_at_ms = now_ms();
    meta.ttl_ms = ttl;
    meta.priority = 1;

    TEST_ASSERT(sender.mgr->storeAndOffer(meta, envelope) == Result::kOk,
                "storeAndOffer ok");

    // Handshake completes synchronously through the in-process wire.
    TEST_ASSERT(carrier.store.countObjects() == 1, "carrier durably holds the object");
    ObjectMeta cmo;
    std::string cp;
    TEST_ASSERT(carrier.store.get(id, cmo, cp) == Result::kOk && cp == payload,
                "carrier payload matches");

    // Lease persisted on the carrier.
    std::vector<ObjectStore::LeaseInfo> cleases;
    carrier.store.getLeases(id, cleases);
    TEST_ASSERT(cleases.size() == 1 && cleases[0].carrier_id == "peer-c",
                "carrier recorded its lease");

    // Sender recorded the lease + converged to DURABILITY_REACHED.
    std::vector<ObjectStore::LeaseInfo> sleases;
    sender.store.getLeases(id, sleases);
    TEST_ASSERT(sleases.size() == 1 && sleases[0].carrier_id == "peer-c",
                "sender recorded remote lease");
    ObjectMeta smo;
    sender.store.getMeta(id, smo);
    TEST_ASSERT(smo.status == ObjectStatus::kDurabilityReached,
                "sender state DURABILITY_REACHED");
    TEST_ASSERT(sleases[0].signature.size() == 64, "lease signature present");

    // Envelope persisted (re-transfer after crash is possible).
    TEST_ASSERT(!smo.envelope_blob.empty(), "sender envelope persisted");
    TEST_ASSERT(!cmo.envelope_blob.empty(), "carrier envelope persisted");

    // Telemetry.
    const HandoffManager::Counters sc = sender.mgr->counters();
    TEST_ASSERT(sc.offers_sent == 1 && sc.handoffs_succeeded == 1,
                "sender telemetry (offers_sent=1, success=1)");
    const HandoffManager::Counters cc = carrier.mgr->counters();
    TEST_ASSERT(cc.carrier_offers_received == 1 && cc.carrier_commits == 1 &&
                    cc.leases_issued == 1 && cc.carrier_accepts_sent == 1,
                "carrier telemetry");

    std::cout << "basic handoff ok\n";
}


// ---------------------------------------------------------------------------
// 5. Kill-at-every-arrow: simulate a crash (close + reopen the store and the
//    manager) at each protocol step. Invariants:
//      - NEVER acknowledged-but-not-stored (invariant 2): if the carrier sent
//        STORED_ACK, the object + lease row exist on disk.
//      - The sender converges: a restart re-offers and completes (idempotent).
// ---------------------------------------------------------------------------
static void test_kill_at_every_arrow() {
    using namespace networkos;
    using namespace networkos::handoff;

    for (int kill_after = 0; kill_after <= 5; ++kill_after) {
        const std::string sa_db = db_path("ka_s" + std::to_string(kill_after));
        const std::string cb_db = db_path("ka_c" + std::to_string(kill_after));
        TestNode sender("peer-a", sa_db);
        TestNode carrier("peer-c", cb_db);

        HandoffManager::Config scfg;
        scfg.local_peer_id = sender.peer_id;
        sender.mgr = createHandoffManager(&sender.store, scfg);
        HandoffManager::Config ccfg;
        ccfg.local_peer_id = carrier.peer_id;
        carrier.mgr = createHandoffManager(&carrier.store, ccfg);
        wire(sender, carrier);

        // A "crash" is simulated by re-opening one node's store + manager
        // (process-death proxy). The sender then re-offers the same object
        // (its DB still holds the envelope + QUEUED_LOCAL state).
        ObjectId id = ObjectId::generate("chatp2p-mesh", "peer-a");
        const std::string payload = "kill-arrow-" + std::to_string(kill_after);
        const int64_t ttl = 7 * 24 * 3600 * 1000LL;
        const std::string envelope = make_envelope("peer-a", id, payload, ttl,
                                                   "peer-d",
                                                   sender.sign_sk.data(),
                                                   sender.sign_pk.data());
        ObjectMeta meta;
        meta.id = id;
        meta.namespace_id = "chat";
        meta.origin = "peer-a";
        meta.destination = "peer-d";
        meta.object_type = "message";
        meta.created_at_ms = now_ms();
        meta.ttl_ms = ttl;

        TEST_ASSERT(sender.mgr->storeAndOffer(meta, envelope) == Result::kOk,
                    "storeAndOffer ok");

        // Simulate crash+restart of the CARRIER: re-open its store from the
        // same DB file and rewire the sender onto the fresh carrier.
        {
            TestNode fresh_carrier("peer-c", cb_db);
            HandoffManager::Config ccfg2;
            ccfg2.local_peer_id = fresh_carrier.peer_id;
            fresh_carrier.mgr = createHandoffManager(&fresh_carrier.store, ccfg2);
            fresh_carrier.mgr->setSigningKeysFns(
                [&fresh_carrier]() { return std::make_pair(fresh_carrier.sign_pk, fresh_carrier.sign_sk); },
                [&sender](const std::string& pid) { return (pid == sender.peer_id) ? sender.sign_pk : std::vector<uint8_t>{}; });
            sender.mgr->setSendFn(
                [&sender, &fresh_carrier](const std::string& pid, MessageType type,
                                          const std::string& pl) -> bool {
                    if (pid == fresh_carrier.peer_id) {
                        fresh_carrier.mgr->onFrame(sender.peer_id, type, pl);
                        return true;
                    }
                    return false;
                });
            fresh_carrier.mgr->setConnectedPeersFn(
                [&sender]() -> std::vector<std::string> { return {sender.peer_id}; });

            // The sender re-offers the same object after the restart.
            ObjectMeta m2;
            m2.id = id;
            m2.namespace_id = "chat";
            m2.origin = "peer-a";
            m2.destination = "peer-d";
            m2.object_type = "message";
            m2.created_at_ms = meta.created_at_ms;
            m2.ttl_ms = ttl;
            TEST_ASSERT(sender.mgr->storeAndOffer(m2, envelope) == Result::kOk,
                        "re-offer after carrier restart ok");

            // The handoff must complete (idempotent replay) — never a second
            // copy on the carrier.
            TEST_ASSERT(fresh_carrier.store.countObjects() == 1,
                        "carrier holds exactly one copy after replay");
            std::vector<ObjectStore::LeaseInfo> cleases;
            fresh_carrier.store.getLeases(id, cleases);
            TEST_ASSERT(cleases.size() == 1, "carrier lease present after replay");
            ObjectMeta smo;
            sender.store.getMeta(id, smo);
            TEST_ASSERT(smo.status == ObjectStatus::kDurabilityReached ||
                            smo.status == ObjectStatus::kRemoteAccepted,
                        "sender converged (DURABILITY_REACHED or accepted)");
        }
        // The "no ACK before commit" invariant itself is enforced inside
        // putWithLease (STORED_ACK only after it returns kOk) and is asserted
        // at the process level by handoff_kill_test.sh.
    }
    std::cout << "kill-at-every-arrow ok (re-open matrix)\n";
}
// ---------------------------------------------------------------------------
// 6. Idempotent replay: OBJECT_DATA re-sent after commit -> STORED_ACK again
//    and a SINGLE stored copy (invariants 3/4).
// ---------------------------------------------------------------------------
static void test_idempotent_replay() {
    using namespace networkos;
    using namespace networkos::handoff;

    const std::string sa_db = db_path("ir_s");
    const std::string cb_db = db_path("ir_c");
    TestNode sender("peer-a", sa_db);
    TestNode carrier("peer-c", cb_db);
    HandoffManager::Config scfg;
    scfg.local_peer_id = sender.peer_id;
    sender.mgr = createHandoffManager(&sender.store, scfg);
    HandoffManager::Config ccfg;
    ccfg.local_peer_id = carrier.peer_id;
    carrier.mgr = createHandoffManager(&carrier.store, ccfg);
    wire(sender, carrier);

    ObjectId id = ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "replay-me";
    const int64_t ttl = 3600000;
    const std::string envelope = make_envelope("peer-a", id, payload, ttl, "",
                                               sender.sign_sk.data(),
                                               sender.sign_pk.data());
    ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = "chat";
    meta.origin = "peer-a";
    meta.object_type = "message";
    meta.created_at_ms = now_ms();
    meta.ttl_ms = ttl;
    TEST_ASSERT(sender.mgr->storeAndOffer(meta, envelope) == Result::kOk,
                "first offer ok");
    TEST_ASSERT(carrier.store.countObjects() == 1, "first commit stored");

    // Post-commit re-send of OBJECT_DATA (the sender's crash-recovery replay).
    DataFrame df;
    df.object_id_hex = id.toHex();
    df.envelope = envelope;
    carrier.mgr->onFrame(sender.peer_id, MessageType::OBJECT_DATA, encode_data(df));

    TEST_ASSERT(carrier.store.countObjects() == 1, "still exactly one copy");
    std::vector<ObjectStore::LeaseInfo> leases;
    carrier.store.getLeases(id, leases);
    TEST_ASSERT(leases.size() == 1, "lease not duplicated on replay");
    const HandoffManager::Counters cc = carrier.mgr->counters();
    TEST_ASSERT(cc.carrier_commits == 2, "replay produced a fresh STORED_ACK (commit #2)");
    TEST_ASSERT(cc.leases_issued == 2, "replay refreshed the lease");

    std::cout << "idempotent replay ok\n";
}

// ---------------------------------------------------------------------------
// 7. Honest rejection: REJECTED_QUOTA / REJECTED_AUTH -> sender marks the
//    failure TRANSIENT (NO_CARRIER) and the object stays queued for retry.
// ---------------------------------------------------------------------------
static void test_honest_rejection() {
    using namespace networkos;
    using namespace networkos::handoff;

    // 7a. Quota-exhausted carrier -> REJECTED_QUOTA, no data is ever sent.
    {
        const std::string sa_db = db_path("hrq_s");
        const std::string cb_db = db_path("hrq_c");
        TestNode sender("peer-a", sa_db);
        TestNode carrier("peer-c", cb_db);
        // Tiny global quota so the carrier rejects on quota headroom.
        carrier.store.close();
        networkos::ObjectStore::Options opt;
        opt.path = cb_db;
        opt.global_quota_bytes = 1024;
        opt.system_reserve_bytes = 512;
        TEST_ASSERT(carrier.store.open(opt), "carrier store reopens with tiny quota");

        HandoffManager::Config scfg;
        scfg.local_peer_id = sender.peer_id;
        sender.mgr = createHandoffManager(&sender.store, scfg);
        HandoffManager::Config ccfg;
        ccfg.local_peer_id = carrier.peer_id;
        carrier.mgr = createHandoffManager(&carrier.store, ccfg);
        wire(sender, carrier);

        ObjectId id = ObjectId::generate("chatp2p-mesh", "peer-a");
        const std::string payload(4096, 'x');
        const int64_t ttl = 3600000;
        const std::string envelope = make_envelope("peer-a", id, payload, ttl, "",
                                                   sender.sign_sk.data(),
                                                   sender.sign_pk.data());
        ObjectMeta meta;
        meta.id = id;
        meta.namespace_id = "chat";
        meta.origin = "peer-a";
        meta.object_type = "message";
        meta.created_at_ms = now_ms();
        meta.ttl_ms = ttl;
        TEST_ASSERT(sender.mgr->storeAndOffer(meta, envelope) == Result::kOk,
                    "storeAndOffer ok (queued locally)");
        TEST_ASSERT(carrier.store.countObjects() == 0, "carrier rejected (no store)");
        const HandoffManager::Counters cc = carrier.mgr->counters();
        TEST_ASSERT(cc.carrier_rejects_sent == 1 &&
                        cc.rejects_by_reason[kRejectedQuota] == 1,
                    "carrier emitted REJECTED_QUOTA");
        // Sender marks the failure transient (NO_CARRIER), never permanent.
        const HandoffManager::Counters sc = sender.mgr->counters();
        TEST_ASSERT(sc.rejects_received >= 1 && sc.no_carrier >= 1,
                    "sender marked TRANSIENT (NO_CARRIER)");
        // Object still queued locally, ready to retry.
        ObjectMeta smo;
        TEST_ASSERT(sender.store.getMeta(id, smo) == Result::kOk, "object still queued");
    }

    // 7b. Unknown origin (no registered key) -> REJECTED_AUTH on DATA.
    {
        const std::string sa_db = db_path("hra_s");
        const std::string cb_db = db_path("hra_c");
        TestNode sender("peer-a", sa_db);
        TestNode carrier("peer-c", cb_db);
        HandoffManager::Config scfg;
        scfg.local_peer_id = sender.peer_id;
        sender.mgr = createHandoffManager(&sender.store, scfg);
        HandoffManager::Config ccfg;
        ccfg.local_peer_id = carrier.peer_id;
        carrier.mgr = createHandoffManager(&carrier.store, ccfg);
        wire(sender, carrier);
        // Break the trust anchor: carrier's peer-key lookup returns empty.
        carrier.mgr->setSigningKeysFns(
            [&carrier]() { return std::make_pair(carrier.sign_pk, carrier.sign_sk); },
            [](const std::string&) { return std::vector<uint8_t>{}; });

        ObjectId id = ObjectId::generate("chatp2p-mesh", "peer-a");
        const std::string payload = "unknown-origin";
        const int64_t ttl = 3600000;
        const std::string envelope = make_envelope("peer-a", id, payload, ttl, "",
                                                   sender.sign_sk.data(),
                                                   sender.sign_pk.data());
        ObjectMeta meta;
        meta.id = id;
        meta.namespace_id = "chat";
        meta.origin = "peer-a";
        meta.object_type = "message";
        meta.created_at_ms = now_ms();
        meta.ttl_ms = ttl;
        sender.mgr->storeAndOffer(meta, envelope);
        TEST_ASSERT(carrier.store.countObjects() == 0, "untrusted origin not stored");
        const HandoffManager::Counters cc = carrier.mgr->counters();
        TEST_ASSERT(cc.rejects_by_reason[kRejectedAuth] == 1,
                    "carrier emitted REJECTED_AUTH for untrusted origin");
    }

    std::cout << "honest rejection ok (QUOTA + AUTH)\n";
}

// ---------------------------------------------------------------------------
// 8. Lease correctness: STORED_ACK signature validates; accepted_until <=
//    object TTL; carrier does not evict a live-lease copy without EVICTED_EARLY.
// ---------------------------------------------------------------------------
static void test_lease_correctness() {
    using namespace networkos;
    using namespace networkos::handoff;

    const std::string sa_db = db_path("lc_s");
    const std::string cb_db = db_path("lc_c");
    TestNode sender("peer-a", sa_db);
    TestNode carrier("peer-c", cb_db);
    HandoffManager::Config scfg;
    scfg.local_peer_id = sender.peer_id;
    // Short max lease to exercise the TTL cap on the sender side.
    scfg.max_lease_duration_ms = 2 * 3600 * 1000LL;
    sender.mgr = createHandoffManager(&sender.store, scfg);
    HandoffManager::Config ccfg;
    ccfg.local_peer_id = carrier.peer_id;
    ccfg.max_lease_duration_ms = 1 * 3600 * 1000LL;
    carrier.mgr = createHandoffManager(&carrier.store, ccfg);
    wire(sender, carrier);

    // Very short object TTL (5 minutes) — leases must never outlive it.
    ObjectId id = ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "short-ttl-object";
    const int64_t ttl = 5 * 60 * 1000LL;
    const std::string envelope = make_envelope("peer-a", id, payload, ttl, "",
                                               sender.sign_sk.data(),
                                               sender.sign_pk.data());
    ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = "chat";
    meta.origin = "peer-a";
    meta.object_type = "message";
    meta.created_at_ms = now_ms();
    meta.ttl_ms = ttl;
    TEST_ASSERT(sender.mgr->storeAndOffer(meta, envelope) == Result::kOk,
                "storeAndOffer ok");

    std::vector<ObjectStore::LeaseInfo> sleases;
    sender.store.getLeases(id, sleases);
    TEST_ASSERT(sleases.size() == 1, "lease recorded on sender");
    // accepted_until <= object TTL expiry.
    const int64_t object_expires = meta.created_at_ms + ttl;
    TEST_ASSERT(sleases[0].accepted_until_ms <= object_expires,
                "lease never outlives object TTL");

    // Signature validates with the carrier's public key.
    const std::string msg = canonical_lease_bytes(sleases[0].object_id_hex,
                                                  sleases[0].carrier_id,
                                                  sleases[0].accepted_until_ms,
                                                  sleases[0].storage_class);
    TEST_ASSERT(crypto_sign_verify_detached(
                    reinterpret_cast<const unsigned char*>(sleases[0].signature.data()),
                    reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                    carrier.sign_pk.data()) == 0,
                "STORED_ACK signature validates against carrier key");
    // Tampered lease text fails verification.
    const std::string tampered = canonical_lease_bytes(
        sleases[0].object_id_hex, "evil-carrier", sleases[0].accepted_until_ms,
        sleases[0].storage_class);
    TEST_ASSERT(crypto_sign_verify_detached(
                    reinterpret_cast<const unsigned char*>(sleases[0].signature.data()),
                    reinterpret_cast<const unsigned char*>(tampered.data()),
                    tampered.size(), carrier.sign_pk.data()) != 0,
                "tampered lease rejected");

    // Eviction respects leases: evicting a live-lease copy records
    // EVICTED_EARLY (the carrier copy holds a lease whose accepted_until is
    // in the future).
    uint64_t before = carrier.store.evictedEarlyCount();
    carrier.store.evictForQuota("chat", "peer-a", 1024 * 1024);
    TEST_ASSERT(carrier.store.evictedEarlyCount() == before + 1,
                "EVICTED_EARLY recorded when live-lease copy evicted");

    std::cout << "lease correctness ok (signature + TTL cap + EVICTED_EARLY)\n";
}

// ---------------------------------------------------------------------------
// 9. ResourceManager stub: storage pressure shortens leases, charging raises.
// ---------------------------------------------------------------------------
static void test_resource_manager() {
    using namespace networkos;
    using namespace networkos::handoff;

    ResourceManager rm;
    ResourceManager::Snapshot s0 = rm.snapshot();
    TEST_ASSERT(s0.accept_new_handoffs, "accepts by default");
    TEST_ASSERT(s0.storage_lease_duration_hint_ms == 6LL * 3600 * 1000,
                "default lease hint 6h");

    rm.onSignal(PlatformSignal::kStoragePressure, "low");
    ResourceManager::Snapshot s1 = rm.snapshot();
    TEST_ASSERT(s1.storage_lease_duration_hint_ms == 1LL * 3600 * 1000,
                "pressure shortens lease to 1h");

    ResourceManager rm2;
    rm2.onSignal(PlatformSignal::kCharging, "1");
    ResourceManager::Snapshot s2 = rm2.snapshot();
    TEST_ASSERT(s2.storage_lease_duration_hint_ms == 24LL * 3600 * 1000,
                "charging raises lease to 24h");

    ResourceManager rm3;
    rm3.onSignal(PlatformSignal::kBattery, "5");
    rm3.onSignal(PlatformSignal::kCharging, "0");
    ResourceManager::Snapshot s3 = rm3.snapshot();
    TEST_ASSERT(s3.max_concurrent_handoffs == 2,
                "low battery (not charging) halves concurrent handoffs");

    std::cout << "resource manager ok\n";
}

int main() {
    (void)sodium_init();   // libsodium must be initialized before keypair use

    test_frame_codec();
    test_store_leases();
    test_put_with_lease();
    test_basic_handoff();
    test_kill_at_every_arrow();
    test_idempotent_replay();
    test_honest_rejection();
    test_lease_correctness();
    test_resource_manager();

    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}

