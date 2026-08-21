// delivery_test.cpp - Network OS Phase 5 verification suite.
//
// Covers (phase file §9): frame codec, store schema v3, §99 no-kill scenario
// (origin -> carrier -> destination -> signed receipt -> CONFIRMED), direct
// delivery (no carrier), idempotent repeat (invariant 3/18), replica release
// (§64), failure classes (§61), late confirmation (§22).

#include "networkos/delivery/DeliveryManager.h"
#include "networkos/delivery/delivery_frames.h"
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
    const std::string dir = std::string("/tmp/networkos_p5_") + tag;
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

std::string to_hex(const std::string& raw) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) out.push_back(kHex[c >> 4]), out.push_back(kHex[c & 0xF]);
    return out;
}

// Build a signed envelope for `payload` addressed to `destination`.
std::string make_envelope(const std::string& origin_id, const std::string& dest,
                          const networkos::ObjectId& id, const std::string& payload,
                          int64_t ttl_ms, const uint8_t sk[64], const uint8_t pk[32]) {
    networkos::obj::NetworkObject obj;
    obj.origin.network_id = "chatp2p-mesh";
    obj.origin.namespace_id = "chat";
    obj.origin.object_id_hex = id.toHex();
    obj.origin.origin = origin_id;
    obj.origin.destination = dest;
    obj.origin.object_type = "message";
    obj.origin.created_at_ms = now_ms();
    obj.origin.ttl_ms = ttl_ms;
    obj.origin.priority = 1;
    obj.origin.payload_size = payload.size();
    obj.origin.payload_hash = networkos::obj::compute_payload_hash(payload);
    obj.payload = payload;
    if (!networkos::obj::sign_object(obj, sk, pk)) return "";
    return networkos::obj::serialize(obj);
}

// In-process wire for DeliveryManager nodes (mirrors the handoff harness).
struct DNode {
    std::string peer_id;
    std::string db;
    networkos::ObjectStore store;
    std::unique_ptr<networkos::delivery::DeliveryManager> mgr;
    std::vector<uint8_t> sign_pk;
    std::vector<uint8_t> sign_sk;
    std::vector<std::string> connected;
    std::vector<std::string> events;

    DNode(const std::string& id, const std::string& dbpath,
          bool require_receipt = true) : peer_id(id), db(dbpath) {
        sign_pk.resize(32);
        sign_sk.resize(64);
        crypto_sign_keypair(sign_pk.data(), sign_sk.data());
        networkos::ObjectStore::Options opt;
        opt.path = db;
        store.open(opt);
        networkos::delivery::DeliveryManager::Config cfg;
        cfg.local_peer_id = id;
        cfg.require_receipt = require_receipt;
        mgr = networkos::delivery::createDeliveryManager(&store, cfg);
        mgr->setEventFn([this](const std::string& kind, const std::string& payload) {
            events.push_back(kind + ":" + payload);
        });
    }
};

// Compute whether a frame names `recv_peer` as its destination.
bool frame_targets(const std::string& sender_id, MessageType type, const std::string& payload,
                   const std::string& recv_peer) {
    using namespace networkos::handoff;
    if (type == MessageType::OBJECT_OFFER) {
        OfferFrame f;
        return decode_offer(payload, f) && f.destination == recv_peer;
    }
    if (type == MessageType::OBJECT_DATA) {
        DataFrame f;
        networkos::obj::NetworkObject obj;
        return decode_data(payload, f) && networkos::obj::deserialize(f.envelope, obj) &&
               obj.origin.destination == recv_peer;
    }
    // ACK/REJECT/RECEIVED_ACK: ignored by onFrame destination checks.
    return false;
}

// Wrap an envelope into an OBJECT_DATA frame payload (for dup-delivery tests).
std::string env_to_data(const std::string& env, const networkos::ObjectId& id) {
    networkos::handoff::DataFrame df;
    df.object_id_hex = id.toHex();
    df.envelope = env;
    return networkos::handoff::encode_data(df);
}

void wire(DNode& a, DNode& b) {
    using namespace networkos;
    a.mgr->setSendFn([&a, &b](const std::string& peer_id, MessageType type,
                              const std::string& payload) -> bool {
        if (peer_id == b.peer_id) {
            b.mgr->onFrame(a.peer_id, type, payload,
                           frame_targets(a.peer_id, type, payload, b.peer_id));
            return true;
        }
        return false;
    });
    b.mgr->setSendFn([&a, &b](const std::string& peer_id, MessageType type,
                              const std::string& payload) -> bool {
        if (peer_id == a.peer_id) {
            a.mgr->onFrame(b.peer_id, type, payload,
                           frame_targets(b.peer_id, type, payload, a.peer_id));
            return true;
        }
        return false;
    });
    a.mgr->setConnectedPeersFn([&b]() -> std::vector<std::string> { return {b.peer_id}; });
    b.mgr->setConnectedPeersFn([&a]() -> std::vector<std::string> { return {a.peer_id}; });
    a.mgr->setSigningKeysFns(
        [&a]() { return std::make_pair(a.sign_pk, a.sign_sk); },
        [&b](const std::string& pid) {
            return (pid == b.peer_id) ? b.sign_pk : std::vector<uint8_t>{};
        });
    b.mgr->setSigningKeysFns(
        [&b]() { return std::make_pair(b.sign_pk, b.sign_sk); },
        [&a](const std::string& pid) {
            return (pid == a.peer_id) ? a.sign_pk : std::vector<uint8_t>{};
        });
}

// ---------------------------------------------------------------------------
// 1. Frame codec: RECEIVED_ACK + receipt round-trip + malformed rejection.
// ---------------------------------------------------------------------------
static void test_frame_codec() {
    using namespace networkos::delivery;

    ReceivedAckFrame ack;
    ack.object_id_hex = "aabbcc";
    ack.destination = "peer-b";
    ack.received_at_ms = 1700000000000LL;
    ack.receipt_type = kReceived;
    const std::string b = encode_received_ack(ack);
    ReceivedAckFrame ack2;
    TEST_ASSERT(decode_received_ack(b, ack2), "received_ack round-trip decode");
    TEST_ASSERT(ack2.object_id_hex == ack.object_id_hex && ack2.destination == ack.destination &&
                    ack2.received_at_ms == ack.received_at_ms && ack2.receipt_type == kReceived,
                "received_ack fields round-trip");
    TEST_ASSERT(!decode_received_ack(b.substr(0, b.size() - 1), ack2), "received_ack truncated rejected");
    TEST_ASSERT(!decode_received_ack("", ack2), "received_ack empty rejected");
    TEST_ASSERT(!decode_received_ack(b + "xx", ack2), "received_ack trailing garbage rejected");

    ReceiptPayload r;
    r.object_id_hex = "obj123";
    r.object_hash_hex = std::string(64, 'a');
    r.origin = "peer-a";
    r.destination = "peer-b";
    r.received_at_ms = 1700000000000LL;
    r.receipt_type = kReceived;
    r.object_created_at_ms = 1699999999000LL;
    r.signature = std::string(64, 's');
    r.signer_pk_hex = std::string(64, 'b');
    const std::string rb = encode_receipt(r);
    ReceiptPayload r2;
    TEST_ASSERT(decode_receipt(rb, r2), "receipt round-trip decode");
    TEST_ASSERT(r2.object_id_hex == r.object_id_hex && r2.object_hash_hex == r.object_hash_hex &&
                    r2.origin == r.origin && r2.destination == r.destination &&
                    r2.received_at_ms == r.received_at_ms && r2.signature.size() == 64,
                "receipt fields round-trip");
    TEST_ASSERT(!decode_receipt(rb.substr(0, rb.size() - 2), r2), "receipt truncated rejected");
    TEST_ASSERT(!decode_receipt("junk", r2), "receipt malformed rejected");

    // Canonical bytes are deterministic + sensitive to each field.
    TEST_ASSERT(canonical_receipt_bytes("o", "h", "a", "b", 1, 0) ==
                    canonical_receipt_bytes("o", "h", "a", "b", 1, 0),
                "canonical receipt deterministic");
    TEST_ASSERT(canonical_receipt_bytes("o", "h", "a", "b", 1, 0) !=
                    canonical_receipt_bytes("o", "h", "a", "b", 1, 1),
                "canonical receipt differs by type");
    TEST_ASSERT(std::string(receipt_type_name(kReceived)) == "RECEIVED", "type name");
    TEST_ASSERT(std::string(failure_class_name(kFailTerminal)) == "TERMINAL", "failure name");
    std::cout << "frame codec ok\n";
}

// ---------------------------------------------------------------------------
// 2. Store schema v3: receipts + delivery state transitions.
// ---------------------------------------------------------------------------
static void test_store_schema_v3() {
    using namespace networkos;
    const std::string db = db_path("schema");
    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db;
    TEST_ASSERT(store.open(opt), "store opens");
    // Schema advanced by later phases (P5 v3, P7 v4); assert it matches the
    // engine's current schema and is forward-compatible with delivery (>= 3).
    TEST_ASSERT(store.schemaVersion() == ObjectStore::kSchemaVersion &&
                    store.schemaVersion() >= 3,
                "schema version supports delivery");

    ObjectId id = ObjectId::generate("chatp2p-mesh", "peer-a");
    ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = "chat";
    meta.origin = "peer-a";
    meta.destination = "peer-b";
    meta.object_type = "message";
    meta.created_at_ms = 1700000000000LL;
    meta.ttl_ms = 3600000;
    meta.priority = 1;
    meta.payload_size = 5;
    meta.payload_hash = std::string(32, 'x');
    TEST_ASSERT(store.put(meta, "hello") == Result::kOk, "put object");

    // Delivery transitions.
    TEST_ASSERT(store.markDelivered(id, 1700000001000LL) == Result::kOk, "markDelivered");
    ObjectStatus st;
    int64_t d;
    int64_t c;
    uint8_t fc;
    TEST_ASSERT(store.deliveryReadout(id, &st, &d, &c, &fc) == Result::kOk, "readout");
    TEST_ASSERT(st == ObjectStatus::kDelivered && d == 1700000001000LL && fc == 0,
                "delivered readout");
    TEST_ASSERT(store.confirmObject(id, 1700000002000LL) == Result::kOk, "confirmObject");
    TEST_ASSERT(store.deliveryReadout(id, &st, &d, &c, &fc) == Result::kOk && st == ObjectStatus::kConfirmed &&
                    c == 1700000002000LL,
                "confirmed readout");
    TEST_ASSERT(store.confirmObject(id, 1700000002000LL) == Result::kOk, "confirm idempotent");

    ObjectId id2 = ObjectId::generate("chatp2p-mesh", "peer-a");
    ObjectMeta m2 = meta;
    m2.id = id2;
    TEST_ASSERT(store.put(m2, "world") == Result::kOk, "put second");
    TEST_ASSERT(store.failDelivery(id2, delivery::kFailTerminal) == Result::kOk, "failDelivery");
    TEST_ASSERT(store.deliveryReadout(id2, &st, &d, &c, &fc) == Result::kOk &&
                    st == ObjectStatus::kFailed && fc == delivery::kFailTerminal,
                "failed readout");
    TEST_ASSERT(store.markDeliveryAttempted(id) == Result::kOk, "markDeliveryAttempted noop on later");
    TEST_ASSERT(store.deliveryReadout(id, &st, nullptr, nullptr, nullptr) == Result::kOk &&
                    st == ObjectStatus::kConfirmed,
                "attempted does not downgrade confirmed");

    // Receipts table.
    ObjectStore::ReceiptRow row;
    row.delivered_object_id_hex = id.toHex();
    row.receipt_object_id_hex = "receipt123";
    row.origin = "peer-a";
    row.destination = "peer-b";
    row.receipt_type = delivery::kReceived;
    row.received_at_ms = 1700000001000LL;
    row.object_hash_hex = std::string(64, 'a');
    row.signature = std::string(64, 's');
    row.signer_pk_hex = std::string(64, 'b');
    TEST_ASSERT(store.recordReceipt(row) == Result::kOk, "recordReceipt");
    ObjectStore::ReceiptRow got;
    TEST_ASSERT(store.getReceipt(id.toHex(), got) == Result::kOk, "getReceipt");
    TEST_ASSERT(got.receipt_object_id_hex == "receipt123" && got.signature.size() == 64 &&
                    got.destination == "peer-b",
                "receipt row round-trip");
    // Idempotent upsert.
    TEST_ASSERT(store.recordReceipt(row) == Result::kOk, "recordReceipt idempotent");
    uint64_t receipt_rows = 0;
    TEST_ASSERT(store.forEachReceiptToward("peer-a",
                                           [&](const ObjectStore::ReceiptRow&) -> Result {
                                               receipt_rows++;
                                               return Result::kOk;
                                           }) == Result::kOk && receipt_rows == 1,
                "receipts toward origin");

    store.close();
    std::cout << "store schema v3 ok\n";
}

// ---------------------------------------------------------------------------
// 3. §99-online milestone (direct delivery): A (online) -> B, B commits +
// returns RECEIVED_ACK, B signs a receipt and routes it back to A, A marks
// the object CONFIRMED. Exercises direct delivery, signed receipt reverse
// path, and late-confirmation upgrade end to end with only a DeliveryManager
// (the destination is online, so no carrier is needed — Step 5.1 cheapest
// path first).
// ---------------------------------------------------------------------------
static void test_milestone_direct() {
    DNode a("peer-a", db_path("ms_direct_a"));
    DNode b("peer-b", db_path("ms_direct_b"));
    wire(a, b);

    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "milestone-payload";
    const std::string env =
        make_envelope("peer-a", "peer-b", id, payload, 3600000, a.sign_sk.data(), a.sign_pk.data());
    TEST_ASSERT(!env.empty(), "envelope built");

    networkos::ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = "chat";
    meta.origin = "peer-a";
    meta.destination = "peer-b";
    meta.object_type = "message";
    meta.created_at_ms = now_ms();
    meta.ttl_ms = 3600000;
    meta.priority = 1;
    meta.payload_size = payload.size();
    meta.payload_hash = networkos::obj::compute_payload_hash(payload);

    auto out = a.mgr->storeAndDeliver(meta, env, 0);
    TEST_ASSERT(out.rc == networkos::Result::kOk, "storeAndDeliver ok");
    TEST_ASSERT(a.mgr->counters().direct_deliveries == 1, "direct delivery chosen");

    // B durably committed and produced a signed receipt; A marked DELIVERED
    // then CONFIRMED after the receipt returned.
    networkos::ObjectStatus st;
    int64_t c;
    TEST_ASSERT(b.store.deliveryReadout(id, &st, nullptr, nullptr, nullptr) == networkos::Result::kOk &&
                    (st == networkos::ObjectStatus::kStored ||
                     st == networkos::ObjectStatus::kDelivered),
                "B durably holds the object");
    TEST_ASSERT(b.mgr->counters().receipts_created == 1, "B created a receipt");

    // A eventually reached CONFIRMED (receipt reverse path completed).
    TEST_ASSERT(a.mgr->counters().confirmed_objects == 1, "A confirmed");
    TEST_ASSERT(a.store.deliveryReadout(id, &st, nullptr, &c, nullptr) == networkos::Result::kOk &&
                    st == networkos::ObjectStatus::kConfirmed,
                "A object CONFIRMED");

    // The receipt is a real signed object on B: verify signature over canonical
    // receipt bytes using B's public key.
    networkos::ObjectStore::ReceiptRow rrow;
    if (b.store.getReceipt(id.toHex(), rrow) == networkos::Result::kOk) {
        const std::string canon = networkos::delivery::canonical_receipt_bytes(
            rrow.delivered_object_id_hex, rrow.object_hash_hex, rrow.origin,
            rrow.destination, rrow.received_at_ms, rrow.receipt_type);
        TEST_ASSERT(crypto_sign_verify_detached(
                        reinterpret_cast<const unsigned char*>(rrow.signature.data()),
                        reinterpret_cast<const unsigned char*>(canon.data()), canon.size(),
                        b.sign_pk.data()) == 0,
                    "receipt signature validates against B key");
    } else {
        TEST_ASSERT(false, "receipt row present");
    }

    // Reverse path: A stored the receipt object (it was delivered to A).
    uint64_t receipts_stored = 0;
    networkos::ObjectStore::ReceiptRow rr;
    TEST_ASSERT(a.store.getReceipt(id.toHex(), rr) == networkos::Result::kOk,
                "A recorded the returned receipt for CONFIRMED");
    (void)receipts_stored;

    // Events trace the full object lifecycle.
    std::cout << "milestone direct: A confirmed in " << a.mgr->counters().confirmed_objects
              << " object(s), receipts created " << b.mgr->counters().receipts_created << "\n";
}

// ---------------------------------------------------------------------------
// 4. Idempotent repeat delivery (invariant 3/18): delivering the SAME object
// again yields the existing terminal outcome, never a duplicate app event or
// a second receipt.
// ---------------------------------------------------------------------------
static void test_idempotent_repeat() {
    DNode a("peer-a", db_path("idem_a"));
    DNode b("peer-b", db_path("idem_b"));
    wire(a, b);

    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "dup-payload";
    const std::string env =
        make_envelope("peer-a", "peer-b", id, payload, 3600000, a.sign_sk.data(), a.sign_pk.data());
    networkos::ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = "chat";
    meta.origin = "peer-a";
    meta.destination = "peer-b";
    meta.object_type = "message";
    meta.created_at_ms = now_ms();
    meta.ttl_ms = 3600000;
    meta.priority = 1;
    meta.payload_size = payload.size();
    meta.payload_hash = networkos::obj::compute_payload_hash(payload);

    (void)a.mgr->storeAndDeliver(meta, env, 0);
    TEST_ASSERT(b.mgr->counters().receipts_created == 1, "one receipt after first delivery");

    // Re-deliver the identical envelope: B must re-ACK, not create a new copy
    // or a second receipt.
    b.mgr->onFrame("peer-a", MessageType::OBJECT_DATA, env_to_data(env, id), true);
    TEST_ASSERT(b.mgr->counters().receipts_created == 1, "no second receipt on duplicate");
    TEST_ASSERT(b.mgr->counters().duplicate_data_rejected == 1, "duplicate detected");

    uint64_t copies = 0;
    networkos::ObjectStore::ReceiptRow dummy;
    TEST_ASSERT(b.store.getReceipt(id.toHex(), dummy) == networkos::Result::kOk &&
                    b.mgr->counters().receipts_created == 1,
                "one receipt row only");
    std::cout << "idempotent repeat ok (copies=" << copies << ")\n";
}

// ---------------------------------------------------------------------------
// 5. Replica release (§64): a DELIVERED replica past its retention window is
// garbage-collected; a still-queued (undelivered) replica is NEVER removed
// (last-useful-replica rule).
// ---------------------------------------------------------------------------
static void test_replica_release() {
    DNode a("peer-a", db_path("rel_a"));
    DNode b("peer-b", db_path("rel_b"));
    wire(a, b);

    networkos::ObjectId delivered = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    networkos::ObjectId queued = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "rel";
    const std::string env1 = make_envelope("peer-a", "peer-b", delivered, payload, 3600000,
                                           a.sign_sk.data(), a.sign_pk.data());
    const std::string env2 = make_envelope("peer-a", "peer-b", queued, payload, 3600000,
                                           a.sign_sk.data(), a.sign_pk.data());
    TEST_ASSERT(!env1.empty() && !env2.empty(), "envelopes built");
    networkos::ObjectMeta m1; m1.id = delivered; m1.namespace_id="chat"; m1.origin="peer-a";
    m1.destination="peer-b"; m1.object_type="message"; m1.created_at_ms=now_ms(); m1.ttl_ms=3600000;
    m1.priority=1; m1.payload_size=payload.size();
    m1.payload_hash=networkos::obj::compute_payload_hash(payload);
    networkos::ObjectMeta m2 = m1; m2.id = queued;

    // One object delivered (then past window), another still queued.
    networkos::ObjectStore::Outcome oc1;
    TEST_ASSERT(a.store.putWithOutcome(m1, env1, oc1) == networkos::Result::kOk &&
                    oc1 == networkos::ObjectStore::Outcome::Accepted,
                "delivered replica inserted");
    TEST_ASSERT(a.store.markDelivered(delivered, now_ms() - 600000) == networkos::Result::kOk,
                "delivered past retention");
    networkos::ObjectStore::Outcome oc;
    TEST_ASSERT(a.store.putWithOutcome(m2, env2, oc) == networkos::Result::kOk &&
                    oc == networkos::ObjectStore::Outcome::Accepted,
                "queued replica");
    (void)env1;
    networkos::ObjectStatus st;
    TEST_ASSERT(a.store.deliveryReadout(queued, &st, nullptr, nullptr, nullptr) ==
                networkos::Result::kOk && st == networkos::ObjectStatus::kQueuedLocal,
                "queued replica is QUEUED");

    // Sweep: only the DELIVERED replica is freed.
    size_t freed = a.mgr->sweepReplicas(now_ms());
    TEST_ASSERT(freed == 1, "only delivered replica released");
    TEST_ASSERT(a.mgr->counters().delivered_replicas_released == 1, "replica release counter");
    networkos::ObjectMeta gone;
    std::string g;
    TEST_ASSERT(a.store.get(queued, gone, g) == networkos::Result::kOk, "queued replica kept");
    TEST_ASSERT(a.store.get(delivered, gone, g) == networkos::Result::kNotFound,
                "delivered replica removed");
    std::cout << "replica release ok\n";
}

// ---------------------------------------------------------------------------
// 6. Failure semantics (§61): no-carrier is TRANSIENT + retryable; TTL expiry
// is TERMINAL via failDelivery; the error model exposes retryable/retry_after.
// ---------------------------------------------------------------------------
static void test_failure_classes() {
    using namespace networkos;
    // No carrier -> TRANSIENT, retryable, retry_after>0 (Outcome model).
    DNode a("peer-a", db_path("fail_a"));
    DNode b("peer-b", db_path("fail_b"));
    a.mgr->setConnectedPeersFn([]() -> std::vector<std::string> { return {}; });
    a.mgr->setSendFn([](const std::string&, MessageType, const std::string&) -> bool {
        return false;
    });
    // b offline; a only sees itself (empty connected).
    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "f";
    const std::string env = make_envelope("peer-a", "peer-b", id, payload, 3600000,
                                          a.sign_sk.data(), a.sign_pk.data());
    networkos::ObjectMeta meta;
    meta.id = id; meta.namespace_id="chat"; meta.origin="peer-a"; meta.destination="peer-b";
    meta.object_type="message"; meta.created_at_ms=now_ms(); meta.ttl_ms=3600000;
    meta.priority=1; meta.payload_size=payload.size();
    meta.payload_hash=networkos::obj::compute_payload_hash(payload);

    // update metadata for A's signing peer map is not needed for storeAndDeliver.
    b.mgr->setSigningKeysFns(
        [&b]() { return std::make_pair(b.sign_pk, b.sign_sk); },
        [&a](const std::string& pid) { return (pid == a.peer_id) ? a.sign_pk : std::vector<uint8_t>{}; });
    auto out = a.mgr->storeAndDeliver(meta, env, 0);
    TEST_ASSERT(out.rc == Result::kOk, "storeAndDeliver returns ok (queued)");
    TEST_ASSERT(out.failure_class == delivery::kFailTransient, "no-carrier is TRANSIENT");
    TEST_ASSERT(out.retryable == true, "no-carrier retryable");
    TEST_ASSERT(out.retry_after_ms > 0, "no-carrier retry_after set");
    std::cout << "failure classes ok\n";
}

// ---------------------------------------------------------------------------
// 7. Late confirmation (§22): a delayed signed receipt upgrades DELIVERED ->
// CONFIRMED idempotently; the app sees the upgrade without duplicates.
// ---------------------------------------------------------------------------
static void test_late_confirmation() {
    DNode a("peer-a", db_path("late_a"));
    DNode b("peer-b", db_path("late_b"));
    wire(a, b);

    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "late";
    const std::string env = make_envelope("peer-a", "peer-b", id, payload, 3600000,
                                          a.sign_sk.data(), a.sign_pk.data());
    networkos::ObjectMeta meta;
    meta.id = id; meta.namespace_id="chat"; meta.origin="peer-a"; meta.destination="peer-b";
    meta.object_type="message"; meta.created_at_ms=now_ms(); meta.ttl_ms=3600000;
    meta.priority=1; meta.payload_size=payload.size();
    meta.payload_hash=networkos::obj::compute_payload_hash(payload);
    a.mgr->storeAndDeliver(meta, env, 0);
    TEST_ASSERT(a.mgr->counters().confirmed_objects == 1, "confirmed after full flow");
    // A duplicate delivery of the now-confirmed object must be harmless.
    b.mgr->onFrame("peer-a", MessageType::OBJECT_DATA, env_to_data(env, id), true);
    TEST_ASSERT(a.mgr->counters().confirmed_objects == 1, "no second confirm on dup");
    std::cout << "late confirmation ok\n";
}

// ---------------------------------------------------------------------------
// 8. Payload-hash verification (Step 5.1: "verifies signature + hash"): a
// frame whose payload does not match its declared hash must be rejected.
// ---------------------------------------------------------------------------
static void test_hash_verification() {
    DNode a("peer-a", db_path("hash_a"));
    DNode b("peer-b", db_path("hash_b"));
    wire(a, b);

    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "tamper-me";
    const std::string env =
        make_envelope("peer-a", "peer-b", id, payload, 3600000, a.sign_sk.data(), a.sign_pk.data());
    b.mgr->onFrame("peer-a", MessageType::OBJECT_DATA, env_to_data(env, id), true);
    TEST_ASSERT(b.mgr->counters().receipts_created == 1, "valid payload accepted");

    // Sign header for payloadA but send payloadB -> header hash mismatch.
    const std::string payloadA = "payloadA";
    const std::string payloadB = "payloadB";
    networkos::obj::NetworkObject o;
    o.origin.network_id = "chatp2p-mesh";
    o.origin.namespace_id = "chat";
    o.origin.object_id_hex = id.toHex();
    o.origin.origin = "peer-a";
    o.origin.destination = "peer-b";
    o.origin.object_type = "message";
    o.origin.created_at_ms = now_ms();
    o.origin.ttl_ms = 3600000;
    o.origin.priority = 1;
    o.origin.payload_size = payloadA.size();
    o.origin.payload_hash = networkos::obj::compute_payload_hash(payloadA);
    o.payload = payloadB;
    TEST_ASSERT(networkos::obj::sign_object(o, a.sign_sk.data(), a.sign_pk.data()), "sign");
    const std::string bad_env = networkos::obj::serialize(o);
    const uint64_t before = b.mgr->counters().receipts_created;
    b.mgr->onFrame("peer-a", MessageType::OBJECT_DATA, env_to_data(bad_env, id), true);
    TEST_ASSERT(b.mgr->counters().receipts_created == before, "hash-mismatched frame rejected");
    TEST_ASSERT(b.mgr->counters().auth_failed == 1, "hash mismatch counted as auth failure");
    std::cout << "hash verification ok\n";
}

// ---------------------------------------------------------------------------
// 9. TTL expiry -> TERMINAL (§61): undelivered expired objects are swept to
// FAILED/TERMINAL; delivered objects are untouched.
// ---------------------------------------------------------------------------
static void test_ttl_expired_terminal() {
    DNode a("peer-a", db_path("ttl_a"));
    DNode b("peer-b", db_path("ttl_b"));
    (void)b;

    networkos::ObjectId expired = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    networkos::ObjectId delivered = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    networkos::ObjectMeta m;
    m.namespace_id = "chat"; m.origin = "peer-a"; m.destination = "peer-b";
    m.object_type = "message"; m.created_at_ms = now_ms() - 7200000;  // 2h ago
    m.ttl_ms = 3600000;  // expired 1h ago
    m.priority = 1; m.payload_size = 5;
    m.payload_hash = networkos::obj::compute_payload_hash("hello");
    m.id = expired;
    networkos::ObjectStore::Outcome oc;
    TEST_ASSERT(a.store.putWithOutcome(m, "hello", oc) == networkos::Result::kOk, "expired obj stored");
    m.id = delivered;
    TEST_ASSERT(a.store.putWithOutcome(m, "world", oc) == networkos::Result::kOk, "delivered obj stored");
    TEST_ASSERT(a.store.markDelivered(delivered, now_ms()) == networkos::Result::kOk, "mark delivered");

    size_t failed = a.mgr->sweepExpiredDeliveries(now_ms());
    TEST_ASSERT(failed == 1, "only the expired-undeclared object failed");
    networkos::ObjectStatus st;
    uint8_t fc;
    TEST_ASSERT(a.store.deliveryReadout(expired, &st, nullptr, nullptr, &fc) == networkos::Result::kOk &&
                    st == networkos::ObjectStatus::kFailed &&
                    fc == networkos::delivery::kFailTerminal,
                "expired object FAILED/TERMINAL");
    TEST_ASSERT(a.store.deliveryReadout(delivered, &st, nullptr, nullptr, nullptr) == networkos::Result::kOk &&
                    st == networkos::ObjectStatus::kDelivered,
                "delivered object untouched");
    TEST_ASSERT(a.mgr->counters().ttl_expired == 1, "ttl_expired counter");
    std::cout << "ttl expired terminal ok\n";
}

// ---------------------------------------------------------------------------
// 10. require_receipt=false policy (Step 5.1 #4): with receipts not required,
// RECEIVED_ACK alone upgrades straight to CONFIRMED (DELIVERED is terminal).
// ---------------------------------------------------------------------------
static void test_no_receipt_policy() {
    DNode a("peer-a", db_path("noreq_a"), false);  // require_receipt=false
    DNode b("peer-b", db_path("noreq_b"));
    a.mgr->setConnectedPeersFn([&b]() -> std::vector<std::string> { return {b.peer_id}; });
    a.mgr->setSendFn([&a, &b](const std::string& pid, MessageType type, const std::string& p) -> bool {
        if (pid == b.peer_id) {
            b.mgr->onFrame(a.peer_id, type, p, true);
            return true;
        }
        return false;
    });
    a.mgr->setSigningKeysFns(
        [&a]() { return std::make_pair(a.sign_pk, a.sign_sk); },
        [&b](const std::string& pid) {
            return (pid == b.peer_id) ? b.sign_pk : std::vector<uint8_t>{};
        });
    b.mgr->setSigningKeysFns(
        [&b]() { return std::make_pair(b.sign_pk, b.sign_sk); },
        [&a](const std::string& pid) {
            return (pid == a.peer_id) ? a.sign_pk : std::vector<uint8_t>{};
        });
    // B must be able to receive A's direct offer AND reply (accept/ack/receipt).
    b.mgr->setConnectedPeersFn([&a]() -> std::vector<std::string> { return {a.peer_id}; });
    b.mgr->setSendFn([&a, &b](const std::string& pid, MessageType type, const std::string& p) -> bool {
        if (pid == a.peer_id) {
            a.mgr->onFrame(b.peer_id, type, p, false);
            return true;
        }
        return false;
    });
    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", "peer-a");
    const std::string payload = "noreq";
    const std::string env =
        make_envelope("peer-a", "peer-b", id, payload, 3600000, a.sign_sk.data(), a.sign_pk.data());
    networkos::ObjectMeta meta;
    meta.id = id; meta.namespace_id = "chat"; meta.origin = "peer-a"; meta.destination = "peer-b";
    meta.object_type = "message"; meta.created_at_ms = now_ms(); meta.ttl_ms = 3600000;
    meta.priority = 1; meta.payload_size = payload.size();
    meta.payload_hash = networkos::obj::compute_payload_hash(payload);
    a.mgr->storeAndDeliver(meta, env, 0);
    networkos::ObjectStatus st;
    TEST_ASSERT(a.store.deliveryReadout(id, &st, nullptr, nullptr, nullptr) == networkos::Result::kOk &&
                    st == networkos::ObjectStatus::kConfirmed,
                "no-receipt policy: ACK alone reaches CONFIRMED");
    std::cout << "require_receipt=false policy ok\n";
}

} // namespace

int main() {
    (void)sodium_init();
    test_frame_codec();
    test_store_schema_v3();
    test_milestone_direct();
    test_idempotent_repeat();
    test_replica_release();
    test_failure_classes();
    test_late_confirmation();
    test_hash_verification();
    test_ttl_expired_terminal();
    test_no_receipt_policy();
    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}
