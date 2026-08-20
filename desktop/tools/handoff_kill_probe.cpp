// handoff_kill_probe.cpp — Network OS Phase 4 SIGKILL harness probe.
//
// Drives the CARRIER side of the two-phase handoff as a standalone process
// and prints a marker line before/after every arrow, so the harness can
// kill -9 at a random point and then verify durability invariants:
//
//   - invariant 2 (never acknowledged-but-not-stored): if ACK_SENT was
//     printed, the object + lease rows are durably committed (putWithLease
//     only returns after COMMIT, and STORED_ACK is sent after that).
//   - all-or-nothing: the commit is one SQLite transaction, so a kill
//     mid-commit leaves exactly the pre- or post-commit state.
//
// Usage:
//   handoff_kill_probe --db <path> --mode run|verify
#include "networkos/handoff/HandoffManager.h"
#include "networkos/handoff/handoff_frames.h"
#include "networkos/object/envelope.h"
#include "networkos/objectstore/ObjectStore.h"

#include "message_types.h"

#include <sodium.h>

#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

namespace {

void mark(const char* s) {
    std::cout << s << std::endl;
    std::cout.flush();
}

std::string arg(int argc, char** argv, const char* key) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == key) return argv[i + 1];
    }
    return {};
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string to_hex(const std::string& raw) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    for (unsigned char c : raw) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0F]);
    }
    return out;
}

} // namespace

int main(int argc, char** argv) {
    (void)sodium_init();
    const std::string db = arg(argc, argv, "--db");
    const std::string mode = arg(argc, argv, "--mode");
    if (db.empty()) {
        std::cerr << "handoff_kill_probe: --db required\n";
        return 2;
    }

    // ---- verify mode: reopen + assert all-or-nothing invariant ------------
    if (mode == "verify") {
        networkos::ObjectStore::Options opt;
        opt.path = db;
        networkos::ObjectStore store;
        if (!store.open(opt)) {
            std::cout << "VERIFY:DB_CORRUPT\n";
            return 1;
        }
        const uint64_t n = store.countObjects();
        const int64_t now = now_ms();
        uint64_t leases = 0;
        store.forEachExpiringLease(now + 365LL * 24 * 3600 * 1000,
                                   [&](const networkos::ObjectStore::LeaseInfo&) {
                                       ++leases;
                                       return networkos::Result::kOk;
                                   });
        std::cout << "VERIFY:objects=" << n << " leases=" << leases << "\n";
        // All-or-nothing: object present iff lease present (single commit).
        if (n != leases) {
            std::cout << "VERIFY:INVARIANT_BROKEN object/lease mismatch\n";
            return 1;
        }
        return 0;
    }

    // ---- run mode: full carrier-side handoff ------------------------------
    networkos::ObjectStore::Options opt;
    opt.path = db;
    networkos::ObjectStore store;
    if (!store.open(opt)) {
        std::cout << "OPEN_FAILED\n";
        return 1;
    }
    mark("CARRIER_OPENED");

    const std::string sender_id = "peer-a";
    const std::string carrier_id = "peer-c";
    std::vector<uint8_t> sender_pk(32), sender_sk(64);
    std::vector<uint8_t> carrier_pk(32), carrier_sk(64);
    crypto_sign_keypair(sender_pk.data(), sender_sk.data());
    crypto_sign_keypair(carrier_pk.data(), carrier_sk.data());

    // A signed envelope as a real sender would produce.
    networkos::obj::NetworkObject obj;
    obj.origin.network_id = "chatp2p-mesh";
    obj.origin.namespace_id = "chat";
    obj.origin.object_type = "message";
    obj.origin.origin = sender_id;
    obj.origin.created_at_ms = now_ms();
    obj.origin.ttl_ms = 7LL * 24 * 3600 * 1000;
    const std::string payload = "kill-probe-payload";
    obj.origin.payload_size = payload.size();
    obj.origin.payload_hash = networkos::obj::compute_payload_hash(payload);
    obj.payload = payload;
    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", sender_id);
    obj.origin.object_id_hex = id.toHex();
    if (!networkos::obj::sign_object(obj, sender_sk.data(), sender_pk.data())) {
        std::cout << "SIGN_FAILED\n";
        return 1;
    }
    const std::string envelope = networkos::obj::serialize(obj);

    networkos::handoff::HandoffManager::Config ccfg;
    ccfg.local_peer_id = carrier_id;
    networkos::handoff::HandoffManager carrier(&store, ccfg);
    carrier.setSigningKeysFns(
        [&]() { return std::make_pair(carrier_pk, carrier_sk); },
        [&](const std::string& pid) { return (pid == sender_id) ? sender_pk : std::vector<uint8_t>{}; });
    // Marker hooks on the OUTBOUND frames (ACCEPT before commit; STORED_ACK
    // only after the durable commit — invariant 2).
    carrier.setSendFn([&](const std::string&, MessageType type,
                          const std::string&) -> bool {
        if (type == MessageType::OBJECT_ACCEPT) mark("ACCEPT_SENT");
        if (type == MessageType::STORED_ACK) mark("ACK_SENT");
        return true;
    });

    networkos::handoff::OfferFrame offer;
    offer.object_id_hex = id.toHex();
    offer.namespace_id = "chat";
    offer.origin = sender_id;
    offer.destination = "";
    offer.size_bytes = payload.size();
    offer.payload_hash_hex = to_hex(obj.origin.payload_hash);
    offer.expires_at_ms = obj.origin.created_at_ms + obj.origin.ttl_ms;
    carrier.onFrame(sender_id, MessageType::OBJECT_OFFER,
                    networkos::handoff::encode_offer(offer));
    mark("OFFER_RECEIVED");

    networkos::handoff::DataFrame df;
    df.object_id_hex = id.toHex();
    df.envelope = envelope;
    mark("DATA_RECEIVED");
    carrier.onFrame(sender_id, MessageType::OBJECT_DATA,
                    networkos::handoff::encode_data(df));
    mark("RUN_DONE");
    return 0;
}
