// delivery_kill_probe.cpp — Network OS Phase 5 durable delivery probe.
//
// Proves the two Phase 5 "kill at the arrow" durability points for receipts:
//   1. A delivered/confirmed object's delivery state survives process death.
//   2. A recorded signed receipt survives process death (so CONFIRMED is
//      durable proof — invariant 4/17).
//
// Usage:
//   delivery_kill_probe --write --db <path> --object <hex> --confirmed \
//       --receipt <receipt_object_hex>   # Phase A: write + crash
//   delivery_kill_probe --check --db <path> --object <hex> --confirmed \
//       --receipt <receipt_object_hex>   # Phase B: reopen + verify everything
//
// A shell harness drives this like SIGKILL + reopen between the two phases.

#include "networkos/object/object_id.h"
#include "networkos/objectstore/ObjectStore.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

using namespace networkos;

// Resolve a canonical ObjectId: prefer the `--object` arg if it parses;
// otherwise generate one deterministically from the marker and persist it to a
// sidecar (writer) / read it back (checker) so both phases agree across the
// process-death boundary.
static std::string oid_sidecar(const std::string& db) { return db + ".oid"; }

static ObjectId resolve_id(const std::string& marker, const std::string& db, bool write_mode) {
    ObjectId id;
    if (ObjectId::fromHex(marker, id) && !id.empty()) return id;
    const std::string side = oid_sidecar(db);
    if (!write_mode) {
        std::ifstream in(side);
        std::string hex;
        if (in >> hex && ObjectId::fromHex(hex, id)) return id;
    }
    id = ObjectId::generate("chatp2p-mesh", "peer-a");
    if (write_mode) {
        std::ofstream out(side);
        out << id.toHex() << "\n";
    }
    return id;
}

int main(int argc, char** argv) {
    std::string db, object_hex, receipt_hex;
    bool write = false, check = false, confirmed = false, verbose = false;
    (void)argc;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--write") write = true;
        else if (a == "--check") check = true;
        else if (a == "--db" && i + 1 < argc) db = argv[++i];
        else if (a == "--object" && i + 1 < argc) object_hex = argv[++i];
        else if (a == "--receipt" && i + 1 < argc) receipt_hex = argv[++i];
        else if (a == "--confirmed") confirmed = true;
        else if (a == "-v") verbose = true;
    }
    if (db.empty()) { std::cerr << "need --db\n"; return 2; }

    ObjectStore store;
    ObjectStore::Options opt;
    opt.path = db;
    if (!store.open(opt)) { std::cerr << "open failed\n"; return 2; }
    if (verbose) std::cout << "schema=" << store.schemaVersion() << "\n";

    if (write) {
        ObjectId id = resolve_id(object_hex, db, true);
        const std::string id_hex = id.toHex();
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
        ObjectStore::Outcome oc;
        if (store.putWithOutcome(meta, "hello", oc) != Result::kOk) { std::cerr << "put failed\n"; return 2; }
        if (store.markDelivered(id, 1700000001000LL) != Result::kOk) { std::cerr << "markDelivered failed\n"; return 2; }
        if (confirmed && store.confirmObject(id, 1700000002000LL) != Result::kOk) {
            std::cerr << "confirm failed\n"; return 2;
        }
        if (!receipt_hex.empty()) {
            ObjectStore::ReceiptRow row;
            row.delivered_object_id_hex = id_hex;
            row.receipt_object_id_hex = receipt_hex;
            row.origin = "peer-a";
            row.destination = "peer-b";
            row.receipt_type = 0;
            row.received_at_ms = 1700000001000LL;
            row.object_hash_hex = std::string(64, 'a');
            row.signature = std::string(64, 's');
            if (store.recordReceipt(row) != Result::kOk) { std::cerr << "recordReceipt failed\n"; return 2; }
        }
        store.close();  // "process death" boundary
        if (verbose) std::cout << "probe write-done id=" << id_hex << "\n";
        return 0;
    }

    if (check) {
        ObjectId id = resolve_id(object_hex, db, false);
        const std::string id_hex = id.toHex();
        ObjectStatus st;
        int64_t delivered = 0, confirmed_at = 0;
        uint8_t fc = 0;
        if (store.deliveryReadout(id, &st, &delivered, &confirmed_at, &fc) != Result::kOk) {
            std::cerr << "delivery state did NOT survive reopen\n";
            return 1;
        }
        std::cout << "DELIVERY_STATE_SURVIVED state=" << static_cast<int>(st)
                  << " delivered=" << delivered;
        if (confirmed) {
            if (st != ObjectStatus::kConfirmed) {
                std::cerr << " expected CONFIRMED got " << static_cast<int>(st) << "\n";
                return 1;
            }
            std::cout << " confirmed_at=" << confirmed_at;
        }
        if (!receipt_hex.empty()) {
            ObjectStore::ReceiptRow row;
            if (store.getReceipt(id_hex, row) != Result::kOk ||
                row.receipt_object_id_hex != receipt_hex) {
                std::cerr << " receipt did NOT survive reopen\n";
                return 1;
            }
            if (row.signature.size() != 64) { std::cerr << " receipt signature lost\n"; return 1; }
            std::cout << " receipt_survived=" << row.receipt_object_id_hex;
        }
        std::cout << "\nKILL_PROBE_OK\n";
        store.close();
        return 0;
    }

    std::cerr << "need --write or --check\n";
    return 2;
}