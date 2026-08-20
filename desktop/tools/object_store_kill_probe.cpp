// object_store_kill_probe.cpp — Network OS Phase 3 crash-consistency probe.
//
// Exercises the SQLite/WAL object store's atomic receive path with kill
// points the harness (object_store_kill_test.sh) SIGKILLs at:
//   --mode burst   : inserts 1..N objects, printing "INSERTED n=<i>" after
//                    EACH durable commit. The harness kills at a random point;
//                    on reopen, EXACTLY the printed count must be present with
//                    no partial rows (invariant 2: never ACK before commit,
//                    and never lose an object after commit).
//   --mode commit  : single atomic insert + wal checkpoint, prints
//                    MARKER_C_COMMITTED, then sleeps. Harness kills after the
//                    marker; on reopen the object MUST be present (a durable
//                    commit survives process death).
//
// Usage: object_store_kill_probe --db <path> --mode burst|commit [--count N]

#include "networkos/objectstore/ObjectStore.h"

#include <cstring>
#include <iostream>
#include <string>

namespace {
void usage() {
    std::cerr << "usage: object_store_kill_probe --db <path> --mode burst|commit [--count N]\n";
    std::exit(2);
}
} // namespace

int main(int argc, char** argv) {
    std::string db, mode;
    int count = 50;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--db") == 0 && i + 1 < argc) db = argv[++i];
        else if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
        else if (std::strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = std::atoi(argv[++i]);
        else usage();
    }
    if (db.empty() || (mode != "burst" && mode != "commit")) usage();

    networkos::ObjectStore store;
    networkos::ObjectStore::Options opt;
    opt.path = db;
    if (!store.open(opt)) { std::cerr << "PROBE: open failed\n"; return 1; }

    if (mode == "burst") {
        for (int i = 0; i < count; ++i) {
            networkos::ObjectMeta m;
            m.id = networkos::ObjectId::generate("chatp2p-mesh", "kill-probe");
            m.namespace_id = "chat";
            m.origin = "kill-probe";
            m.object_type = "message";
            m.created_at_ms = 1700000000000LL + i;
            m.ttl_ms = 3600000;
            networkos::ObjectStore::Outcome oc;
            const auto rc = store.putWithOutcome(m, "payload-" + std::to_string(i), oc);
            if (rc != networkos::Result::kOk) { std::cerr << "PROBE: put failed\n"; return 1; }
            std::cout << "INSERTED n=" << (i + 1) << "\n" << std::flush;
        }
        return 0;
    }

    // commit mode
    networkos::ObjectId id = networkos::ObjectId::generate("chatp2p-mesh", "kill-probe-commit");
    networkos::ObjectMeta m;
    m.id = id;
    m.namespace_id = "chat";
    m.origin = "kill-probe-commit";
    m.object_type = "message";
    m.created_at_ms = 1700000000000LL;
    m.ttl_ms = 3600000;
    networkos::ObjectStore::Outcome oc;
    const auto rc = store.putWithOutcome(m, "committed-payload", oc);
    std::cout << "MARKER_C_INSERTED id=" << id.toHex()
              << " present=" << (store.contains(id) ? 1 : 0) << "\n"
              << std::flush;
    (void)store.commit();
    std::cout << "MARKER_C_COMMITTED\n" << std::flush;
    for (;;) { /* harness SIGKILLs us here */ }
    return 0;
}