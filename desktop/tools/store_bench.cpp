// store_bench.cpp — Network OS Phase 3 object-store performance probe.
//
// Measures the durable store under realistic per-object-transaction load:
//   - put throughput (objects/sec), individual WAL transactions
//   - get throughput (reads/sec)
//   - cold open latency for a populated DB
//   - DB size overhead vs raw payload bytes
//   - single-commit (fsync) latency
//
// Usage: store_bench [--count N] [--payload P] [--db <path>]
//   defaults: 10000 objects, 512-byte payloads.

#include "networkos/objectstore/ObjectStore.h"
#include "networkos/object/object_id.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

uint64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

uint64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

} // namespace

int main(int argc, char** argv) {
    int count = 10000;
    int payload = 512;
    std::string db = "/tmp/networkos_p3_bench/objects.sqlite";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--payload") == 0 && i + 1 < argc) payload = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--db") == 0 && i + 1 < argc) db = argv[++i];
    }
    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::path(db).parent_path(), ec);
    std::filesystem::create_directories(std::filesystem::path(db).parent_path(), ec);

    const int64_t NOW = 1700000000000LL;
    const std::string pl(payload, 'x');
    std::vector<networkos::ObjectId> ids;
    ids.reserve(count);

    networkos::ObjectStore store;
    networkos::ObjectStore::Options opt;
    opt.path = db;
    opt.global_quota_bytes = 16ull * 1024 * 1024 * 1024;  // no quota interference
    if (!store.open(opt)) { std::cerr << "open failed\n"; return 1; }

    // ---- put throughput -----------------------------------------------------
    const uint64_t t0 = now_ms();
    networkos::ObjectStore::Outcome oc;
    int rejected = 0;
    for (int i = 0; i < count; ++i) {
        networkos::ObjectMeta m;
        m.id = networkos::ObjectId::generate("chatp2p-mesh", "bench");
        m.namespace_id = "chat";
        m.origin = "bench";
        m.object_type = "message";
        m.created_at_ms = NOW;
        m.ttl_ms = 3600000;
        if (store.putWithOutcome(m, pl, oc) != networkos::Result::kOk) { std::cerr << "put fail\n"; return 1; }
        if (oc != networkos::ObjectStore::Outcome::Accepted) ++rejected;
        ids.push_back(m.id);
    }
    const uint64_t put_ms = now_ms() - t0;

    // ---- get throughput -----------------------------------------------------
    const uint64_t t1 = now_ms();
    networkos::ObjectMeta mo;
    std::string po;
    for (int i = 0; i < count; ++i) {
        if (store.get(ids[i], mo, po) != networkos::Result::kOk) { std::cerr << "get fail\n"; return 1; }
    }
    const uint64_t get_ms = now_ms() - t1;

    // ---- single-commit (fsync) latency --------------------------------------
    const uint64_t t2 = now_us();
    store.commit();
    const uint64_t commit_us = now_us() - t2;

    // ---- cold open latency --------------------------------------------------
    store.close();
    const uint64_t t3 = now_ms();
    networkos::ObjectStore reopen;
    if (!reopen.open(opt)) { std::cerr << "reopen failed\n"; return 1; }
    const uint64_t open_ms = now_ms() - t3;
    if (reopen.countObjects() != static_cast<uint64_t>(count)) {
        std::cerr << "reopen count mismatch\n"; return 1;
    }
    reopen.close();

    const uint64_t file_bytes = std::filesystem::file_size(db, ec);
    const uint64_t raw_bytes = static_cast<uint64_t>(count) * static_cast<uint64_t>(payload);

    std::cout << "store_bench: count=" << count << " payload=" << payload << "B\n";
    std::cout << "  put:   " << put_ms << " ms => "
              << (count * 1000.0 / put_ms) << " obj/s (individual txns, WAL)\n";
    std::cout << "  get:   " << get_ms << " ms => "
              << (count * 1000.0 / get_ms) << " obj/s\n";
    std::cout << "  commit(fsync/wal checkpoint): " << commit_us << " us\n";
    std::cout << "  cold open: " << open_ms << " ms\n";
    std::cout << "  db size: " << file_bytes << " B vs raw " << raw_bytes
              << " B (" << (file_bytes * 100 / (raw_bytes > 0 ? raw_bytes : 1)) << "%)\n";
    std::cout << "  rejected: " << rejected << "\n";
    return 0;
}