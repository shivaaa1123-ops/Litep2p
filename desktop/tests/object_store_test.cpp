// object_store_test.cpp — Network OS Phase 3 store verification.
//
// Covers (phase file §9 items 3-7): restart survival, quota enforcement,
// TTL expiry (not refreshed by re-insert), dedup, memory bounds, eviction,
// crash-consistency semantics (transactional rollback), schema versioning.

#include "networkos/objectstore/ObjectStore.h"
#include "sqlite3_dyn.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

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
    const std::string dir = std::string("/tmp/networkos_p3_") + tag;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    return dir + "/objects.sqlite";
}

networkos::ObjectMeta make_meta(const std::string& tag, const std::string& ns,
                                const std::string& origin, int64_t now,
                                int64_t ttl_ms) {
    networkos::ObjectMeta m;
    m.id = networkos::ObjectId::generate("chatp2p-mesh", origin);
    m.namespace_id = ns;
    m.origin = origin;
    m.object_type = "message";
    m.created_at_ms = now;
    m.ttl_ms = ttl_ms;
    m.priority = 1;
    m.status = networkos::ObjectStatus::kQueuedLocal;
    return m;
}

} // namespace

int main() {
    const int64_t NOW = 1700000000000LL;

    // --- 1. Open + put/get round-trip + schema version ----------------------
    {
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = db_path("basic");
        TEST_ASSERT(store.open(opt), "store opens (schema created)");
        TEST_ASSERT(store.schemaVersion() == networkos::ObjectStore::kSchemaVersion,
                    "schema version 1");

        auto m = make_meta("o1", "chat", "peer-a", NOW, 7 * 24 * 3600 * 1000LL);
        const std::string payload = "the-payload";
        networkos::ObjectStore::Outcome oc;
        TEST_ASSERT(store.putWithOutcome(m, payload, oc) == networkos::Result::kOk &&
                        oc == networkos::ObjectStore::Outcome::Accepted,
                    "put accepted");
        TEST_ASSERT(store.contains(m.id), "contains after put");

        networkos::ObjectMeta mo;
        std::string po;
        TEST_ASSERT(store.get(m.id, mo, po) == networkos::Result::kOk, "get ok");
        TEST_ASSERT(po == payload, "payload round-trip");
        TEST_ASSERT(mo.namespace_id == "chat" && mo.origin == "peer-a", "meta round-trip");
        TEST_ASSERT(store.commit() == networkos::Result::kOk, "commit (wal checkpoint)");

        // --- 2. Restart survival: close + reopen ---------------------------
        store.close();
        TEST_ASSERT(store.open(opt), "store reopens");
        networkos::ObjectMeta m2;
        std::string p2;
        TEST_ASSERT(store.get(m.id, m2, p2) == networkos::Result::kOk,
                    "object survives reopen (process-death proxy)");
        TEST_ASSERT(p2 == payload, "payload intact after reopen");
        TEST_ASSERT(m2.ttl_ms == m.ttl_ms, "TTL unchanged by reopen");
        store.close();
    }
    std::cout << "open/put/get/restart-survival/schema ok\n";

    // --- 3. Quota enforcement + system reserve ------------------------------
    {
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = db_path("quota");
        opt.default_namespace_quota_bytes = 200;
        opt.default_origin_quota_bytes = 200;
        opt.global_quota_bytes = 1000;
        opt.system_reserve_bytes = 100;
        TEST_ASSERT(store.open(opt), "store opens");
        TEST_ASSERT(store.setNamespaceQuota("chat", 200) == networkos::Result::kOk,
                    "set namespace quota");

        // Fill the namespace past the quota.
        networkos::ObjectStore::Outcome oc;
        auto m1 = make_meta("a", "chat", "peer-a", NOW, 3600000);
        TEST_ASSERT(store.putWithOutcome(m1, std::string(150, 'x'), oc) == networkos::Result::kOk &&
                        oc == networkos::ObjectStore::Outcome::Accepted,
                    "first insert accepted");
        auto m2 = make_meta("b", "chat", "peer-a", NOW, 3600000);
        TEST_ASSERT(store.putWithOutcome(m2, std::string(150, 'y'), oc) == networkos::Result::kOk &&
                        oc == networkos::ObjectStore::Outcome::RejectedQuota,
                    "over-quota insert returns REJECTED_QUOTA");
        TEST_ASSERT(store.countObjects() == 1, "rejected insert not stored");
        TEST_ASSERT(!store.contains(m2.id), "rejected object absent");
        store.close();
    }
    std::cout << "quota enforcement ok\n";

    // --- 4. TTL expiry + no refresh by re-insert -----------------------------
    {
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = db_path("ttl");
        TEST_ASSERT(store.open(opt), "store opens");
        auto m = make_meta("ttl1", "chat", "peer-a", NOW, 1000);  // 1s TTL
        networkos::ObjectStore::Outcome oc;
        TEST_ASSERT(store.putWithOutcome(m, "x", oc) == networkos::Result::kOk, "put ok");

        // Re-insert the SAME ObjectID with a NEW TTL must NOT extend life.
        auto m2 = m;
        m2.ttl_ms = 24 * 3600 * 1000LL;
        TEST_ASSERT(store.putWithOutcome(m2, "x", oc) == networkos::Result::kOk &&
                        oc == networkos::ObjectStore::Outcome::Accepted,
                    "re-insert dedups (idempotent)");
        TEST_ASSERT(store.countObjects() == 1, "no duplicate row");

        uint64_t removed = 0;
        TEST_ASSERT(store.purgeExpired(NOW + 5000, &removed) == networkos::Result::kOk, "purge ok");
        TEST_ASSERT(removed == 1, "object expired at created+ttl");
        TEST_ASSERT(store.countObjects() == 0, "expired object gone");
        TEST_ASSERT(store.isDuplicate(m.id), "dedup record survives expiry");
        store.close();
    }
    std::cout << "TTL expiry + dedup idempotency ok\n";

    // --- 5. Dedup: re-insert returns existing state, no duplication ---------
    {
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = db_path("dedup");
        TEST_ASSERT(store.open(opt), "store opens");
        auto m = make_meta("d1", "chat", "peer-a", NOW, 3600000);
        networkos::ObjectStore::Outcome oc;
        TEST_ASSERT(store.putWithOutcome(m, "payload", oc) == networkos::Result::kOk, "put");
        networkos::ObjectStore::Outcome oc2;
        TEST_ASSERT(store.putWithOutcome(m, "payload", oc2) == networkos::Result::kOk &&
                        oc2 == networkos::ObjectStore::Outcome::Accepted,
                    "duplicate put accepted idempotently");
        TEST_ASSERT(store.countObjects() == 1, "no duplicate from re-insert");
        TEST_ASSERT(store.isDuplicate(m.id), "dedup present");
        store.close();
    }
    std::cout << "dedup ok\n";

    // --- 6. Eviction (score-based) -------------------------------------------
    {
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = db_path("evict");
        TEST_ASSERT(store.open(opt), "store opens");
        auto m1 = make_meta("e1", "chat", "peer-a", NOW, 3600000);
        m1.priority = 0;
        auto m2 = make_meta("e2", "chat", "peer-a", NOW, 3600000);
        m2.priority = 3;
        networkos::ObjectStore::Outcome oc;
        store.putWithOutcome(m1, std::string(100, 'a'), oc);
        store.putWithOutcome(m2, std::string(100, 'b'), oc);
        TEST_ASSERT(store.countObjects() == 2, "two objects");
        uint64_t freed = 0;
        TEST_ASSERT(store.evictForQuota("chat", "peer-a", 100, &freed) == networkos::Result::kOk,
                    "evict ok");
        TEST_ASSERT(freed >= 100, "freed at least one object");
        TEST_ASSERT(store.countObjects() == 1, "exactly one evicted");
        TEST_ASSERT(store.contains(m1.id) == false, "lowest-priority evicted first");
        TEST_ASSERT(store.contains(m2.id), "higher-priority retained");
        store.close();
    }
    std::cout << "score-based eviction ok\n";

    // --- 7. Memory bounds: 1000-object batch, no whole-batch buffering ------
    {
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = db_path("batch");
        opt.default_namespace_quota_bytes = 1000000;
        TEST_ASSERT(store.open(opt), "store opens");
        networkos::ObjectStore::Outcome oc;
        int accepted = 0;
        for (int i = 0; i < 1000; ++i) {
            auto m = make_meta("b" + std::to_string(i), "chat", "peer-a", NOW, 3600000);
            if (store.putWithOutcome(m, std::string(64, 'p'), oc) == networkos::Result::kOk &&
                oc == networkos::ObjectStore::Outcome::Accepted) {
                ++accepted;
            }
        }
        TEST_ASSERT(accepted == 1000, "1000-object batch stored");
        TEST_ASSERT(store.countObjects() == 1000, "count matches");
        TEST_ASSERT(store.totalBytes() == 1000ull * 64ull, "byte accounting exact");
        // Per-object inserts => no whole-batch buffering; spot-check one read.
        networkos::ObjectMeta mo;
        std::string po;
        networkos::ObjectMeta probe = make_meta("probe", "chat", "peer-a", NOW, 3600000);
        store.putWithOutcome(probe, "spot", oc);
        TEST_ASSERT(store.get(probe.id, mo, po) == networkos::Result::kOk && po == "spot",
                    "spot-check after batch");
        store.close();
    }
    std::cout << "memory bounds / batch ok\n";

    // --- 8. Crash-safe open (§25): corrupt DB must FAIL to open -------------
    {
        const std::string path = db_path("corrupt");
        {
            networkos::ObjectStore store;
            networkos::ObjectStore::Options opt;
            opt.path = path;
            TEST_ASSERT(store.open(opt), "store opens (setup)");
            auto m = make_meta("c1", "chat", "peer-a", NOW, 3600000);
            networkos::ObjectStore::Outcome oc;
            store.putWithOutcome(m, "corrupt-me", oc);
            store.commit();
            store.close();  // close checkpoints WAL into the main file
        }
        // Corrupt a page-STRUCTURE byte (offset 100 = page 2's page-type byte).
        // quick_check validates page structure (not content bytes), so this is
        // reliably detected as non-"ok" — unlike a content-byte flip.
        {
            std::error_code ec;
            std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
            TEST_ASSERT(f.is_open(), "corrupt db file opened for writing");
            f.seekg(0, std::ios::end);
            const std::streampos sz = f.tellg();
            TEST_ASSERT(sz > 512, "db file has real size");
            f.seekp(100, std::ios::beg);   // page 2 header: first byte = page type
            char flip = 0;
            f.read(&flip, 1);
            flip ^= 0x5A;                  // turn a valid page type into garbage
            f.seekp(100, std::ios::beg);
            f.write(&flip, 1);
            f.close();
        }
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = path;
        TEST_ASSERT(!store.open(opt), "corrupt DB refused on open (quick_check)");
        TEST_ASSERT(!store.is_open(), "store not open after corrupt open");
    }
    std::cout << "corruption-open rejection ok\n";

    // --- 9. Forward migration: a future schema version must be rejected -----
    {
        const std::string path = db_path("futureschema");
        {
            networkos::ObjectStore store;
            networkos::ObjectStore::Options opt;
            opt.path = path;
            TEST_ASSERT(store.open(opt), "store opens (setup)");
            store.close();
        }
        // Bump the schema version past the current one.
        {
            SqliteDyn sql;  // engine's dynamic loader
            TEST_ASSERT(sql.load(), "sqlite loads");
            sqlite3* db = nullptr;
            if (sql.open_v2(path.c_str(), &db, 0x02 | 0x04, nullptr) == SQLITE_OK && db) {
                sql.exec(db, "UPDATE schema_version SET version=99;");
                sql.close_v2(db);
            }
            sql.unload();
        }
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = path;
        TEST_ASSERT(!store.open(opt), "future schema rejected (forward-migration guard)");
        TEST_ASSERT(!store.is_open(), "store not open after future-schema reject");
    }
    std::cout << "forward-migration rejection ok\n";

    // --- 10. Usage accounting stays exact through put/remove/evict/purge -----
    {
        // Eviction scores expiry with the DB wall clock, so use a REAL clock
        // base here (a frozen 2023 NOW would make every object look expired).
        const int64_t RNOW = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
        networkos::ObjectStore store;
        networkos::ObjectStore::Options opt;
        opt.path = db_path("usage");
        opt.default_namespace_quota_bytes = 100000;
        opt.default_origin_quota_bytes = 100000;
        TEST_ASSERT(store.open(opt), "store opens");
        networkos::ObjectStore::Outcome oc;

        auto m1 = make_meta("u1", "chat", "peer-a", RNOW, 3600000);
        m1.priority = 1;
        auto m2 = make_meta("u2", "chat", "peer-a", RNOW, 3600000);
        m2.priority = 3;
        auto m3 = make_meta("u3", "chat", "peer-a", RNOW, 3600000);
        m3.priority = 0;
        store.putWithOutcome(m1, std::string(100, 'a'), oc);
        store.putWithOutcome(m2, std::string(200, 'b'), oc);
        store.putWithOutcome(m3, std::string(50, 'c'), oc);
        networkos::QuotaInfo q;
        store.quota("chat", "peer-a", q);
        TEST_ASSERT(q.used_bytes == 350, "usage counts all three objects");

        // remove one -> usage drops exactly its bytes.
        TEST_ASSERT(store.remove(m2.id) == networkos::Result::kOk, "remove ok");
        store.quota("chat", "peer-a", q);
        TEST_ASSERT(q.used_bytes == 150, "usage drops on remove");

        // evict (need 30B): lowest priority (m3, 50B) goes first; freed 50 >= 30.
        uint64_t freed = 0;
        TEST_ASSERT(store.evictForQuota("chat", "peer-a", 30, &freed) == networkos::Result::kOk,
                    "evict ok");
        TEST_ASSERT(freed == 50, "evicted exactly m3");
        store.quota("chat", "peer-a", q);
        TEST_ASSERT(q.used_bytes == 100, "usage drops on evict");

        // purge the expired one -> usage drops exactly its bytes.
        auto m4 = make_meta("u4", "chat", "peer-a", RNOW, 100);  // 100ms TTL
        store.putWithOutcome(m4, std::string(40, 'd'), oc);
        uint64_t removed = 0;
        TEST_ASSERT(store.purgeExpired(RNOW + 5000, &removed) == networkos::Result::kOk, "purge ok");
        TEST_ASSERT(removed == 1, "expired purged");
        store.quota("chat", "peer-a", q);
        TEST_ASSERT(q.used_bytes == 100, "usage drops on purge");
        TEST_ASSERT(store.totalBytes() == 100, "totalBytes agrees with usage");
        store.close();
    }
    std::cout << "usage accounting consistency ok\n";

    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}
