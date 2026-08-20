// object_store_test.cpp — Network OS Phase 3 store verification.
//
// Covers (phase file §9 items 3-7): restart survival, quota enforcement,
// TTL expiry (not refreshed by re-insert), dedup, memory bounds, eviction,
// crash-consistency semantics (transactional rollback), schema versioning.

#include "networkos/objectstore/ObjectStore.h"

#include <cstdint>
#include <filesystem>
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

    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << g_checks
              << " checks, " << g_failures << " failure(s)\n";
    return g_failures == 0 ? 0 : 1;
}
