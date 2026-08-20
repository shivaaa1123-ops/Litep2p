// ObjectStore.cpp — SQLite (WAL) durable object store.

#include "networkos/objectstore/ObjectStore.h"

#include "sqlite3_dyn.h"

#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>

namespace networkos {

namespace {

using DestructorType = void (*)(void*);
inline DestructorType kTransient() { return reinterpret_cast<DestructorType>(-1); }
constexpr int kSqliteOpenReadWriteCreate = 0x02 | 0x04;  // READWRITE | CREATE

} // namespace

const char* ObjectStore::outcome_name(ObjectStore::Outcome o) {
    switch (o) {
        case Outcome::Accepted: return "ACCEPTED";
        case Outcome::RejectedAuth: return "REJECTED_AUTH";
        case Outcome::RejectedPolicy: return "REJECTED_POLICY";
        case Outcome::RejectedQuota: return "REJECTED_QUOTA";
        case Outcome::Busy: return "BUSY";
        case Outcome::RetryAfter: return "RETRY_AFTER";
        case Outcome::Unsupported: return "UNSUPPORTED";
    }
    return "UNKNOWN";
}

struct ObjectStore::Impl {
    SqliteDyn sqlite;
    sqlite3* db{nullptr};
    Options opts;
    mutable std::mutex mu;
    // Amortized dedup-prune counter: the "COUNT(*) FROM dedup" gate is a full
    // table scan, so running it on every put makes inserts O(N) again. We only
    // re-check (and possibly prune) every 256 puts — bounded amortized cost.
    uint64_t puts_since_dedup_prune{0};

    bool exec(const char* sql) {
        return db && sqlite.exec(db, sql) == SQLITE_OK;
    }

    // Lock-free teardown (caller holds mu). Used by close() and by open()'s
    // failure paths — open() must never call close() while holding mu (the
    // mutex is non-recursive; doing so self-deadlocks).
    void teardown() {
        if (db) {
            sqlite.close_v2(db);
            db = nullptr;
        }
        sqlite.unload();
    }

    struct Stmt {
        SqliteDyn& s;
        sqlite3_stmt* st{nullptr};
        Stmt(SqliteDyn& sql, sqlite3* db, const char* sql_text) : s(sql) {
            if (db) s.prepare_v2(db, sql_text, -1, &st, nullptr);
        }
        ~Stmt() { if (st) s.finalize(st); }
        bool ok() const { return st != nullptr; }
        int step() { return s.step(st); }
        void bind_text(int idx, const std::string& v) {
            s.bind_text(st, idx, v.data(), static_cast<int>(v.size()), kTransient());
        }
        void bind_int(int idx, int v) { s.bind_int(st, idx, v); }
        void bind_int64(int idx, int64_t v) { s.bind_int64(st, idx, v); }
        std::string col_text(int idx) const {
            const unsigned char* p = s.column_text(st, idx);
            const int n = s.column_bytes(st, idx);
            if (!p || n < 0) return {};
            return std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
        }
        int col_int(int idx) const { return s.column_int(st, idx); }
        int64_t col_int64(int idx) const { return s.column_int64(st, idx); }
    };
};

ObjectStore::ObjectStore() : m_impl(std::make_unique<Impl>()) {}
ObjectStore::~ObjectStore() { close(); }

bool ObjectStore::open(const Options& options) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (m_open) return true;
    m_options = options;
    m_impl->opts = options;

    if (!m_impl->sqlite.load()) {
        return false;  // SQLite runtime unavailable
    }
    if (m_impl->sqlite.open_v2(options.path.c_str(), &m_impl->db,
                               kSqliteOpenReadWriteCreate, nullptr) != SQLITE_OK) {
        m_impl->db = nullptr;
        return false;
    }

    if (options.enable_wal) m_impl->exec("PRAGMA journal_mode=WAL;");
    m_impl->exec("PRAGMA synchronous=NORMAL;");
    m_impl->exec("PRAGMA busy_timeout=5000;");
    m_impl->exec("PRAGMA foreign_keys=ON;");

    {  // Corruption detection on open (Step 3.5/§25): require quick_check to
        // return exactly the "ok" row. A corrupt DB returns one or more error
        // rows instead — those must FAIL the open.
        Impl::Stmt st(m_impl->sqlite, m_impl->db, "PRAGMA quick_check;");
        bool healthy = false;
        if (st.ok() && st.step() == SQLITE_ROW) {
            healthy = st.col_text(0) == "ok";
        }
        if (!healthy) {
            m_impl->teardown();
            return false;
        }
    }

    const char* kSchema[] = {
        "CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);",
        "CREATE TABLE IF NOT EXISTS namespaces("
        "  namespace_id TEXT PRIMARY KEY,"
        "  quota_bytes INTEGER NOT NULL DEFAULT 67108864,"
        "  reserved INTEGER NOT NULL DEFAULT 0);",
        "CREATE TABLE IF NOT EXISTS objects("
        "  object_id TEXT PRIMARY KEY,"
        "  namespace_id TEXT NOT NULL,"
        "  origin TEXT NOT NULL,"
        "  destination TEXT,"
        "  object_type TEXT,"
        "  created_at_ms INTEGER NOT NULL,"
        "  ttl_ms INTEGER NOT NULL,"
        "  expires_at_ms INTEGER NOT NULL,"
        "  priority INTEGER NOT NULL DEFAULT 0,"
        "  payload_size INTEGER NOT NULL DEFAULT 0,"
        "  payload_hash TEXT,"
        "  payload_blob BLOB,"
        "  origin_header_blob BLOB,"
        "  origin_signature BLOB,"
        "  forwarding_header_blob BLOB,"
        "  envelope_blob BLOB,"
        "  state INTEGER NOT NULL DEFAULT 0,"
        "  lease_expires_at_ms INTEGER,"
        "  replica_hint INTEGER,"
        "  delivered_at_ms INTEGER,"
        "  confirmed_at_ms INTEGER,"
        "  failure_class INTEGER NOT NULL DEFAULT 0);",
        // Incremental usage counter (one row per namespace+origin). Quota
        // checks read this instead of SUM() over objects — otherwise every
        // insert is O(all objects) and the store degrades to O(N^2) (measured
        // ~250 obj/s at 10k objects). Updated in the same transaction as the
        // object rows, so it can never drift.
        "CREATE TABLE IF NOT EXISTS usage("
        "  ns TEXT NOT NULL,"
        "  origin TEXT NOT NULL,"
        "  bytes INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY(ns, origin));",
        "CREATE INDEX IF NOT EXISTS idx_objects_expires ON objects(expires_at_ms);",
        "CREATE INDEX IF NOT EXISTS idx_objects_dest ON objects(destination);",
        "CREATE INDEX IF NOT EXISTS idx_objects_ns ON objects(namespace_id);",
        "CREATE TABLE IF NOT EXISTS dedup("
        "  object_id TEXT PRIMARY KEY,"
        "  terminal_state INTEGER NOT NULL,"
        "  created_at_ms INTEGER NOT NULL);",
        // Phase 4 (schema v2): signed replica leases (master doc §11).
        // - sender rows: carrier_id = a carrier holding OUR object
        // - carrier rows: carrier_id = our own promise to hold the object
        "CREATE TABLE IF NOT EXISTS leases("
        "  object_id TEXT NOT NULL,"
        "  carrier_id TEXT NOT NULL,"
        "  accepted_until_ms INTEGER NOT NULL,"
        "  storage_class INTEGER NOT NULL,"
        "  lease_signature BLOB,"
        "  carrier_pk_hex TEXT,"
        "  PRIMARY KEY(object_id, carrier_id));",
        "CREATE INDEX IF NOT EXISTS idx_leases_until ON leases(accepted_until_ms);",
        // EVICTED_EARLY record (§27): carrier evicted a copy while its lease
        // was still live; Phase 7 repair reads this to re-replicate.
        "CREATE TABLE IF NOT EXISTS evicted_early("
        "  object_id TEXT NOT NULL,"
        "  carrier_id TEXT NOT NULL,"
        "  evicted_at_ms INTEGER NOT NULL,"
        "  lease_was_until_ms INTEGER NOT NULL);",
        // Phase 5 (schema v3): direct delivery + signed receipts.
        // - objects gains delivery state / timestamps / failure class.
        // - receipts links a delivered object to its signed receipt object.
        "CREATE TABLE IF NOT EXISTS receipts("
        "  delivered_object_id TEXT PRIMARY KEY,"
        "  receipt_object_id TEXT NOT NULL,"
        "  origin TEXT NOT NULL,"
        "  destination TEXT NOT NULL,"
        "  receipt_type INTEGER NOT NULL,"
        "  received_at_ms INTEGER NOT NULL,"
        "  object_hash_hex TEXT NOT NULL,"
        "  signature BLOB,"
        "  signer_pk_hex TEXT);",
    };
    for (const char* sql : kSchema) {
        if (!m_impl->exec(sql)) { m_impl->teardown(); return false; }
    }

    {  // Schema versioning + forward migration (Step 6).
        Impl::Stmt st(m_impl->sqlite, m_impl->db,
                      "SELECT version FROM schema_version LIMIT 1;");
        int current = 0;
        if (st.ok() && st.step() == SQLITE_ROW) current = st.col_int(0);
        if (current > kSchemaVersion) { m_impl->teardown(); return false; }  // future DB
        if (current == 0) {
            // Fresh database: the CREATEs above already contain every
            // column/table through schema v3.
            m_impl->exec("INSERT INTO schema_version(version) VALUES (3);");
        } else if (current < kSchemaVersion) {
            // Migration v1 -> v2: Phase 4 tables (leases, evicted_early —
            // already created by the idempotent CREATEs above) plus the
            // envelope_blob column on objects.
            bool has_envelope_col = false;
            {
                Impl::Stmt info(m_impl->sqlite, m_impl->db,
                                "PRAGMA table_info(objects);");
                if (info.ok()) {
                    while (info.step() == SQLITE_ROW) {
                        if (info.col_text(1) == "envelope_blob") has_envelope_col = true;
                    }
                }
            }
            if (!has_envelope_col &&
                !m_impl->exec("ALTER TABLE objects ADD COLUMN envelope_blob BLOB;")) {
                m_impl->teardown();
                return false;
            }
            if (current < 2) {
                if (!m_impl->exec("UPDATE schema_version SET version=2;")) {
                    m_impl->teardown();
                    return false;
                }
            }
            // Migration v2 -> v3: Phase 5 delivery columns on objects.
            for (const char* col : {"delivered_at_ms", "confirmed_at_ms",
                                    "failure_class"}) {
                bool has = false;
                {
                    Impl::Stmt info(m_impl->sqlite, m_impl->db,
                                    "PRAGMA table_info(objects);");
                    if (info.ok()) {
                        while (info.step() == SQLITE_ROW) {
                            if (info.col_text(1) == col) has = true;
                        }
                    }
                }
                if (!has &&
                    !m_impl->exec(std::string("ALTER TABLE objects ADD COLUMN " +
                                              std::string(col) +
                                              (std::string(col) == "failure_class"
                                                   ? " INTEGER NOT NULL DEFAULT 0;"
                                                   : " INTEGER;"))
                                      .c_str())) {
                    m_impl->teardown();
                    return false;
                }
            }
            if (!m_impl->exec("UPDATE schema_version SET version=3;")) {
                m_impl->teardown();
                return false;
            }
        }
    }

    m_open = true;
    return true;
}

void ObjectStore::close() {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    m_impl->teardown();
    m_open = false;
}

namespace {

int64_t namespace_quota_locked(ObjectStore::Impl& impl, const std::string& ns) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "SELECT quota_bytes FROM namespaces WHERE namespace_id=?1;");
    if (!st.ok()) return static_cast<int64_t>(impl.opts.default_namespace_quota_bytes);
    st.bind_text(1, ns);
    if (st.step() == SQLITE_ROW) return st.col_int64(0);
    return static_cast<int64_t>(impl.opts.default_namespace_quota_bytes);
}

// Usage reads go through the incremental `usage` table (PK lookups / tiny
// scans) — never SUM over `objects`. See the schema comment.
int64_t global_used_locked(ObjectStore::Impl& impl) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "SELECT COALESCE(SUM(bytes),0) FROM usage;");
    if (st.ok() && st.step() == SQLITE_ROW) return st.col_int64(0);
    return 0;
}

int64_t namespace_used_locked(ObjectStore::Impl& impl, const std::string& ns) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "SELECT COALESCE(SUM(bytes),0) FROM usage WHERE ns=?1;");
    if (!st.ok()) return 0;
    st.bind_text(1, ns);
    if (st.step() == SQLITE_ROW) return st.col_int64(0);
    return 0;
}

int64_t origin_used_locked(ObjectStore::Impl& impl, const std::string& ns,
                           const std::string& origin) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "SELECT bytes FROM usage WHERE ns=?1 AND origin=?2;");
    if (!st.ok()) return 0;
    st.bind_text(1, ns);
    st.bind_text(2, origin);
    if (st.step() == SQLITE_ROW) return st.col_int64(0);
    return 0;
}

// In-transaction usage accounting helpers (must run inside the same
// transaction as the object row change so they can never drift).
bool usage_add_locked(ObjectStore::Impl& impl, const std::string& ns,
                      const std::string& origin, int64_t bytes) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "INSERT INTO usage(ns, origin, bytes) VALUES(?1,?2,?3)"
        " ON CONFLICT(ns, origin) DO UPDATE SET bytes = bytes + excluded.bytes;");
    if (!st.ok()) return false;
    st.bind_text(1, ns);
    st.bind_text(2, origin);
    st.bind_int64(3, bytes);
    return st.step() == SQLITE_DONE;
}

bool usage_sub_locked(ObjectStore::Impl& impl, const std::string& ns,
                      const std::string& origin, int64_t bytes) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "UPDATE usage SET bytes = MAX(0, bytes - ?1) WHERE ns=?2 AND origin=?3;");
    if (!st.ok()) return false;
    st.bind_int64(1, bytes);
    st.bind_text(2, ns);
    st.bind_text(3, origin);
    return st.step() == SQLITE_DONE;
}

// Phase 4: upsert a signed lease row (must run inside the object's insert
// transaction on the carrier path; standalone on the sender path).
bool insertLeaseLocked(ObjectStore::Impl& impl, const std::string& object_id_hex,
                       const ObjectStore::LeaseInfo& lease) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "INSERT OR REPLACE INTO leases(object_id, carrier_id, accepted_until_ms,"
        " storage_class, lease_signature, carrier_pk_hex)"
        " VALUES(?1,?2,?3,?4,?5,?6);");
    if (!st.ok()) return false;
    st.bind_text(1, object_id_hex);
    st.bind_text(2, lease.carrier_id);
    st.bind_int64(3, lease.accepted_until_ms);
    st.bind_int64(4, lease.storage_class);
    st.bind_text(5, lease.signature);
    st.bind_text(6, lease.carrier_id_hex);
    return st.step() == SQLITE_DONE;
}

} // namespace

Result ObjectStore::put(const ObjectMeta& meta, std::string_view payload) {
    Outcome o;
    return putWithOutcome(meta, payload, o);
}

Result ObjectStore::putWithOutcome(const ObjectMeta& meta, std::string_view payload,
                                   Outcome& out) {
    return putInternal(meta, payload, nullptr, out);
}

Result ObjectStore::putWithLease(const ObjectMeta& meta, std::string_view payload,
                                 const LeaseInfo& lease, Outcome& out) {
    if (lease.carrier_id.empty()) {
        out = Outcome::RejectedPolicy;
        return Result::kInvalidArg;
    }
    if (!lease.object_id_hex.empty() && lease.object_id_hex != meta.id.toHex()) {
        out = Outcome::RejectedPolicy;
        return Result::kInvalidArg;
    }
    return putInternal(meta, payload, &lease, out);
}

Result ObjectStore::putInternal(const ObjectMeta& meta, std::string_view payload,
                                const LeaseInfo* lease, Outcome& out) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    if (meta.id.empty()) { out = Outcome::RejectedPolicy; return Result::kInvalidArg; }
    if (payload.size() > m_options.max_object_bytes) {
        out = Outcome::RejectedPolicy;   // §34 memory bound
        return Result::kInvalidArg;
    }

    const std::string id = meta.id.toHex();

    // Dedup check BEFORE expensive work (§65/§29).
    {
        Impl::Stmt st(m_impl->sqlite, m_impl->db,
                      "SELECT 1 FROM dedup WHERE object_id=?1;");
        if (st.ok()) {
            st.bind_text(1, id);
            if (st.step() == SQLITE_ROW) {
                // Idempotent duplicate. The carrier path still records the
                // (possibly refreshed) lease so a post-commit re-send is
                // answered with a fresh STORED_ACK — never a second copy.
                if (lease) {
                    if (!m_impl->exec("BEGIN IMMEDIATE;")) {
                        out = Outcome::Busy;
                        return Result::kBusy;
                    }
                    if (!insertLeaseLocked(*m_impl, id, *lease)) {
                        m_impl->exec("ROLLBACK;");
                        out = Outcome::Unsupported;
                        return Result::kIo;
                    }
                    Impl::Stmt up(m_impl->sqlite, m_impl->db,
                        "UPDATE objects SET lease_expires_at_ms=?1 WHERE object_id=?2;");
                    if (up.ok()) {
                        up.bind_int64(1, lease->accepted_until_ms);
                        up.bind_text(2, id);
                        up.step();
                    }
                    if (!m_impl->exec("COMMIT;")) {
                        m_impl->exec("ROLLBACK;");
                        out = Outcome::RetryAfter;
                        return Result::kIo;
                    }
                }
                out = Outcome::Accepted;   // idempotent duplicate
                return Result::kOk;
            }
        }
    }

    const int64_t now = meta.created_at_ms;
    const int64_t expires = meta.ttl_ms > 0 ? now + meta.ttl_ms : INT64_MAX;
    const int64_t added_bytes = static_cast<int64_t>(payload.size());

    if (!m_impl->exec("BEGIN IMMEDIATE;")) {
        out = Outcome::Busy;
        return Result::kBusy;
    }

    const int64_t ns_used = namespace_used_locked(*m_impl, meta.namespace_id);
    const int64_t ns_quota = namespace_quota_locked(*m_impl, meta.namespace_id);
    const int64_t origin_used = origin_used_locked(*m_impl, meta.namespace_id, meta.origin);

    // Hierarchical quotas (§26/§53): global cap (minus system reserve), then
    // namespace cap, then origin cap — all inside the insert transaction,
    // all O(1)-ish reads off the incremental usage table.
    {
        const int64_t global_used = global_used_locked(*m_impl);
        const int64_t usable = static_cast<int64_t>(m_impl->opts.global_quota_bytes) -
                               static_cast<int64_t>(m_impl->opts.system_reserve_bytes);
        if (usable > 0 && global_used + added_bytes > usable) {
            m_impl->exec("ROLLBACK;");
            out = Outcome::RejectedQuota;
            return Result::kOk;  // rejected cleanly, not an error
        }
    }
    if (ns_quota > 0 && ns_used + added_bytes > ns_quota) {
        m_impl->exec("ROLLBACK;");
        out = Outcome::RejectedQuota;
        return Result::kOk;
    }
    const int64_t origin_quota = static_cast<int64_t>(m_impl->opts.default_origin_quota_bytes);
    if (origin_quota > 0 && origin_used + added_bytes > origin_quota) {
        m_impl->exec("ROLLBACK;");
        out = Outcome::RejectedQuota;
        return Result::kOk;
    }

    Impl::Stmt ins(m_impl->sqlite, m_impl->db,
        "INSERT INTO objects(object_id, namespace_id, origin, destination, object_type,"
        " created_at_ms, ttl_ms, expires_at_ms, priority, payload_size, payload_hash,"
        " payload_blob, origin_header_blob, origin_signature, forwarding_header_blob,"
        " envelope_blob, state, lease_expires_at_ms, replica_hint)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19);");
    if (!ins.ok()) {
        m_impl->exec("ROLLBACK;");
        out = Outcome::Unsupported;
        return Result::kIo;
    }
    ins.bind_text(1, id);
    ins.bind_text(2, meta.namespace_id);
    ins.bind_text(3, meta.origin);
    ins.bind_text(4, meta.destination.value_or(""));
    ins.bind_text(5, meta.object_type);
    ins.bind_int64(6, meta.created_at_ms);
    ins.bind_int64(7, meta.ttl_ms);
    ins.bind_int64(8, expires);
    ins.bind_int(9, static_cast<int>(meta.priority));
    ins.bind_int64(10, static_cast<int64_t>(payload.size()));
    ins.bind_text(11, meta.payload_hash);
    ins.bind_text(12, std::string(payload));
    ins.bind_text(13, meta.origin_header_blob);
    ins.bind_text(14, meta.origin_signature);
    ins.bind_text(15, meta.forwarding_header_blob);
    ins.bind_text(16, meta.envelope_blob);
    ins.bind_int(17, static_cast<int>(meta.status));
    // The carrier-side path records the lease's expiry as the object's lease
    // expiry (accepted_until); the sender path uses its own meta hint.
    ins.bind_int64(18, lease ? lease->accepted_until_ms : meta.lease_expires_at_ms);
    ins.bind_int64(19, meta.replica_hint);
    if (ins.step() != SQLITE_DONE) {
        m_impl->exec("ROLLBACK;");
        out = Outcome::Unsupported;
        return Result::kIo;
    }

    {  // Dedup record (bounded cleanup below).
        Impl::Stmt ds(m_impl->sqlite, m_impl->db,
            "INSERT OR REPLACE INTO dedup(object_id, terminal_state, created_at_ms)"
            " VALUES(?1,?2,?3);");
        if (ds.ok()) {
            ds.bind_text(1, id);
            ds.bind_int(2, static_cast<int>(meta.status));
            ds.bind_int64(3, now);
            ds.step();
        }
    }

    {  // Increment the usage counter (same transaction — cannot drift).
        if (!usage_add_locked(*m_impl, meta.namespace_id, meta.origin, added_bytes)) {
            m_impl->exec("ROLLBACK;");
            out = Outcome::Unsupported;
            return Result::kIo;
        }
    }

    // Carrier-side: the signed lease is committed in the SAME transaction as
    // the object (invariant 2: never ACK before this COMMIT succeeds).
    if (lease) {
        if (!insertLeaseLocked(*m_impl, id, *lease)) {
            m_impl->exec("ROLLBACK;");
            out = Outcome::Unsupported;
            return Result::kIo;
        }
    }

    if (!m_impl->exec("COMMIT;")) {
        m_impl->exec("ROLLBACK;");
        out = Outcome::RetryAfter;
        return Result::kIo;
    }

    // Bounded dedup table: prune expired records when over capacity.
    // Amortized — the COUNT gate is a full-table scan, so it only runs every
    // 256 puts (O(1) amortized instead of O(N) per put).
    ++m_impl->puts_since_dedup_prune;
    if (m_impl->opts.max_dedup_entries > 0 &&
        m_impl->puts_since_dedup_prune % 256 == 0) {
        Impl::Stmt cnt(m_impl->sqlite, m_impl->db, "SELECT COUNT(*) FROM dedup;");
        int64_t n = 0;
        if (cnt.ok() && cnt.step() == SQLITE_ROW) n = cnt.col_int64(0);
        if (n > static_cast<int64_t>(m_impl->opts.max_dedup_entries)) {
            const int64_t cutoff = now -
                static_cast<int64_t>(m_impl->opts.dedup_ttl_hours) * 3600LL * 1000LL;
            Impl::Stmt del(m_impl->sqlite, m_impl->db,
                "DELETE FROM dedup WHERE created_at_ms < ?1;");
            if (del.ok()) {
                del.bind_int64(1, cutoff);
                del.step();
            }
        }
    }

    out = Outcome::Accepted;
    return Result::kOk;
}

Result ObjectStore::recordLease(const ObjectId& id, const LeaseInfo& lease) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    const std::string id_hex = id.toHex();
    if (!m_impl->exec("BEGIN IMMEDIATE;")) return Result::kBusy;
    if (!insertLeaseLocked(*m_impl, id_hex, lease)) {
        m_impl->exec("ROLLBACK;");
        return Result::kIo;
    }
    Impl::Stmt up(m_impl->sqlite, m_impl->db,
        "UPDATE objects SET lease_expires_at_ms=?1 WHERE object_id=?2;");
    if (up.ok()) {
        up.bind_int64(1, lease.accepted_until_ms);
        up.bind_text(2, id_hex);
        up.step();
    }
    if (!m_impl->exec("COMMIT;")) {
        m_impl->exec("ROLLBACK;");
        return Result::kIo;
    }
    return Result::kOk;
}

Result ObjectStore::getLeases(const ObjectId& id, std::vector<LeaseInfo>& out) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    out.clear();
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT carrier_id, accepted_until_ms, storage_class, lease_signature,"
        " carrier_pk_hex FROM leases WHERE object_id=?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, id.toHex());
    while (st.step() == SQLITE_ROW) {
        LeaseInfo l;
        l.object_id_hex = id.toHex();
        l.carrier_id = st.col_text(0);
        l.accepted_until_ms = st.col_int64(1);
        l.storage_class = st.col_int64(2);
        l.signature = st.col_text(3);
        l.carrier_id_hex = st.col_text(4);
        out.push_back(std::move(l));
    }
    return Result::kOk;
}

Result ObjectStore::updateObjectState(const ObjectId& id, ObjectStatus status) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "UPDATE objects SET state=?1 WHERE object_id=?2;");
    if (!st.ok()) return Result::kIo;
    st.bind_int(1, static_cast<int>(status));
    st.bind_text(2, id.toHex());
    if (st.step() != SQLITE_DONE) return Result::kIo;
    // Terminal states also refresh the dedup record (compact, §65).
    if (status == ObjectStatus::kDurabilityReached) {
        Impl::Stmt d(m_impl->sqlite, m_impl->db,
            "UPDATE dedup SET terminal_state=5 WHERE object_id=?1;");
        if (d.ok()) {
            d.bind_text(1, id.toHex());
            d.step();
        }
    }
    return Result::kOk;
}

// ---------------------------------------------------------------------------
// Phase 5: direct delivery + signed receipts
// ---------------------------------------------------------------------------
Result ObjectStore::recordReceipt(const ReceiptRow& row) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    // Idempotent upsert keyed by delivered_object_id: a duplicate delivery
    // never creates a duplicate receipt row (invariant 3, 18).
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "INSERT OR REPLACE INTO receipts(delivered_object_id, receipt_object_id,"
        " origin, destination, receipt_type, received_at_ms, object_hash_hex,"
        " signature, signer_pk_hex) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9);");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, row.delivered_object_id_hex);
    st.bind_text(2, row.receipt_object_id_hex);
    st.bind_text(3, row.origin);
    st.bind_text(4, row.destination);
    st.bind_int(5, static_cast<int>(row.receipt_type));
    st.bind_int64(6, row.received_at_ms);
    st.bind_text(7, row.object_hash_hex);
    st.bind_text(8, row.signature);
    st.bind_text(9, row.signer_pk_hex);
    return st.step() == SQLITE_DONE ? Result::kOk : Result::kIo;
}

Result ObjectStore::getReceipt(const std::string& delivered_object_id_hex,
                               ReceiptRow& out) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT receipt_object_id, origin, destination, receipt_type,"
        " received_at_ms, object_hash_hex, signature, signer_pk_hex"
        " FROM receipts WHERE delivered_object_id=?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, delivered_object_id_hex);
    if (st.step() != SQLITE_ROW) return Result::kNotFound;
    out.delivered_object_id_hex = delivered_object_id_hex;
    out.receipt_object_id_hex = st.col_text(0);
    out.origin = st.col_text(1);
    out.destination = st.col_text(2);
    out.receipt_type = static_cast<uint8_t>(st.col_int(3));
    out.received_at_ms = st.col_int64(4);
    out.object_hash_hex = st.col_text(5);
    out.signature = st.col_text(6);
    out.signer_pk_hex = st.col_text(7);
    return Result::kOk;
}

Result ObjectStore::forEachReceiptToward(
    const std::string& destination,
    const std::function<Result(const ReceiptRow&)>& fn) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    // "Aimed at `destination`" = the origin/recipient of the delivered object
    // that the receipt is being returned TO. The recipient is recorded in the
    // `origin` column (the signer is `destination`).
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT delivered_object_id, receipt_object_id, origin, destination,"
        " receipt_type, received_at_ms, object_hash_hex, signature, signer_pk_hex"
        " FROM receipts WHERE origin=?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, destination);
    while (st.step() == SQLITE_ROW) {
        ReceiptRow row;
        row.delivered_object_id_hex = st.col_text(0);
        row.receipt_object_id_hex = st.col_text(1);
        row.origin = st.col_text(2);
        row.destination = st.col_text(3);
        row.receipt_type = static_cast<uint8_t>(st.col_int(4));
        row.received_at_ms = st.col_int64(5);
        row.object_hash_hex = st.col_text(6);
        row.signature = st.col_text(7);
        row.signer_pk_hex = st.col_text(8);
        const Result rc = fn(row);
        if (rc != Result::kOk) return rc;
    }
    return Result::kOk;
}

Result ObjectStore::forEachUndelivered(
    const std::string& destination,
    const std::function<Result(const ObjectId&)>& fn) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    // state IN (kStored=1, kDurabilityReached=5): not yet delivered/confirmed/
    // failed/attempted. Order oldest-first so delivery is fair.
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT object_id FROM objects WHERE destination=?1 AND"
        " state IN (1,5) ORDER BY created_at_ms;");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, destination);
    std::vector<ObjectId> ids;
    while (st.step() == SQLITE_ROW) {
        ObjectId id;
        if (ObjectId::fromHex(st.col_text(0), id)) ids.push_back(std::move(id));
    }
    for (const ObjectId& id : ids) {
        const Result rc = fn(id);
        if (rc != Result::kOk) return rc;
    }
    return Result::kOk;
}

Result ObjectStore::forEachDeliveredReplica(
    int64_t before_ms, const std::function<Result(const ObjectId&)>& fn) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    // state == kDelivered (7): the destination durably committed, so this
    // replica is a candidate for release after its retention window.
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT object_id FROM objects WHERE state=7 AND delivered_at_ms <= ?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_int64(1, before_ms);
    std::vector<ObjectId> ids;
    while (st.step() == SQLITE_ROW) {
        ObjectId id;
        if (ObjectId::fromHex(st.col_text(0), id)) ids.push_back(std::move(id));
    }
    for (const ObjectId& id : ids) {
        const Result rc = fn(id);
        if (rc != Result::kOk) return rc;
    }
    return Result::kOk;
}

Result ObjectStore::enumerateInventory(
    uint32_t limit,
    const std::function<Result(const ObjectId&, ObjectStatus, int64_t)>& fn) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    if (limit == 0) return Result::kOk;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT object_id, state, created_at_ms FROM objects"
        " ORDER BY created_at_ms LIMIT ?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_int(1, static_cast<int>(limit));
    uint32_t yielded = 0;
    while (st.step() == SQLITE_ROW) {
        if (yielded >= limit) break;
        ObjectId id;
        const std::string hex = st.col_text(0);
        if (!ObjectId::fromHex(hex, id)) continue;
        const ObjectStatus s = static_cast<ObjectStatus>(st.col_int(1));
        const int64_t created = st.col_int64(2);
        ++yielded;
        const Result rc = fn(id, s, created);
        if (rc != Result::kOk) return rc;
    }
    return Result::kOk;
}

Result ObjectStore::markDelivered(const ObjectId& id, int64_t delivered_at_ms) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "UPDATE objects SET state=?1, delivered_at_ms=?2, failure_class=0"
        " WHERE object_id=?3;");
    if (!st.ok()) return Result::kIo;
    st.bind_int(1, static_cast<int>(ObjectStatus::kDelivered));
    st.bind_int64(2, delivered_at_ms);
    st.bind_text(3, id.toHex());
    if (st.step() != SQLITE_DONE) return Result::kIo;
    Impl::Stmt d(m_impl->sqlite, m_impl->db,
        "UPDATE dedup SET terminal_state=7 WHERE object_id=?1;");
    if (d.ok()) { d.bind_text(1, id.toHex()); d.step(); }
    return Result::kOk;
}

Result ObjectStore::markDeliveryAttempted(const ObjectId& id) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "UPDATE objects SET state=?1 WHERE object_id=?2 AND state < ?1;");
    // Idempotent forward-only: only lift toward DELIVERY_ATTEMPTED (6).
    if (!st.ok()) return Result::kIo;
    st.bind_int(1, static_cast<int>(ObjectStatus::kDeliveryAttempted));
    st.bind_text(2, id.toHex());
    st.step();
    return Result::kOk;
}

Result ObjectStore::confirmObject(const ObjectId& id, int64_t confirmed_at_ms) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "UPDATE objects SET state=?1, confirmed_at_ms=?2 WHERE object_id=?3;");
    if (!st.ok()) return Result::kIo;
    st.bind_int(1, static_cast<int>(ObjectStatus::kConfirmed));
    st.bind_int64(2, confirmed_at_ms);
    st.bind_text(3, id.toHex());
    st.step();
    Impl::Stmt d(m_impl->sqlite, m_impl->db,
        "UPDATE dedup SET terminal_state=8 WHERE object_id=?1;");
    if (d.ok()) { d.bind_text(1, id.toHex()); d.step(); }
    return Result::kOk;
}

Result ObjectStore::failDelivery(const ObjectId& id, uint8_t failure_class) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "UPDATE objects SET state=?1, failure_class=?2 WHERE object_id=?3;");
    if (!st.ok()) return Result::kIo;
    st.bind_int(1, static_cast<int>(ObjectStatus::kFailed));
    st.bind_int(2, static_cast<int>(failure_class));
    st.bind_text(3, id.toHex());
    st.step();
    Impl::Stmt d(m_impl->sqlite, m_impl->db,
        "UPDATE dedup SET terminal_state=9 WHERE object_id=?1;");
    if (d.ok()) { d.bind_text(1, id.toHex()); d.step(); }
    return Result::kOk;
}

Result ObjectStore::deliveryReadout(const ObjectId& id, ObjectStatus* status_out,
                                   int64_t* delivered_at_ms_out,
                                   int64_t* confirmed_at_ms_out,
                                   uint8_t* failure_class_out) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT state, delivered_at_ms, confirmed_at_ms, failure_class"
        " FROM objects WHERE object_id=?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, id.toHex());
    if (st.step() != SQLITE_ROW) return Result::kNotFound;
    if (status_out) *status_out = static_cast<ObjectStatus>(st.col_int(0));
    if (delivered_at_ms_out) *delivered_at_ms_out = st.col_int64(1);
    if (confirmed_at_ms_out) *confirmed_at_ms_out = st.col_int64(2);
    if (failure_class_out) *failure_class_out = static_cast<uint8_t>(st.col_int(3));
    return Result::kOk;
}

Result ObjectStore::forEachExpiringLease(
    int64_t before_ms, const std::function<Result(const LeaseInfo&)>& fn) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT object_id, carrier_id, accepted_until_ms, storage_class,"
        " lease_signature, carrier_pk_hex FROM leases"
        " WHERE accepted_until_ms <= ?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_int64(1, before_ms);
    while (st.step() == SQLITE_ROW) {
        LeaseInfo l;
        l.object_id_hex = st.col_text(0);
        l.carrier_id = st.col_text(1);
        l.accepted_until_ms = st.col_int64(2);
        l.storage_class = st.col_int64(3);
        l.signature = st.col_text(4);
        l.carrier_id_hex = st.col_text(5);
        const Result rc = fn(l);
        if (rc != Result::kOk) return rc;
    }
    return Result::kOk;
}

Result ObjectStore::markEvictedEarly(const ObjectId& id, const std::string& carrier_id,
                                     int64_t lease_was_until_ms) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "INSERT INTO evicted_early(object_id, carrier_id, evicted_at_ms,"
        " lease_was_until_ms) VALUES(?1,?2,?3,?4);");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, id.toHex());
    st.bind_text(2, carrier_id);
    st.bind_int64(3,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    st.bind_int64(4, lease_was_until_ms);
    return st.step() == SQLITE_DONE ? Result::kOk : Result::kIo;
}

uint64_t ObjectStore::evictedEarlyCount() const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return 0;
    Impl::Stmt st(m_impl->sqlite, m_impl->db, "SELECT COUNT(*) FROM evicted_early;");
    if (st.ok() && st.step() == SQLITE_ROW) {
        return static_cast<uint64_t>(st.col_int64(0));
    }
    return 0;
}

Result ObjectStore::getMeta(const ObjectId& id, ObjectMeta& meta_out) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT namespace_id, origin, destination, object_type, created_at_ms,"
        " ttl_ms, expires_at_ms, priority, payload_size, payload_hash,"
        " origin_header_blob, origin_signature, forwarding_header_blob,"
        " envelope_blob, state, lease_expires_at_ms, replica_hint FROM objects"
        " WHERE object_id=?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, id.toHex());
    if (st.step() != SQLITE_ROW) return Result::kNotFound;
    meta_out.id = id;
    meta_out.namespace_id = st.col_text(0);
    meta_out.origin = st.col_text(1);
    meta_out.destination = st.col_text(2);
    meta_out.object_type = st.col_text(3);
    meta_out.created_at_ms = st.col_int64(4);
    meta_out.ttl_ms = st.col_int64(5);
    meta_out.priority = static_cast<uint32_t>(st.col_int(7));
    meta_out.payload_size = static_cast<uint64_t>(st.col_int64(8));
    meta_out.payload_hash = st.col_text(9);
    meta_out.origin_header_blob = st.col_text(10);
    meta_out.origin_signature = st.col_text(11);
    meta_out.forwarding_header_blob = st.col_text(12);
    meta_out.envelope_blob = st.col_text(13);
    meta_out.status = static_cast<ObjectStatus>(st.col_int(14));
    meta_out.lease_expires_at_ms = st.col_int64(15);
    meta_out.replica_hint = st.col_int64(16);
    return Result::kOk;
}

Result ObjectStore::get(const ObjectId& id, ObjectMeta& meta_out,
                        std::string& payload_out) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT namespace_id, origin, destination, object_type, created_at_ms,"
        " ttl_ms, expires_at_ms, priority, payload_size, payload_hash,"
        " origin_header_blob, origin_signature, forwarding_header_blob,"
        " envelope_blob, state, lease_expires_at_ms, replica_hint, payload_blob FROM objects"
        " WHERE object_id=?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_text(1, id.toHex());
    if (st.step() != SQLITE_ROW) return Result::kNotFound;
    meta_out.id = id;
    meta_out.namespace_id = st.col_text(0);
    meta_out.origin = st.col_text(1);
    meta_out.destination = st.col_text(2);
    meta_out.object_type = st.col_text(3);
    meta_out.created_at_ms = st.col_int64(4);
    meta_out.ttl_ms = st.col_int64(5);
    meta_out.priority = static_cast<uint32_t>(st.col_int(7));
    meta_out.payload_size = static_cast<uint64_t>(st.col_int64(8));
    meta_out.payload_hash = st.col_text(9);
    meta_out.origin_header_blob = st.col_text(10);
    meta_out.origin_signature = st.col_text(11);
    meta_out.forwarding_header_blob = st.col_text(12);
    meta_out.envelope_blob = st.col_text(13);
    meta_out.status = static_cast<ObjectStatus>(st.col_int(14));
    meta_out.lease_expires_at_ms = st.col_int64(15);
    meta_out.replica_hint = st.col_int64(16);
    payload_out = st.col_text(17);
    return Result::kOk;
}

Result ObjectStore::remove(const ObjectId& id) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    const std::string id_hex = id.toHex();
    if (!m_impl->exec("BEGIN IMMEDIATE;")) return Result::kBusy;

    // Read the row's accounting before deleting it (usage decrement needs it).
    std::string ns, origin;
    int64_t size = 0;
    bool found = false;
    {
        Impl::Stmt sel(m_impl->sqlite, m_impl->db,
            "SELECT namespace_id, origin, payload_size FROM objects WHERE object_id=?1;");
        if (sel.ok()) {
            sel.bind_text(1, id_hex);
            if (sel.step() == SQLITE_ROW) {
                ns = sel.col_text(0);
                origin = sel.col_text(1);
                size = sel.col_int64(2);
                found = true;
            }
        }
    }
    {
        Impl::Stmt del(m_impl->sqlite, m_impl->db,
                       "DELETE FROM objects WHERE object_id=?1;");
        if (!del.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        del.bind_text(1, id_hex);
        del.step();
    }
    if (found) {
        if (!usage_sub_locked(*m_impl, ns, origin, size)) {
            m_impl->exec("ROLLBACK;");
            return Result::kIo;
        }
    }
    {  // Terminal dedup record survives the payload (compact; §65).
        Impl::Stmt up(m_impl->sqlite, m_impl->db,
            "UPDATE dedup SET terminal_state=2 WHERE object_id=?1;");
        if (up.ok()) {
            up.bind_text(1, id_hex);
            up.step();
        }
    }
    if (!m_impl->exec("COMMIT;")) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
    return Result::kOk;
}

Result ObjectStore::commit() {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    // Durable-commit gate (invariant 2): make the WAL current in the main file.
    return m_impl->exec("PRAGMA wal_checkpoint(PASSIVE);") ? Result::kOk : Result::kIo;
}

Result ObjectStore::forEachExpired(int64_t now_ms,
                                   const std::function<Result(const ObjectId&)>& fn) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT object_id FROM objects WHERE expires_at_ms <= ?1;");
    if (!st.ok()) return Result::kIo;
    st.bind_int64(1, now_ms);
    while (st.step() == SQLITE_ROW) {
        const std::string id_hex = st.col_text(0);
        ObjectId id;
        if (!ObjectId::fromHex(id_hex, id)) continue;
        const Result rc = fn(id);
        if (rc != Result::kOk) return rc;
    }
    return Result::kOk;
}

Result ObjectStore::purgeExpired(int64_t now_ms, uint64_t* removed) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    if (!m_impl->exec("BEGIN IMMEDIATE;")) return Result::kBusy;
    int64_t n = 0;
    for (;;) {
        // Read one expired object at a time and delete it, decrementing the
        // usage counter in the same transaction.
        Impl::Stmt sel(m_impl->sqlite, m_impl->db,
            "SELECT object_id, namespace_id, origin, payload_size FROM objects"
            " WHERE expires_at_ms <= ?1 LIMIT 1;");
        if (!sel.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        sel.bind_int64(1, now_ms);
        if (sel.step() != SQLITE_ROW) break;
        const std::string id_hex = sel.col_text(0);
        const std::string ns = sel.col_text(1);
        const std::string origin = sel.col_text(2);
        const int64_t size = sel.col_int64(3);

        Impl::Stmt del(m_impl->sqlite, m_impl->db,
                       "DELETE FROM objects WHERE object_id=?1;");
        if (!del.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        del.bind_text(1, id_hex);
        if (del.step() != SQLITE_DONE) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        if (!usage_sub_locked(*m_impl, ns, origin, size)) {
            m_impl->exec("ROLLBACK;");
            return Result::kIo;
        }
        ++n;
    }
    if (!m_impl->exec("COMMIT;")) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
    if (removed) *removed = static_cast<uint64_t>(n);
    return Result::kOk;
}

Result ObjectStore::quota(const std::string& namespace_id, const std::string& origin,
                          QuotaInfo& out) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    const int64_t ns_used = namespace_used_locked(*m_impl, namespace_id);
    const int64_t ns_quota = namespace_quota_locked(*m_impl, namespace_id);
    const int64_t org_used = origin.empty() ? ns_used
                                            : origin_used_locked(*m_impl, namespace_id, origin);
    out.used_bytes = static_cast<uint64_t>(org_used);
    out.max_bytes = static_cast<uint64_t>(ns_quota);
    out.used_entries = 0;
    out.max_entries = 0;
    out.within_limits = org_used <= ns_quota;
    return Result::kOk;
}

bool ObjectStore::contains(const ObjectId& id) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return false;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
                  "SELECT 1 FROM objects WHERE object_id=?1;");
    if (!st.ok()) return false;
    st.bind_text(1, id.toHex());
    return st.step() == SQLITE_ROW;
}

bool ObjectStore::isDuplicate(const ObjectId& id) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return false;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
                  "SELECT 1 FROM dedup WHERE object_id=?1;");
    if (!st.ok()) return false;
    st.bind_text(1, id.toHex());
    return st.step() == SQLITE_ROW;
}

Result ObjectStore::evictForQuota(const std::string& namespace_id,
                                  const std::string& origin,
                                  uint64_t need_bytes, uint64_t* freed) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    uint64_t released = 0;
    if (!m_impl->exec("BEGIN IMMEDIATE;")) return Result::kBusy;
    while (released < need_bytes) {
        // §27 score: expired first, then lowest priority, then oldest expiry.
        Impl::Stmt v(m_impl->sqlite, m_impl->db,
            "SELECT object_id, payload_size, lease_expires_at_ms FROM objects"
            " WHERE namespace_id=?1 AND origin=?2"
            " ORDER BY (expires_at_ms <= strftime('%s','now')*1000) DESC,"
            " priority ASC, expires_at_ms ASC LIMIT 1;");
        if (!v.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        v.bind_text(1, namespace_id);
        v.bind_text(2, origin);
        if (v.step() != SQLITE_ROW) break;
        const std::string victim = v.col_text(0);
        const int64_t victim_size = v.col_int64(1);
        const int64_t lease_until = v.col_int64(2);
        // EVICTED_EARLY (§27): evicting a copy whose lease is still live must
        // be recorded so Phase 7 repair can re-replicate before accepted_until.
        if (lease_until > 0 &&
            lease_until >= std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count()) {
            Impl::Stmt ev(m_impl->sqlite, m_impl->db,
                "INSERT INTO evicted_early(object_id, carrier_id, evicted_at_ms,"
                " lease_was_until_ms) VALUES(?1,?2,?3,?4);");
            if (ev.ok()) {
                ev.bind_text(1, victim);
                ev.bind_text(2, origin);   // carrier_id is the local peer id
                ev.bind_int64(3, std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
                ev.bind_int64(4, lease_until);
                ev.step();
            }
        }
        Impl::Stmt del(m_impl->sqlite, m_impl->db,
                       "DELETE FROM objects WHERE object_id=?1;");
        if (!del.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        del.bind_text(1, victim);
        if (del.step() != SQLITE_DONE) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        if (!usage_sub_locked(*m_impl, namespace_id, origin, victim_size)) {
            m_impl->exec("ROLLBACK;");
            return Result::kIo;
        }
        released += static_cast<uint64_t>(victim_size > 0 ? victim_size : 0);
    }
    if (!m_impl->exec("COMMIT;")) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
    if (freed) *freed = released;
    return Result::kOk;
}

Result ObjectStore::setNamespaceQuota(const std::string& namespace_id,
                                      uint64_t quota_bytes) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt ups(m_impl->sqlite, m_impl->db,
        "INSERT INTO namespaces(namespace_id, quota_bytes, reserved)"
        " VALUES(?1,?2,0)"
        " ON CONFLICT(namespace_id) DO UPDATE SET quota_bytes=excluded.quota_bytes;");
    if (!ups.ok()) return Result::kIo;
    ups.bind_text(1, namespace_id);
    ups.bind_int64(2, static_cast<int64_t>(quota_bytes));
    return ups.step() == SQLITE_DONE ? Result::kOk : Result::kIo;
}

uint64_t ObjectStore::countObjects() const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return 0;
    Impl::Stmt st(m_impl->sqlite, m_impl->db, "SELECT COUNT(*) FROM objects;");
    if (!st.ok()) return 0;
    if (st.step() == SQLITE_ROW) return static_cast<uint64_t>(st.col_int64(0));
    return 0;
}

uint64_t ObjectStore::totalBytes() const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return 0;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
                  "SELECT COALESCE(SUM(payload_size),0) FROM objects;");
    if (!st.ok()) return 0;
    if (st.step() == SQLITE_ROW) return static_cast<uint64_t>(st.col_int64(0));
    return 0;
}

int ObjectStore::schemaVersion() const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return 0;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
                  "SELECT version FROM schema_version LIMIT 1;");
    if (!st.ok()) return 0;
    if (st.step() == SQLITE_ROW) return st.col_int(0);
    return 0;
}

} // namespace networkos
