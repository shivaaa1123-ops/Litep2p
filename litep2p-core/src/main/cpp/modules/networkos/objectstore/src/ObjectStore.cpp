// ObjectStore.cpp — SQLite (WAL) durable object store.

#include "networkos/objectstore/ObjectStore.h"

#include "sqlite3_dyn.h"

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

    bool exec(const char* sql) {
        return db && sqlite.exec(db, sql) == SQLITE_OK;
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

    {  // Corruption detection on open (Step 3.5/§25).
        Impl::Stmt st(m_impl->sqlite, m_impl->db, "PRAGMA quick_check;");
        if (!st.ok() || st.step() != SQLITE_ROW) {
            close();
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
        "  state INTEGER NOT NULL DEFAULT 0,"
        "  lease_expires_at_ms INTEGER,"
        "  replica_hint INTEGER);",
        "CREATE INDEX IF NOT EXISTS idx_objects_expires ON objects(expires_at_ms);",
        "CREATE INDEX IF NOT EXISTS idx_objects_dest ON objects(destination);",
        "CREATE INDEX IF NOT EXISTS idx_objects_ns ON objects(namespace_id);",
        "CREATE TABLE IF NOT EXISTS dedup("
        "  object_id TEXT PRIMARY KEY,"
        "  terminal_state INTEGER NOT NULL,"
        "  created_at_ms INTEGER NOT NULL);",
    };
    for (const char* sql : kSchema) {
        if (!m_impl->exec(sql)) { close(); return false; }
    }

    {  // Schema versioning + forward migration (Step 6).
        Impl::Stmt st(m_impl->sqlite, m_impl->db,
                      "SELECT version FROM schema_version LIMIT 1;");
        int current = 0;
        if (st.ok() && st.step() == SQLITE_ROW) current = st.col_int(0);
        if (current > kSchemaVersion) { close(); return false; }  // future DB
        if (current == 0) m_impl->exec("INSERT INTO schema_version(version) VALUES (1);");
    }

    m_open = true;
    return true;
}

void ObjectStore::close() {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (m_impl->db) {
        m_impl->sqlite.close_v2(m_impl->db);
        m_impl->db = nullptr;
    }
    m_impl->sqlite.unload();
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

int64_t namespace_used_locked(ObjectStore::Impl& impl, const std::string& ns) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "SELECT COALESCE(SUM(payload_size),0) FROM objects WHERE namespace_id=?1;");
    if (!st.ok()) return 0;
    st.bind_text(1, ns);
    if (st.step() == SQLITE_ROW) return st.col_int64(0);
    return 0;
}

int64_t origin_used_locked(ObjectStore::Impl& impl, const std::string& ns,
                           const std::string& origin) {
    ObjectStore::Impl::Stmt st(impl.sqlite, impl.db,
        "SELECT COALESCE(SUM(payload_size),0) FROM objects "
        "WHERE namespace_id=?1 AND origin=?2;");
    if (!st.ok()) return 0;
    st.bind_text(1, ns);
    st.bind_text(2, origin);
    if (st.step() == SQLITE_ROW) return st.col_int64(0);
    return 0;
}

} // namespace

Result ObjectStore::put(const ObjectMeta& meta, std::string_view payload) {
    Outcome o;
    return putWithOutcome(meta, payload, o);
}

Result ObjectStore::putWithOutcome(const ObjectMeta& meta, std::string_view payload,
                                   Outcome& out) {
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
    // namespace cap, then origin cap — all inside the insert transaction.
    {
        Impl::Stmt st(m_impl->sqlite, m_impl->db,
                      "SELECT COALESCE(SUM(payload_size),0) FROM objects;");
        int64_t global_used = 0;
        if (st.ok() && st.step() == SQLITE_ROW) global_used = st.col_int64(0);
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
        " state, lease_expires_at_ms, replica_hint)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18);");
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
    ins.bind_int(16, static_cast<int>(meta.status));
    ins.bind_int64(17, meta.lease_expires_at_ms);
    ins.bind_int64(18, meta.replica_hint);
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

    if (!m_impl->exec("COMMIT;")) {
        m_impl->exec("ROLLBACK;");
        out = Outcome::RetryAfter;
        return Result::kIo;
    }

    // Bounded dedup table: prune expired records when over capacity.
    if (m_impl->opts.max_dedup_entries > 0) {
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

Result ObjectStore::getMeta(const ObjectId& id, ObjectMeta& meta_out) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    Impl::Stmt st(m_impl->sqlite, m_impl->db,
        "SELECT namespace_id, origin, destination, object_type, created_at_ms,"
        " ttl_ms, expires_at_ms, priority, payload_size, payload_hash,"
        " origin_header_blob, origin_signature, forwarding_header_blob,"
        " state, lease_expires_at_ms, replica_hint FROM objects"
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
    meta_out.status = static_cast<ObjectStatus>(st.col_int(13));
    meta_out.lease_expires_at_ms = st.col_int64(14);
    meta_out.replica_hint = st.col_int64(15);
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
        " state, lease_expires_at_ms, replica_hint, payload_blob FROM objects"
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
    meta_out.status = static_cast<ObjectStatus>(st.col_int(13));
    meta_out.lease_expires_at_ms = st.col_int64(14);
    meta_out.replica_hint = st.col_int64(15);
    payload_out = st.col_text(16);
    return Result::kOk;
}

Result ObjectStore::remove(const ObjectId& id) {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    if (!m_open) return Result::kInvalidState;
    const std::string id_hex = id.toHex();
    if (!m_impl->exec("BEGIN IMMEDIATE;")) return Result::kBusy;
    {
        Impl::Stmt del(m_impl->sqlite, m_impl->db,
                       "DELETE FROM objects WHERE object_id=?1;");
        if (!del.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        del.bind_text(1, id_hex);
        del.step();
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
    int64_t n = 0;
    {
        Impl::Stmt cnt(m_impl->sqlite, m_impl->db,
                       "SELECT COUNT(*) FROM objects WHERE expires_at_ms <= ?1;");
        if (cnt.ok()) {
            cnt.bind_int64(1, now_ms);
            if (cnt.step() == SQLITE_ROW) n = cnt.col_int64(0);
        }
    }
    Impl::Stmt del(m_impl->sqlite, m_impl->db,
                   "DELETE FROM objects WHERE expires_at_ms <= ?1;");
    if (!del.ok()) return Result::kIo;
    del.bind_int64(1, now_ms);
    if (del.step() != SQLITE_DONE) return Result::kIo;
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
            "SELECT object_id, payload_size FROM objects"
            " WHERE namespace_id=?1 AND origin=?2"
            " ORDER BY (expires_at_ms <= strftime('%s','now')*1000) DESC,"
            " priority ASC, expires_at_ms ASC LIMIT 1;");
        if (!v.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        v.bind_text(1, namespace_id);
        v.bind_text(2, origin);
        if (v.step() != SQLITE_ROW) break;
        const std::string victim = v.col_text(0);
        const int64_t victim_size = v.col_int64(1);
        Impl::Stmt del(m_impl->sqlite, m_impl->db,
                       "DELETE FROM objects WHERE object_id=?1;");
        if (!del.ok()) { m_impl->exec("ROLLBACK;"); return Result::kIo; }
        del.bind_text(1, victim);
        del.step();
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
