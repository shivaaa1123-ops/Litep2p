#include "sqlite3_dyn.h"

#include "logger.h"

#include <dlfcn.h>
#include <vector>

namespace {

#if defined(__APPLE__)
constexpr const char* kDefaultLibs[] = {
    "libsqlite3.dylib",
    "/usr/lib/libsqlite3.dylib",
};
#elif defined(__ANDROID__)
constexpr const char* kDefaultLibs[] = {
    "libsqlite.so",
    "libsqlite3.so",
};
#else
constexpr const char* kDefaultLibs[] = {
    "libsqlite3.so",
    "libsqlite3.so.0",
};
#endif

} // namespace

SqliteDyn::SqliteDyn()
    : m_handle(nullptr),
      p_open_v2(nullptr),
      p_close_v2(nullptr),
      p_exec(nullptr),
      p_prepare_v2(nullptr),
      p_finalize(nullptr),
      p_step(nullptr),
      p_reset(nullptr),
      p_clear_bindings(nullptr),
      p_bind_text(nullptr),
      p_bind_int(nullptr),
      p_bind_int64(nullptr),
      p_column_text(nullptr),
      p_column_int(nullptr),
      p_column_int64(nullptr),
      p_errmsg(nullptr) {}

SqliteDyn::~SqliteDyn() {
    unload();
}

bool SqliteDyn::is_loaded() const {
    return m_handle != nullptr;
}

bool SqliteDyn::resolve_symbol_(void** fn, const char* name) {
    if (!m_handle) return false;
    void* sym = dlsym(m_handle, name);
    if (!sym) {
        return false;
    }
    *fn = sym;
    return true;
}

bool SqliteDyn::load() {
    if (m_handle) return true;

    for (const char* lib : kDefaultLibs) {
        if (!lib) continue;
        void* h = dlopen(lib, RTLD_LAZY | RTLD_LOCAL);
        if (h) {
            m_handle = h;
            break;
        }
    }

    if (!m_handle) {
        LOG_WARN("LocalPeerDb: SQLite library not found (dlopen failed)");
        return false;
    }

    bool ok = true;
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_open_v2), "sqlite3_open_v2");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_close_v2), "sqlite3_close_v2");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_exec), "sqlite3_exec");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_prepare_v2), "sqlite3_prepare_v2");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_finalize), "sqlite3_finalize");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_step), "sqlite3_step");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_reset), "sqlite3_reset");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_clear_bindings), "sqlite3_clear_bindings");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_bind_text), "sqlite3_bind_text");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_bind_int), "sqlite3_bind_int");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_bind_int64), "sqlite3_bind_int64");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_column_text), "sqlite3_column_text");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_column_int), "sqlite3_column_int");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_column_int64), "sqlite3_column_int64");
    ok &= resolve_symbol_(reinterpret_cast<void**>(&p_errmsg), "sqlite3_errmsg");

    if (!ok) {
        LOG_WARN("LocalPeerDb: SQLite symbols missing; disabling");
        unload();
        return false;
    }

    return true;
}

void SqliteDyn::unload() {
    if (m_handle) {
        dlclose(m_handle);
        m_handle = nullptr;
    }

    p_open_v2 = nullptr;
    p_close_v2 = nullptr;
    p_exec = nullptr;
    p_prepare_v2 = nullptr;
    p_finalize = nullptr;
    p_step = nullptr;
    p_reset = nullptr;
    p_clear_bindings = nullptr;
    p_bind_text = nullptr;
    p_bind_int = nullptr;
    p_bind_int64 = nullptr;
    p_column_text = nullptr;
    p_column_int = nullptr;
    p_column_int64 = nullptr;
    p_errmsg = nullptr;
}

int SqliteDyn::open_v2(const char* filename, sqlite3** db, int flags, const char* vfs) {
    if (!p_open_v2) return -1;
    return p_open_v2(filename, db, flags, vfs);
}

int SqliteDyn::close_v2(sqlite3* db) {
    if (!p_close_v2) return -1;
    return p_close_v2(db);
}

int SqliteDyn::exec(sqlite3* db, const char* sql) {
    if (!p_exec) return -1;
    char* errmsg = nullptr;
    int rc = p_exec(db, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) {
            LOG_WARN(std::string("LocalPeerDb: sqlite3_exec failed: ") + errmsg);
            // sqlite3_free would be ideal, but we avoid depending on it.
        } else if (p_errmsg && db) {
            LOG_WARN(std::string("LocalPeerDb: sqlite3_exec failed: ") + p_errmsg(db));
        }
    }
    return rc;
}

int SqliteDyn::prepare_v2(sqlite3* db, const char* sql, int nbytes, sqlite3_stmt** stmt, const char** tail) {
    if (!p_prepare_v2) return -1;
    return p_prepare_v2(db, sql, nbytes, stmt, tail);
}

int SqliteDyn::finalize(sqlite3_stmt* stmt) {
    if (!p_finalize) return -1;
    return p_finalize(stmt);
}

int SqliteDyn::step(sqlite3_stmt* stmt) {
    if (!p_step) return -1;
    return p_step(stmt);
}

int SqliteDyn::reset(sqlite3_stmt* stmt) {
    if (!p_reset) return -1;
    return p_reset(stmt);
}

int SqliteDyn::clear_bindings(sqlite3_stmt* stmt) {
    if (!p_clear_bindings) return -1;
    return p_clear_bindings(stmt);
}

int SqliteDyn::bind_text(sqlite3_stmt* stmt, int idx, const char* value, int nbytes, void (*destructor)(void*)) {
    if (!p_bind_text) return -1;
    return p_bind_text(stmt, idx, value, nbytes, destructor);
}

int SqliteDyn::bind_int(sqlite3_stmt* stmt, int idx, int value) {
    if (!p_bind_int) return -1;
    return p_bind_int(stmt, idx, value);
}

int SqliteDyn::bind_int64(sqlite3_stmt* stmt, int idx, int64_t value) {
    if (!p_bind_int64) return -1;
    return p_bind_int64(stmt, idx, value);
}

const unsigned char* SqliteDyn::column_text(sqlite3_stmt* stmt, int col) {
    if (!p_column_text) return nullptr;
    return p_column_text(stmt, col);
}

int SqliteDyn::column_int(sqlite3_stmt* stmt, int col) {
    if (!p_column_int) return 0;
    return p_column_int(stmt, col);
}

int64_t SqliteDyn::column_int64(sqlite3_stmt* stmt, int col) {
    if (!p_column_int64) return 0;
    return p_column_int64(stmt, col);
}

const char* SqliteDyn::errmsg(sqlite3* db) {
    if (!p_errmsg) return "";
    return p_errmsg(db);
}
