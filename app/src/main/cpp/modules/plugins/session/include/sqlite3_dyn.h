#pragma once

#include <cstdint>
#include <string>

// Minimal SQLite3 API surface loaded dynamically at runtime via dlopen.
// This avoids vendoring SQLite and keeps builds portable.

struct sqlite3;
struct sqlite3_stmt;

enum SqliteResult {
    SQLITE_OK = 0,
    SQLITE_ROW = 100,
    SQLITE_DONE = 101,
};

enum SqliteOpenFlags {
    SQLITE_OPEN_READONLY = 0x00000001,
    SQLITE_OPEN_READWRITE = 0x00000002,
    SQLITE_OPEN_CREATE = 0x00000004,
    SQLITE_OPEN_NOMUTEX = 0x00008000,
    SQLITE_OPEN_FULLMUTEX = 0x00010000,
};

class SqliteDyn {
public:
    SqliteDyn();
    ~SqliteDyn();

    SqliteDyn(const SqliteDyn&) = delete;
    SqliteDyn& operator=(const SqliteDyn&) = delete;

    bool load();
    void unload();

    bool is_loaded() const;

    int open_v2(const char* filename, sqlite3** db, int flags, const char* vfs);
    int close_v2(sqlite3* db);

    int exec(sqlite3* db, const char* sql);

    int prepare_v2(sqlite3* db, const char* sql, int nbytes, sqlite3_stmt** stmt, const char** tail);
    int finalize(sqlite3_stmt* stmt);

    int step(sqlite3_stmt* stmt);
    int reset(sqlite3_stmt* stmt);
    int clear_bindings(sqlite3_stmt* stmt);

    int bind_text(sqlite3_stmt* stmt, int idx, const char* value, int nbytes, void (*destructor)(void*));
    int bind_int(sqlite3_stmt* stmt, int idx, int value);
    int bind_int64(sqlite3_stmt* stmt, int idx, int64_t value);

    const unsigned char* column_text(sqlite3_stmt* stmt, int col);
    int column_int(sqlite3_stmt* stmt, int col);
    int64_t column_int64(sqlite3_stmt* stmt, int col);

    const char* errmsg(sqlite3* db);

private:
    void* m_handle;

    // function pointers
    int (*p_open_v2)(const char*, sqlite3**, int, const char*);
    int (*p_close_v2)(sqlite3*);
    int (*p_exec)(sqlite3*, const char*, int (*)(void*, int, char**, char**), void*, char**);
    int (*p_prepare_v2)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
    int (*p_finalize)(sqlite3_stmt*);
    int (*p_step)(sqlite3_stmt*);
    int (*p_reset)(sqlite3_stmt*);
    int (*p_clear_bindings)(sqlite3_stmt*);
    int (*p_bind_text)(sqlite3_stmt*, int, const char*, int, void (*)(void*));
    int (*p_bind_int)(sqlite3_stmt*, int, int);
    int (*p_bind_int64)(sqlite3_stmt*, int, int64_t);
    const unsigned char* (*p_column_text)(sqlite3_stmt*, int);
    int (*p_column_int)(sqlite3_stmt*, int);
    int64_t (*p_column_int64)(sqlite3_stmt*, int);
    const char* (*p_errmsg)(sqlite3*);

    bool resolve_symbol_(void** fn, const char* name);
};
