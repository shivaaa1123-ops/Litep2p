#include "crash_handler.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unwind.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Shared pre-formatted context (read by the signal handler)
// ---------------------------------------------------------------------------
namespace crash_ctx {
char buffer[16384];
std::atomic<size_t> length{0};
} // namespace crash_ctx

namespace {

// The resolved crash directory, pre-formatted for the handler's open().
char g_dir_path[512];
size_t g_dir_len = 0;

// Monotonic sequence for unique filenames. `volatile` + simple increment; only
// the crashing thread runs this, so no atomicity is needed for uniqueness.
volatile unsigned long g_seq = 0;

constexpr int kSignals[] = {
    SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGSYS,
};
constexpr int kSignalCount = static_cast<int>(sizeof(kSignals) / sizeof(kSignals[0]));

const char* signame(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGABRT: return "SIGABRT";
        case SIGBUS: return "SIGBUS";
        case SIGFPE: return "SIGFPE";
        case SIGILL: return "SIGILL";
        case SIGTRAP: return "SIGTRAP";
        case SIGSYS: return "SIGSYS";
        default: return "SIG?";
    }
}

// ---- async-signal-safe primitives ------------------------------------------

inline void raw_write(int fd, const char* s, size_t n) {
    if (n == 0) return;
    size_t off = 0;
    while (off < n) {
        const ssize_t w = ::write(fd, s + off, n - off);
        if (w <= 0) return;  // give up on partial/EINTR
        off += static_cast<size_t>(w);
    }
}

inline void write_str(int fd, const char* s) { raw_write(fd, s, std::strlen(s)); }

// Unsigned 64-bit -> hex (lowercase), written without any libc formatting.
void write_u64_hex(int fd, unsigned long long v) {
    char buf[17];
    const char* hex = "0123456789abcdef";
    int i = 16;
    buf[i--] = '\0';
    do {
        buf[i--] = hex[v & 0xF];
        v >>= 4;
    } while (v != 0);
    raw_write(fd, buf + i + 1, 16 - i - 1);
}

void write_u64_dec(int fd, unsigned long long v) {
    char buf[24];
    int i = 23;
    buf[i--] = '\0';
    do {
        buf[i--] = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v != 0);
    raw_write(fd, buf + i + 1, 23 - i - 1);
}

void write_ptr_hex(int fd, const void* p) {
    write_str(fd, "0x");
    write_u64_hex(fd, reinterpret_cast<unsigned long long>(p));
}

// Build "<dir>/crash_<pid>_<seq>.json" into out. Returns length, or 0.
size_t build_path(char* out, size_t out_cap) {
    if (g_dir_len == 0 || g_dir_len + 40 >= out_cap) return 0;
    size_t n = 0;
    std::memcpy(out, g_dir_path, g_dir_len);
    n += g_dir_len;
    const char* name = "/crash_";
    std::memcpy(out + n, name, 7);
    n += 7;
    // pid (digits only — do NOT copy the terminating NUL of the temp buffer)
    {
        char tmp[16];
        int i = 15;
        tmp[i--] = '\0';
        unsigned long long pid = static_cast<unsigned long long>(::getpid());
        do {
            tmp[i--] = static_cast<char>('0' + (pid % 10));
            pid /= 10;
        } while (pid != 0);
        const size_t plen = 14 - i;  // exclude tmp[15] ('\0')
        std::memcpy(out + n, tmp + i + 1, plen);
        n += plen;
    }
    out[n++] = '_';
    // sequence (digits only)
    {
        char tmp[24];
        int i = 23;
        tmp[i--] = '\0';
        unsigned long long seq = ++g_seq;
        do {
            tmp[i--] = static_cast<char>('0' + (seq % 10));
            seq /= 10;
        } while (seq != 0);
        const size_t slen = 22 - i;  // exclude tmp[23] ('\0')
        std::memcpy(out + n, tmp + i + 1, slen);
        n += slen;
    }
    const char* ext = ".json";
    std::memcpy(out + n, ext, 5);
    n += 5;
    out[n] = '\0';
    return n;
}

// Best-effort backtrace (return addresses) via the platform unwinder.
// _Unwind_Backtrace is available on macOS, Linux and Android NDK and walks the
// stack without allocating (safe enough for a signal handler; glibc's
// backtrace() is not available on Android bionic).
struct BacktraceFrameBuffer {
    const void* frames[16];
    int count;
};

_Unwind_Reason_Code unwind_cb(struct _Unwind_Context* ctx, void* arg) {
    auto* buf = static_cast<BacktraceFrameBuffer*>(arg);
    if (buf->count < 16) {
        buf->frames[buf->count++] = reinterpret_cast<const void*>(_Unwind_GetIP(ctx));
    }
    return _URC_NO_REASON;
}

void write_backtrace(int fd) {
    BacktraceFrameBuffer buf{};
    buf.count = 0;
    ::_Unwind_Backtrace(unwind_cb, &buf);
    write_str(fd, ",\"backtrace\":[");
    for (int i = 0; i < buf.count; ++i) {
        if (i > 0) write_str(fd, ",");
        write_str(fd, "\"");
        write_ptr_hex(fd, buf.frames[i]);
        write_str(fd, "\"");
    }
    write_str(fd, "]");
}

} // namespace

// ---------------------------------------------------------------------------
// CrashHandler
// ---------------------------------------------------------------------------

CrashHandler& CrashHandler::getInstance() {
    static CrashHandler instance;
    return instance;
}

bool CrashHandler::isInstalled() const {
    return m_installed.load(std::memory_order_acquire);
}

std::string CrashHandler::directory() const { return m_directory; }

void CrashHandler::updateContext(const std::string& json_inner) {
    if (json_inner.size() >= sizeof(crash_ctx::buffer)) {
        return;  // too big to ever fit; keep the previous (stale) snapshot
    }
    std::memcpy(crash_ctx::buffer, json_inner.data(), json_inner.size());
    // Publish length last (release) so the handler reads a consistent fragment.
    crash_ctx::length.store(json_inner.size(), std::memory_order_release);
}

void CrashHandler::install(const std::string& dir) {
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_installed.load(std::memory_order_acquire)) {
        // Re-point the directory on re-configure.
        m_directory = dir;
        g_dir_len = dir.size() < sizeof(g_dir_path) ? dir.size() : sizeof(g_dir_path) - 1;
        std::memcpy(g_dir_path, dir.data(), g_dir_len);
        g_dir_path[g_dir_len] = '\0';
        return;
    }
    m_directory = dir;
    g_dir_len = dir.size() < sizeof(g_dir_path) ? dir.size() : sizeof(g_dir_path) - 1;
    std::memcpy(g_dir_path, dir.data(), g_dir_len);
    g_dir_path[g_dir_len] = '\0';

    // Alternate signal stack so we can still write a report on stack overflow.
    static char alt_stack[65536];
    stack_t ss;
    std::memset(&ss, 0, sizeof(ss));
    ss.ss_sp = alt_stack;
    ss.ss_size = sizeof(alt_stack);
    ::sigaltstack(&ss, nullptr);

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = [](int sig, siginfo_t* info, void* uctx) {
        CrashHandler::onCrash(sig, info, uctx);
    };
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < kSignalCount; ++i) {
        ::sigaction(kSignals[i], &sa, nullptr);
    }

    m_installed.store(true, std::memory_order_release);
}

void CrashHandler::uninstall() {
    std::lock_guard<std::mutex> lock(m_mu);
    struct sigaction dfl;
    std::memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    for (int i = 0; i < kSignalCount; ++i) {
        ::sigaction(kSignals[i], &dfl, nullptr);
    }
    m_installed.store(false, std::memory_order_release);
}

void CrashHandler::onCrash(int sig, void*, void*) {
    // Build the report path first (async-signal-safe, no allocation).
    char path[600];
    const size_t plen = build_path(path, sizeof(path));
    if (plen == 0) {
        ::signal(sig, SIG_DFL);
        ::raise(sig);
        ::_exit(128 + sig);
    }

    const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        ::signal(sig, SIG_DFL);
        ::raise(sig);
        ::_exit(128 + sig);
    }

    // Header: schema, crash id, signal, exact crash epoch.
    write_str(fd, "{\"schema\":\"litep2p-crash/1\",\"crash_id\":\"");
    write_u64_hex(fd, static_cast<unsigned long long>(::getpid()));
    write_str(fd, "-");
    write_u64_hex(fd, static_cast<unsigned long long>(::time(nullptr)));
    write_str(fd, "\",\"signal\":");
    write_u64_dec(fd, static_cast<unsigned long long>(sig));
    write_str(fd, ",\"signame\":\"");
    write_str(fd, signame(sig));
    write_str(fd, "\",\"crash_epoch_s\":");
    write_u64_dec(fd, static_cast<unsigned long long>(::time(nullptr)));

    write_backtrace(fd);

    // Splice the pre-formatted context (uptime/device/telemetry/etc.).
    const size_t clen = crash_ctx::length.load(std::memory_order_acquire);
    if (clen > 0 && clen < sizeof(crash_ctx::buffer)) {
        write_str(fd, ",\"crash_context\":{");
        raw_write(fd, crash_ctx::buffer, clen);
        write_str(fd, "}}");
    } else {
        write_str(fd, "}");
    }
    write_str(fd, "\n");
    ::close(fd);

    // Restore the default action and re-raise so the process dies with the
    // correct signal semantics (and a core dump when enabled).
    ::signal(sig, SIG_DFL);
    ::raise(sig);
    // If raise somehow returns, exit with the conventional status.
    ::_exit(128 + sig);
}

