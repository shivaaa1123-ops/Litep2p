#pragma once

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>

// ============================================================================
// CrashHandler — best-effort native crash capture (SIGSEGV/SIGABRT/...).
//
// Hard native faults (segfaults, aborts, bus errors, illegal instructions)
// cannot be reported by the graceful AnomalyReporter path — the process is
// about to die. This module installs POSIX signal handlers that write a
// self-contained `crash_<ts>.json` report into the same anomalies directory
// using ONLY async-signal-safe calls (open/write/close/time/_exit), then
// re-raise the signal with the default action so the process still dies with
// the correct status/core-dump semantics.
//
// The rich context (uptime, device info, config fingerprint, telemetry
// snapshot, event counts) is NOT built inside the handler — that would need
// malloc/threading which is unsafe post-crash. Instead the engine keeps a
// pre-formatted JSON fragment in a static shared buffer, refreshed
// periodically (CrashHandler::updateContext). The handler only has to splice
// that buffer into the report alongside the signal info and a best-effort
// backtrace (return addresses via backtrace()).
//
// Reports are picked up by AnomalyReporter's uploader (crash_* files are
// listed as pending), so a crash is delivered to the collector by the NEXT
// engine start — the standard crash-reporting pattern.
// ============================================================================

class CrashHandler final {
public:
    static CrashHandler& getInstance();

    // Installs handlers for the crash signals. Idempotent. `dir` is the
    // resolved incidents directory (already created by the caller).
    void install(const std::string& dir);
    void uninstall();
    bool isInstalled() const;

    // Refreshes the shared, signal-handler-safe context snapshot. `json_inner`
    // must be a JSON object body WITHOUT braces, e.g.
    //   "\"timestamp_utc\":\"...\",\"engine_uptime_ms\":123,..."
    // Called periodically by AnomalyReporter and right before incidents.
    void updateContext(const std::string& json_inner);

    std::string directory() const;

private:
    CrashHandler() = default;
    ~CrashHandler() = default;
    CrashHandler(const CrashHandler&) = delete;
    CrashHandler& operator=(const CrashHandler&) = delete;

    static void onCrash(int sig, void* info, void* uctx);

    std::atomic<bool> m_installed{false};
    std::string m_directory;
    std::mutex m_mu;
};

// The shared context buffer (extern so the signal handler in the .cpp can
// access it without going through the class instance).
namespace crash_ctx {
// 16 KB pre-formatted JSON context, populated by CrashHandler::updateContext.
extern char buffer[16384];
extern std::atomic<size_t> length;
}
