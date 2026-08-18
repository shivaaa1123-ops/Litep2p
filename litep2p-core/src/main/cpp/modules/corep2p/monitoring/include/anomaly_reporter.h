#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// ============================================================================
// AnomalyReporter — field-diagnostics incident logger + uploader.
//
// Purpose: whenever the engine hits an anomaly (peer disconnect, connect
// failure, stall that did not recover, socket restart failure, any runtime
// error), it writes a self-contained, human-readable JSON incident file that
// includes:
//   - when it happened (UTC timestamp) and the incident id
//   - how long the engine had been running (uptime_ms)
//   - which peer/endpoint was affected
//   - the engine version, local peer id and a config fingerprint
//   - device info (brand/model/os/abi — pushed by the platform layer)
//   - a telemetry snapshot (counters/gauges) when enabled
//
// The files live in <base_dir>/anomalies/ so they can be inspected from a
// terminal or via `adb shell run-as <pkg> ls files/anomalies` during
// development. In production, `tick()` (called from the engine maintenance
// loop) periodically POSTs pending incident files to a collector server
// (`anomaly_reporter.upload_url`), then deletes the successfully uploaded
// files. This is how field data (device brand/model/OS, config, uptime,
// failure details) gets back to the developer for analysis.
//
// All methods are thread-safe. Reporting must be cheap (JSON is small; the
// file write is O(incident)). The uploader is best-effort: failures leave the
// file pending for the next interval, capped by `max_files` rotation.
// ============================================================================

class AnomalyReporter final {
public:
    struct Config {
        bool enabled = true;
        std::string base_dir;              // parent directory; incidents go to <base_dir>/<subdir>
        std::string subdir = "anomalies";  // e.g. "files/anomalies" on Android
        int max_files = 200;
        bool upload_enabled = false;
        std::string upload_url;            // "http://host:port/path" (plain HTTP for now)
        int upload_interval_ms = 300000;   // 5 minutes
        bool include_telemetry = true;     // embed Telemetry snapshot in each incident
        std::string engine_version = "0.4.0";
        std::string peer_id;
    };

    // One incident. `extras` are free-form key/value pairs appended to the JSON
    // (e.g. retry counts, previous state, error code).
    struct Event {
        std::string type;       // "peer_disconnected", "connect_failed", "handshake_failed",
                                // "stall_not_recovered", "runtime_error", ...
        std::string peer_id;
        std::string network_id;
        std::string detail;
        std::vector<std::pair<std::string, std::string>> extras;
    };

    static AnomalyReporter& getInstance();

    void configure(const Config& cfg);
    bool isEnabled() const;

    // Device info JSON: {"brand":"...","model":"...","os":"...","abi":"...",...}
    // Set by the platform layer (Android JNI / desktop main) before/after start.
    void setDeviceInfo(const std::string& json);

    // Engine-uptime provider (ms since engine start). Installed by the session
    // manager at start; falls back to time since configure() when unset.
    void setUptimeProvider(std::function<int64_t()> provider);

    // Record an anomaly: writes <base_dir>/<subdir>/anomaly_<ts>_<seq>.json
    // and (when upload is enabled) marks it pending for the next tick().
    void report(const Event& ev);

    // Periodic housekeeping: upload pending files (if enabled), rotate to
    // max_files. Call from the maintenance loop every ~5s.
    void tick();

    // Resolved incidents directory (for terminal/ADB inspection).
    std::string directory() const;
    int pendingFileCount() const;

private:
    AnomalyReporter() = default;
    ~AnomalyReporter() = default;
    AnomalyReporter(const AnomalyReporter&) = delete;
    AnomalyReporter& operator=(const AnomalyReporter&) = delete;

    std::string build_incident_(const Event& ev, int64_t now_ms, int64_t uptime_ms,
                                const std::string& telemetry_json);
    bool write_incident_(const std::string& json, std::string& out_path);
    void rotate_locked_(int max_files);
    bool upload_file_(const std::string& path);
    std::vector<std::string> list_pending_locked_() const;

    static std::string iso8601_utc_(int64_t ms);
    static std::string random_hex_(size_t bytes);
    static std::string json_escape_(const std::string& s);

    mutable std::mutex m_mu;
    Config m_cfg;
    std::string m_device_info = "{}";
    std::string m_directory;
    std::function<int64_t()> m_uptime_provider;
    int64_t m_configured_at_ms{0};
    int64_t m_last_upload_attempt_ms{0};
    uint64_t m_seq{0};
};

// Convenience: short-hand for report() with no extras.
inline void report_anomaly(const std::string& type, const std::string& peer_id,
                           const std::string& network_id, const std::string& detail) {
    AnomalyReporter::Event ev;
    ev.type = type;
    ev.peer_id = peer_id;
    ev.network_id = network_id;
    ev.detail = detail;
    AnomalyReporter::getInstance().report(ev);
}
