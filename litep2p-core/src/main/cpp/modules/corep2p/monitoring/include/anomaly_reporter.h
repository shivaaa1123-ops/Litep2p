#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
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
        // ---- Dedup / rate limiting (production resource guard) ----
        // Repeated identical anomalies must NOT spam incident files: the same
        // (type, peer, detail) is logged at most once per min_interval_ms, and
        // each type is capped per rolling hour. Suppressed occurrences are
        // counted and folded into the next incident (`suppressed_count`), so
        // analysts still see how often an error repeated without the device
        // writing hundreds of files.
        int min_interval_ms = 60000;        // min gap between identical incidents
        int max_per_type_per_hour = 10;     // cap per event_type per rolling hour
    };

    // One incident. `extras` are free-form key/value pairs appended to the JSON
    // (e.g. retry counts, previous state, error code).
    struct Event {
        std::string type;       // taxonomy: "peer_disconnected", "connect_failed",
                                // "handshake_failed", "peer_failed",
                                // "stall_not_recovered", "runtime_error",
                                // "security_error", "resource_pressure"
        std::string severity;   // "info" | "warning" | "critical"
        std::string reason;     // WHY this incident was created (the rule that tripped)
        std::string peer_id;
        std::string network_id;
        std::string detail;     // WHAT the error was at the time
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
                                const std::string& telemetry_json,
                                int64_t suppressed_count, int64_t event_total);
    bool write_incident_(const std::string& json, std::string& out_path);
    void rotate_locked_(int max_files);
    bool upload_file_(const std::string& path);
    std::vector<std::string> list_pending_locked_() const;

    static std::string iso8601_utc_(int64_t ms);
    static std::string random_hex_(size_t bytes);
    static std::string json_escape_(const std::string& s);
    static std::string detail_fingerprint_(const std::string& detail);
    static std::string hash_hex_(const std::string& s);
    std::string config_fingerprint_();

    mutable std::mutex m_mu;
    Config m_cfg;
    std::string m_device_info = "{}";
    std::string m_directory;
    std::function<int64_t()> m_uptime_provider;
    int64_t m_configured_at_ms{0};
    int64_t m_last_upload_attempt_ms{0};
    uint64_t m_seq{0};

    // ---- Dedup / rate-limit state (guarded by m_mu) ----
    // key = "<type>|<peer_id>|<detail-fingerprint>"
    struct DedupState {
        int64_t last_reported_ms{0};   // when this exact incident was last written
        int64_t suppressed_count{0};   // how many repeats were folded in since
        int64_t last_summary_ms{0};    // when the suppression summary was last flushed
        std::string type;              // original event type (for the summary)
        std::string peer_id;           // original peer id
        std::string detail;            // original detail
    };
    std::unordered_map<std::string, DedupState> m_dedup;       // exact-incident key -> state
    std::unordered_map<std::string, int64_t> m_type_count;     // event_type -> count in window
    std::unordered_map<std::string, int64_t> m_type_window_start;  // event_type -> window start ms
    std::unordered_map<std::string, int64_t> m_event_totals;   // event_type -> total since configure

    // Called from tick(): writes one `repeated_anomaly` incident per dedup key
    // that accumulated suppressed repeats (frequency data for analysts), then
    // resets the counters. Rate-limited to min_interval_ms per key.
    void flush_suppression_summaries_();
};

// Convenience: short-hand for report() with no extras.
inline void report_anomaly(const std::string& type, const std::string& severity,
                           const std::string& reason, const std::string& peer_id,
                           const std::string& network_id, const std::string& detail) {
    AnomalyReporter::Event ev;
    ev.type = type;
    ev.severity = severity;
    ev.reason = reason;
    ev.peer_id = peer_id;
    ev.network_id = network_id;
    ev.detail = detail;
    AnomalyReporter::getInstance().report(ev);
}
