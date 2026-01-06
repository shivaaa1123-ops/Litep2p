#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Lightweight, local-only telemetry (no network export).
// - Counters: monotonically increasing
// - Gauges: last-set values
// - Histograms: count/sum/min/max (good enough for latency + state duration)
//
// Output:
// - Periodic flush as a single-line JSON blob (LOG + optional file append)
//
// Design goals:
// - Safe in production (low overhead, no allocations on hot path after first use)
// - Works on Android + desktop
// - No external dependencies required (JSON is generated manually)

class Telemetry final {
public:
    struct Config {
        bool enabled = true;
        bool log_json = true;
        int flush_interval_ms = 30000; // 30s
        std::string file_path;         // optional (append JSONL)
        bool include_peer_ids = true;  // include peer_id in some metric names (best-effort)
    };

    static Telemetry& getInstance();

    // Re-entrant / idempotent init; safe to call multiple times.
    void initialize(const std::string& engine_id, const Config& cfg);
    bool is_enabled() const { return m_enabled.load(std::memory_order_acquire); }

    // Called from a periodic tick (e.g., TimerTickEvent).
    void tick();

    // Manual flush (e.g., on shutdown).
    void flush(const std::string& reason);

    // Snapshot current telemetry as a single-line JSON (no side effects; does not log or write to file).
    std::string snapshot_json(const std::string& reason = "snapshot");

    // Metrics API (thread-safe).
    void inc_counter(const std::string& name, int64_t delta = 1);
    void set_gauge(const std::string& name, int64_t value);
    void observe_hist_ms(const std::string& name, int64_t ms);

private:
    Telemetry() = default;
    ~Telemetry() = default;
    Telemetry(const Telemetry&) = delete;
    Telemetry& operator=(const Telemetry&) = delete;

    struct Counter { std::atomic<int64_t> v{0}; };
    struct Gauge { std::atomic<int64_t> v{0}; };
    struct Hist {
        std::atomic<int64_t> count{0};
        std::atomic<int64_t> sum{0};
        std::atomic<int64_t> min{INT64_MAX};
        std::atomic<int64_t> max{INT64_MIN};
    };

    Counter* get_or_create_counter_(const std::string& name);
    Gauge* get_or_create_gauge_(const std::string& name);
    Hist* get_or_create_hist_(const std::string& name);

    std::string build_flush_json_(const std::string& reason);
    void append_to_file_(const std::string& line);

    std::atomic<bool> m_enabled{false};
    std::atomic<bool> m_log_json{true};
    std::atomic<int> m_flush_interval_ms{30000};
    std::atomic<int64_t> m_start_ms{0};
    std::atomic<int64_t> m_last_flush_ms{0};

    // Config/state
    mutable std::mutex m_mu;
    std::string m_engine_id;
    std::string m_file_path;
    bool m_include_peer_ids{true};

    std::unordered_map<std::string, Counter> m_counters;
    std::unordered_map<std::string, Gauge> m_gauges;
    std::unordered_map<std::string, Hist> m_hists;
};


