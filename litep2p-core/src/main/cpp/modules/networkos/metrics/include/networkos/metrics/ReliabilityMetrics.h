#pragma once

// Network OS Phase 11 — ReliabilityMetrics (master doc §44 reliability model).
//
// Turns "reliability" from a claim into measured, reproducible numbers:
//   P(delivery before TTL), P(receipt returned), median/P95 delivery time,
//   replica survival over TTL, bytes per delivered object, wakeups per day,
//   CPU ms per object, and an energy estimate per delivered object.
//
// Design rules:
//   * Every buffer is BOUNDED (fixed-capacity latency sample ring with
//     deterministic decimation) — a metrics sink must never become the
//     unbounded-allocation bug it exists to catch.
//   * Fully deterministic given the same event stream (no RNG anywhere).
//   * Thread-safe (single mutex); cheap enough to call from hot paths.
//   * Zero dependencies — usable by the engine, tests, and the standalone
//     churn simulator alike.

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace networkos {
namespace metrics {

class ReliabilityMetrics {
public:
    struct Options {
        size_t latency_samples_max{4096};  // bounded delivery-latency sample set
        size_t cpu_samples_max{1024};      // bounded per-object CPU ms samples
        // Energy model constants (documented approximations for a mid-range
        // Android device; recalibrate per device class in the report):
        double radio_wakeup_cost_mj{18.0};  // mJ per radio wakeup
        double cpu_cost_mj_per_ms{0.35};    // mJ per CPU millisecond
        double radio_cost_mj_per_kb{1.2};   // mJ per KB transferred
    };

    explicit ReliabilityMetrics();
    explicit ReliabilityMetrics(const Options& options);

    // ---- event inputs (engine paths + simulator) ---------------------------
    void noteObjectPublished(uint64_t bytes, int64_t published_ms, int64_t ttl_ms);
    void noteDeliveryCompleted(int64_t delivered_ms, uint64_t bytes);
    void noteDeliveryExpired();
    void noteReceiptReturned(int64_t latency_ms);
    void noteReceiptExpected();       // delivery confirmed; receipt now expected
    void noteReceiptMissing();        // expected receipt did not arrive in window
    void noteReplicaSample(bool survived);  // TTL-checkpoint replica sampling
    void noteWakeup(const char* subsystem); // §77-style accounting (also energy)
    void noteCpuMs(double ms);              // measured engine work per object
    void noteBytesSent(uint64_t bytes);
    void noteElapsedWindowMs(int64_t ms);   // observation-window length

    // ---- readouts -----------------------------------------------------------
    struct Snapshot {
        // Reliability (§44).
        uint64_t published{0};
        uint64_t delivered_before_ttl{0};
        uint64_t expired{0};
        double p_delivery_before_ttl{0.0};
        double p_receipt_returned{0.0};
        int64_t median_delivery_ms{0};
        int64_t p95_delivery_ms{0};
        uint64_t replica_samples{0};
        double replica_survival{0.0};           // fraction surviving over TTL
        // Cost.
        double bytes_per_delivered_object{0.0};
        double wakeups_per_day{0.0};
        double cpu_ms_per_object{0.0};
        double energy_mj_per_object{0.0};
        // Raw totals (auditability — every derived number traces back).
        uint64_t receipts_expected{0};
        uint64_t receipts_returned{0};
        uint64_t receipts_missing{0};
        uint64_t wakeups{0};
        double cpu_ms_total{0.0};
        uint64_t bytes_sent_total{0};
        int64_t elapsed_window_ms{0};
    };

    Snapshot snapshot() const;
    std::string snapshotJson() const;   // stable field order; embeds Snapshot
    void reset();

private:
    void noteDeliveryLatencyMs_(int64_t ms);   // bounded insert + decimation
    static int64_t percentile_(std::vector<int64_t> sorted, double frac);

    mutable std::mutex m_mu_;
    Options m_opt_;
    std::vector<int64_t> m_latencies_;   // bounded (decimated when full)
    std::vector<double> m_cpu_ms_;       // bounded (decimated when full)

    uint64_t m_published_{0};
    uint64_t m_delivered_{0};
    uint64_t m_expired_{0};
    uint64_t m_receipts_expected_{0};
    uint64_t m_receipts_returned_{0};
    uint64_t m_receipts_missing_{0};
    uint64_t m_replica_alive_{0};
    uint64_t m_replica_samples_{0};
    uint64_t m_wakeups_{0};
    double m_cpu_ms_total_{0.0};
    uint64_t m_bytes_sent_{0};
    uint64_t m_bytes_delivered_{0};
    int64_t m_elapsed_ms_{0};
};

std::string reliability_snapshot_json(const ReliabilityMetrics& m);  // convenience

} // namespace metrics
} // namespace networkos