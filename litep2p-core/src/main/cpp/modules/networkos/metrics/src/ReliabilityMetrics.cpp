// Phase 11 — ReliabilityMetrics implementation. See header for contract.

#include "networkos/metrics/ReliabilityMetrics.h"

#include <algorithm>
#include <cstdio>

namespace networkos {
namespace metrics {

ReliabilityMetrics::ReliabilityMetrics() : ReliabilityMetrics(Options{}) {}

ReliabilityMetrics::ReliabilityMetrics(const Options& options) : m_opt_(options) {
    m_latencies_.reserve(m_opt_.latency_samples_max);
    m_cpu_ms_.reserve(m_opt_.cpu_samples_max);
}

void ReliabilityMetrics::noteObjectPublished(uint64_t /*bytes*/, int64_t /*published_ms*/,
                                             int64_t /*ttl_ms*/) {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_published_;
}

void ReliabilityMetrics::noteDeliveryCompleted(int64_t delivered_ms, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_delivered_;
    noteDeliveryLatencyMs_(delivered_ms);
    m_bytes_delivered_ += bytes;
}

void ReliabilityMetrics::noteDeliveryExpired() {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_expired_;
}

void ReliabilityMetrics::noteReceiptReturned(int64_t latency_ms) {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_receipts_returned_;
    (void)latency_ms;  // receipt latency folded into delivery samples below
}

void ReliabilityMetrics::noteReceiptExpected() {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_receipts_expected_;
}

void ReliabilityMetrics::noteReceiptMissing() {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_receipts_missing_;
}

void ReliabilityMetrics::noteReplicaSample(bool survived) {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_replica_samples_;
    if (survived) ++m_replica_alive_;
}

void ReliabilityMetrics::noteWakeup(const char* /*subsystem*/) {
    std::lock_guard<std::mutex> lock(m_mu_);
    ++m_wakeups_;
}

void ReliabilityMetrics::noteCpuMs(double ms) {
    std::lock_guard<std::mutex> lock(m_mu_);
    m_cpu_ms_total_ += ms;
    if (m_cpu_ms_.size() >= m_opt_.cpu_samples_max) {
        // Deterministic decimation: keep every other sample (halves the set,
        // preserves the distribution shape, no RNG).
        std::vector<double> kept;
        kept.reserve(m_cpu_ms_.size() / 2 + 1);
        for (size_t i = 0; i < m_cpu_ms_.size(); i += 2) kept.push_back(m_cpu_ms_[i]);
        m_cpu_ms_.swap(kept);
    }
    m_cpu_ms_.push_back(ms);
}

void ReliabilityMetrics::noteBytesSent(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(m_mu_);
    m_bytes_sent_ += bytes;
}

void ReliabilityMetrics::noteElapsedWindowMs(int64_t ms) {
    std::lock_guard<std::mutex> lock(m_mu_);
    if (ms > m_elapsed_ms_) m_elapsed_ms_ = ms;
}

void ReliabilityMetrics::noteDeliveryLatencyMs_(int64_t ms) {
    if (m_latencies_.size() >= m_opt_.latency_samples_max) {
        // Deterministic decimation (same policy as noteCpuMs_).
        std::vector<int64_t> kept;
        kept.reserve(m_latencies_.size() / 2 + 1);
        for (size_t i = 0; i < m_latencies_.size(); i += 2) kept.push_back(m_latencies_[i]);
        m_latencies_.swap(kept);
    }
    m_latencies_.push_back(ms < 0 ? 0 : ms);
}

int64_t ReliabilityMetrics::percentile_(std::vector<int64_t> sorted, double frac) {
    if (sorted.empty()) return 0;
    std::sort(sorted.begin(), sorted.end());
    size_t idx = static_cast<size_t>(frac * static_cast<double>(sorted.size() - 1) + 0.5);
    if (idx >= sorted.size()) idx = sorted.size() - 1;
    return sorted[idx];
}

ReliabilityMetrics::Snapshot ReliabilityMetrics::snapshot() const {
    std::lock_guard<std::mutex> lock(m_mu_);
    Snapshot s;
    s.published = m_published_;
    s.delivered_before_ttl = m_delivered_;
    s.expired = m_expired_;
    const double denom = static_cast<double>(m_published_ > 0 ? m_published_ : 1);
    s.p_delivery_before_ttl = static_cast<double>(m_delivered_) / denom;
    s.receipts_expected = m_receipts_expected_;
    s.receipts_returned = m_receipts_returned_;
    s.receipts_missing = m_receipts_missing_;
    const double rdenom =
        static_cast<double>(m_receipts_expected_ > 0 ? m_receipts_expected_ : 1);
    s.p_receipt_returned = static_cast<double>(m_receipts_returned_) / rdenom;
    s.median_delivery_ms = percentile_(m_latencies_, 0.50);
    s.p95_delivery_ms = percentile_(m_latencies_, 0.95);
    s.replica_samples = m_replica_samples_;
    s.replica_survival =
        m_replica_samples_ == 0
            ? 0.0
            : static_cast<double>(m_replica_alive_) / static_cast<double>(m_replica_samples_);
    s.bytes_per_delivered_object =
        m_delivered_ == 0
            ? 0.0
            : static_cast<double>(m_bytes_delivered_) / static_cast<double>(m_delivered_);
    s.wakeups = m_wakeups_;
    const double days = static_cast<double>(m_elapsed_ms_) / 86400000.0;
    s.wakeups_per_day = days > 0.0 ? static_cast<double>(m_wakeups_) / days : 0.0;
    s.cpu_ms_total = m_cpu_ms_total_;
    s.cpu_ms_per_object =
        m_delivered_ == 0 ? 0.0 : m_cpu_ms_total_ / static_cast<double>(m_delivered_);
    s.bytes_sent_total = m_bytes_sent_;
    s.elapsed_window_ms = m_elapsed_ms_;
    // Energy model (documented constants): radio wakeups + CPU + transfer.
    const double kb = static_cast<double>(m_bytes_sent_) / 1024.0;
    s.energy_mj_per_object =
        m_delivered_ == 0
            ? 0.0
            : (static_cast<double>(m_wakeups_) * m_opt_.radio_wakeup_cost_mj +
               m_cpu_ms_total_ * m_opt_.cpu_cost_mj_per_ms +
               kb * m_opt_.radio_cost_mj_per_kb) /
                  static_cast<double>(m_delivered_);
    return s;
}

std::string ReliabilityMetrics::snapshotJson() const {
    const Snapshot s = snapshot();
    char buf[1024];
    std::snprintf(buf, sizeof(buf),
                  "{\"published\":%llu,\"delivered_before_ttl\":%llu,\"expired\":%llu,"
                  "\"p_delivery_before_ttl\":%.6f,\"p_receipt_returned\":%.6f,"
                  "\"median_delivery_ms\":%lld,\"p95_delivery_ms\":%lld,"
                  "\"replica_survival\":%.6f,\"replica_samples\":%llu,"
                  "\"bytes_per_delivered_object\":%.1f,\"wakeups_per_day\":%.2f,"
                  "\"cpu_ms_per_object\":%.4f,\"energy_mj_per_object\":%.2f,"
                  "\"receipts_expected\":%llu,\"receipts_returned\":%llu,"
                  "\"receipts_missing\":%llu,\"wakeups\":%llu,\"cpu_ms_total\":%.3f,"
                  "\"bytes_sent_total\":%llu,\"elapsed_window_ms\":%lld}",
                  static_cast<unsigned long long>(s.published),
                  static_cast<unsigned long long>(s.delivered_before_ttl),
                  static_cast<unsigned long long>(s.expired), s.p_delivery_before_ttl,
                  s.p_receipt_returned, static_cast<long long>(s.median_delivery_ms),
                  static_cast<long long>(s.p95_delivery_ms), s.replica_survival,
                  static_cast<unsigned long long>(s.replica_samples),
                  s.bytes_per_delivered_object, s.wakeups_per_day, s.cpu_ms_per_object,
                  s.energy_mj_per_object,
                  static_cast<unsigned long long>(s.receipts_expected),
                  static_cast<unsigned long long>(s.receipts_returned),
                  static_cast<unsigned long long>(s.receipts_missing),
                  static_cast<unsigned long long>(s.wakeups), s.cpu_ms_total,
                  static_cast<unsigned long long>(s.bytes_sent_total),
                  static_cast<long long>(s.elapsed_window_ms));
    return std::string(buf);
}

void ReliabilityMetrics::reset() {
    std::lock_guard<std::mutex> lock(m_mu_);
    m_latencies_.clear();
    m_cpu_ms_.clear();
    m_published_ = 0;
    m_delivered_ = 0;
    m_expired_ = 0;
    m_receipts_expected_ = 0;
    m_receipts_returned_ = 0;
    m_receipts_missing_ = 0;
    m_replica_alive_ = 0;
    m_replica_samples_ = 0;
    m_wakeups_ = 0;
    m_cpu_ms_total_ = 0.0;
    m_bytes_sent_ = 0;
    m_bytes_delivered_ = 0;
    m_elapsed_ms_ = 0;
}

std::string reliability_snapshot_json(const ReliabilityMetrics& m) {
    return m.snapshotJson();
}

} // namespace metrics
} // namespace networkos
