#include "telemetry.h"

#include "logger.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace {
int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// Minimal JSON string escape (enough for ids/paths/names).
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c));
                    out += oss.str();
                } else {
                    out += c;
                }
        }
    }
    return out;
}

template <typename T>
void atomic_update_min(std::atomic<T>& a, T v) {
    T cur = a.load(std::memory_order_relaxed);
    while (v < cur && !a.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {}
}

template <typename T>
void atomic_update_max(std::atomic<T>& a, T v) {
    T cur = a.load(std::memory_order_relaxed);
    while (v > cur && !a.compare_exchange_weak(cur, v, std::memory_order_relaxed)) {}
}
} // namespace

Telemetry& Telemetry::getInstance() {
    static Telemetry t;
    return t;
}

void Telemetry::initialize(const std::string& engine_id, const Config& cfg) {
    {
        std::lock_guard<std::mutex> lk(m_mu);
        m_engine_id = engine_id;
        m_file_path = cfg.file_path;
        m_include_peer_ids = cfg.include_peer_ids;
    }

    m_enabled.store(cfg.enabled, std::memory_order_release);
    m_log_json.store(cfg.log_json, std::memory_order_release);
    m_flush_interval_ms.store(cfg.flush_interval_ms, std::memory_order_release);

    const int64_t t = now_ms();
    if (m_start_ms.load(std::memory_order_acquire) == 0) {
        m_start_ms.store(t, std::memory_order_release);
    }
    // Force an early flush after startup (helps confirm it's on in production).
    if (m_last_flush_ms.load(std::memory_order_acquire) == 0) {
        m_last_flush_ms.store(t, std::memory_order_release);
    }
}

void Telemetry::tick() {
    if (!is_enabled()) return;
    const int64_t t = now_ms();
    const int64_t last = m_last_flush_ms.load(std::memory_order_acquire);
    const int interval = m_flush_interval_ms.load(std::memory_order_acquire);
    if (interval <= 0) return;
    if ((t - last) >= interval) {
        // Best-effort: avoid stampede flushes.
        int64_t expected = last;
        if (m_last_flush_ms.compare_exchange_strong(expected, t, std::memory_order_acq_rel)) {
            flush("periodic");
        }
    }
}

void Telemetry::flush(const std::string& reason) {
    if (!is_enabled()) return;
    const std::string line = build_flush_json_(reason);
    if (m_log_json.load(std::memory_order_acquire)) {
        LOG_INFO("TELEMETRY " + line);
    }
    append_to_file_(line);
}

std::string Telemetry::snapshot_json(const std::string& reason) {
    if (!is_enabled()) return "{}";
    return build_flush_json_(reason);
}

Telemetry::Counter* Telemetry::get_or_create_counter_(const std::string& name) {
    std::lock_guard<std::mutex> lk(m_mu);
    return &m_counters[name];
}

Telemetry::Gauge* Telemetry::get_or_create_gauge_(const std::string& name) {
    std::lock_guard<std::mutex> lk(m_mu);
    return &m_gauges[name];
}

Telemetry::Hist* Telemetry::get_or_create_hist_(const std::string& name) {
    std::lock_guard<std::mutex> lk(m_mu);
    return &m_hists[name];
}

void Telemetry::inc_counter(const std::string& name, int64_t delta) {
    if (!is_enabled()) return;
    auto* c = get_or_create_counter_(name);
    c->v.fetch_add(delta, std::memory_order_relaxed);
}

void Telemetry::set_gauge(const std::string& name, int64_t value) {
    if (!is_enabled()) return;
    auto* g = get_or_create_gauge_(name);
    g->v.store(value, std::memory_order_relaxed);
}

void Telemetry::observe_hist_ms(const std::string& name, int64_t ms) {
    if (!is_enabled()) return;
    auto* h = get_or_create_hist_(name);
    h->count.fetch_add(1, std::memory_order_relaxed);
    h->sum.fetch_add(ms, std::memory_order_relaxed);
    atomic_update_min(h->min, ms);
    atomic_update_max(h->max, ms);
}

std::string Telemetry::build_flush_json_(const std::string& reason) {
    const int64_t t = now_ms();
    const int64_t start = m_start_ms.load(std::memory_order_acquire);
    const int64_t uptime = (start > 0) ? (t - start) : 0;

    // Snapshot maps under lock to keep output consistent.
    std::unordered_map<std::string, int64_t> counters;
    std::unordered_map<std::string, int64_t> gauges;
    struct HistSnap { int64_t count, sum, min, max; };
    std::unordered_map<std::string, HistSnap> hists;
    std::string engine_id;
    std::string file_path;
    bool include_peer_ids = true;

    {
        std::lock_guard<std::mutex> lk(m_mu);
        engine_id = m_engine_id;
        file_path = m_file_path;
        include_peer_ids = m_include_peer_ids;

        counters.reserve(m_counters.size());
        for (auto& kv : m_counters) {
            counters.emplace(kv.first, kv.second.v.load(std::memory_order_relaxed));
        }
        gauges.reserve(m_gauges.size());
        for (auto& kv : m_gauges) {
            gauges.emplace(kv.first, kv.second.v.load(std::memory_order_relaxed));
        }
        hists.reserve(m_hists.size());
        for (auto& kv : m_hists) {
            HistSnap s;
            s.count = kv.second.count.load(std::memory_order_relaxed);
            s.sum = kv.second.sum.load(std::memory_order_relaxed);
            s.min = kv.second.min.load(std::memory_order_relaxed);
            s.max = kv.second.max.load(std::memory_order_relaxed);
            // Normalize uninitialized min/max.
            if (s.count == 0) {
                s.min = 0;
                s.max = 0;
            } else {
                if (s.min == INT64_MAX) s.min = 0;
                if (s.max == INT64_MIN) s.max = 0;
            }
            hists.emplace(kv.first, s);
        }
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"ts_ms\":" << t << ",";
    oss << "\"uptime_ms\":" << uptime << ",";
    oss << "\"engine_id\":\"" << json_escape(engine_id) << "\",";
    oss << "\"reason\":\"" << json_escape(reason) << "\",";
    oss << "\"include_peer_ids\":" << (include_peer_ids ? "true" : "false") << ",";

    oss << "\"counters\":{";
    bool first = true;
    for (const auto& kv : counters) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << json_escape(kv.first) << "\":" << kv.second;
    }
    oss << "},";

    oss << "\"gauges\":{";
    first = true;
    for (const auto& kv : gauges) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << json_escape(kv.first) << "\":" << kv.second;
    }
    oss << "},";

    oss << "\"hists_ms\":{";
    first = true;
    for (const auto& kv : hists) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << json_escape(kv.first) << "\":{"
            << "\"count\":" << kv.second.count << ","
            << "\"sum\":" << kv.second.sum << ","
            << "\"min\":" << kv.second.min << ","
            << "\"max\":" << kv.second.max
            << "}";
    }
    oss << "}";

    oss << "}";
    return oss.str();
}

void Telemetry::append_to_file_(const std::string& line) {
    std::string path;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        path = m_file_path;
    }
    if (path.empty()) return;

    // Best-effort append; never throw.
    try {
        std::ofstream out(path, std::ios::out | std::ios::app);
        if (!out.is_open()) {
            LOG_WARN("Telemetry: Failed to open telemetry file for append: " + path);
            return;
        }
        out << line << "\n";
    } catch (...) {
        // swallow
    }
}


