#ifndef ADAPTIVE_SCALER_H
#define ADAPTIVE_SCALER_H

#include <chrono>
#include <atomic>
#include <memory>
#include <vector>

/**
 * Adaptive scaling engine - automatically switches optimization strategies
 * based on peer count and system load
 * 
 * Strategies:
 * 1. <1000 peers: Single-threaded, vector lookups (low overhead)
 * 2. 1000-10000: HashMap + thread pool (balanced)
 * 3. 10000-50000: UDP batching + multi-socket (high scale)
 * 4. 50000+: LRU cache + extreme optimizations (mega scale)
 */
class AdaptiveScaler {
public:
    enum class ScalingStrategy {
        SINGLE_THREADED = 0,      // <1000 peers
        BALANCED = 1,              // 1000-10000 peers
        HIGH_SCALE = 2,            // 10000-50000 peers
        MEGA_SCALE = 3             // 50000+ peers
    };

    struct Config {
        bool enable_auto_scaling = true;
        int measurement_interval_sec = 10;
        int history_size = 60;
        float cpu_threshold_percent = 80.0f;
        float memory_threshold_percent = 75.0f;
    };

    explicit AdaptiveScaler(const Config& config);
    ~AdaptiveScaler() = default;

    // Report metrics (call periodically)
    void report_metrics(int peer_count, float cpu_percent, float memory_percent, 
                       float event_latency_ms);

    // Get current strategy
    ScalingStrategy get_current_strategy() const;

    // Get recommended strategy based on metrics
    ScalingStrategy get_recommended_strategy() const;

    // Should scale up/down?
    bool should_scale_up() const;
    bool should_scale_down() const;

    // Get scaling recommendations
    struct Recommendation {
        ScalingStrategy current;
        ScalingStrategy recommended;
        const char* reason;
        bool urgent;  // true = immediate action needed
    };
    Recommendation get_recommendation() const;

    // Get performance metrics
    struct Metrics {
        int peer_count = 0;
        float avg_cpu_percent = 0.0f;
        float avg_memory_percent = 0.0f;
        float avg_latency_ms = 0.0f;
        float max_latency_ms = 0.0f;
    };
    Metrics get_metrics() const;

private:
    Config m_config;
    ScalingStrategy m_current_strategy;
    
    std::atomic<int> m_peer_count;
    std::vector<float> m_cpu_history;
    std::vector<float> m_memory_history;
    std::vector<float> m_latency_history;
    size_t m_history_index = 0;
    
    float compute_average(const std::vector<float>& history) const;
    ScalingStrategy compute_strategy(int peer_count, float avg_cpu, float avg_memory) const;
};

#endif // ADAPTIVE_SCALER_H
