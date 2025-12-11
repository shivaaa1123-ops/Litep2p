#include "adaptive_scaler.h"
#include <algorithm>

AdaptiveScaler::AdaptiveScaler(const Config& config)
    : m_config(config), m_current_strategy(ScalingStrategy::SINGLE_THREADED),
      m_peer_count(0), m_cpu_history(config.history_size, 0.0f),
      m_memory_history(config.history_size, 0.0f),
      m_latency_history(config.history_size, 0.0f) {}

void AdaptiveScaler::report_metrics(int peer_count, float cpu_percent, float memory_percent,
                                     float event_latency_ms) {
    m_peer_count = peer_count;
    
    // Add to history
    m_cpu_history[m_history_index] = cpu_percent;
    m_memory_history[m_history_index] = memory_percent;
    m_latency_history[m_history_index] = event_latency_ms;
    
    m_history_index = (m_history_index + 1) % m_config.history_size;
    
    if (m_config.enable_auto_scaling) {
        float avg_cpu = compute_average(m_cpu_history);
        float avg_memory = compute_average(m_memory_history);
        
        ScalingStrategy recommended = compute_strategy(peer_count, avg_cpu, avg_memory);
        if (recommended != m_current_strategy) {
            m_current_strategy = recommended;
        }
    }
}

AdaptiveScaler::ScalingStrategy AdaptiveScaler::get_current_strategy() const {
    return m_current_strategy;
}

AdaptiveScaler::ScalingStrategy AdaptiveScaler::get_recommended_strategy() const {
    float avg_cpu = compute_average(m_cpu_history);
    float avg_memory = compute_average(m_memory_history);
    return compute_strategy(m_peer_count, avg_cpu, avg_memory);
}

bool AdaptiveScaler::should_scale_up() const {
    ScalingStrategy current = m_current_strategy;
    ScalingStrategy recommended = get_recommended_strategy();
    return recommended > current;
}

bool AdaptiveScaler::should_scale_down() const {
    ScalingStrategy current = m_current_strategy;
    ScalingStrategy recommended = get_recommended_strategy();
    return recommended < current;
}

AdaptiveScaler::Recommendation AdaptiveScaler::get_recommendation() const {
    Recommendation rec;
    rec.current = m_current_strategy;
    rec.recommended = get_recommended_strategy();
    rec.urgent = false;
    
    float avg_cpu = compute_average(m_cpu_history);
    float avg_memory = compute_average(m_memory_history);
    float avg_latency = compute_average(m_latency_history);
    
    if (rec.recommended > rec.current) {
        if (avg_cpu > m_config.cpu_threshold_percent) {
            rec.reason = "High CPU - need more workers";
            rec.urgent = (avg_cpu > m_config.cpu_threshold_percent + 10);
        } else if (avg_memory > m_config.memory_threshold_percent) {
            rec.reason = "High memory - need batching";
            rec.urgent = false;
        } else if (avg_latency > 50.0f) {
            rec.reason = "High latency - need optimization";
            rec.urgent = false;
        } else {
            rec.reason = "Peer count exceeded threshold";
            rec.urgent = false;
        }
    } else if (rec.recommended < rec.current) {
        rec.reason = "Underutilized - can reduce resources";
        rec.urgent = false;
    } else {
        rec.reason = "Strategy optimal";
        rec.urgent = false;
    }
    
    return rec;
}

AdaptiveScaler::Metrics AdaptiveScaler::get_metrics() const {
    Metrics m;
    m.peer_count = m_peer_count;
    m.avg_cpu_percent = compute_average(m_cpu_history);
    m.avg_memory_percent = compute_average(m_memory_history);
    m.avg_latency_ms = compute_average(m_latency_history);
    m.max_latency_ms = *std::max_element(m_latency_history.begin(), m_latency_history.end());
    return m;
}

float AdaptiveScaler::compute_average(const std::vector<float>& history) const {
    if (history.empty()) return 0.0f;
    
    float sum = 0.0f;
    for (float val : history) {
        sum += val;
    }
    return sum / history.size();
}

AdaptiveScaler::ScalingStrategy AdaptiveScaler::compute_strategy(int peer_count, float avg_cpu,
                                                                   float avg_memory) const {
    // Decision logic
    if (peer_count < 1000) {
        if (avg_cpu < 20 && avg_memory < 30) {
            return ScalingStrategy::SINGLE_THREADED;
        }
        return ScalingStrategy::BALANCED;
    } else if (peer_count < 10000) {
        if (avg_cpu > 80 || avg_memory > 80) {
            return ScalingStrategy::HIGH_SCALE;
        }
        return ScalingStrategy::BALANCED;
    } else if (peer_count < 50000) {
        if (avg_memory > 75) {
            return ScalingStrategy::MEGA_SCALE;
        }
        return ScalingStrategy::HIGH_SCALE;
    } else {
        return ScalingStrategy::MEGA_SCALE;
    }
}
