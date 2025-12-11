#include "peer_reconnect_policy.h"
#include "logger.h"
#include <algorithm>
#include <cmath>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>

static std::mt19937 g_random_engine(std::chrono::steady_clock::now().time_since_epoch().count());

PeerReconnectPolicy& PeerReconnectPolicy::getInstance() {
    static PeerReconnectPolicy instance;
    return instance;
}

void PeerReconnectPolicy::initialize(int battery_level_percent, bool network_wifi) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    battery_percent_ = battery_level_percent;
    is_wifi_ = network_wifi;
    is_network_available_ = true;
    is_charging_ = false;
    
    // Determine battery level
    if (battery_percent_ < 10) {
        current_battery_level_ = BatteryLevel::CRITICAL;
    } else if (battery_percent_ < 20) {
        current_battery_level_ = BatteryLevel::LOW;
    } else if (battery_percent_ < 80) {
        current_battery_level_ = BatteryLevel::NORMAL;
    } else {
        current_battery_level_ = BatteryLevel::HIGH;
    }
    
    // Determine initial network condition
    current_network_condition_ = NetworkCondition::EXCELLENT;
    
    // Aggressive mode if on WiFi with good battery
    use_aggressive_reconnect_ = is_wifi_ && (battery_percent_ > 80 || is_charging_);
    use_battery_aware_mode_ = !is_wifi_ && battery_percent_ < 30;
    
    nativeLog("PeerReconnectPolicy: Initialized, battery=" + std::to_string(battery_percent_) + "%, aggressive=" + std::to_string(use_aggressive_reconnect_));
}

void PeerReconnectPolicy::track_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    if (peer_stats_.find(peer_id) == peer_stats_.end()) {
        PeerConnectionStats stats = {};
        stats.peer_id = peer_id;
        stats.connected = false;
        stats.attempting_reconnect = false;
        stats.consecutive_failures = 0;
        stats.total_failures = 0;
        stats.successful_connections = 0;
        stats.last_connection_attempt_ms = 0;
        stats.last_successful_connection_ms = 0;
        stats.average_rtt_ms = 100;      // Assume 100ms initially
        stats.max_rtt_ms = 1000;
        stats.min_rtt_ms = 10;
        stats.packet_loss_rate = 0.0f;
        stats.current_condition = NetworkCondition::EXCELLENT;
        stats.retry_count_current_cycle = 0;
        stats.backoff_level = 1;
        stats.next_retry_time_ms = 0;
        stats.last_used_method = "TCP";
        stats.tcp_available = true;
        stats.udp_available = true;
        stats.relay_available = false;
        
        peer_stats_[peer_id] = stats;
        nativeLog("PeerReconnectPolicy: Tracking peer " + peer_id);
    }
}

void PeerReconnectPolicy::untrack_peer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peer_stats_.erase(peer_id);
    nativeLog("PeerReconnectPolicy: Stopped tracking peer " + peer_id);
}

void PeerReconnectPolicy::on_connection_success(const std::string& peer_id,
                                               const std::string& method,
                                               uint32_t rtt_ms) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) return;
    
    PeerConnectionStats& stats = it->second;
    stats.connected = true;
    stats.attempting_reconnect = false;
    stats.consecutive_failures = 0;
    stats.retry_count_current_cycle = 0;
    stats.backoff_level = 1;
    stats.successful_connections++;
    stats.last_successful_connection_ms = 0;  // Reset timer
    stats.last_used_method = method;
    
    // Update RTT statistics (exponential moving average)
    if (stats.average_rtt_ms == 0) {
        stats.average_rtt_ms = rtt_ms;
    } else {
        stats.average_rtt_ms = (stats.average_rtt_ms * 3 + rtt_ms) / 4;  // 75% old, 25% new
    }
    stats.max_rtt_ms = std::max(stats.max_rtt_ms, rtt_ms);
    stats.min_rtt_ms = std::min(stats.min_rtt_ms, rtt_ms);
    
    // Update network condition based on RTT
    stats.current_condition = detect_network_condition(stats.average_rtt_ms, stats.packet_loss_rate);
    
    nativeLog("PeerReconnectPolicy: Connection success for " + peer_id + " via " + method + " (rtt=" + std::to_string(rtt_ms) + "ms, avg=" + std::to_string(stats.average_rtt_ms) + "ms)");
}

void PeerReconnectPolicy::on_connection_failure(const std::string& peer_id,
                                               const std::string& attempted_method,
                                               float packet_loss_rate) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) return;
    
    PeerConnectionStats& stats = it->second;
    stats.connected = false;
    stats.consecutive_failures++;
    stats.total_failures++;
    stats.packet_loss_rate = packet_loss_rate;
    stats.attempting_reconnect = true;
    stats.current_condition = detect_network_condition(stats.average_rtt_ms, packet_loss_rate);
    
    // Don't retry if too many consecutive failures (circuit breaker)
    RetryConfig config = get_retry_config_for_battery();
    if (stats.consecutive_failures > config.max_retries) {
    nativeLog("PeerReconnectPolicy: Connection failed for " + peer_id + " (" + std::to_string(stats.consecutive_failures) + " failures)");
        stats.backoff_level = std::min(stats.backoff_level * 2, 16);  // Cap at 16
        stats.consecutive_failures = 1;  // Reset counter for next backoff level
    } else {
        stats.retry_count_current_cycle++;
        stats.backoff_level = 1 << std::min(stats.consecutive_failures, 5);  // 1, 2, 4, 8, 16, 32...
    }
    
    // Calculate next retry time with jitter
    uint32_t backoff_ms = calculate_backoff_with_jitter(std::log2(stats.backoff_level));
    stats.next_retry_time_ms = backoff_ms;
    
    nativeLog("PeerReconnectPolicy: Connection failure - " + peer_id + " via " + attempted_method + " (failures=" + std::to_string(stats.consecutive_failures) + ", backoff=" + std::to_string(stats.backoff_level) + "ms, next_retry_in=" + std::to_string(stats.next_retry_time_ms) + "ms)");
}

bool PeerReconnectPolicy::should_reconnect_now(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) return false;
    
    PeerConnectionStats& stats = it->second;
    
    // Don't reconnect if already connected
    if (stats.connected) return false;
    
    // Check if enough time has passed
    if (stats.next_retry_time_ms > 0) return false;
    
    // Check battery constraints
    if (!is_reconnect_battery_safe(peer_id)) {
        return false;
    }
    
    // Check if network is available
    if (!is_network_available_) return false;
    
    return true;
}

std::string PeerReconnectPolicy::get_next_peer_to_reconnect() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    std::string best_peer;
    float best_priority = -1.0f;
    
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    uint32_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    
    for (auto& pair : peer_stats_) {
        PeerConnectionStats& stats = pair.second;
        
        // Skip connected peers
        if (stats.connected) continue;
        
        // Skip if not ready to retry yet
        if (stats.next_retry_time_ms > 0 && stats.last_connection_attempt_ms + stats.next_retry_time_ms > now_ms) {
            continue;
        }
        
        // Calculate priority (higher = more urgent)
        float priority = calculate_peer_priority(stats);
        
        if (priority > best_priority) {
            best_priority = priority;
            best_peer = pair.first;
        }
    }
    
    return best_peer;
}

PeerReconnectPolicy::RetryStrategy PeerReconnectPolicy::get_retry_strategy(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    RetryStrategy strategy = {};
    strategy.should_retry = false;
    strategy.backoff_ms = 30000;  // Default to 30s
    strategy.methods = {"TCP", "UDP", "Relay"};
    
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) return strategy;
    
    PeerConnectionStats& stats = it->second;
    
    // Determine retry strategy based on network condition
    RetryConfig config = get_retry_config_for_battery();
    
    strategy.should_retry = (stats.consecutive_failures <= config.max_retries);
    strategy.backoff_ms = stats.next_retry_time_ms;
    
    // Decide which methods to try based on what worked before
    strategy.methods.clear();
    
    // Always try TCP first if available
    if (stats.tcp_available) {
        strategy.methods.push_back("TCP");
    }
    
    // Try UDP if peer supports it and network condition is good
    if (stats.udp_available && stats.current_condition <= NetworkCondition::FAIR) {
        strategy.methods.push_back("UDP");
    }
    
    // Try relay if direct connection failed 3+ times
    if (stats.relay_available || stats.consecutive_failures >= 3) {
        strategy.methods.push_back("Relay");
    }
    
    // If no methods available, allow fallback
    if (strategy.methods.empty()) {
        strategy.methods = {"TCP", "Relay"};
    }
    
    nativeLog("PeerReconnectPolicy: Retry strategy for " + peer_id + " - backoff=" + std::to_string(strategy.backoff_ms) + "ms, should_retry=" + (strategy.should_retry ? "true" : "false"));
    
    return strategy;
}

void PeerReconnectPolicy::set_battery_level(int percent, bool is_charging) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    battery_percent_ = percent;
    is_charging_ = is_charging;
    
    if (percent < 10) {
        current_battery_level_ = BatteryLevel::CRITICAL;
    } else if (percent < 20) {
        current_battery_level_ = BatteryLevel::LOW;
    } else if (percent < 80) {
        current_battery_level_ = BatteryLevel::NORMAL;
    } else {
        current_battery_level_ = BatteryLevel::HIGH;
    }
    
    // Update aggressive/battery-aware modes
    use_aggressive_reconnect_ = is_wifi_ && (percent > 80 || is_charging_);
    use_battery_aware_mode_ = !is_wifi_ && percent < 30;
    
    nativeLog("PeerReconnectPolicy: Battery update - " + std::to_string(percent) + "% (" + std::string(is_charging_ ? "charging" : "on_battery") + "), aggressive=" + (use_aggressive_reconnect_ ? "true" : "false"));
}

void PeerReconnectPolicy::set_network_type(bool is_wifi, bool is_available) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    is_wifi_ = is_wifi;
    is_network_available_ = is_available;
    
    use_aggressive_reconnect_ = is_wifi && (battery_percent_ > 80 || is_charging_);
    use_battery_aware_mode_ = !is_wifi && battery_percent_ < 30;
    
    nativeLog("PeerReconnectPolicy: Network update - " + std::string(is_wifi ? "WiFi" : "Mobile") + " (" + std::string(is_available ? "available" : "unavailable") + "), aggressive=" + (use_aggressive_reconnect_ ? "true" : "false"));
}

NetworkCondition PeerReconnectPolicy::detect_network_condition(uint32_t rtt_ms, float packet_loss_rate) {
    // Classify based on RTT and packet loss
    if (rtt_ms < 50 && packet_loss_rate < 0.01f) {
        return NetworkCondition::EXCELLENT;
    } else if (rtt_ms < 150 && packet_loss_rate < 0.01f) {
        return NetworkCondition::GOOD;
    } else if (rtt_ms < 300 && packet_loss_rate < 0.05f) {
        return NetworkCondition::FAIR;
    } else if (rtt_ms < 1000 && packet_loss_rate < 0.20f) {
        return NetworkCondition::POOR;
    } else {
        return NetworkCondition::CRITICAL;
    }
}

PeerConnectionStats PeerReconnectPolicy::get_peer_stats(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_stats_.find(peer_id);
    if (it != peer_stats_.end()) {
        return it->second;
    }
    
    return {};
}

std::vector<std::string> PeerReconnectPolicy::get_tracked_peers() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    std::vector<std::string> peers;
    for (const auto& pair : peer_stats_) {
        peers.push_back(pair.first);
    }
    return peers;
}

void PeerReconnectPolicy::reset_peer_stats(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_stats_.find(peer_id);
    if (it != peer_stats_.end()) {
        PeerConnectionStats& stats = it->second;
        stats.consecutive_failures = 0;
        stats.retry_count_current_cycle = 0;
        stats.backoff_level = 1;
        stats.next_retry_time_ms = 0;
        stats.average_rtt_ms = 100;
        
        nativeLog("PeerReconnectPolicy: Reset stats for peer " + peer_id);
    }
}

float PeerReconnectPolicy::estimate_battery_drain(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    // Rough estimate: 1-3% per connection attempt depending on method
    // TCP scan: 2-3% (requires network scan)
    // UDP probe: 1-2% (quick)
    // Relay: 3-5% (uses more bandwidth)
    
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) return 3.0f;
    
    const PeerConnectionStats& stats = it->second;
    
    float drain = 0.0f;
    if (stats.last_used_method == "Relay") {
        drain = 4.0f;
    } else if (stats.last_used_method == "TCP") {
        drain = 2.5f;
    } else if (stats.last_used_method == "UDP") {
        drain = 1.5f;
    } else {
        drain = 2.0f;
    }
    
    // Increase drain estimate based on consecutive failures (scanning longer)
    drain += (stats.consecutive_failures * 0.5f);
    
    return drain;
}

bool PeerReconnectPolicy::is_reconnect_battery_safe(const std::string& peer_id) {
    if (is_charging_) {
        return true;  // Always safe if charging
    }
    
    // Critical battery: very restrictive
    if (current_battery_level_ == BatteryLevel::CRITICAL) {
        return battery_percent_ > 5;  // Only if above 5%
    }
    
    // Low battery: restrictive
    if (current_battery_level_ == BatteryLevel::LOW) {
        float drain = estimate_battery_drain(peer_id);
        return battery_percent_ > (drain * 2);  // Need at least 2x drain capacity
    }
    
    // Normal/High battery: not restrictive
    return true;
}

uint32_t PeerReconnectPolicy::get_keepalive_interval_seconds() const {
    // Keepalive intervals based on battery and network
    // WiFi + Good Battery: 5-10s (aggressive)
    // WiFi + Low Battery: 15-20s
    // Mobile + Good Battery: 10-15s
    // Mobile + Low Battery: 30-45s
    // Critical Battery: 60-120s (very conservative)
    
    if (current_battery_level_ == BatteryLevel::CRITICAL) {
        return 120;
    }
    
    if (current_battery_level_ == BatteryLevel::LOW) {
        return is_wifi_ ? 20 : 45;
    }
    
    if (current_battery_level_ == BatteryLevel::NORMAL) {
        return is_wifi_ ? 10 : 15;
    }
    
    // HIGH battery
    return is_wifi_ ? 5 : 10;
}

std::string PeerReconnectPolicy::get_status_json() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    std::stringstream ss;
    ss << "{\"battery\":" << battery_percent_ << ",\"network\":\"" 
       << (is_wifi_ ? "WiFi" : "Mobile") << "\",\"peers\":[";
    
    bool first = true;
    for (const auto& pair : peer_stats_) {
        if (!first) ss << ",";
        
        const PeerConnectionStats& stats = pair.second;
        ss << "{\"id\":\"" << stats.peer_id << "\",\"connected\":" 
           << (stats.connected ? "true" : "false")
           << ",\"failures\":" << stats.consecutive_failures
           << ",\"rtt_ms\":" << stats.average_rtt_ms
           << ",\"condition\":" << static_cast<int>(stats.current_condition) << "}";
        
        first = false;
    }
    
    ss << "]}";
    return ss.str();
}

void PeerReconnectPolicy::shutdown() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peer_stats_.clear();
    nativeLog("PeerReconnectPolicy: Shutdown complete");
}

// ============ Private Methods ============

PeerReconnectPolicy::RetryConfig PeerReconnectPolicy::get_retry_config_for_battery() {
    RetryConfig config;
    
    if (use_aggressive_reconnect_) {
        // WiFi + Good Battery: Aggressive retry every 500ms, 1s, 2s, 4s, 8s
        config.initial_backoff_ms = 500;
        config.max_backoff_ms = 8000;
        config.max_retries = 5;
        config.aggressive_mode = true;
        config.battery_drain_threshold = 0.05f;  // 5% per connection
    } else if (use_battery_aware_mode_) {
        // Mobile + Low Battery: Conservative retry 5s, 15s, 60s, 5min
        config.initial_backoff_ms = 5000;
        config.max_backoff_ms = 300000;
        config.max_retries = 3;
        config.aggressive_mode = false;
        config.battery_drain_threshold = 0.01f;  // 1% per connection
    } else {
        // Balanced: Normal retry 1s, 2s, 5s, 15s, 30s, 1min
        config.initial_backoff_ms = 1000;
        config.max_backoff_ms = 60000;
        config.max_retries = 6;
        config.aggressive_mode = false;
        config.battery_drain_threshold = 0.03f;  // 3% per connection
    }
    
    // Adjust for network condition
    if (current_network_condition_ >= NetworkCondition::POOR) {
        // Poor/Critical network: increase retry times
        config.initial_backoff_ms *= 2;
        config.max_backoff_ms *= 2;
        config.max_retries += 2;
    }
    
    return config;
}

uint32_t PeerReconnectPolicy::calculate_backoff_with_jitter(int backoff_level) {
    RetryConfig config = get_retry_config_for_battery();
    
    // Calculate base backoff: initial * 2^level
    uint32_t base_backoff = config.initial_backoff_ms;
    for (int i = 0; i < backoff_level; i++) {
        base_backoff = std::min(base_backoff * 2, config.max_backoff_ms);
    }
    
    // Add random jitter (±20%)
    std::uniform_real_distribution<float> dist(0.8f, 1.2f);
    float jitter = dist(g_random_engine);
    
    uint32_t result = static_cast<uint32_t>(base_backoff * jitter);
    return std::min(result, config.max_backoff_ms);
}

float PeerReconnectPolicy::calculate_peer_priority(const PeerConnectionStats& stats) {
    float priority = 0.0f;
    
    // Higher priority = more urgent to reconnect
    // Factor 1: Time since last success (longer = more urgent)
    if (stats.last_successful_connection_ms > 0) {
        priority += (stats.last_successful_connection_ms / 1000.0f) * 0.3f;
    }
    
    // Factor 2: Network condition (poor condition = higher priority)
    priority += static_cast<float>(stats.current_condition) * 0.2f;
    
    // Factor 3: Previous success rate (had good connection = higher priority)
    if (stats.successful_connections > 0) {
        float success_rate = static_cast<float>(stats.successful_connections) / 
                           (stats.successful_connections + stats.total_failures);
        priority += success_rate * 0.3f;
    }
    
    // Factor 4: Time since last attempt (prevent thrashing)
    if (stats.last_connection_attempt_ms > 0) {
        priority -= (stats.last_connection_attempt_ms / 5000.0f) * 0.2f;
    }
    
    return priority;
}
