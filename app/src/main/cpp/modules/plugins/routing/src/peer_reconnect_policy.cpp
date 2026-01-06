#include "peer_reconnect_policy.h"
#include "logger.h"
#include "config_manager.h"
#include <algorithm>
#include <cmath>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace {
uint64_t steady_now_ms() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}
}

PeerReconnectPolicy::PeerReconnectPolicy()
    : random_engine_(std::chrono::steady_clock::now().time_since_epoch().count()) {
}

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
    
    // Get battery thresholds from config
    int level_critical = ConfigManager::getInstance().getBatteryLevelCritical();
    int level_low = ConfigManager::getInstance().getBatteryLevelLow();
    int level_medium = ConfigManager::getInstance().getBatteryLevelMedium();
    
    // Determine battery level
    if (battery_percent_ < level_critical) {
        current_battery_level_ = BatteryLevel::CRITICAL;
    } else if (battery_percent_ < level_low) {
        current_battery_level_ = BatteryLevel::LOW;
    } else if (battery_percent_ < level_medium) {
        current_battery_level_ = BatteryLevel::NORMAL;
    } else {
        current_battery_level_ = BatteryLevel::HIGH;
    }
    
    // Determine initial network condition
    current_network_condition_ = NetworkCondition::EXCELLENT;

    // Allow config.json to select a mode unless a runtime override was applied.
    if (!reconnect_mode_overridden_) {
        reconnect_mode_ = parse_reconnect_mode_string_(ConfigManager::getInstance().getReconnectPolicyMode());
    }
    recompute_effective_mode_flags_locked_();

    nativeLog("PeerReconnectPolicy: Initialized, battery=" + std::to_string(battery_percent_) +
              "%, wifi=" + std::to_string(is_wifi_) +
              ", mode=" + std::to_string(static_cast<int>(reconnect_mode_)) +
              ", aggressive=" + std::to_string(use_aggressive_reconnect_));
}

void PeerReconnectPolicy::set_reconnect_mode(ReconnectMode mode) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    reconnect_mode_ = mode;
    reconnect_mode_overridden_ = true;
    recompute_effective_mode_flags_locked_();
    nativeLog("PeerReconnectPolicy: Mode override set to " + std::to_string(static_cast<int>(reconnect_mode_)));
}

void PeerReconnectPolicy::set_reconnect_mode_string(const std::string& mode) {
    set_reconnect_mode(parse_reconnect_mode_string_(mode));
}

ReconnectMode PeerReconnectPolicy::get_reconnect_mode() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return reconnect_mode_;
}

uint32_t PeerReconnectPolicy::get_reconnect_attempt_interval_ms() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    if (!is_network_available_) {
        return 60000;
    }

    switch (reconnect_mode_) {
        case ReconnectMode::AGGRESSIVE:
            return 250;
        case ReconnectMode::POWER_SAVER:
            return 5000;
        case ReconnectMode::BALANCED:
            return 1000;
        case ReconnectMode::AUTO:
        default:
            if (use_aggressive_reconnect_) return 250;
            if (use_battery_aware_mode_) return 5000;
            return 1000;
    }
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
        stats.circuit_breaker_until_ms = 0;
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
	const uint64_t now_ms = steady_now_ms();
    stats.connected = true;
    stats.attempting_reconnect = false;
    stats.consecutive_failures = 0;
    stats.retry_count_current_cycle = 0;
    stats.backoff_level = 1;
    stats.successful_connections++;
    stats.last_successful_connection_ms = now_ms;
    stats.last_connection_attempt_ms = now_ms;
    stats.next_retry_time_ms = 0;
    stats.circuit_breaker_until_ms = 0;
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
	const uint64_t now_ms = steady_now_ms();
    stats.connected = false;
    stats.consecutive_failures++;
    stats.total_failures++;
    stats.packet_loss_rate = packet_loss_rate;
    stats.attempting_reconnect = true;
    stats.last_connection_attempt_ms = now_ms;
    stats.current_condition = detect_network_condition(stats.average_rtt_ms, packet_loss_rate);
    
    RetryConfig config = get_retry_config_for_battery();
    stats.retry_count_current_cycle++;

    // Exponential backoff level (keep historical field bounded)
    const int exponent = std::min(std::max(stats.consecutive_failures - 1, 0), 10);
    stats.backoff_level = 1 << std::min(exponent, 4);  // 1..16

    // Calculate next retry moment with jitter
    const uint32_t backoff_delay_ms = calculate_backoff_with_jitter(exponent);
    stats.next_retry_time_ms = now_ms + backoff_delay_ms;

    if (stats.consecutive_failures > config.max_retries) {
        // Open the circuit breaker for a bounded cooldown (at least max_backoff). This avoids
        // permanently disabling reconnect after a peer restarts or comes back later.
        const uint32_t cooldown_ms = std::max<uint32_t>(config.max_backoff_ms, backoff_delay_ms);
        stats.circuit_breaker_until_ms = now_ms + cooldown_ms;
        nativeLog("PeerReconnectPolicy: Connection failed for " + peer_id + " (" + std::to_string(stats.consecutive_failures) + " failures) - circuit breaker open (cooldown=" + std::to_string(cooldown_ms) + "ms)");
    }

    nativeLog("PeerReconnectPolicy: Connection failure - " + peer_id + " via " + attempted_method +
            " (failures=" + std::to_string(stats.consecutive_failures) +
            ", backoff_level=" + std::to_string(stats.backoff_level) +
            ", next_retry_in=" + std::to_string(backoff_delay_ms) + "ms)");
}

bool PeerReconnectPolicy::should_reconnect_now(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_stats_.find(peer_id);
    if (it == peer_stats_.end()) return false;
    
    PeerConnectionStats& stats = it->second;
    const uint64_t now_ms = steady_now_ms();
    const RetryConfig config = get_retry_config_for_battery();
    
    // Don't reconnect if already connected
    if (stats.connected) return false;

    // Circuit breaker (time-bounded)
    if (stats.consecutive_failures > config.max_retries) {
        if (stats.circuit_breaker_until_ms != 0 && now_ms >= stats.circuit_breaker_until_ms) {
            // Cooldown elapsed: close breaker and allow future reconnect attempts.
            stats.circuit_breaker_until_ms = 0;
            // Keep failures bounded (the caller still uses per-peer backoff).
            stats.consecutive_failures = std::min(stats.consecutive_failures, config.max_retries);
            stats.next_retry_time_ms = 0;
            nativeLog("PeerReconnectPolicy: Circuit breaker cooldown elapsed for " + peer_id + "; resuming retries");
        } else {
            return false;
        }
    }
    
    // Check if enough time has passed
    if (stats.next_retry_time_ms != 0 && now_ms < stats.next_retry_time_ms) {
        return false;
    }
    
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
    
	const uint64_t now_ms = steady_now_ms();
	const RetryConfig config = get_retry_config_for_battery();
    
    for (auto& pair : peer_stats_) {
        PeerConnectionStats& stats = pair.second;
        
        // Skip connected peers
        if (stats.connected) continue;

		// Circuit breaker
		if (stats.consecutive_failures > config.max_retries) continue;
        
        // Skip if not ready to retry yet
		if (stats.next_retry_time_ms != 0 && now_ms < stats.next_retry_time_ms) continue;
        
        // Calculate priority (higher = more urgent)
		float priority = calculate_peer_priority(stats, now_ms);
        
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
	const uint64_t now_ms = steady_now_ms();

    // Determine retry strategy, keeping it consistent with should_reconnect_now().
    // This function is used for logging/debugging and scheduling decisions, so it must
    // reflect global gating (connected/battery/network) as well as per-peer backoff.
    RetryConfig config = get_retry_config_for_battery();

    // If already connected, do not suggest retries.
    if (stats.connected) {
        strategy.should_retry = false;
        strategy.backoff_ms = 0;
        strategy.methods.clear();
        nativeLog("PeerReconnectPolicy: Retry strategy for " + peer_id + " - backoff=" + std::to_string(strategy.backoff_ms) + "ms, should_retry=" + (strategy.should_retry ? "true" : "false"));
        return strategy;
    }

    // Circuit breaker (time-bounded): do not suggest retries until cooldown elapses.
    if (stats.consecutive_failures > config.max_retries) {
        if (stats.circuit_breaker_until_ms != 0 && now_ms < stats.circuit_breaker_until_ms) {
            strategy.should_retry = false;
            const uint64_t remaining = stats.circuit_breaker_until_ms - now_ms;
            strategy.backoff_ms = static_cast<uint32_t>(std::min<uint64_t>(remaining, UINT32_MAX));
            nativeLog("PeerReconnectPolicy: Retry strategy for " + peer_id + " - backoff=" + std::to_string(strategy.backoff_ms) + "ms, should_retry=" + (strategy.should_retry ? "true" : "false"));
            return strategy;
        }
        // If cooldown elapsed, allow normal scheduling.
    }

    // Global gating.
    if (!is_network_available_) {
        strategy.should_retry = false;
        strategy.backoff_ms = 60000;
        nativeLog("PeerReconnectPolicy: Retry strategy for " + peer_id + " - backoff=" + std::to_string(strategy.backoff_ms) + "ms, should_retry=" + (strategy.should_retry ? "true" : "false"));
        return strategy;
    }
    if (!is_reconnect_battery_safe(peer_id)) {
        strategy.should_retry = false;
        strategy.backoff_ms = 60000;
        nativeLog("PeerReconnectPolicy: Retry strategy for " + peer_id + " - backoff=" + std::to_string(strategy.backoff_ms) + "ms, should_retry=" + (strategy.should_retry ? "true" : "false"));
        return strategy;
    }

    // Per-peer retry budget.
    strategy.should_retry = (stats.consecutive_failures <= config.max_retries);

    // Backoff until the next allowed retry time.
    if (stats.next_retry_time_ms == 0 || now_ms >= stats.next_retry_time_ms) {
        strategy.backoff_ms = 0;
    } else {
        strategy.backoff_ms = static_cast<uint32_t>(std::min<uint64_t>(stats.next_retry_time_ms - now_ms, UINT32_MAX));
    }
    
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

    // Battery thresholds are config-driven (keep consistent with initialize()).
    const int level_critical = ConfigManager::getInstance().getBatteryLevelCritical();
    const int level_low = ConfigManager::getInstance().getBatteryLevelLow();
    const int level_medium = ConfigManager::getInstance().getBatteryLevelMedium();

    if (battery_percent_ < level_critical) {
        current_battery_level_ = BatteryLevel::CRITICAL;
    } else if (battery_percent_ < level_low) {
        current_battery_level_ = BatteryLevel::LOW;
    } else if (battery_percent_ < level_medium) {
        current_battery_level_ = BatteryLevel::NORMAL;
    } else {
        current_battery_level_ = BatteryLevel::HIGH;
    }
    
    recompute_effective_mode_flags_locked_();

    nativeLog("PeerReconnectPolicy: Battery update - " + std::to_string(percent) + "% (" +
              std::string(is_charging_ ? "charging" : "on_battery") + "), mode=" +
              std::to_string(static_cast<int>(reconnect_mode_)) + ", aggressive=" +
              (use_aggressive_reconnect_ ? "true" : "false"));
}

void PeerReconnectPolicy::set_network_type(bool is_wifi, bool is_available) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    is_wifi_ = is_wifi;
    is_network_available_ = is_available;

    // Keep a coarse global network condition so retry configs can adjust even
    // before per-peer RTT/loss statistics exist.
    if (!is_network_available_) {
        current_network_condition_ = NetworkCondition::OFFLINE;
    } else {
        current_network_condition_ = is_wifi_ ? NetworkCondition::GOOD : NetworkCondition::FAIR;
    }
    
    recompute_effective_mode_flags_locked_();

    nativeLog("PeerReconnectPolicy: Network update - " + std::string(is_wifi ? "WiFi" : "Mobile") +
              " (" + std::string(is_available ? "available" : "unavailable") + "), mode=" +
              std::to_string(static_cast<int>(reconnect_mode_)) + ", aggressive=" +
              (use_aggressive_reconnect_ ? "true" : "false"));
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
        stats.circuit_breaker_until_ms = 0;
        stats.last_connection_attempt_ms = 0;
        stats.last_successful_connection_ms = 0;
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
    std::lock_guard<std::mutex> lock(peers_mutex_);
    // Keepalive intervals based on battery and network
    // WiFi + Good Battery: 5-10s (aggressive)
    // WiFi + Low Battery: 15-20s
    // Mobile + Good Battery: 10-15s
    // Mobile + Low Battery: 30-45s
    // Critical Battery: 60-120s (very conservative)
    
    uint32_t base = 10;
    if (current_battery_level_ == BatteryLevel::CRITICAL) {
        base = 120;
    } else if (current_battery_level_ == BatteryLevel::LOW) {
        base = is_wifi_ ? 20 : 45;
    } else if (current_battery_level_ == BatteryLevel::NORMAL) {
        base = is_wifi_ ? 10 : 15;
    } else {
        // HIGH battery
        base = is_wifi_ ? 5 : 10;
    }

    // Mode-based adjustment (bounded).
    switch (reconnect_mode_) {
        case ReconnectMode::AGGRESSIVE:
            return std::max<uint32_t>(3, base / 2);
        case ReconnectMode::POWER_SAVER:
            return std::min<uint32_t>(300, base * 3);
        case ReconnectMode::BALANCED:
        case ReconnectMode::AUTO:
        default:
            return base;
    }
}

std::string PeerReconnectPolicy::get_status_json() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    const uint64_t now_ms = steady_now_ms();
    
    std::stringstream ss;
    ss << "{\"battery\":" << battery_percent_ << ",\"network\":\"" 
       << (is_wifi_ ? "WiFi" : "Mobile") << "\",\"mode\":"
       << static_cast<int>(reconnect_mode_) << ",\"peers\":[";
    
    bool first = true;
    for (const auto& pair : peer_stats_) {
        if (!first) ss << ",";
        
        const PeerConnectionStats& stats = pair.second;
        const uint64_t breaker_remaining_ms =
            (stats.circuit_breaker_until_ms != 0 && now_ms < stats.circuit_breaker_until_ms)
                ? (stats.circuit_breaker_until_ms - now_ms)
                : 0;
        ss << "{\"id\":\"" << stats.peer_id << "\",\"connected\":" 
           << (stats.connected ? "true" : "false")
           << ",\"failures\":" << stats.consecutive_failures
           << ",\"breaker_ms\":" << breaker_remaining_ms
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

    if (reconnect_mode_ == ReconnectMode::AGGRESSIVE) {
        // Reliability-first.
        config.initial_backoff_ms = 250;
        config.max_backoff_ms = 8000;
        config.max_retries = 8;
        config.aggressive_mode = true;
        config.battery_drain_threshold = 0.07f;
    } else if (reconnect_mode_ == ReconnectMode::POWER_SAVER) {
        // Mobile-first / battery-first.
        config.initial_backoff_ms = 8000;
        config.max_backoff_ms = 600000; // 10 min
        config.max_retries = 3;
        config.aggressive_mode = false;
        config.battery_drain_threshold = 0.01f;
    } else if (use_aggressive_reconnect_) {
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
    float jitter = dist(random_engine_);
    
    uint32_t result = static_cast<uint32_t>(base_backoff * jitter);
    return std::min(result, config.max_backoff_ms);
}

float PeerReconnectPolicy::calculate_peer_priority(const PeerConnectionStats& stats, uint64_t now_ms) {
    float priority = 0.0f;
    
    // Higher priority = more urgent to reconnect
    // Factor 1: Time since last success (longer = more urgent)
	if (stats.last_successful_connection_ms > 0 && now_ms >= stats.last_successful_connection_ms) {
		priority += (static_cast<float>(now_ms - stats.last_successful_connection_ms) / 1000.0f) * 0.3f;
	} else if (stats.last_successful_connection_ms == 0) {
		priority += 10.0f;  // Never connected: give a small boost
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
	if (stats.last_connection_attempt_ms > 0 && now_ms >= stats.last_connection_attempt_ms) {
		priority -= (static_cast<float>(now_ms - stats.last_connection_attempt_ms) / 5000.0f) * 0.2f;
	}
    
    return priority;
}

ReconnectMode PeerReconnectPolicy::parse_reconnect_mode_string_(std::string mode) {
    mode = to_lower_ascii(std::move(mode));
    if (mode == "aggressive" || mode == "reliability" || mode == "reliable" || mode == "fast") {
        return ReconnectMode::AGGRESSIVE;
    }
    if (mode == "power_saver" || mode == "powersaver" || mode == "eco" || mode == "mobile") {
        return ReconnectMode::POWER_SAVER;
    }
    if (mode == "balanced" || mode == "normal") {
        return ReconnectMode::BALANCED;
    }
    return ReconnectMode::AUTO;
}

void PeerReconnectPolicy::recompute_effective_mode_flags_locked_() {
    // Battery thresholds are config-driven.
    const int level_medium = ConfigManager::getInstance().getBatteryLevelMedium();

    switch (reconnect_mode_) {
        case ReconnectMode::AGGRESSIVE:
            use_aggressive_reconnect_ = true;
            use_battery_aware_mode_ = false;
            break;
        case ReconnectMode::POWER_SAVER:
            use_aggressive_reconnect_ = false;
            use_battery_aware_mode_ = true;
            break;
        case ReconnectMode::BALANCED:
            use_aggressive_reconnect_ = false;
            use_battery_aware_mode_ = false;
            break;
        case ReconnectMode::AUTO:
        default:
            use_aggressive_reconnect_ = is_wifi_ && (battery_percent_ > level_medium || is_charging_);
            use_battery_aware_mode_ = !is_wifi_ && battery_percent_ < 30;
            break;
    }
}
