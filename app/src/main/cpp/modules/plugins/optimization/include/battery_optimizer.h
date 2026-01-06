#ifndef BATTERY_OPTIMIZER_H
#define BATTERY_OPTIMIZER_H

#include <string>
#include <chrono>
#include <vector>
#include <memory>

// Battery optimization strategies for Android P2P
// Target: Minimize CPU/radio on-time, reduce wakeups

class BatteryOptimizer {
public:
    enum class NetworkType {
        WIFI,           // Free energy, aggressive sync
        CELLULAR,       // Expensive, minimize sync
        UNKNOWN
    };

    enum class OptimizationLevel {
        AGGRESSIVE,     // Max battery savings (might increase latency)
        BALANCED,       // Default: balanced perf/battery
        PERFORMANCE     // Min battery savings, max responsiveness
    };

    struct OptimizationConfig {
        OptimizationLevel level;
        NetworkType network_type;
        
        // Keepalive settings
        int ping_interval_sec;              // How often to ping peers
        int peer_timeout_sec;               // Disconnect if no response
        
        // Message batching
        int batch_delay_ms;                 // Wait before sending batch
        int batch_max_messages;             // Max messages per batch
        
        // Session management
        bool enable_session_resumption;     // Cache session keys
        bool enable_selective_encryption;   // Only encrypt on cellular
        bool wifi_only_mode;                // Only sync on WiFi
        
        // Buffer optimization
        bool enable_buffer_pooling;         // Reuse allocations
        int buffer_pool_size;               // Pre-allocated buffers
    };

    BatteryOptimizer();
    ~BatteryOptimizer();

    // Set optimization profile
    void set_optimization_level(OptimizationLevel level);
    
    // Detect current network type
    void set_network_type(NetworkType type);
    
    // Get optimized configuration
    OptimizationConfig get_config() const { return m_config; }

    // Adaptive settings based on network
    int get_ping_interval() const;
    int get_batch_delay() const;
    bool should_sync_now() const;
    bool is_wifi_available() const { return m_network_type == NetworkType::WIFI; }

private:
    OptimizationConfig m_config;
    NetworkType m_network_type;
    std::chrono::steady_clock::time_point m_last_sync;
};

#endif // BATTERY_OPTIMIZER_H
