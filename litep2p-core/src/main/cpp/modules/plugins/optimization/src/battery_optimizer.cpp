#include "battery_optimizer.h"
#include "logger.h"

BatteryOptimizer::BatteryOptimizer()
    : m_network_type(NetworkType::UNKNOWN),
      m_last_sync(std::chrono::steady_clock::now()) {
    
    // Default: BALANCED on WIFI
    m_config.level = OptimizationLevel::BALANCED;
    m_config.network_type = NetworkType::WIFI;
    
    // BALANCED profile settings
    m_config.ping_interval_sec = 10;           // Ping every 10s (down from ~1s)
    m_config.peer_timeout_sec = 30;            // Disconnect after 30s no response
    m_config.batch_delay_ms = 50;              // Wait 50ms for message batching
    m_config.batch_max_messages = 10;          // Batch up to 10 messages
    m_config.enable_session_resumption = true;
    m_config.enable_selective_encryption = true;
    m_config.wifi_only_mode = false;
    m_config.enable_buffer_pooling = true;
    m_config.buffer_pool_size = 32;
    
    nativeLog("BatteryOptimizer: Initialized with BALANCED profile");
}

BatteryOptimizer::~BatteryOptimizer() = default;

void BatteryOptimizer::set_optimization_level(OptimizationLevel level) {
    m_config.level = level;
    
    switch (level) {
        case OptimizationLevel::AGGRESSIVE:
            // Aggressive battery saving - prioritize battery over responsiveness
            m_config.ping_interval_sec = 30;           // Ping every 30s
            m_config.peer_timeout_sec = 60;            // Longer timeout
            m_config.batch_delay_ms = 200;             // Wait longer for batching
            m_config.batch_max_messages = 50;
            m_config.wifi_only_mode = true;            // Only sync on WiFi
            nativeLog("BatteryOptimizer: AGGRESSIVE profile - max battery savings");
            break;
            
        case OptimizationLevel::BALANCED:
            // Default balanced profile
            m_config.ping_interval_sec = 10;
            m_config.peer_timeout_sec = 30;
            m_config.batch_delay_ms = 50;
            m_config.batch_max_messages = 10;
            m_config.wifi_only_mode = false;
            nativeLog("BatteryOptimizer: BALANCED profile - normal operation");
            break;
            
        case OptimizationLevel::PERFORMANCE:
            // Minimal battery optimization - low latency
            m_config.ping_interval_sec = 3;            // Ping every 3s
            m_config.peer_timeout_sec = 15;            // Quick timeout
            m_config.batch_delay_ms = 5;               // Minimal batching delay
            m_config.batch_max_messages = 2;
            m_config.wifi_only_mode = false;
            nativeLog("BatteryOptimizer: PERFORMANCE profile - responsiveness first");
            break;
    }
}

void BatteryOptimizer::set_network_type(NetworkType type) {
    m_network_type = type;
    
    switch (type) {
        case NetworkType::WIFI:
            nativeLog("BatteryOptimizer: WiFi detected - aggressive sync");
            // WiFi is free energy - allow more aggressive activity
            if (m_config.level == OptimizationLevel::BALANCED) {
                m_config.ping_interval_sec = 5;       // More frequent pings
                m_config.batch_delay_ms = 25;         // Less batching delay
            }
            break;
            
        case NetworkType::CELLULAR:
            nativeLog("BatteryOptimizer: Cellular detected - conservative sync");
            // Cellular is expensive - minimize activity
            if (m_config.level == OptimizationLevel::BALANCED) {
                m_config.ping_interval_sec = 30;      // Less frequent pings
                m_config.batch_delay_ms = 200;        // More batching delay
                m_config.enable_selective_encryption = true;
            }
            break;
            
        case NetworkType::UNKNOWN:
            nativeLog("BatteryOptimizer: Network type unknown - using balanced");
            break;
    }
    
    m_config.network_type = type;
}

int BatteryOptimizer::get_ping_interval() const {
    // If WiFi only mode enabled and not on WiFi, don't ping at all
    if (m_config.wifi_only_mode && m_network_type != NetworkType::WIFI) {
        return 999;  // Signal "don't ping"
    }
    return m_config.ping_interval_sec;
}

int BatteryOptimizer::get_batch_delay() const {
    // On cellular, batch more aggressively
    if (m_network_type == NetworkType::CELLULAR) {
        return std::max(m_config.batch_delay_ms, 100);  // At least 100ms on cellular
    }
    return m_config.batch_delay_ms;
}

bool BatteryOptimizer::should_sync_now() const {
    // Check if enough time has passed since last sync
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_last_sync
    ).count();
    
    int interval = get_ping_interval();
    return elapsed >= interval;
}
