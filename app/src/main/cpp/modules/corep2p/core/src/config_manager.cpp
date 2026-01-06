#include "config_manager.h"
#include "logger.h"
#include <fstream>
#include <iterator>
#include <sstream>
#include <unistd.h>

namespace {

template <typename T>
T jsonGetOr(const json& root, std::initializer_list<const char*> path, const T& fallback) {
    const json* cur = &root;
    for (const char* key : path) {
        if (!cur->is_object()) {
            return fallback;
        }
        auto it = cur->find(key);
        if (it == cur->end()) {
            return fallback;
        }
        cur = &(*it);
    }
    try {
        return cur->get<T>();
    } catch (...) {
        return fallback;
    }
}

const json* jsonPtr(const json& root, std::initializer_list<const char*> path) {
    const json* cur = &root;
    for (const char* key : path) {
        if (!cur->is_object()) {
            return nullptr;
        }
        auto it = cur->find(key);
        if (it == cur->end()) {
            return nullptr;
        }
        cur = &(*it);
    }
    return cur;
}

} // namespace

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

ConfigManager::ConfigManager() {
}

bool ConfigManager::loadConfig(const std::string& config_path) {
    try {
        std::ifstream config_file(config_path);
        if (!config_file.is_open()) {
            char cwd[1024];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                LOG_WARN("ConfigManager: Failed to open config file: " + config_path + " (CWD: " + std::string(cwd) + ")");
            } else {
                LOG_WARN("ConfigManager: Failed to open config file: " + config_path);
            }
            return false;
        }

        std::string config_content((std::istreambuf_iterator<char>(config_file)),
                                   std::istreambuf_iterator<char>());

        json parsed = json::parse(config_content, nullptr, true, true);

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_config = std::move(parsed);
            m_config_path = config_path;
        }

        LOG_INFO("ConfigManager: Configuration loaded from: " + config_path);
        return true;
    } catch (const std::exception& e) {
        LOG_WARN(std::string("ConfigManager: Config loading failed: ") + e.what());
        return false;
    }
}

bool ConfigManager::saveConfig(const std::string& config_path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::ofstream out(config_path);
    if (!out.is_open()) {
        LOG_WARN("ConfigManager: Failed to open config file for writing: " + config_path);
        return false;
    }

    out << m_config.dump(4);
    if (!out.good()) {
        LOG_WARN("ConfigManager: Failed to write configuration to disk: " + config_path);
        return false;
    }

    m_config_path = config_path;
    return true;
}

bool ConfigManager::saveConfig() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_config_path.empty()) {
        LOG_WARN("ConfigManager: No configuration path recorded; cannot persist");
        return false;
    }

    std::ofstream out(m_config_path);
    if (!out.is_open()) {
        LOG_WARN("ConfigManager: Failed to open config file for writing: " + m_config_path);
        return false;
    }

    out << m_config.dump(4);
    if (!out.good()) {
        LOG_WARN("ConfigManager: Failed to write configuration to disk: " + m_config_path);
        return false;
    }

    return true;
}

std::string ConfigManager::getDefaultProtocol() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "TCP";
    return jsonGetOr<std::string>(m_config, {"communication", "default_protocol"}, "UDP");
}

bool ConfigManager::isUDPEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"communication", "udp", "enabled"}, true);
}

bool ConfigManager::isTCPEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"communication", "tcp", "enabled"}, true);
}

int ConfigManager::getUDPPort() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 30001;
    return jsonGetOr<int>(m_config, {"communication", "udp", "port"}, 30001);
}

int ConfigManager::getTCPPort() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 30001;
    return jsonGetOr<int>(m_config, {"communication", "tcp", "port"}, 30001);
}

int ConfigManager::getUDPBufferSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 65535;
    return jsonGetOr<int>(m_config, {"communication", "udp", "buffer_size"}, 65535);
}

int ConfigManager::getTCPBufferSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 4096;
    return jsonGetOr<int>(m_config, {"communication", "tcp", "buffer_size"}, 4096);
}

int ConfigManager::getUDPTimeout() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 5000;
    return jsonGetOr<int>(m_config, {"communication", "udp", "timeout_ms"}, 5000);
}

bool ConfigManager::isTCPNoDelayEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"communication", "tcp", "nodelay"}, true);
}

int ConfigManager::getTCPConnectTimeout() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 5;
    return jsonGetOr<int>(m_config, {"communication", "tcp", "connect_timeout_sec"}, 5);
}

std::string ConfigManager::getReconnectPolicyMode() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "auto";
    return jsonGetOr<std::string>(m_config, {"reconnect_policy", "mode"}, "auto");
}

bool ConfigManager::isNoiseNKEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"security", "noise_nk_protocol", "enabled"}, true);
}

bool ConfigManager::isNoiseNKMandatory() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"security", "noise_nk_protocol", "mandatory"}, true);
}

std::string ConfigManager::getKeyStorePath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "keystore";
    return jsonGetOr<std::string>(m_config, {"security", "noise_nk_protocol", "key_store_path"}, "keystore");
}

int ConfigManager::getKeyRotationInterval() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 24;
    return jsonGetOr<int>(m_config, {"security", "noise_nk_protocol", "key_rotation_interval_hours"}, 24);
}

bool ConfigManager::isBatchManagerEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"batch_connection_manager", "enabled"}, true);
}

int ConfigManager::getMaxPeersPerBatch() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 10;
    return jsonGetOr<int>(m_config, {"batch_connection_manager", "max_peers_per_batch"}, 10);
}

int ConfigManager::getMaxBatches() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 5;
    return jsonGetOr<int>(m_config, {"batch_connection_manager", "max_batches"}, 5);
}

int ConfigManager::getBatchDelayMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 100;
    return jsonGetOr<int>(m_config, {"batch_connection_manager", "batch_delay_ms"}, 100);
}

int ConfigManager::getBatchMaxMessages() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 50;
    return jsonGetOr<int>(m_config, {"batch_connection_manager", "batch_max_messages"}, 50);
}

int ConfigManager::getCleanupInterval() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 60000;
    return jsonGetOr<int>(m_config, {"batch_connection_manager", "cleanup_interval_ms"}, 60000);
}

int ConfigManager::getNumWorkers() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 4;
    return jsonGetOr<int>(m_config, {"session_manager", "num_workers"}, 4);
}

int ConfigManager::getCacheSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 100;
    return jsonGetOr<int>(m_config, {"session_manager", "cache_size"}, 100);
}

int ConfigManager::getSessionCacheLifetimeSec() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 3600;
    return jsonGetOr<int>(m_config, {"session_manager", "cache_lifetime_sec"}, 3600);
}

int ConfigManager::getSessionTimeout() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 30000;
    return jsonGetOr<int>(m_config, {"session_manager", "session_timeout_ms"}, 30000);
}

int ConfigManager::getMaxConcurrentSessions() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 100;
    return jsonGetOr<int>(m_config, {"session_manager", "max_concurrent_sessions"}, 100);
}

int ConfigManager::getHeartbeatIntervalSec() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 10;
    return jsonGetOr<int>(m_config, {"peer_management", "heartbeat_interval_sec"}, 10);
}

int ConfigManager::getPeerExpirationTimeoutMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 30000;
    return jsonGetOr<int>(m_config, {"peer_management", "peer_expiration_timeout_ms"}, 30000);
}

int ConfigManager::getEventQueueWaitTimeoutMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 100;
    return jsonGetOr<int>(m_config, {"event_manager", "queue_wait_timeout_ms"}, 100);
}

int ConfigManager::getTimerTickIntervalMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 500;
    return jsonGetOr<int>(m_config, {"event_manager", "timer_tick_interval_ms"}, 500);
}

int ConfigManager::getEventThreadSleepMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 100;
    return jsonGetOr<int>(m_config, {"event_manager", "thread_sleep_ms"}, 100);
}

bool ConfigManager::isBatteryOptimizerEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"battery_optimizer", "enabled"}, true);
}

bool ConfigManager::isAggressiveMode() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return false;
    return jsonGetOr<bool>(m_config, {"battery_optimizer", "aggressive_mode"}, false);
}

int ConfigManager::getPowerSaveThreshold() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 20;
    return jsonGetOr<int>(m_config, {"battery_optimizer", "power_save_threshold"}, 20);
}

int ConfigManager::getBatteryLevelCritical() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 10;
    return jsonGetOr<int>(m_config, {"battery_optimizer", "level_critical"}, 10);
}

int ConfigManager::getBatteryLevelLow() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 20;
    return jsonGetOr<int>(m_config, {"battery_optimizer", "level_low"}, 20);
}

int ConfigManager::getBatteryLevelMedium() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 80;
    return jsonGetOr<int>(m_config, {"battery_optimizer", "level_medium"}, 80);
}

std::string ConfigManager::getLogLevel() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "debug";
    return jsonGetOr<std::string>(m_config, {"logging", "level"}, "debug");
}

std::string ConfigManager::getLogFormat() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "text";
    return jsonGetOr<std::string>(m_config, {"logging", "format"}, "text");
}

std::string ConfigManager::getLogFilePath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "litep2p.log";
    return jsonGetOr<std::string>(m_config, {"logging", "file_path"}, "litep2p.log");
}

int ConfigManager::getLogMaxFileSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 10;
    return jsonGetOr<int>(m_config, {"logging", "max_file_size_mb"}, 10);
}

int ConfigManager::getLogRetentionDays() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 7;
    return jsonGetOr<int>(m_config, {"logging", "retention_days"}, 7);
}

bool ConfigManager::isConsoleOutput() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"logging", "console_output"}, true);
}

int ConfigManager::getEventThreadPoolWorkers() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 4;
    return jsonGetOr<int>(m_config, {"performance", "event_thread_pool_workers"}, 4);
}

bool ConfigManager::isMessageBatcherEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"performance", "message_batcher_enabled"}, true);
}

bool ConfigManager::isMonitoringEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return false;
    return jsonGetOr<bool>(m_config, {"monitoring", "enabled"}, false);
}

int ConfigManager::getMetricsPort() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 9090;
    return jsonGetOr<int>(m_config, {"monitoring", "metrics_port"}, 9090);
}

int ConfigManager::getHealthCheckInterval() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 30000;
    return jsonGetOr<int>(m_config, {"monitoring", "health_check_interval_ms"}, 30000);
}

bool ConfigManager::isTelemetryEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"monitoring", "telemetry", "enabled"}, true);
}

bool ConfigManager::isTelemetryLogEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"monitoring", "telemetry", "log_json"}, true);
}

int ConfigManager::getTelemetryFlushIntervalMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 30000;
    return jsonGetOr<int>(m_config, {"monitoring", "telemetry", "flush_interval_ms"}, 30000);
}

std::string ConfigManager::getTelemetryFilePath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "";
    return jsonGetOr<std::string>(m_config, {"monitoring", "telemetry", "file_path"}, "");
}

bool ConfigManager::telemetryIncludePeerIds() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"monitoring", "telemetry", "include_peer_ids"}, true);
}

bool ConfigManager::isNATTraversalEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"nat_traversal", "enabled"}, true);
}

std::string ConfigManager::getNATMode() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "auto";
    return jsonGetOr<std::string>(m_config, {"nat_traversal", "mode"}, "auto");
}

bool ConfigManager::isSTUNEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"nat_traversal", "stun_enabled"}, true);
}

bool ConfigManager::isUPnPEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"nat_traversal", "upnp_enabled"}, true);
}

int ConfigManager::getUPnPTimeout() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 5000;
    return jsonGetOr<int>(m_config, {"nat_traversal", "upnp_timeout_ms"}, 5000);
}

bool ConfigManager::isHolePunchingEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"nat_traversal", "hole_punching_enabled"}, true);
}

std::vector<std::string> ConfigManager::getSTUNServers() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return {};
    std::vector<std::string> servers;

    const json* arr = jsonPtr(m_config, {"nat_traversal", "stun_servers"});
    if (!arr || !arr->is_array()) {
        return servers;
    }

    for (const auto& server : *arr) {
        if (server.is_object()) {
            std::string host = server.value("hostname", std::string{});
            if (!host.empty()) {
                servers.push_back(host);
            }
        }
    }
    return servers;
}

int ConfigManager::getMaxExternalPortAttempts() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 10;
    return jsonGetOr<int>(m_config, {"nat_traversal", "max_external_port_attempts"}, 10);
}

int ConfigManager::getStunTimeout() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 2000;
    return jsonGetOr<int>(m_config, {"nat_traversal", "stun_timeout_ms"}, 2000);
}

int ConfigManager::getNATHeartbeatIntervalSec() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 15;
    return jsonGetOr<int>(m_config, {"nat_traversal", "heartbeat_interval_sec"}, 15);
}

int ConfigManager::getNATCleanupIntervalSec() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 60;
    return jsonGetOr<int>(m_config, {"nat_traversal", "cleanup_interval_sec"}, 60);
}

int ConfigManager::getNATHeartbeatTimeoutMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 45000;
    return jsonGetOr<int>(m_config, {"nat_traversal", "heartbeat_timeout_ms"}, 45000);
}

bool ConfigManager::isPeerDiscoveryEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"nat_traversal", "peer_discovery", "enabled"}, true);
}

int ConfigManager::getDiscoveryInterval() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 5000;
    return jsonGetOr<int>(m_config, {"nat_traversal", "peer_discovery", "discovery_interval_ms"}, 5000);
}

int ConfigManager::getMaxPeerCache() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 100;
    return jsonGetOr<int>(m_config, {"nat_traversal", "peer_discovery", "max_peer_cache"}, 100);
}

int ConfigManager::getVerifiedPeerTimeout() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 300000;
    return jsonGetOr<int>(m_config, {"nat_traversal", "peer_discovery", "verified_peer_timeout_ms"}, 300000);
}

bool ConfigManager::isGlobalDiscoveryEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return false;
    return jsonGetOr<bool>(m_config, {"global_discovery", "enabled"}, false);
}

std::vector<std::string> ConfigManager::getBootstrapNodes() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return {};
    const json* bootstrap_array = jsonPtr(m_config, {"global_discovery", "bootstrap_nodes"});
    std::vector<std::string> nodes;

    if (!bootstrap_array || !bootstrap_array->is_array()) {
        return nodes;
    }

    for (const auto& node : *bootstrap_array) {
        if (!node.is_object()) continue;
        const std::string ip = node.value("ip", std::string{});
        const int port = node.value("port", 0);
        if (!ip.empty() && port > 0 && port <= 65535) {
            nodes.push_back(ip + ":" + std::to_string(port));
        }
    }
    return nodes;
}

std::string ConfigManager::getDiscoveryStrategy() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "broadcast";
    return jsonGetOr<std::string>(m_config, {"global_discovery", "discovery_strategy"}, "broadcast");
}

bool ConfigManager::isLocalNetworkScanEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"global_discovery", "local_network_scan"}, true);
}

bool ConfigManager::shouldAnnounceself() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"global_discovery", "announce_self"}, true);
}

int ConfigManager::getAnnounceInterval() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 30000;
    return jsonGetOr<int>(m_config, {"global_discovery", "announce_interval_ms"}, 30000);
}

json ConfigManager::getConfigSnapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

bool ConfigManager::setValueAtPath(const std::vector<std::string>& path, const json& value) {
    if (path.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) {
        m_config = json::object();
    }

    json* current = &m_config;
    for (size_t i = 0; i + 1 < path.size(); ++i) {
        const auto& key = path[i];
        if (!current->contains(key) || !(*current)[key].is_object()) {
            (*current)[key] = json::object();
        }
        current = &((*current)[key]);
    }

    (*current)[path.back()] = value;
    return true;
}

bool ConfigManager::eraseValueAtPath(const std::vector<std::string>& path) {
    if (path.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) {
        return false;
    }

    json* current = &m_config;
    for (size_t i = 0; i + 1 < path.size(); ++i) {
        const auto& key = path[i];
        auto it = current->find(key);
        if (it == current->end() || !(*it).is_object()) {
            return false;
        }
        current = &(*it);
    }

    if (!current->is_object()) {
        return false;
    }

    return current->erase(path.back()) > 0;
}

std::string ConfigManager::getConfigPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config_path;
}

// ============================================================================
// Signaling Configuration
// ============================================================================

bool ConfigManager::isSignalingEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    return jsonGetOr<bool>(m_config, {"signaling", "enabled"}, true);
}

std::string ConfigManager::getSignalingUrl() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "ws://64.227.140.251:8765";
    return jsonGetOr<std::string>(m_config, {"signaling", "url"}, "ws://64.227.140.251:8765");
}

int ConfigManager::getSignalingReconnectIntervalMs() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 5000;
    return jsonGetOr<int>(m_config, {"signaling", "reconnect_interval_ms"}, 5000);
}

bool ConfigManager::isPeerDbEnabled() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return true;
    // Default ON so persistence is available even when no config is present.
    return jsonGetOr<bool>(m_config, {"storage", "peer_db", "enabled"}, true);
}

std::string ConfigManager::getPeerDbPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return "";
    return jsonGetOr<std::string>(m_config, {"storage", "peer_db", "path"}, "");
}

int ConfigManager::getPeerDbReconnectCandidateLimit() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 2000;
    return jsonGetOr<int>(m_config, {"storage", "peer_db", "reconnect_candidate_limit"}, 2000);
}

int ConfigManager::getPeerDbPruneAfterDays() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_config.is_object()) return 15;
    return jsonGetOr<int>(m_config, {"storage", "peer_db", "prune_after_days"}, 15);
}
