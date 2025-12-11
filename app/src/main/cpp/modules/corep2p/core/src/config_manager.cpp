#include "config_manager.h"
#include <fstream>

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::loadConfig(const std::string& config_path) {
    try {
        std::ifstream config_file(config_path);
        if (!config_file.is_open()) {
            std::cerr << "ERROR: Failed to open config file: " << config_path << std::endl;
            return false;
        }
        config_file >> m_config;
        std::cout << "INFO: Configuration loaded successfully from: " << config_path << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Config loading failed: " << e.what() << std::endl;
        return false;
    }
}

std::string ConfigManager::getDefaultProtocol() const {
    return m_config.value("communication", json::object())
        .value("default_protocol", "UDP");
}

bool ConfigManager::isUDPEnabled() const {
    return m_config["communication"]["udp"]["enabled"].get<bool>();
}

bool ConfigManager::isTCPEnabled() const {
    return m_config["communication"]["tcp"]["enabled"].get<bool>();
}

int ConfigManager::getUDPPort() const {
    return m_config["communication"]["udp"]["port"].get<int>();
}

int ConfigManager::getTCPPort() const {
    return m_config["communication"]["tcp"]["port"].get<int>();
}

int ConfigManager::getUDPBufferSize() const {
    return m_config["communication"]["udp"]["buffer_size"].get<int>();
}

int ConfigManager::getUDPTimeout() const {
    return m_config["communication"]["udp"]["timeout_ms"].get<int>();
}

bool ConfigManager::isNoiseNKEnabled() const {
    return m_config["security"]["noise_nk_protocol"]["enabled"].get<bool>();
}

bool ConfigManager::isNoiseNKMandatory() const {
    return m_config["security"]["noise_nk_protocol"]["mandatory"].get<bool>();
}

std::string ConfigManager::getKeyStorePath() const {
    return m_config["security"]["noise_nk_protocol"]["key_store_path"].get<std::string>();
}

int ConfigManager::getKeyRotationInterval() const {
    return m_config["security"]["noise_nk_protocol"]["key_rotation_interval_hours"].get<int>();
}

bool ConfigManager::isBatchManagerEnabled() const {
    return m_config["batch_connection_manager"]["enabled"].get<bool>();
}

int ConfigManager::getMaxPeersPerBatch() const {
    return m_config["batch_connection_manager"]["max_peers_per_batch"].get<int>();
}

int ConfigManager::getMaxBatches() const {
    return m_config["batch_connection_manager"]["max_batches"].get<int>();
}

int ConfigManager::getBatchDelayMs() const {
    return m_config["batch_connection_manager"]["batch_delay_ms"].get<int>();
}

int ConfigManager::getBatchMaxMessages() const {
    return m_config["batch_connection_manager"]["batch_max_messages"].get<int>();
}

int ConfigManager::getCleanupInterval() const {
    return m_config["batch_connection_manager"]["cleanup_interval_ms"].get<int>();
}

int ConfigManager::getNumWorkers() const {
    return m_config["session_manager"]["num_workers"].get<int>();
}

int ConfigManager::getCacheSize() const {
    return m_config["session_manager"]["cache_size"].get<int>();
}

int ConfigManager::getSessionTimeout() const {
    return m_config["session_manager"]["session_timeout_ms"].get<int>();
}

int ConfigManager::getMaxConcurrentSessions() const {
    return m_config["session_manager"]["max_concurrent_sessions"].get<int>();
}

bool ConfigManager::isBatteryOptimizerEnabled() const {
    return m_config["battery_optimizer"]["enabled"].get<bool>();
}

bool ConfigManager::isAggressiveMode() const {
    return m_config["battery_optimizer"]["aggressive_mode"].get<bool>();
}

int ConfigManager::getPowerSaveThreshold() const {
    return m_config["battery_optimizer"]["power_save_threshold"].get<int>();
}

std::string ConfigManager::getLogLevel() const {
    return m_config["logging"]["level"].get<std::string>();
}

std::string ConfigManager::getLogFormat() const {
    return m_config["logging"]["format"].get<std::string>();
}

std::string ConfigManager::getLogFilePath() const {
    return m_config["logging"]["file_path"].get<std::string>();
}

int ConfigManager::getLogMaxFileSize() const {
    return m_config["logging"]["max_file_size_mb"].get<int>();
}

int ConfigManager::getLogRetentionDays() const {
    return m_config["logging"]["retention_days"].get<int>();
}

bool ConfigManager::isConsoleOutput() const {
    return m_config["logging"]["console_output"].get<bool>();
}

int ConfigManager::getEventThreadPoolWorkers() const {
    return m_config["performance"]["event_thread_pool_workers"].get<int>();
}

bool ConfigManager::isMessageBatcherEnabled() const {
    return m_config["performance"]["message_batcher_enabled"].get<bool>();
}

bool ConfigManager::isMonitoringEnabled() const {
    return m_config["monitoring"]["enabled"].get<bool>();
}

int ConfigManager::getMetricsPort() const {
    return m_config["monitoring"]["metrics_port"].get<int>();
}

int ConfigManager::getHealthCheckInterval() const {
    return m_config["monitoring"]["health_check_interval_ms"].get<int>();
}

bool ConfigManager::isNATTraversalEnabled() const {
    return m_config["nat_traversal"]["enabled"].get<bool>();
}

std::string ConfigManager::getNATMode() const {
    return m_config["nat_traversal"]["mode"].get<std::string>();
}

bool ConfigManager::isSTUNEnabled() const {
    return m_config["nat_traversal"]["stun_enabled"].get<bool>();
}

bool ConfigManager::isUPnPEnabled() const {
    return m_config["nat_traversal"]["upnp_enabled"].get<bool>();
}

int ConfigManager::getUPnPTimeout() const {
    return m_config["nat_traversal"]["upnp_timeout_ms"].get<int>();
}

bool ConfigManager::isHolePunchingEnabled() const {
    return m_config["nat_traversal"]["hole_punching_enabled"].get<bool>();
}

std::vector<std::string> ConfigManager::getSTUNServers() const {
    auto stun_array = m_config["nat_traversal"]["stun_servers"];
    std::vector<std::string> servers;
    for (const auto& server : stun_array) {
        servers.push_back(server["hostname"].get<std::string>());
    }
    return servers;
}

int ConfigManager::getMaxExternalPortAttempts() const {
    return m_config["nat_traversal"]["max_external_port_attempts"].get<int>();
}

bool ConfigManager::isPeerDiscoveryEnabled() const {
    return m_config["nat_traversal"]["peer_discovery"]["enabled"].get<bool>();
}

int ConfigManager::getDiscoveryInterval() const {
    return m_config["nat_traversal"]["peer_discovery"]["discovery_interval_ms"].get<int>();
}

int ConfigManager::getMaxPeerCache() const {
    return m_config["nat_traversal"]["peer_discovery"]["max_peer_cache"].get<int>();
}

int ConfigManager::getVerifiedPeerTimeout() const {
    return m_config["nat_traversal"]["peer_discovery"]["verified_peer_timeout_ms"].get<int>();
}

bool ConfigManager::isGlobalDiscoveryEnabled() const {
    return m_config["global_discovery"]["enabled"].get<bool>();
}

std::vector<std::string> ConfigManager::getBootstrapNodes() const {
    auto bootstrap_array = m_config["global_discovery"]["bootstrap_nodes"];
    std::vector<std::string> nodes;
    for (const auto& node : bootstrap_array) {
        nodes.push_back(node["ip"].get<std::string>() + ":" + 
                       std::to_string(node["port"].get<int>()));
    }
    return nodes;
}

std::string ConfigManager::getDiscoveryStrategy() const {
    return m_config["global_discovery"]["discovery_strategy"].get<std::string>();
}

bool ConfigManager::isLocalNetworkScanEnabled() const {
    return m_config["global_discovery"]["local_network_scan"].get<bool>();
}

bool ConfigManager::shouldAnnounceself() const {
    return m_config["global_discovery"]["announce_self"].get<bool>();
}

int ConfigManager::getAnnounceInterval() const {
    return m_config["global_discovery"]["announce_interval_ms"].get<int>();
}
