#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <memory>
#include <iostream>

using json = nlohmann::json;

class ConfigManager {
public:
    static ConfigManager& getInstance();
    
    bool loadConfig(const std::string& config_path);
    
    // Communication
    std::string getDefaultProtocol() const;
    bool isUDPEnabled() const;
    bool isTCPEnabled() const;
    int getUDPPort() const;
    int getTCPPort() const;
    int getUDPBufferSize() const;
    int getUDPTimeout() const;
    
    // Security
    bool isNoiseNKEnabled() const;
    bool isNoiseNKMandatory() const;
    std::string getKeyStorePath() const;
    int getKeyRotationInterval() const;
    
    // Batch Connection Manager
    bool isBatchManagerEnabled() const;
    int getMaxPeersPerBatch() const;
    int getMaxBatches() const;
    int getBatchDelayMs() const;
    int getBatchMaxMessages() const;
    int getCleanupInterval() const;
    
    // Session Manager
    int getNumWorkers() const;
    int getCacheSize() const;
    int getSessionTimeout() const;
    int getMaxConcurrentSessions() const;
    
    // Battery Optimizer
    bool isBatteryOptimizerEnabled() const;
    bool isAggressiveMode() const;
    int getPowerSaveThreshold() const;
    
    // Logging
    std::string getLogLevel() const;
    std::string getLogFormat() const;
    std::string getLogFilePath() const;
    int getLogMaxFileSize() const;
    int getLogRetentionDays() const;
    bool isConsoleOutput() const;
    
    // Performance
    int getEventThreadPoolWorkers() const;
    bool isMessageBatcherEnabled() const;
    
    // Monitoring
    bool isMonitoringEnabled() const;
    int getMetricsPort() const;
    int getHealthCheckInterval() const;
    
    // NAT Traversal
    bool isNATTraversalEnabled() const;
    std::string getNATMode() const;
    bool isSTUNEnabled() const;
    bool isUPnPEnabled() const;
    int getUPnPTimeout() const;
    bool isHolePunchingEnabled() const;
    std::vector<std::string> getSTUNServers() const;
    int getMaxExternalPortAttempts() const;
    
    // Peer Discovery
    bool isPeerDiscoveryEnabled() const;
    int getDiscoveryInterval() const;
    int getMaxPeerCache() const;
    int getVerifiedPeerTimeout() const;
    
    // Global Discovery
    bool isGlobalDiscoveryEnabled() const;
    std::vector<std::string> getBootstrapNodes() const;
    std::string getDiscoveryStrategy() const;
    bool isLocalNetworkScanEnabled() const;
    bool shouldAnnounceself() const;
    int getAnnounceInterval() const;
    
private:
    ConfigManager() = default;
    json m_config;
};
