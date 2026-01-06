#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <memory>
#include <iostream>
#include <mutex>
#include <vector>

using json = nlohmann::json;

class ConfigManager {
public:
    static ConfigManager& getInstance();
    
    ConfigManager(); // Made public for now or just defined
    
    bool loadConfig(const std::string& config_path);
    bool saveConfig(const std::string& config_path);
    bool saveConfig();
    
    // Communication
    std::string getDefaultProtocol() const;
    bool isUDPEnabled() const;
    bool isTCPEnabled() const;
    int getUDPPort() const;
    int getTCPPort() const;
    int getUDPBufferSize() const;
    int getTCPBufferSize() const;
    int getUDPTimeout() const;
    bool isTCPNoDelayEnabled() const;
    int getTCPConnectTimeout() const;
    
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
    int getSessionCacheLifetimeSec() const;
    int getSessionTimeout() const;
    int getMaxConcurrentSessions() const;

    // Peer Management
    int getHeartbeatIntervalSec() const;
    int getPeerExpirationTimeoutMs() const;

    // Event Manager
    int getEventQueueWaitTimeoutMs() const;
    int getTimerTickIntervalMs() const;
    int getEventThreadSleepMs() const;
    
    // Battery Optimizer
    bool isBatteryOptimizerEnabled() const;
    bool isAggressiveMode() const;
    int getPowerSaveThreshold() const;
    int getBatteryLevelCritical() const;
    int getBatteryLevelLow() const;
    int getBatteryLevelMedium() const;
    
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

    // Telemetry (local metrics, periodic JSON flush)
    bool isTelemetryEnabled() const;
    bool isTelemetryLogEnabled() const;
    int getTelemetryFlushIntervalMs() const;
    std::string getTelemetryFilePath() const;
    bool telemetryIncludePeerIds() const;
    
    // NAT Traversal
    bool isNATTraversalEnabled() const;
    std::string getNATMode() const;
    bool isSTUNEnabled() const;
    bool isUPnPEnabled() const;
    int getUPnPTimeout() const;
    bool isHolePunchingEnabled() const;
    std::vector<std::string> getSTUNServers() const;
    int getMaxExternalPortAttempts() const;
    int getStunTimeout() const;
    int getNATHeartbeatIntervalSec() const;
    int getNATCleanupIntervalSec() const;
    int getNATHeartbeatTimeoutMs() const;
    
    // Peer Discovery
    bool isPeerDiscoveryEnabled() const;
    int getDiscoveryInterval() const;
    int getMaxPeerCache() const;
    int getVerifiedPeerTimeout() const;
    
    // Signaling
    bool isSignalingEnabled() const;
    std::string getSignalingUrl() const;
    int getSignalingReconnectIntervalMs() const;

    // Reconnect Policy
    std::string getReconnectPolicyMode() const;

    // Local storage
    bool isPeerDbEnabled() const;
    std::string getPeerDbPath() const;
    int getPeerDbReconnectCandidateLimit() const;
    int getPeerDbPruneAfterDays() const;
    
    // Global Discovery
    bool isGlobalDiscoveryEnabled() const;
    std::vector<std::string> getBootstrapNodes() const;
    std::string getDiscoveryStrategy() const;
    bool isLocalNetworkScanEnabled() const;
    bool shouldAnnounceself() const;
    int getAnnounceInterval() const;

    // Dynamic configuration helpers
    json getConfigSnapshot() const;
    bool setValueAtPath(const std::vector<std::string>& path, const json& value);
    bool eraseValueAtPath(const std::vector<std::string>& path);
    std::string getConfigPath() const;
    
private:
    // ConfigManager() = default;
    json m_config;
    std::string m_config_path;
    mutable std::mutex m_mutex;
};
