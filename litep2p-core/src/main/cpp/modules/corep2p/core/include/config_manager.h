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

    // Communication mode: "HOMOGENEOUS" (accept only the default protocol) or
    // "HETEROGENEOUS" (accept UDP and TCP simultaneously). Read from
    // `communication.mode`. Homogeneous is the safe default and matches the
    // historic single-protocol behavior.
    std::string getCommsMode() const;
    void setCommsMode(const std::string& mode);
    void setDefaultProtocol(const std::string& protocol);
    
    // Security
    bool isNoiseNKEnabled() const;
    bool isNoiseNKMandatory() const;
    std::string getKeyStorePath() const;
    int getKeyRotationInterval() const;
    // Optional shared transport key (64 hex chars). When set, all peers use it
    // for transport-layer encryption instead of their device-local key.
    std::string getTransportKeyHex() const;

    // Dynamic data-listener port range (network.port_range = [min, max]).
    // When configured, the engine picks a random free port in the range at
    // startup (censorship resistance: a static port blocklist cannot pin a
    // fixed port). Returns false when unset/malformed.
    bool getDataPortRange(int& lo, int& hi) const;

    // LAN discovery listener/broadcast port (network.discovery_port).
    // Historically hardcoded to 30000; now config-driven so deployments (and
    // hermetic tests) can use a distinct port. Falls back to 30000.
    int getDiscoveryPort() const;

    // LAN discovery master switch (network.discovery_enabled, default true).
    // When false the engine never binds/sends discovery announcements
    // (deployments that rely purely on signaling/peer-DB can disable LAN
    // discovery; hermetic tests use it to keep the FSM fully isolated).
    bool isDiscoveryEnabled() const;

    // Discovery fingerprint controls (network.discovery_magic + network.discovery_shared_key).
    // - magic: prefix bytes on discovery announcements; set to a random string
    //   per deployment so packets are not recognizable as "LITEP2P_DISCOVERY".
    // - shared_key: 64-hex-char AEAD key; when set, discovery announcements are
    //   encrypted (XChaCha20-Poly1305) and padded, so even the peer id/port are
    //   opaque to passive observers.
    std::string getDiscoveryMagic() const;
    bool getDiscoverySharedKey(std::vector<uint8_t>& key_out) const;
    
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
    // v0.4 backpressure: max plain-send events allowed in the engine event
    // queue before litep2p_send() returns LITEP2P_ERR_QUEUE_FULL.
    int getMaxPendingSends() const;

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

    // AnomalyReporter (field-diagnostics incident log + uploader, v0.4)
    // Write a structured incident file for every anomaly (disconnect, connect
    // failure, stall, runtime error) and optionally upload it to a collector.
    bool isAnomalyReporterEnabled() const;
    std::string getAnomalyDirectory() const;      // subdir under base_dir, e.g. "anomalies"
    int getAnomalyMaxFiles() const;               // rotation cap
    bool isAnomalyUploadEnabled() const;
    std::string getAnomalyUploadUrl() const;      // "http://host:port/path"
    int getAnomalyUploadIntervalMs() const;
    bool anomalyIncludeTelemetry() const;         // embed Telemetry snapshot
    int getAnomalyStallThresholdMs() const;       // peer stuck in CONNECTING/HANDSHAKING => stall
    
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

    // Offline queue (store-and-forward mailbox, v0.4 ask.md §2)
    bool isOfflineQueueEnabled() const;
    int getOfflineQueueMaxMessages() const;
    int64_t getOfflineQueueTtlMs() const;
    // Directory for the persistent reliable-send outbox (set by the C ABI from
    // files_dir; empty = outbox persistence disabled).
    std::string getReliableOutboxDir() const;

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
