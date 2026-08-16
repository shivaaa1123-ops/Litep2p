#pragma once

#include "config_manager.h"
#include "logger.h"

#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace litep2p::dynamic_config {

// Signature that identifies configuration commands embedded in heartbeat packets.
static constexpr const char* kCommandSignature = "LITEP2P_CONFIG";

// Result of processing a dynamic configuration message.
struct CommandResult {
    bool success = false;
    std::string message;
};

// Represents a parsed configuration command extracted from heartbeat payloads.
struct ConfigCommand {
    std::string action;                    // e.g., "set", "reset", "reload"
    std::vector<std::string> key_path;     // dotted path split into components
    std::string value;                     // new value (string form)
    bool persist = true;                   // whether the change should be persisted
};

// DynamicConfigurationManager parses heartbeat messages for commands, updates
// the in-memory configuration, and persists changes back to config.json so they
// survive engine restarts.
class DynamicConfigurationManager {
public:
    using CommandCallback = std::function<void(const ConfigCommand&)>;

    DynamicConfigurationManager();

    // Inject current configuration manager reference.
    void initialize(ConfigManager* config_manager, const std::string& config_path);

    // Process an incoming heartbeat payload. If a configuration command is
    // detected (prefixed with kCommandSignature), apply it and persist changes.
    CommandResult processHeartbeatMessage(const std::string& heartbeat_payload);

    // Manually apply a configuration command.
    CommandResult applyCommand(const ConfigCommand& command);

    // Register an observer notified whenever a configuration command is applied.
    void addObserver(CommandCallback callback);

    // Retrieve last processed command result for introspection/testing.
    std::optional<ConfigCommand> getLastCommand() const;

    // Reload configuration from disk, discarding transient in-memory overrides.
    CommandResult reloadFromDisk();

private:
    std::optional<ConfigCommand> parseCommandFromPayload(const std::string& payload) const;
    bool applyToConfig(ConfigManager& manager, const ConfigCommand& command, std::string& error_message);
    bool persistConfig(ConfigManager& manager, std::string& error_message);

    ConfigManager* m_config_manager;
    std::string m_config_path;

    mutable std::mutex m_mutex;
    std::vector<CommandCallback> m_observers;
    std::optional<ConfigCommand> m_last_command;
};

} // namespace litep2p::dynamic_config
