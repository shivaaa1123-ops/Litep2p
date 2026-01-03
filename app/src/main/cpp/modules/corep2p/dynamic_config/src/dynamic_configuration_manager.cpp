#include "dynamic_configuration/dynamic_configuration_manager.h"

#include <cctype>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>

namespace litep2p::dynamic_config {

namespace {

std::vector<std::string> splitKeyPath(const std::string& dotted_path) {
    std::vector<std::string> parts;
    std::stringstream ss(dotted_path);
    std::string segment;
    while (std::getline(ss, segment, '.')) {
        if (!segment.empty()) {
            parts.push_back(segment);
        }
    }
    return parts;
}

} // namespace

DynamicConfigurationManager::DynamicConfigurationManager()
    : m_config_manager(nullptr) {}

void DynamicConfigurationManager::initialize(ConfigManager* config_manager, const std::string& config_path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config_manager = config_manager;
    m_config_path = config_path;
}

CommandResult DynamicConfigurationManager::processHeartbeatMessage(const std::string& heartbeat_payload) {
    auto command = parseCommandFromPayload(heartbeat_payload);
    if (!command.has_value()) {
        return {false, "No dynamic configuration directive detected"};
    }
    return applyCommand(command.value());
}

CommandResult DynamicConfigurationManager::applyCommand(const ConfigCommand& command) {
    std::lock_guard<std::mutex> lock(m_mutex);

    CommandResult result;
    if (!m_config_manager) {
        result.success = false;
        result.message = "DynamicConfigurationManager is not initialized";
        return result;
    }

    std::string error;
    if (!applyToConfig(*m_config_manager, command, error)) {
        result.success = false;
        result.message = error;
        return result;
    }

    if (command.persist) {
        if (!persistConfig(*m_config_manager, error)) {
            result.success = false;
            result.message = error;
            return result;
        }
    }

    m_last_command = command;

    for (const auto& observer : m_observers) {
        observer(command);
    }

    result.success = true;
    result.message = "Configuration updated";
    return result;
}

void DynamicConfigurationManager::addObserver(CommandCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_observers.push_back(std::move(callback));
}

std::optional<ConfigCommand> DynamicConfigurationManager::getLastCommand() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_last_command;
}

CommandResult DynamicConfigurationManager::reloadFromDisk() {
    std::lock_guard<std::mutex> lock(m_mutex);
    CommandResult result;
    if (!m_config_manager) {
        result.success = false;
        result.message = "DynamicConfigurationManager is not initialized";
        return result;
    }

    if (!m_config_manager->loadConfig(m_config_path)) {
        result.success = false;
        result.message = "Failed to reload configuration from disk";
        return result;
    }

    result.success = true;
    result.message = "Configuration reloaded from disk";
    return result;
}

std::optional<ConfigCommand> DynamicConfigurationManager::parseCommandFromPayload(const std::string& payload) const {
    auto signature_pos = payload.find(kCommandSignature);
    if (signature_pos == std::string::npos) {
        return std::nullopt;
    }

    auto command_start = signature_pos + std::strlen(kCommandSignature);
    while (command_start < payload.size() && std::isspace(static_cast<unsigned char>(payload[command_start]))) {
        ++command_start;
    }

    std::string command_str = payload.substr(command_start);
    std::stringstream parser(command_str);

    ConfigCommand command;
    parser >> command.action;
    if (command.action.empty()) {
        return std::nullopt;
    }

    if (command.action == "set") {
        std::string key_path;
        parser >> key_path;
        if (key_path.empty()) {
            return std::nullopt;
        }
        command.key_path = splitKeyPath(key_path);

        std::string value;
        std::getline(parser, value);
        if (!value.empty() && value.front() == ' ') {
            value.erase(value.begin());
        }
        command.value = value;
        command.persist = true;
    } else if (command.action == "reset") {
        std::string key_path;
        parser >> key_path;
        command.key_path = splitKeyPath(key_path);
        command.persist = true;
    } else if (command.action == "reload") {
        command.persist = false;
    } else {
        return std::nullopt;
    }

    return command;
}

bool DynamicConfigurationManager::applyToConfig(ConfigManager& manager, const ConfigCommand& command, std::string& error_message) {
    if (command.action == "reload") {
        if (!manager.loadConfig(m_config_path)) {
            error_message = "Failed to reload configuration";
            return false;
        }
        return true;
    }

    if (command.key_path.empty()) {
        error_message = "Configuration command missing key path";
        return false;
    }

    if (command.action == "set") {
        json value_json;
        if (!command.value.empty()) {
            try {
                value_json = json::parse(command.value);
            } catch (const std::exception&) {
                value_json = command.value;
            }
        } else {
            value_json = nullptr;
        }

        if (!manager.setValueAtPath(command.key_path, value_json)) {
            error_message = "Failed to apply configuration change";
            return false;
        }
        return true;
    }

    if (command.action == "reset") {
        if (m_config_path.empty()) {
            error_message = "Configuration path is not set";
            return false;
        }

        std::ifstream config_file(m_config_path);
        if (!config_file.is_open()) {
            error_message = "Unable to open config file";
            return false;
        }

        std::string content((std::istreambuf_iterator<char>(config_file)),
                            std::istreambuf_iterator<char>());

        json baseline;
        try {
            baseline = json::parse(content, nullptr, true, true);
        } catch (const std::exception&) {
            error_message = "Failed to parse baseline configuration";
            return false;
        }

        const json* node = &baseline;
        for (size_t i = 0; i < command.key_path.size(); ++i) {
            if (!node->is_object()) {
                node = nullptr;
                break;
            }
            auto it = node->find(command.key_path[i]);
            if (it == node->end()) {
                node = nullptr;
                break;
            }
            node = &(*it);
        }

        if (node != nullptr) {
            if (!manager.setValueAtPath(command.key_path, *node)) {
                error_message = "Failed to restore configuration value";
                return false;
            }
        } else if (!manager.eraseValueAtPath(command.key_path)) {
            error_message = "Configuration key not found";
            return false;
        }
        return true;
    }

    error_message = "Unsupported configuration action";
    return false;
}

bool DynamicConfigurationManager::persistConfig(ConfigManager& manager, std::string& error_message) {
    if (m_config_path.empty()) {
        error_message = "Configuration path is not set";
        return false;
    }

    if (!manager.saveConfig(m_config_path)) {
        error_message = "Failed to write configuration to disk";
        return false;
    }
    return true;
}

} // namespace litep2p::dynamic_config
