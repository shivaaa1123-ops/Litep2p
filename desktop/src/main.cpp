#include "p2p_node.h"
#include "terminal_cli.h"
#include "logger.h"
#include "device_utils.h"
#include "config_manager.h"
#include "anomaly_reporter.h"
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>
#include <cctype>
#include <signal.h>
#include <filesystem>

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --id ID         Set explicit peer id (useful for testing)\n"
              << "  --port PORT     Listen port (default: 30001)\n"
              << "  --config FILE   Path to configuration file (default: config.json)\n"
              << "  --log-level LVL Log level: debug|info|warning|error|none (default: none)\n"
              << "  --proxy ROLE    Set local proxy role: off|gateway|exit|client|both (default: off)\n"
              << "  --mode MODE     Communication mode: homogeneous|heterogeneous (default: homogeneous)\n"
              << "                    homogeneous: \n"
              << "                    accept connections ONLY via --protocol / communication.default_protocol\n"
              << "                    heterogeneous: accept BOTH UDP and TCP connections simultaneously\n"
              << "  --protocol P    Transport protocol for homogeneous mode: UDP|TCP (default: config default_protocol)\n"
              << "  --tui-telemetry-ms MS  Telemetry pane refresh interval in ms (default: 1000)\n"
              << "  --no-tui        Force plain log output (no interactive UI)\n"
              << "  --daemon        Run as daemon (no stdin, suitable for background/testing)\n"
              << "  --help          Show this help message\n"
              << "\nInteractive CLI (after startup):\n"
              << "  Type 'help' to see commands. Useful ones:\n"
              << "    proxy <off|gateway|exit|client|both|status>\n"
              << "    admin_proxy <peer_id> <off|gateway|exit|client|both>   (alias: ap)\n"
              << "\nRemote proxy control notes:\n"
              << "  'admin_proxy' sends an LP_ADMIN command to the target peer.\n"
              << "  The target peer must allow it in its config.json:\n"
              << "    \"remote_control\": { \"enabled\": true, \"allowed_senders\": [\"<your_peer_id>\"] }\n"
              << std::endl;
}

static LogLevel parse_log_level(const std::string& value) {
    std::string v = value;
    for (auto& c : v) c = static_cast<char>(::tolower(c));
    if (v == "debug") return LogLevel::DEBUG;
    if (v == "info") return LogLevel::INFO;
    if (v == "warn" || v == "warning") return LogLevel::WARNING;
    if (v == "error") return LogLevel::ERROR;
    if (v == "none") return LogLevel::NONE;
    // Default fallback
    return LogLevel::ERROR;
}

int main(int argc, char* argv[]) {
    // Ignore SIGPIPE to prevent process termination on socket write errors
    signal(SIGPIPE, SIG_IGN);
    
    // Test suite uses SIGUSR1 to simulate an "interruption". By default, SIGUSR1
    // terminates the process, which makes recovery tests fail and can emit
    // "User defined signal 1" job-control noise in bash. Ignore it so the peer
    // can continue running (and optionally implement a real interruption hook later).
#if defined(SIGUSR1)
    signal(SIGUSR1, SIG_IGN);
#endif

    // Suppress all logs initially for clean startup
    set_log_level(LogLevel::NONE);
    
    uint16_t port = 30001;
    std::string custom_peer_id = "";
    std::string config_path = "config.json";
    LogLevel requested_log_level = LogLevel::INFO;  // Default to INFO for TUI
    bool force_plain_cli = false;
    bool daemon_mode = false;
    std::string proxy_role;
    int tui_telemetry_ms = 1000;
    std::string comms_mode_override;
    std::string protocol_override;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--config") {
            if (i + 1 < argc) {
                config_path = argv[++i];
            } else {
                std::cerr << "Error: --config requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--id") {
            if (i + 1 < argc) {
                custom_peer_id = argv[++i];
            } else {
                std::cerr << "Error: --id requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--port") {
            if (i + 1 < argc) {
                try {
                    int p = std::stoi(argv[++i]);
                    if (p < 1 || p > 65535) {
                        std::cerr << "Error: Port must be between 1 and 65535" << std::endl;
                        return 1;
                    }
                    port = static_cast<uint16_t>(p);
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid port number: " << e.what() << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Error: --port requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--log-level") {
            if (i + 1 < argc) {
                requested_log_level = parse_log_level(argv[++i]);
            } else {
                std::cerr << "Error: --log-level requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--proxy") {
            if (i + 1 < argc) {
                proxy_role = argv[++i];
            } else {
                std::cerr << "Error: --proxy requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--mode") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --mode requires an argument (homogeneous|heterogeneous)" << std::endl;
                return 1;
            }
            comms_mode_override = argv[++i];
            for (auto& c : comms_mode_override) c = static_cast<char>(::tolower((unsigned char)c));
            if (comms_mode_override != "homogeneous" && comms_mode_override != "heterogeneous") {
                std::cerr << "Error: --mode must be 'homogeneous' or 'heterogeneous'" << std::endl;
                return 1;
            }
        } else if (arg == "--protocol") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --protocol requires an argument (UDP|TCP)" << std::endl;
                return 1;
            }
            protocol_override = argv[++i];
            for (auto& c : protocol_override) c = static_cast<char>(::toupper((unsigned char)c));
            if (protocol_override != "UDP" && protocol_override != "TCP" && protocol_override != "QUIC") {
                std::cerr << "Error: --protocol must be 'UDP', 'TCP', or 'QUIC'" << std::endl;
                return 1;
            }
        } else if (arg == "--tui-telemetry-ms") {
            if (i + 1 < argc) {
                try {
                    int v = std::stoi(argv[++i]);
                    if (v < 100) v = 100;
                    if (v > 60000) v = 60000;
                    tui_telemetry_ms = v;
                } catch (...) {
                    std::cerr << "Error: invalid --tui-telemetry-ms value" << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Error: --tui-telemetry-ms requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "--no-tui" || arg == "--plain") {
            force_plain_cli = true;
        } else if (arg == "--daemon") {
            daemon_mode = true;
            force_plain_cli = true;  // Daemon also implies no TUI
        } else {
            std::cerr << "Error: Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

        // Load configuration with smart fallbacks (useful when running from build/bin)
        auto try_load = [](const std::string& path) -> bool {
            try {
                return ConfigManager::getInstance().loadConfig(path);
            } catch (...) {
                return false;
            }
        };

        std::vector<std::string> candidates;
        candidates.push_back(config_path); // user-specified or default
        candidates.push_back("../config.json");
        candidates.push_back("../../config.json");
        candidates.push_back("../../../config.json");

        // Also attempt paths relative to the executable location
        try {
            std::filesystem::path exe_path = std::filesystem::absolute(argv[0]);
            std::filesystem::path exe_dir = exe_path.parent_path();
            candidates.push_back((exe_dir / "config.json").string());
            candidates.push_back((exe_dir / "../config.json").lexically_normal().string());
            candidates.push_back((exe_dir / "../../config.json").lexically_normal().string());
            candidates.push_back((exe_dir / "../../../config.json").lexically_normal().string());
        } catch (...) {
            // ignore
        }

        std::string chosen_config;
        for (const auto& c : candidates) {
            if (try_load(c)) {
                chosen_config = c;
                break;
            }
        }

        if (chosen_config.empty()) {
            std::cerr << "CRITICAL ERROR: Failed to load configuration. Tried paths:" << std::endl;
            for (const auto& c : candidates) {
                std::cerr << "  - " << c << std::endl;
            }
            return 1;
        }
        // Config loaded silently - no need to print
    
    // Create P2P node (not started yet)
    P2PNode node;
    std::string peer_id = custom_peer_id.empty() ? get_persistent_device_id() : custom_peer_id;

    // Field diagnostics: identify this host in incident logs (AnomalyReporter).
    {
        std::ostringstream dev;
        dev << "{\"brand\":\"desktop\",\"model\":\"";
#if defined(__APPLE__)
        dev << "macOS";
#elif defined(__linux__)
        dev << "Linux";
#else
        dev << "desktop";
#endif
        dev << "\",\"os\":\"";
#if defined(__APPLE__)
        dev << "macOS";
#elif defined(__linux__)
        dev << "Linux";
#endif
        dev << "\",\"abi\":\"";
#if defined(__x86_64__) || defined(_M_X64)
        dev << "x86_64";
#elif defined(__aarch64__)
        dev << "arm64";
#elif defined(__i386__)
        dev << "x86";
#else
        dev << "unknown";
#endif
        dev << "\",\"peer_id\":\"" << peer_id << "\"}";
        AnomalyReporter::getInstance().setDeviceInfo(dev.str());
    }
    
    nativeLog("MAIN: P2PNode created, peer_id=" + peer_id);
    
    // Create CLI FIRST so log callback is registered before engine starts
    // This ensures startup logs are captured and displayed
    nativeLog("MAIN: Creating TerminalCLI...");
    TerminalCLI cli(node, force_plain_cli, daemon_mode);
    cli.setTelemetryRefreshIntervalMs(tui_telemetry_ms);
    nativeLog("MAIN: TerminalCLI created");
    
    // Set user-requested log level (CLI constructor sets INFO by default)
    set_log_level(requested_log_level);
    
    nativeLog("MAIN: About to start engine...");
    
    // Start engine - calls SessionManager::start() exactly like JNI bridge.
    // First apply any explicit CLI overrides for mode/protocol so the session
    // manager (which reads the effective config) starts in the requested mode.
    ConfigManager& cfg = ConfigManager::getInstance();
    if (!comms_mode_override.empty()) {
        cfg.setCommsMode(comms_mode_override == "heterogeneous" ? "HETEROGENEOUS" : "HOMOGENEOUS");
        nativeLog("MAIN: Communication mode overridden via --mode: " + comms_mode_override);
    }
    if (!protocol_override.empty()) {
        cfg.setDefaultProtocol(protocol_override);
        nativeLog("MAIN: Protocol overridden via --protocol: " + protocol_override);
    }

    std::string protocol = cfg.getDefaultProtocol();
    if (protocol.empty()) {
        protocol = "TCP"; // Fallback
    }
    const std::string mode = cfg.getCommsMode();

    nativeLog("MAIN: Calling node.start() with port=" + std::to_string(port) + ", peer_id=" + peer_id
              + ", protocol=" + protocol + ", mode=" + mode);
    
    if (!node.start(port, peer_id, protocol)) {
        std::cerr << "Error: Failed to start P2P node" << std::endl;
        return 1;
    }

    if (!proxy_role.empty()) {
        std::string err;
        if (!node.setProxyRole(proxy_role, &err)) {
            std::cerr << "Warning: failed to set proxy role ('" << proxy_role << "'): "
                      << (err.empty() ? "unknown error" : err) << std::endl;
        }
    }
    
    // Run interactive CLI
    cli.run();
    
    return 0;
}
