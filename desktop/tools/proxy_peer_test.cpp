/**
 * proxy_peer_test.cpp
 *
 * Interactive test tool for proxy network transition scenarios.
 *
 * This tool runs a peer that can:
 * 1. Connect to another peer through an Android proxy gateway
 * 2. Send/receive messages through the proxy
 * 3. Survive network transitions (proxy → direct LAN)
 * 4. Track peer identity across IP changes
 *
 * Usage:
 *   Peer A (acceptor/final hop):
 *     ./proxy_peer_test --id peer_a --port 32001 --role acceptor --gateway <android_id>
 *
 *   Peer B (client):
 *     ./proxy_peer_test --id peer_b --port 32002 --role client --gateway <android_id> --target peer_a
 */

#include "session_manager.h"
#include "proxy_endpoint.h"
#include "config_manager.h"
#include "device_utils.h"
#include "logger.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <signal.h>
#include <sstream>
#include <string>
#include <thread>
#include <arpa/inet.h>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running.store(false);
}

struct Args {
    std::string id;
    uint16_t port = 32001;
    std::string role; // "acceptor" or "client"
    std::string gateway_peer_id;
    std::string target_peer_id; // For client: the final hop peer id
    std::string config_path = "config.json";
    LogLevel log_level = LogLevel::ERROR;
};

static void print_usage(const char* argv0) {
    std::cout
        << "proxy_peer_test - Interactive proxy network transition test\n\n"
        << "Usage:\n"
        << "  " << argv0 << " --id ID --port PORT --role acceptor --gateway ANDROID_ID\n"
        << "  " << argv0 << " --id ID --port PORT --role client --gateway ANDROID_ID --target PEER_ID\n\n"
        << "Options:\n"
        << "  --id ID          Peer ID for this instance\n"
        << "  --port PORT      UDP listen port\n"
        << "  --role ROLE      'acceptor' (final hop) or 'client' (initiator)\n"
        << "  --gateway ID     Android gateway peer ID\n"
        << "  --target ID      Target peer ID (client mode only)\n"
        << "  --config FILE    config.json path\n"
        << "  --log-level LVL  debug|info|warning|error|none\n\n"
        << "Commands (interactive):\n"
        << "  send <message>   Send a message through proxy\n"
        << "  direct           Switch to direct LAN connection (after proxy is down)\n"
        << "  peers            List known peers and their connection status\n"
        << "  identity         Show peer identity tracking info\n"
        << "  quit             Exit\n";
}

static LogLevel parse_log_level(const std::string& value) {
    std::string v = value;
    for (auto& c : v) c = static_cast<char>(::tolower(c));
    if (v == "debug") return LogLevel::DEBUG;
    if (v == "info") return LogLevel::INFO;
    if (v == "warn" || v == "warning") return LogLevel::WARNING;
    if (v == "error") return LogLevel::ERROR;
    if (v == "none") return LogLevel::NONE;
    return LogLevel::ERROR;
}

static bool try_load_config(const std::string& path) {
    try {
        return ConfigManager::getInstance().loadConfig(path);
    } catch (...) {
        return false;
    }
}

static bool load_config_with_fallbacks(const std::string& hint_path, const char* argv0, std::string& chosen) {
    std::vector<std::string> candidates;
    candidates.push_back(hint_path);
    candidates.push_back("../config.json");
    candidates.push_back("../../config.json");
    candidates.push_back("../../../config.json");

    try {
        std::filesystem::path exe_path = std::filesystem::absolute(argv0);
        std::filesystem::path exe_dir = exe_path.parent_path();
        candidates.push_back((exe_dir / "config.json").string());
        candidates.push_back((exe_dir / "../config.json").lexically_normal().string());
        candidates.push_back((exe_dir / "../../config.json").lexically_normal().string());
        candidates.push_back((exe_dir / "../../../config.json").lexically_normal().string());
    } catch (...) {}

    for (const auto& c : candidates) {
        if (try_load_config(c)) {
            chosen = c;
            return true;
        }
    }
    return false;
}

static bool is_private_ipv4(const std::string& ip) {
    struct in_addr addr;
    if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
    const uint32_t h = ntohl(addr.s_addr);
    if ((h & 0xFF000000u) == 0x0A000000u) return true;  // 10.0.0.0/8
    if ((h & 0xFFF00000u) == 0xAC100000u) return true;  // 172.16.0.0/12
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return true;  // 192.168.0.0/16
    return false;
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return false;
        }
        auto need = [&](const char* name) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("Missing value for ") + name);
            return std::string(argv[++i]);
        };

        if (arg == "--id") a.id = need("--id");
        else if (arg == "--port") a.port = static_cast<uint16_t>(std::stoi(need("--port")));
        else if (arg == "--role") a.role = need("--role");
        else if (arg == "--gateway") a.gateway_peer_id = need("--gateway");
        else if (arg == "--target") a.target_peer_id = need("--target");
        else if (arg == "--config") a.config_path = need("--config");
        else if (arg == "--log-level") a.log_level = parse_log_level(need("--log-level"));
        else throw std::runtime_error("Unknown option: " + arg);
    }

    if (a.id.empty()) a.id = get_persistent_device_id();
    if (a.role.empty()) throw std::runtime_error("--role is required");
    if (a.role != "acceptor" && a.role != "client") throw std::runtime_error("--role must be 'acceptor' or 'client'");
    if (a.gateway_peer_id.empty()) throw std::runtime_error("--gateway is required");
    if (a.role == "client" && a.target_peer_id.empty()) throw std::runtime_error("--target is required for client role");

    return true;
}

// Track peer identity across network changes
struct PeerIdentityTracker {
    std::mutex mu;
    
    struct PeerRecord {
        std::string peer_id;
        std::vector<std::string> seen_ips;
        std::vector<std::string> seen_network_ids;
        int connection_count = 0;
        std::string first_seen_via; // "proxy" or "direct"
        std::string last_seen_via;
        std::chrono::steady_clock::time_point first_seen_time;
        std::chrono::steady_clock::time_point last_seen_time;
    };
    
    std::map<std::string, PeerRecord> records;
    
    void record_peer(const std::string& peer_id, const std::string& ip, const std::string& network_id,
                     bool via_proxy) {
        std::lock_guard<std::mutex> lk(mu);
        auto& r = records[peer_id];
        r.peer_id = peer_id;
        
        if (std::find(r.seen_ips.begin(), r.seen_ips.end(), ip) == r.seen_ips.end() && !ip.empty()) {
            r.seen_ips.push_back(ip);
        }
        if (std::find(r.seen_network_ids.begin(), r.seen_network_ids.end(), network_id) == r.seen_network_ids.end() && !network_id.empty()) {
            r.seen_network_ids.push_back(network_id);
        }
        
        r.connection_count++;
        std::string via = via_proxy ? "proxy" : "direct";
        if (r.first_seen_via.empty()) {
            r.first_seen_via = via;
            r.first_seen_time = Clock::now();
        }
        r.last_seen_via = via;
        r.last_seen_time = Clock::now();
    }
    
    void print_report() {
        std::lock_guard<std::mutex> lk(mu);
        std::cout << "\n=== PEER IDENTITY TRACKING ===\n";
        for (const auto& kv : records) {
            const auto& r = kv.second;
            std::cout << "Peer: " << r.peer_id << "\n";
            std::cout << "  Connection count: " << r.connection_count << "\n";
            std::cout << "  First seen via: " << r.first_seen_via << "\n";
            std::cout << "  Last seen via: " << r.last_seen_via << "\n";
            std::cout << "  Seen IPs: ";
            for (size_t i = 0; i < r.seen_ips.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << r.seen_ips[i];
            }
            std::cout << "\n";
            std::cout << "  Seen network_ids: ";
            for (size_t i = 0; i < r.seen_network_ids.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << r.seen_network_ids[i];
            }
            std::cout << "\n";
            
            bool same_peer_different_network = r.seen_ips.size() > 1;
            if (same_peer_different_network) {
                std::cout << "  >>> SAME PEER detected across DIFFERENT NETWORKS <<<\n";
            }
        }
        std::cout << "==============================\n\n";
    }
};

} // namespace

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

#if !ENABLE_PROXY_MODULE
    std::cerr << "proxy_peer_test requires ENABLE_PROXY_MODULE=ON" << std::endl;
    return 2;
#else
    Args args;
    try {
        if (!parse_args(argc, argv, args)) return 0;
    } catch (const std::exception& e) {
        std::cerr << "Argument error: " << e.what() << "\n\n";
        print_usage(argv[0]);
        return 2;
    }

    set_log_level(args.log_level);

    std::string chosen_cfg;
    if (!load_config_with_fallbacks(args.config_path, argv[0], chosen_cfg)) {
        std::cerr << "CRITICAL: Failed to load config.json" << std::endl;
        return 2;
    }

    std::string protocol = ConfigManager::getInstance().getDefaultProtocol();
    if (protocol.empty()) protocol = "UDP";

    SessionManager sm;
    PeerIdentityTracker tracker;

    std::mutex peers_mu;
    std::map<std::string, Peer> known_peers;
    std::condition_variable peers_cv;

    // Message tracking
    std::mutex msg_mu;
    int messages_sent = 0;
    int messages_received = 0;

    sm.start(args.port,
             [&](const std::vector<Peer>& peers) {
                 std::lock_guard<std::mutex> lk(peers_mu);
                 for (const auto& p : peers) {
                     bool is_new = known_peers.find(p.id) == known_peers.end();
                     bool was_connected = known_peers.count(p.id) && known_peers[p.id].connected;
                     known_peers[p.id] = p;
                     
                     if (p.connected && !was_connected) {
                         bool via_proxy = !is_private_ipv4(p.ip);
                         tracker.record_peer(p.id, p.ip, p.network_id, via_proxy);
                         std::cout << "[CONNECTED] " << p.id << " ip=" << p.ip << " port=" << p.port
                                   << " via=" << (via_proxy ? "PROXY" : "DIRECT_LAN") << "\n";
                     } else if (!p.connected && was_connected) {
                         std::cout << "[DISCONNECTED] " << p.id << "\n";
                     }
                 }
                 peers_cv.notify_all();
             },
             protocol,
             args.id);

    auto wait_connected = [&](const std::string& id, int ms) -> bool {
        auto deadline = Clock::now() + std::chrono::milliseconds(ms);
        std::unique_lock<std::mutex> lk(peers_mu);
        while (Clock::now() < deadline) {
            auto it = known_peers.find(id);
            if (it != known_peers.end() && it->second.connected) return true;
            peers_cv.wait_for(lk, std::chrono::milliseconds(50));
        }
        return false;
    };

    // Configure proxy
    auto* px = sm.get_proxy_endpoint();
    if (!px) {
        std::cerr << "CRITICAL: proxy endpoint not available" << std::endl;
        return 2;
    }

    if (args.role == "acceptor") {
        // This tool is a harness. Enable client mode so the acceptor can send echoed bytes back.
        sm.configure_proxy(proxy::ProxySettings{.enable_gateway = true, .enable_client = true, .enable_test_echo = true});
    } else {
        sm.configure_proxy(proxy::ProxySettings{.enable_gateway = false, .enable_client = true});
    }

    // Set up message callbacks
    const uint32_t stream_id = 999999;

    px->set_control_callback([&](const std::string& from, const proxy::json& msg) {
        const std::string type = msg.value("type", "");
        std::cout << "[PROXY_CTRL] from=" << from << " type=" << type;
        if (type == proxy::kProxyAccept) {
            // Legacy behavior: dumb-proxy mode should not emit ACCEPT/REJECT.
            std::cout << " for=" << msg.value("for", "") << " ok=" << (msg.value("ok", false) ? 1 : 0);
        }
        std::cout << "\n";
    });

    px->set_stream_data_callback([&](const std::string& from, uint32_t sid, std::string_view data, bool is_close) {
        std::lock_guard<std::mutex> lk(msg_mu);
        if (is_close) {
            std::cout << "[STREAM CLOSED] from=" << from << " stream=" << sid << "\n";
            return;
        }
        messages_received++;
        std::cout << "[MESSAGE RECEIVED] from=" << from << " stream=" << sid
                  << " data=\"" << std::string(data) << "\" (total received: " << messages_received << ")\n";
        
        // If acceptor, echo back
        if (args.role == "acceptor") {
            std::string reply = "ECHO: " + std::string(data);
            px->client_send_stream_data(from, sid, reply);
            std::cout << "[MESSAGE SENT] echo to=" << from << "\n";
        }
    });

    std::cout << "\n========================================\n";
    std::cout << "PROXY PEER TEST - " << args.role << " mode\n";
    std::cout << "  Peer ID: " << args.id << "\n";
    std::cout << "  Port: " << args.port << "\n";
    std::cout << "  Gateway: " << args.gateway_peer_id << "\n";
    if (args.role == "client") {
        std::cout << "  Target: " << args.target_peer_id << "\n";
    }
    std::cout << "========================================\n\n";

    // Connect to gateway
    std::cout << "Connecting to Android gateway...\n";
    bool gateway_connected = false;
    for (int i = 0; i < 20 && !gateway_connected; ++i) {
        sm.connectToPeer(args.gateway_peer_id);
        gateway_connected = wait_connected(args.gateway_peer_id, 1000);
    }

    if (!gateway_connected) {
        std::cerr << "Failed to connect to gateway within 20s\n";
        // Continue anyway for interactive mode
    }

    // Client: best-effort OPEN_STREAM to establish routing state (no proxy-level handshake)
    if (args.role == "client") {
        std::cout << "Sending OPEN_STREAM to gateway (best-effort)...\n";
        for (int i = 0; i < 3; ++i) {
            px->client_open_stream(args.gateway_peer_id, stream_id, "TCP", "", 0,
                                   std::vector<std::string>{args.target_peer_id});
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        std::cout << "Ready to send messages through proxy (no OPEN/ACCEPT confirmation in dumb-proxy mode).\n";
    }

    std::cout << "\nInteractive mode. Commands:\n";
    std::cout << "  send <message>  - Send message through proxy\n";
    std::cout << "  direct          - Connect directly to target (LAN)\n";
    std::cout << "  peers           - List known peers\n";
    std::cout << "  identity        - Show peer identity tracking\n";
    std::cout << "  quit            - Exit\n\n";

    // Interactive loop
    std::string line;
    while (g_running.load() && std::getline(std::cin, line)) {
        if (line.empty()) continue;
        
        if (line == "quit" || line == "exit") {
            break;
        } else if (line == "peers") {
            std::lock_guard<std::mutex> lk(peers_mu);
            std::cout << "\n=== KNOWN PEERS ===\n";
            for (const auto& kv : known_peers) {
                const auto& p = kv.second;
                std::cout << "  " << p.id << " ip=" << p.ip << " port=" << p.port
                          << " connected=" << (p.connected ? "YES" : "NO")
                          << " latency=" << p.latency << "ms"
                          << " network=" << p.network_id << "\n";
            }
            std::cout << "===================\n\n";
        } else if (line == "identity") {
            tracker.print_report();
        } else if (line == "direct") {
            // Attempt direct LAN connection to target
            std::string target = (args.role == "client") ? args.target_peer_id : "";
            if (target.empty()) {
                std::cout << "Enter target peer ID: ";
                std::getline(std::cin, target);
            }
            if (!target.empty()) {
                std::cout << "Attempting direct LAN connection to " << target << "...\n";
                sm.connectToPeer(target);
                if (wait_connected(target, 10000)) {
                    std::lock_guard<std::mutex> lk(peers_mu);
                    auto it = known_peers.find(target);
                    if (it != known_peers.end()) {
                        std::cout << "Direct connection established: ip=" << it->second.ip << "\n";
                    }
                } else {
                    std::cout << "Direct connection not established within 10s\n";
                }
            }
        } else if (line.substr(0, 5) == "send ") {
            std::string msg = line.substr(5);
            if (args.role == "client") {
                px->client_send_stream_data(args.gateway_peer_id, stream_id, msg);
                std::lock_guard<std::mutex> lk(msg_mu);
                messages_sent++;
                std::cout << "[MESSAGE SENT] \"" << msg << "\" (total sent: " << messages_sent << ")\n";
            } else if (args.role == "acceptor") {
                std::cout << "Acceptor receives messages; use client to send.\n";
            } else {
                std::cout << "Client role required to send.\n";
            }
        } else {
            std::cout << "Unknown command. Type 'quit' to exit.\n";
        }
    }

    std::cout << "\n=== FINAL SUMMARY ===\n";
    {
        std::lock_guard<std::mutex> lk(msg_mu);
        std::cout << "Messages sent: " << messages_sent << "\n";
        std::cout << "Messages received: " << messages_received << "\n";
    }
    tracker.print_report();

    sm.stop();
    return 0;
#endif
}
