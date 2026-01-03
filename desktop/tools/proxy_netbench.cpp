#include "session_manager.h"
#include "proxy_endpoint.h"

#include "wire_codec.h"

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
#include <numeric>
#include <optional>
#include <signal.h>
#include <sstream>
#include <string>
#include <thread>
#include <arpa/inet.h>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

struct Args {
    std::string mode; // acceptor | rtt | gateway | final | admin

    uint16_t port = 30001;
    std::string peer_id;
    std::string config_path = "config.json";
    LogLevel log_level = LogLevel::ERROR;

    // RTT mode
    std::string gateway_peer_id;
    std::string final_peer_id;
    // Optional explicit route hops (excluding the initial gateway). If provided, RTT mode will
    // open a proxied stream with route=[...hops..., final].
    std::vector<std::string> route_peer_ids;
    int count = 200;
    int interval_ms = 50;
    int timeout_ms = 2000;

    // Acceptor/gateway/final modes
    // Optional: proactively connect to one or more peers so routing/handshakes are established.
    // Can be specified multiple times.
    std::vector<std::string> connect_peer_ids;

    // Final mode
    bool final_echo = true;

    // Diagnostics
    bool print_peers = false;

    // Admin mode
    std::string admin_target_peer_id;
    std::string admin_role; // gateway | exit | client | off
    std::optional<bool> admin_enable_gateway;
    std::optional<bool> admin_enable_client;
    std::optional<bool> admin_enable_test_echo;
    int admin_timeout_ms = -1; // if unset, falls back to --timeout-ms
};

static void print_usage(const char* argv0) {
    std::cout
        << "proxy_netbench - proxy/mobile network measurement tool\n\n"
        << "Usage:\n"
        << "  " << argv0 << " --mode acceptor [--id ID] [--port PORT] [--config FILE] [--log-level LVL]\n"
        << "        [--connect PEER_ID]...\n"
        << "  " << argv0 << " --mode gateway --id ID --port PORT [--config FILE] [--log-level LVL]\n"
        << "        --connect PEER_ID [--connect PEER_ID]...\n"
        << "  " << argv0 << " --mode final --id ID --port PORT [--config FILE] [--log-level LVL]\n"
        << "        [--connect PEER_ID]... [--final-echo 0|1]\n"
        << "  " << argv0 << " --mode rtt --gateway PEER_ID --final PEER_ID [--id ID] [--port PORT]\n"
        << "        [--count N] [--interval-ms MS] [--timeout-ms MS] [--config FILE] [--log-level LVL]\n\n"
        << "  " << argv0 << " --mode admin --target PEER_ID [--role gateway|exit|client|off]\n"
        << "        [--enable-gateway 0|1] [--enable-client 0|1] [--enable-test-echo 0|1]\n"
        << "        [--timeout-ms MS] [--id ID] [--port PORT] [--config FILE] [--log-level LVL]\n\n"
        << "Modes:\n"
        << "  acceptor  Starts an engine peer with proxy gateway enabled (final hop echo).\n"
        << "  gateway   Starts a proxy gateway peer (forwards A->C, no echo).\n"
        << "  final     Starts a final-hop peer that logs who it sees as sender and (optionally) echoes.\n"
        << "  rtt       Connects to a gateway peer and measures RTT/jitter for a proxied echo path.\n\n"
        << "  admin     Sends an LP_ADMIN control message (over APPLICATION_DATA) to a target peer.\n\n"
        << "Notes:\n"
        << "  - This tool measures application-level RTT over the Proxy module (PROXY_STREAM_DATA echo).\n"
        << "  - For a forced Android path B->Android->A->Android->B, start Android with proxy gateway enabled\n"
        << "    and ensure Android is connected to A (e.g., have A connect to Android once).\n\n"
        << "Options:\n"
        << "  --mode M         acceptor|gateway|final|rtt\n"
        << "  --id ID          explicit peer id (default: persistent device id)\n"
        << "  --port PORT      listen port (default: 30001)\n"
        << "  --config FILE    config.json path hint (default: config.json)\n"
        << "  --log-level LVL  debug|info|warning|error|none (default: error)\n"
        << "  --gateway ID     gateway peer id (Android) [rtt]\n"
        << "                  Use 'auto' to pick the first discovered peer id (useful for quick demos).\n"
        << "  --final ID       final hop peer id (A) [rtt]\n"
        << "  --route ID       (rtt) add a route hop after the gateway. May be repeated.\n"
        << "                  Example: --gateway Android --route peer_b --final peer_c => Android->peer_b->peer_c\n"
        << "  --connect ID     (acceptor/gateway/final) proactively connect to this peer. May be repeated.\n"
        << "  --final-echo B   (final) echo received bytes back through the proxy (default: 1)\n"
        << "  --count N        number of pings (default: 200)\n"
        << "  --interval-ms MS delay between pings (default: 50)\n"
        << "  --timeout-ms MS  per-ping timeout (default: 2000)\n";
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
    } catch (...) {
        // ignore
    }

    for (const auto& c : candidates) {
        if (try_load_config(c)) {
            chosen = c;
            return true;
        }
    }

    return false;
}

static uint64_t now_ns() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count());
}

static void put_u64_be(std::string& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<char>((v >> (i * 8)) & 0xFF));
    }
}

static bool get_u64_be(std::string_view s, size_t off, uint64_t& v) {
    if (off + 8 > s.size()) return false;
    v = 0;
    for (size_t i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<unsigned char>(s[off + i]);
    }
    return true;
}

struct Stats {
    double min_ms = 0;
    double max_ms = 0;
    double mean_ms = 0;
    double stddev_ms = 0;
    double p50_ms = 0;
    double p90_ms = 0;
    double p99_ms = 0;
    double jitter_ms = 0; // mean abs diff between consecutive samples
};

static double percentile_ms(std::vector<double> v, double p) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double clamped = std::max(0.0, std::min(1.0, p));
    const double idx = clamped * (static_cast<double>(v.size() - 1));
    const size_t lo = static_cast<size_t>(std::floor(idx));
    const size_t hi = static_cast<size_t>(std::ceil(idx));
    if (lo == hi) return v[lo];
    const double frac = idx - static_cast<double>(lo);
    return v[lo] * (1.0 - frac) + v[hi] * frac;
}

static Stats compute_stats_ms(const std::vector<double>& samples_ms) {
    Stats s;
    if (samples_ms.empty()) return s;

    s.min_ms = *std::min_element(samples_ms.begin(), samples_ms.end());
    s.max_ms = *std::max_element(samples_ms.begin(), samples_ms.end());
    s.mean_ms = std::accumulate(samples_ms.begin(), samples_ms.end(), 0.0) / static_cast<double>(samples_ms.size());

    double var = 0.0;
    for (double x : samples_ms) {
        const double d = x - s.mean_ms;
        var += d * d;
    }
    var /= static_cast<double>(samples_ms.size());
    s.stddev_ms = std::sqrt(var);

    s.p50_ms = percentile_ms(samples_ms, 0.50);
    s.p90_ms = percentile_ms(samples_ms, 0.90);
    s.p99_ms = percentile_ms(samples_ms, 0.99);

    if (samples_ms.size() >= 2) {
        double acc = 0.0;
        for (size_t i = 1; i < samples_ms.size(); ++i) {
            acc += std::abs(samples_ms[i] - samples_ms[i - 1]);
        }
        s.jitter_ms = acc / static_cast<double>(samples_ms.size() - 1);
    }

    return s;
}

static std::string json_escape(std::string s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                    out += oss.str();
                } else {
                    out.push_back(c);
                }
                break;
        }
    }
    return out;
}

static bool parse_args(int argc, char** argv, Args& a) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return false;
        }
        auto need = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string("Missing value for ") + name);
            }
            return std::string(argv[++i]);
        };

        if (arg == "--mode") {
            a.mode = need("--mode");
        } else if (arg == "--id") {
            a.peer_id = need("--id");
        } else if (arg == "--port") {
            a.port = static_cast<uint16_t>(std::stoi(need("--port")));
        } else if (arg == "--config") {
            a.config_path = need("--config");
        } else if (arg == "--log-level") {
            a.log_level = parse_log_level(need("--log-level"));
        } else if (arg == "--gateway") {
            a.gateway_peer_id = need("--gateway");
        } else if (arg == "--final") {
            a.final_peer_id = need("--final");
        } else if (arg == "--route") {
            a.route_peer_ids.push_back(need("--route"));
        } else if (arg == "--connect") {
            a.connect_peer_ids.push_back(need("--connect"));
        } else if (arg == "--final-echo") {
            const std::string v = need("--final-echo");
            a.final_echo = (v != "0");
        } else if (arg == "--count") {
            a.count = std::stoi(need("--count"));
        } else if (arg == "--interval-ms") {
            a.interval_ms = std::stoi(need("--interval-ms"));
        } else if (arg == "--timeout-ms") {
            a.timeout_ms = std::stoi(need("--timeout-ms"));
        } else if (arg == "--target") {
            a.admin_target_peer_id = need("--target");
        } else if (arg == "--role") {
            a.admin_role = need("--role");
        } else if (arg == "--enable-gateway") {
            const std::string v = need("--enable-gateway");
            a.admin_enable_gateway = (v != "0");
        } else if (arg == "--enable-client") {
            const std::string v = need("--enable-client");
            a.admin_enable_client = (v != "0");
        } else if (arg == "--enable-test-echo") {
            const std::string v = need("--enable-test-echo");
            a.admin_enable_test_echo = (v != "0");
        } else if (arg == "--admin-timeout-ms") {
            a.admin_timeout_ms = std::stoi(need("--admin-timeout-ms"));
        } else if (arg == "--print-peers") {
            a.print_peers = true;
        } else {
            throw std::runtime_error("Unknown option: " + arg);
        }
    }

    if (a.mode.empty()) {
        throw std::runtime_error("--mode is required");
    }

    if (a.port == 0) {
        throw std::runtime_error("--port must be between 1 and 65535");
    }

    if (a.peer_id.empty()) {
        a.peer_id = get_persistent_device_id();
    }

    if (a.mode == "rtt") {
        if (a.gateway_peer_id.empty()) throw std::runtime_error("--gateway is required for rtt mode");
        if (a.final_peer_id.empty()) throw std::runtime_error("--final is required for rtt mode");
        if (a.count <= 0) throw std::runtime_error("--count must be > 0");
        if (a.interval_ms < 0) throw std::runtime_error("--interval-ms must be >= 0");
        if (a.timeout_ms <= 0) throw std::runtime_error("--timeout-ms must be > 0");
    } else if (a.mode == "acceptor") {
        // ok
    } else if (a.mode == "gateway") {
        if (a.connect_peer_ids.empty()) throw std::runtime_error("--connect is required for gateway mode (downstream peer(s))");
    } else if (a.mode == "final") {
        // ok
    } else if (a.mode == "admin") {
        if (a.admin_target_peer_id.empty()) throw std::runtime_error("--target is required for admin mode");
        if (a.admin_timeout_ms <= 0) {
            a.admin_timeout_ms = a.timeout_ms;
        }
        if (a.admin_timeout_ms <= 0) throw std::runtime_error("--timeout-ms must be > 0");
    } else {
        throw std::runtime_error("Unsupported --mode: " + a.mode);
    }

    return true;
}

static bool is_private_ipv4(const std::string& ip) {
    struct in_addr addr;
    if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }

    const uint32_t h = ntohl(addr.s_addr);

    // 10.0.0.0/8
    if ((h & 0xFF000000u) == 0x0A000000u) return true;
    // 172.16.0.0/12
    if ((h & 0xFFF00000u) == 0xAC100000u) return true;
    // 192.168.0.0/16
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return true;

    return false;
}

// Minimal LPX1 tunnel encoding (for final-hop echo in dumb-proxy mode).
static std::string encode_lpx1_tunnel(uint32_t flow_id, std::string_view data, uint8_t flags = 0) {
    auto put_u32_be_local = [](std::string& out, uint32_t v) {
        out.push_back(static_cast<char>((v >> 24) & 0xFF));
        out.push_back(static_cast<char>((v >> 16) & 0xFF));
        out.push_back(static_cast<char>((v >> 8) & 0xFF));
        out.push_back(static_cast<char>(v & 0xFF));
    };

    std::string payload;
    payload.reserve(4 + 1 + 1 + 4 + data.size());
    payload.append("LPX1", 4);
    payload.push_back(static_cast<char>(2)); // kind=TUNNEL
    payload.push_back(static_cast<char>(flags));
    put_u32_be_local(payload, flow_id);
    payload.append(data.data(), data.size());
    return payload;
}

} // namespace

int main(int argc, char** argv) {
    // Ignore SIGPIPE to prevent process termination on socket write errors
    signal(SIGPIPE, SIG_IGN);

#if !ENABLE_PROXY_MODULE
    std::cerr << "proxy_netbench requires ENABLE_PROXY_MODULE=ON" << std::endl;
    return 2;
#else
    Args args;
    try {
        if (!parse_args(argc, argv, args)) {
            return 0;
        }
    } catch (const std::exception& e) {
        std::cerr << "Argument error: " << e.what() << "\n\n";
        print_usage(argv[0]);
        return 2;
    }

    set_log_level(args.log_level);

    std::string chosen_cfg;
    if (!load_config_with_fallbacks(args.config_path, argv[0], chosen_cfg)) {
        std::cerr << "CRITICAL: Failed to load config.json (hint='" << args.config_path << "')." << std::endl;
        return 2;
    }

    std::string protocol = ConfigManager::getInstance().getDefaultProtocol();
    if (protocol.empty()) protocol = "TCP";

    SessionManager sm;

    std::mutex peers_mu;
    std::map<std::string, bool> connected;
    std::map<std::string, Peer> last_peer;
    std::condition_variable peers_cv;

    sm.start(args.port,
             [&](const std::vector<Peer>& peers) {
                 std::lock_guard<std::mutex> lk(peers_mu);
                 for (const auto& p : peers) {
                     connected[p.id] = p.connected;
                     last_peer[p.id] = p;

                     if (args.print_peers) {
                         std::cout << "PEER id=" << p.id << " ip=" << p.ip << " port=" << p.port
                                   << " connected=" << (p.connected ? 1 : 0)
                                   << " latency=" << p.latency
                                   << " network_id=" << p.network_id
                                   << "\n";
                         std::cout.flush();
                     }
                 }
                 peers_cv.notify_all();
             },
             protocol,
             args.peer_id);

    auto wait_connected = [&](const std::string& id, int ms) -> bool {
        const int wait_ms = std::max(0, ms);
        auto deadline = Clock::now() + std::chrono::milliseconds(wait_ms);
        std::unique_lock<std::mutex> lk(peers_mu);
        for (;;) {
            auto it = connected.find(id);
            if (it != connected.end() && it->second) return true;

            if (wait_ms == 0 || Clock::now() >= deadline) {
                break;
            }
            peers_cv.wait_for(lk, std::chrono::milliseconds(50));
        }
        return false;
    };

    auto wait_peer_private_ip = [&](const std::string& id, int ms) -> bool {
        auto deadline = Clock::now() + std::chrono::milliseconds(ms);
        std::unique_lock<std::mutex> lk(peers_mu);
        while (Clock::now() < deadline) {
            auto it = last_peer.find(id);
            if (it != last_peer.end() && is_private_ipv4(it->second.ip)) {
                return true;
            }
            peers_cv.wait_for(lk, std::chrono::milliseconds(100));
        }
        return false;
    };

    auto wait_peer_discovered = [&](const std::string& id, int ms) -> bool {
        auto deadline = Clock::now() + std::chrono::milliseconds(ms);
        std::unique_lock<std::mutex> lk(peers_mu);
        while (Clock::now() < deadline) {
            if (last_peer.find(id) != last_peer.end()) {
                return true;
            }
            peers_cv.wait_for(lk, std::chrono::milliseconds(100));
        }
        return false;
    };

    if (args.mode == "admin") {
        const std::string target = args.admin_target_peer_id;
        const std::string request_id = std::to_string(now_ns());

        std::mutex ack_mu;
        std::condition_variable ack_cv;
        bool acked = false;
        std::string ack_payload;

        sm.setMessageReceivedCallback([&](const std::string& from_peer_id, const std::string& message) {
            if (from_peer_id != target) return;
            // Minimal gate: only capture LP_ADMIN_ACK matching our request_id.
            if (message.find("LP_ADMIN_ACK") == std::string::npos) return;
            if (message.find(request_id) == std::string::npos) return;
            {
                std::lock_guard<std::mutex> lk(ack_mu);
                acked = true;
                ack_payload = message;
            }
            ack_cv.notify_all();
        });

        // Discovery/connect.
        (void)wait_peer_discovered(target, std::min(2000, args.admin_timeout_ms));
        sm.connectToPeer(target);
        (void)wait_connected(target, std::min(3000, args.admin_timeout_ms));

        std::ostringstream oss;
        oss << "{"
            << "\"type\":\"LP_ADMIN\","
            << "\"version\":1,"
            << "\"cmd\":\"SET_PROXY_SETTINGS\","
            << "\"target_peer_id\":\"" << json_escape(target) << "\","
            << "\"request_id\":\"" << json_escape(request_id) << "\"";

        if (!args.admin_role.empty()) {
            oss << ",\"role\":\"" << json_escape(args.admin_role) << "\"";
        }

        if (args.admin_enable_gateway.has_value() || args.admin_enable_client.has_value() || args.admin_enable_test_echo.has_value()) {
            oss << ",\"settings\":{";
            bool first = true;
            auto put_bool = [&](const char* key, std::optional<bool> v) {
                if (!v.has_value()) return;
                if (!first) oss << ",";
                first = false;
                oss << "\"" << key << "\":" << (*v ? "true" : "false");
            };
            put_bool("enable_gateway", args.admin_enable_gateway);
            put_bool("enable_client", args.admin_enable_client);
            put_bool("enable_test_echo", args.admin_enable_test_echo);
            oss << "}";
        }

        oss << "}";
        const std::string cmd = oss.str();

        std::cout << "ADMIN_SEND to=" << target << " request_id=" << request_id << " payload=" << cmd << "\n";
        std::cout.flush();

        sm.sendMessageToPeer(target, cmd);

        // Wait for ack.
        {
            std::unique_lock<std::mutex> lk(ack_mu);
            ack_cv.wait_for(lk, std::chrono::milliseconds(args.admin_timeout_ms), [&] { return acked; });
        }

        if (acked) {
            std::cout << "ADMIN_ACK from=" << target << " payload=" << ack_payload << "\n";
            std::cout.flush();
            sm.stop();
            return 0;
        }

        std::cerr << "ADMIN_ERROR: timed out waiting for LP_ADMIN_ACK (timeout_ms=" << args.admin_timeout_ms << ")\n";
        sm.stop();
        return 1;
    }

    // Configure proxy roles.
    if (auto* px = sm.get_proxy_endpoint()) {
        if (args.mode == "acceptor") {
            sm.configure_proxy(proxy::ProxySettings{.enable_gateway = true, .enable_client = false, .enable_test_echo = true});

            // Diagnostics: print any proxy control messages we receive (helps confirm forwarding).
            px->set_control_callback([&](const std::string& from_peer_id, const proxy::json& msg) {
                const std::string type = msg.value("type", "");
                std::cout << "ACCEPTOR_PROXY_CTRL from=" << from_peer_id << " type=" << type;
                if (type == proxy::kProxyAccept) {
                    std::cout << " for=" << msg.value("for", "")
                              << " ok=" << (msg.value("ok", false) ? 1 : 0);
                    const uint32_t sid = msg.value("stream_id", 0u);
                    if (sid != 0u) std::cout << " stream_id=" << sid;
                    const std::string err = msg.value("error", "");
                    if (!err.empty()) std::cout << " error=" << err;
                } else if (type == proxy::kProxyOpenStream || type == proxy::kProxyCloseStream) {
                    const uint32_t sid = msg.value("stream_id", 0u);
                    if (sid != 0u) std::cout << " stream_id=" << sid;
                    const std::string reason = msg.value("reason", "");
                    if (!reason.empty()) std::cout << " reason=" << reason;
                }
                std::cout << "\n";
                std::cout.flush();
            });
        } else if (args.mode == "gateway") {
            sm.configure_proxy(proxy::ProxySettings{.enable_gateway = true, .enable_client = false, .enable_test_echo = false});

            px->set_control_callback([&](const std::string& from_peer_id, const proxy::json& msg) {
                const std::string type = msg.value("type", "");
                std::cout << "GATEWAY_PROXY_CTRL from=" << from_peer_id << " type=" << type << "\n";
                std::cout.flush();
            });
        } else if (args.mode == "final") {
            // Final hop does NOT behave as a proxy gateway. It only observes incoming proxy frames.
            // We keep test_echo off so the callback always fires (then we explicitly echo if requested).
            sm.configure_proxy(proxy::ProxySettings{.enable_gateway = false, .enable_client = false, .enable_test_echo = false});

            px->set_stream_data_callback([&](const std::string& from_peer_id, uint32_t stream_id, std::string_view data, bool is_close) {
                std::string from_network;
                {
                    std::lock_guard<std::mutex> lk(peers_mu);
                    auto it = last_peer.find(from_peer_id);
                    if (it != last_peer.end()) {
                        from_network = it->second.network_id;
                    }
                }

                if (is_close) {
                    std::cout << "FINAL_STREAM_CLOSED from=" << from_peer_id << " from_network_id=" << from_network
                              << " stream_id=" << stream_id << "\n";
                    std::cout.flush();
                    return;
                }

                std::cout << "FINAL_RX from=" << from_peer_id << " from_network_id=" << from_network
                          << " stream_id=" << stream_id << " len=" << data.size() << "\n";
                std::cout.flush();

                if (args.final_echo) {
                    const std::string lpx = encode_lpx1_tunnel(stream_id, data, 0);
                    sm.sendMessageToPeer(from_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, lpx));
                }
            });
        } else {
            sm.configure_proxy(proxy::ProxySettings{.enable_gateway = false, .enable_client = true});
        }
    }

    auto spawn_connect_thread = [&](const std::string& who, const std::string& connect_to) {
        if (connect_to.empty()) {
            return;
        }

        std::thread([&]() {
            bool announced = false;
            bool waited_for_private = false;
            for (;;) {
                // Prefer LAN/private IP connectivity when available.
                if (!waited_for_private) {
                    (void)wait_peer_private_ip(connect_to, 10000);
                    waited_for_private = true;
                }

                sm.connectToPeer(connect_to);

                if (wait_connected(connect_to, 5000)) {
                    std::lock_guard<std::mutex> lk(peers_mu);
                    auto it = last_peer.find(connect_to);
                    if (it != last_peer.end() && !announced) {
                        const auto& p = it->second;
                        std::cout << who << "_CONNECTED id=" << p.id << " ip=" << p.ip << " port=" << p.port
                                  << " network_id=" << p.network_id << "\n";
                        std::cout.flush();
                        announced = true;
                    }
                    break;
                }

                if (!announced) {
                    std::cerr << who << "_CONNECT_PENDING id=" << connect_to << "\n";
                    std::cerr.flush();
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }).detach();
    };

    if (args.mode == "acceptor") {
        std::cout << "ACCEPTOR_READY peer_id=" << args.peer_id << " port=" << args.port << " protocol=" << protocol << "\n";
        std::cout << "(Leave this running. It will echo proxy stream bytes as the final hop.)\n";
        std::cout.flush();

        // Optional: proactively connect to a peer (typically the Android gateway) so it can forward
        // OPEN_STREAM frames to this final hop.
        for (const auto& id : args.connect_peer_ids) {
            spawn_connect_thread("ACCEPTOR", id);
        }

        // Idle forever.
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
    }

    if (args.mode == "gateway") {
        std::cout << "GATEWAY_READY peer_id=" << args.peer_id << " port=" << args.port << " protocol=" << protocol;
        if (!args.connect_peer_ids.empty()) {
            std::cout << " connect=[";
            for (size_t i = 0; i < args.connect_peer_ids.size(); ++i) {
                if (i) std::cout << ",";
                std::cout << args.connect_peer_ids[i];
            }
            std::cout << "]";
        }
        std::cout << "\n";
        std::cout.flush();
        for (const auto& id : args.connect_peer_ids) {
            spawn_connect_thread("GATEWAY", id);
        }
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
    }

    if (args.mode == "final") {
        std::cout << "FINAL_READY peer_id=" << args.peer_id << " port=" << args.port << " protocol=" << protocol
                  << " echo=" << (args.final_echo ? 1 : 0) << "\n";
        std::cout.flush();
        // Optional: connect to gateway/peers so the gateway can immediately send to us.
        for (const auto& id : args.connect_peer_ids) {
            spawn_connect_thread("FINAL", id);
        }
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
    }

    // RTT mode
    auto* px = sm.get_proxy_endpoint();
    if (!px) {
        std::cerr << "CRITICAL: proxy endpoint not available (unexpected)" << std::endl;
        return 2;
    }

    // In dumb-proxy mode, there is no proxy-level ACCEPT/REJECT.
    // Keep a mutex for potential future diagnostics, but do not gate progress on control acks.
    std::mutex ctl_mu;
    std::condition_variable ctl_cv;

    std::mutex rx_mu;
    std::condition_variable rx_cv;
    std::map<uint64_t, double> rtts_ms;

    px->set_control_callback([&](const std::string& from_peer_id, const proxy::json& msg) {
        const std::string type = msg.value("type", "");

        // Print all control messages for debugging.
        std::cout << "PROXY_CTRL from=" << from_peer_id << " type=" << type;
        if (type == proxy::kProxyAccept) {
            std::cout << " for=" << msg.value("for", "")
                      << " ok=" << (msg.value("ok", false) ? 1 : 0);
            const uint32_t sid = msg.value("stream_id", 0u);
            if (sid != 0u) std::cout << " stream_id=" << sid;
            const std::string err = msg.value("error", "");
            if (!err.empty()) std::cout << " error=" << err;
        } else if (type == proxy::kProxyOpenStream || type == proxy::kProxyCloseStream) {
            const uint32_t sid = msg.value("stream_id", 0u);
            if (sid != 0u) std::cout << " stream_id=" << sid;
            const std::string reason = msg.value("reason", "");
            if (!reason.empty()) std::cout << " reason=" << reason;
        }
        std::cout << "\n";
        std::cout.flush();
    });

    px->set_stream_data_callback([&](const std::string& from_peer_id, uint32_t stream_id, std::string_view data, bool is_close) {
        (void)from_peer_id;
        (void)stream_id;
        (void)is_close;

        // Expected payload: [seq u64 BE][send_ts_ns u64 BE]
        uint64_t seq = 0;
        uint64_t send_ts = 0;
        if (!get_u64_be(data, 0, seq)) return;
        if (!get_u64_be(data, 8, send_ts)) return;

        const uint64_t recv_ts = now_ns();
        const double rtt_ms = static_cast<double>(recv_ts - send_ts) / 1e6;

        std::lock_guard<std::mutex> lk(rx_mu);
        // First one wins.
        if (rtts_ms.find(seq) == rtts_ms.end()) {
            rtts_ms[seq] = rtt_ms;
            rx_cv.notify_all();
        }
    });

    auto wait_any_peer = [&](int ms) -> std::optional<std::string> {
        auto deadline = Clock::now() + std::chrono::milliseconds(ms);
        std::unique_lock<std::mutex> lk(peers_mu);
        while (Clock::now() < deadline) {
            // Prefer LAN/private IP peers first (avoids wrong external-mapped placeholders on same NAT).
            for (const auto& kv : last_peer) {
                if (kv.first == args.peer_id) continue;
                if (is_private_ipv4(kv.second.ip)) {
                    return kv.first;
                }
            }
            // Fallback: any non-self peer id.
            for (const auto& kv : last_peer) {
                if (kv.first != args.peer_id) return kv.first;
            }
            peers_cv.wait_for(lk, std::chrono::milliseconds(100));
        }
        return std::nullopt;
    };

    // Resolve gateway if requested.
    if (args.gateway_peer_id == "auto") {
        auto maybe = wait_any_peer(10000);
        if (!maybe) {
            std::cerr << "--gateway auto: no peers discovered within 10s."
                      << " Ensure Android is running and connected to signaling." << std::endl;
            return 1;
        }
        args.gateway_peer_id = *maybe;
        std::cout << "AUTO_GATEWAY_SELECTED id=" << args.gateway_peer_id << "\n";
        std::cout.flush();
    }

    // Ensure the gateway is known before attempting to connect.
    // SessionManager::connectToPeer() is a no-op for unknown peers.
    if (!wait_peer_discovered(args.gateway_peer_id, 15000)) {
        std::cerr << "Gateway not discovered within 15s: " << args.gateway_peer_id << "\n"
                  << "Make sure the Android peer is running and visible in your peer list." << std::endl;
        return 1;
    }

    // Ensure we have a connection to the gateway.
    // If we're on the same LAN, prefer a private IP (RFC1918) instead of an external-mapped placeholder.
    bool saw_private = wait_peer_private_ip(args.gateway_peer_id, 1000);

    const auto connect_deadline = Clock::now() + std::chrono::seconds(20);
    while (!wait_connected(args.gateway_peer_id, 0)) {
        sm.connectToPeer(args.gateway_peer_id);

        if (wait_connected(args.gateway_peer_id, 2500)) {
            break;
        }

        if (!saw_private) {
            saw_private = wait_peer_private_ip(args.gateway_peer_id, 2000);
        }

        if (Clock::now() >= connect_deadline) {
            std::cerr << "Failed to connect to gateway within 20s: " << args.gateway_peer_id << "\n"
                      << "Make sure the Android peer is running and reachable." << std::endl;
            return 1;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    {
        std::lock_guard<std::mutex> lk(peers_mu);
        auto it = last_peer.find(args.gateway_peer_id);
        if (it != last_peer.end()) {
            const auto& p = it->second;
            std::cout << "GATEWAY_CONNECTED id=" << p.id << " ip=" << p.ip << " port=" << p.port << "\n";
            std::cout.flush();
        }
    }

    const uint32_t stream_id = 424242;

    // Build multi-hop route (excluding the initial gateway).
    // Default: gateway -> final.
    std::vector<std::string> route = args.route_peer_ids;
    if (route.empty() || route.back() != args.final_peer_id) {
        route.push_back(args.final_peer_id);
    }

    // Best-effort: send OPEN_STREAM a few times to let the gateway build routing state.
    // There is no proxy-level ACCEPT/REJECT; success is measured by end-to-end echoes.
    {
        const int attempts = 3;
        for (int attempt = 0; attempt < attempts; ++attempt) {
            std::cout << "SEND_OPEN_STREAM attempt=" << (attempt + 1) << "/" << attempts
                      << " to=" << args.gateway_peer_id
                      << " stream_id=" << stream_id
                      << " route=[";
            for (size_t i = 0; i < route.size(); ++i) {
                if (i) std::cout << ",";
                std::cout << route[i];
            }
            std::cout << "]\n";
            std::cout.flush();
            px->client_open_stream(args.gateway_peer_id, stream_id, "TCP", "", 0, route);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    const auto start = Clock::now();

    int sent = 0;
    int received = 0;
    int timeouts = 0;

    for (int i = 0; i < args.count; ++i) {
        const uint64_t seq = static_cast<uint64_t>(i + 1);
        const uint64_t ts = now_ns();

        std::string payload;
        payload.reserve(16);
        put_u64_be(payload, seq);
        put_u64_be(payload, ts);

        px->client_send_stream_data(args.gateway_peer_id, stream_id, payload);
        sent++;

        // Wait for echo
        {
            std::unique_lock<std::mutex> lk(rx_mu);
            const auto deadline = Clock::now() + std::chrono::milliseconds(args.timeout_ms);
            while (Clock::now() < deadline) {
                if (rtts_ms.find(seq) != rtts_ms.end()) {
                    received++;
                    break;
                }
                rx_cv.wait_for(lk, std::chrono::milliseconds(10));
            }
            if (rtts_ms.find(seq) == rtts_ms.end()) {
                timeouts++;
            }
        }

        if (args.interval_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(args.interval_ms));
        }
    }

    px->client_close_stream(args.gateway_peer_id, stream_id, "bench_done");

    const auto end = Clock::now();
    const double elapsed_s = std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();

    std::vector<double> samples;
    samples.reserve(rtts_ms.size());
    for (const auto& kv : rtts_ms) {
        samples.push_back(kv.second);
    }

    const Stats st = compute_stats_ms(samples);

    // Human summary
    std::cout << "RTT_BENCH_DONE\n";
    std::cout << "  peer_id:    " << args.peer_id << "\n";
    std::cout << "  gateway:    " << args.gateway_peer_id << "\n";
    std::cout << "  final:      " << args.final_peer_id << "\n";
    std::cout << "  sent:       " << sent << "\n";
    std::cout << "  received:   " << received << "\n";
    std::cout << "  timeouts:   " << timeouts << "\n";
    std::cout << "  elapsed_s:  " << elapsed_s << "\n";
    if (!samples.empty()) {
        std::cout << "  rtt_ms:     min=" << st.min_ms << " mean=" << st.mean_ms << " p50=" << st.p50_ms
                  << " p90=" << st.p90_ms << " p99=" << st.p99_ms << " max=" << st.max_ms << "\n";
        std::cout << "  jitter_ms:  mean_abs_diff=" << st.jitter_ms << " stddev=" << st.stddev_ms << "\n";
    }

    // Machine-readable one-line JSON (easy to copy/paste)
    std::cout << "JSON: {"
              << "\"peer_id\":\"" << json_escape(args.peer_id) << "\","
              << "\"gateway\":\"" << json_escape(args.gateway_peer_id) << "\","
              << "\"final\":\"" << json_escape(args.final_peer_id) << "\","
              << "\"sent\":" << sent << ","
              << "\"received\":" << received << ","
              << "\"timeouts\":" << timeouts << ","
              << "\"elapsed_s\":" << elapsed_s;

    if (!samples.empty()) {
        std::cout << ",\"rtt_ms\":{"
                  << "\"min\":" << st.min_ms << ","
                  << "\"mean\":" << st.mean_ms << ","
                  << "\"p50\":" << st.p50_ms << ","
                  << "\"p90\":" << st.p90_ms << ","
                  << "\"p99\":" << st.p99_ms << ","
                  << "\"max\":" << st.max_ms << "}"
                  << ",\"jitter_ms\":{"
                  << "\"mean_abs_diff\":" << st.jitter_ms << ","
                  << "\"stddev\":" << st.stddev_ms << "}";
    }

    std::cout << "}\n";

    // If we got no responses at all, strongly hint at the missing prerequisite.
    if (received == 0) {
        std::cerr << "No echoes received. Common causes:\n"
                  << "  - Android proxy gateway not enabled at runtime (toggle in app)\n"
                  << "  - Android is not connected to the final hop peer (A). Have A connect to Android once.\n";
        return 1;
    }

    return 0;
#endif
}
