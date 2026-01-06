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
#include <deque>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <signal.h>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using Clock = std::chrono::steady_clock;

struct Args {
    uint16_t p2p_port = 32002;
    std::string p2p_peer_id;
    std::string config_path = "config.json";
    LogLevel log_level = LogLevel::ERROR;

    std::string gateway_peer_id;

    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 1080;

    // Optional: expose a local UDP DNS forwarder.
    // If enabled, applications can point their resolver to 127.0.0.1:dns_listen_port.
    uint16_t dns_listen_port = 0;
    std::string dns_upstream_host = "1.1.1.1";
    uint16_t dns_upstream_port = 53;
};

static std::atomic<bool> g_stop{false};

static void on_sigint(int) {
    g_stop.store(true);
}

static void print_usage(const char* argv0) {
    std::cout
        << "proxy_socks5 - local SOCKS5 endpoint over LiteP2P proxy tunnel\n\n"
        << "Usage:\n"
        << "  " << argv0 << " --gateway PEER_ID [options]\n\n"
        << "Required:\n"
        << "  --gateway ID          Proxy gateway peer id (Android)\n\n"
        << "Options:\n"
        << "  --listen-host HOST    Local listen host (default: 127.0.0.1)\n"
        << "  --listen-port PORT    Local SOCKS5 listen port (default: 1080)\n"
        << "  --port PORT           Local LiteP2P port (default: 32002)\n"
        << "  --id ID               Local LiteP2P peer id (default: persistent device id)\n"
        << "  --config FILE         config.json path hint (default: config.json)\n"
        << "  --log-level LVL       debug|info|warning|error|none (default: error)\n"
        << "  --dns-port PORT       Optional local UDP DNS port to expose (0 disables; default: 0)\n"
        << "  --dns-upstream HOST:PORT  Upstream DNS server (default: 1.1.1.1:53)\n\n"
        << "Example:\n"
        << "  " << argv0 << " --gateway 11c7... --listen-port 1080\n";
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

static bool parse_host_port(const std::string& s, std::string& host, uint16_t& port) {
    auto pos = s.rfind(':');
    if (pos == std::string::npos) return false;
    host = s.substr(0, pos);
    const int p = std::stoi(s.substr(pos + 1));
    if (p <= 0 || p > 65535) return false;
    port = static_cast<uint16_t>(p);
    return true;
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

        if (arg == "--gateway") {
            a.gateway_peer_id = need("--gateway");
        } else if (arg == "--listen-host") {
            a.listen_host = need("--listen-host");
        } else if (arg == "--listen-port") {
            a.listen_port = static_cast<uint16_t>(std::stoi(need("--listen-port")));
        } else if (arg == "--port") {
            a.p2p_port = static_cast<uint16_t>(std::stoi(need("--port")));
        } else if (arg == "--id") {
            a.p2p_peer_id = need("--id");
        } else if (arg == "--config") {
            a.config_path = need("--config");
        } else if (arg == "--log-level") {
            a.log_level = parse_log_level(need("--log-level"));
        } else if (arg == "--dns-port") {
            a.dns_listen_port = static_cast<uint16_t>(std::stoi(need("--dns-port")));
        } else if (arg == "--dns-upstream") {
            std::string hp = need("--dns-upstream");
            if (!parse_host_port(hp, a.dns_upstream_host, a.dns_upstream_port)) {
                throw std::runtime_error("Invalid --dns-upstream (expected HOST:PORT)");
            }
        } else {
            throw std::runtime_error("Unknown arg: " + arg);
        }
    }

    if (a.gateway_peer_id.empty()) {
        throw std::runtime_error("--gateway is required");
    }
    return true;
}

static ssize_t recv_exact(int fd, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        const ssize_t r = ::recv(fd, reinterpret_cast<char*>(buf) + got, n - got, 0);
        if (r == 0) return 0;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(got);
}

static bool send_all(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        const ssize_t w = ::send(fd, reinterpret_cast<const char*>(buf) + sent, n - sent, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (w == 0) return false;
        sent += static_cast<size_t>(w);
    }
    return true;
}

struct TcpConn {
    int client_fd{-1};
    uint32_t stream_id{0};

    std::atomic<bool> stop{false};
    std::mutex in_mu;
    std::condition_variable in_cv;
    std::deque<std::string> in_q;

    std::mutex state_mu;
    bool remote_closed{false};

    std::thread reader;
    std::thread writer;

    void request_stop() {
        stop.store(true);
        in_cv.notify_all();
    }
};

struct UdpFlow {
    uint32_t stream_id{0};
    sockaddr_storage client_addr{};
    socklen_t client_len{0};
    std::chrono::steady_clock::time_point last_used{Clock::now()};
};

static int make_tcp_listener(const std::string& host, uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    addr.sin_port = htons(port);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 128) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

static bool socks5_handshake_and_get_dest(int client_fd, std::string& host, uint16_t& port) {
    uint8_t hdr[2];
    if (recv_exact(client_fd, hdr, 2) <= 0) return false;
    const uint8_t ver = hdr[0];
    const uint8_t nmethods = hdr[1];
    if (ver != 0x05) return false;
    std::vector<uint8_t> methods(nmethods);
    if (nmethods > 0) {
        if (recv_exact(client_fd, methods.data(), methods.size()) <= 0) return false;
    }

    bool has_no_auth = false;
    for (uint8_t m : methods) {
        if (m == 0x00) has_no_auth = true;
    }

    uint8_t sel[2] = {0x05, static_cast<uint8_t>(has_no_auth ? 0x00 : 0xFF)};
    if (!send_all(client_fd, sel, sizeof(sel))) return false;
    if (!has_no_auth) return false;

    // Request
    uint8_t req[4];
    if (recv_exact(client_fd, req, 4) <= 0) return false;
    if (req[0] != 0x05) return false;
    const uint8_t cmd = req[1];
    const uint8_t atyp = req[3];

    if (cmd != 0x01) {
        // Only CONNECT supported.
        return false;
    }

    if (atyp == 0x01) {
        // IPv4
        uint8_t ip[4];
        if (recv_exact(client_fd, ip, 4) <= 0) return false;
        char buf[INET_ADDRSTRLEN];
        if (!::inet_ntop(AF_INET, ip, buf, sizeof(buf))) return false;
        host = buf;
    } else if (atyp == 0x03) {
        // Domain
        uint8_t len;
        if (recv_exact(client_fd, &len, 1) <= 0) return false;
        std::string name;
        name.resize(len);
        if (len > 0) {
            if (recv_exact(client_fd, name.data(), len) <= 0) return false;
        }
        host = name;
    } else if (atyp == 0x04) {
        // IPv6
        uint8_t ip6[16];
        if (recv_exact(client_fd, ip6, 16) <= 0) return false;
        char buf[INET6_ADDRSTRLEN];
        if (!::inet_ntop(AF_INET6, ip6, buf, sizeof(buf))) return false;
        host = buf;
    } else {
        return false;
    }

    uint8_t pbuf[2];
    if (recv_exact(client_fd, pbuf, 2) <= 0) return false;
    port = (static_cast<uint16_t>(pbuf[0]) << 8) | static_cast<uint16_t>(pbuf[1]);
    return true;
}

static bool socks5_send_reply(int client_fd, uint8_t rep) {
    // Reply: VER=5, REP, RSV=0, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
    uint8_t out[10];
    out[0] = 0x05;
    out[1] = rep;
    out[2] = 0x00;
    out[3] = 0x01;
    out[4] = 0x00;
    out[5] = 0x00;
    out[6] = 0x00;
    out[7] = 0x00;
    out[8] = 0x00;
    out[9] = 0x00;
    return send_all(client_fd, out, sizeof(out));
}

} // namespace

int main(int argc, char** argv) {
    // Ignore SIGPIPE to prevent process termination on socket write errors
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

#if !ENABLE_PROXY_MODULE
    std::cerr << "proxy_socks5 requires ENABLE_PROXY_MODULE=ON" << std::endl;
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
    sm.start(args.p2p_port,
             [&](const std::vector<Peer>&) {},
             protocol,
             args.p2p_peer_id);

    auto* px = sm.get_proxy_endpoint();
    if (!px) {
        std::cerr << "CRITICAL: proxy endpoint not available" << std::endl;
        return 2;
    }

    sm.configure_proxy(proxy::ProxySettings{.enable_gateway = false, .enable_client = true});

    // Connect to gateway.
    sm.connectToPeer(args.gateway_peer_id);

    auto wait_connected = [&](const std::string& id, int ms) -> bool {
        auto deadline = Clock::now() + std::chrono::milliseconds(ms);
        while (Clock::now() < deadline) {
            if (sm.isPeerConnected(id)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return false;
    };

    if (!wait_connected(args.gateway_peer_id, 20000)) {
        std::cerr << "WARNING: not connected to gateway within 20s: " << args.gateway_peer_id << "\n";
        std::cerr << "Continuing anyway; SOCKS connects may hang until the P2P hop is up." << std::endl;
    }

    std::mutex conns_mu;
    std::unordered_map<uint32_t, std::shared_ptr<TcpConn>> conns;

    std::mutex udp_mu;
    std::unordered_map<uint32_t, UdpFlow> udp_by_stream;
    std::unordered_map<std::string, uint32_t> udp_by_client;

    std::atomic<uint32_t> next_stream_id{10000};

    int dns_fd = -1;

    px->set_stream_data_callback([&](const std::string& from_peer_id, uint32_t stream_id, std::string_view data, bool is_close) {
        (void)from_peer_id;

        // UDP (DNS) flows.
        if (dns_fd >= 0) {
            std::optional<UdpFlow> uf;
            {
                std::lock_guard<std::mutex> lk(udp_mu);
                auto it = udp_by_stream.find(stream_id);
                if (it != udp_by_stream.end()) {
                    uf = it->second;
                    if (is_close) {
                        // Remove mappings.
                        // Best-effort: remove reverse mapping by scanning (small maps expected).
                        for (auto it2 = udp_by_client.begin(); it2 != udp_by_client.end(); ) {
                            if (it2->second == stream_id) {
                                it2 = udp_by_client.erase(it2);
                            } else {
                                ++it2;
                            }
                        }
                        udp_by_stream.erase(it);
                    }
                }
            }

            if (uf.has_value() && !is_close && !data.empty()) {
                (void)::sendto(dns_fd, data.data(), data.size(), 0,
                              reinterpret_cast<const sockaddr*>(&uf->client_addr), uf->client_len);
                return;
            }
            if (uf.has_value()) {
                return;
            }
        }

        // TCP (SOCKS) flows.
        std::shared_ptr<TcpConn> c;
        {
            std::lock_guard<std::mutex> lk(conns_mu);
            auto it = conns.find(stream_id);
            if (it == conns.end()) {
                return;
            }
            c = it->second;
        }

        if (!c) return;

        if (is_close) {
            {
                std::lock_guard<std::mutex> lk(c->state_mu);
                c->remote_closed = true;
            }
            c->request_stop();
            // Best-effort shutdown of local socket.
            if (c->client_fd >= 0) {
                ::shutdown(c->client_fd, SHUT_RDWR);
            }
            return;
        }

        {
            std::lock_guard<std::mutex> lk(c->in_mu);
            c->in_q.emplace_back(data.data(), data.size());
        }
        c->in_cv.notify_one();
    });

    const int listen_fd = make_tcp_listener(args.listen_host, args.listen_port);
    if (listen_fd < 0) {
        std::cerr << "CRITICAL: failed to bind SOCKS5 listener on " << args.listen_host << ":" << args.listen_port << std::endl;
        return 2;
    }

    std::cout << "SOCKS5_READY host=" << args.listen_host << " port=" << args.listen_port
              << " gateway=" << args.gateway_peer_id << "\n";
    if (args.dns_listen_port != 0) {
        std::cout << "DNS_UDP_ENABLED port=" << args.dns_listen_port
                  << " upstream=" << args.dns_upstream_host << ":" << args.dns_upstream_port << "\n";
    }
    std::cout.flush();

    std::thread dns_thread;
    if (args.dns_listen_port != 0) {
        dns_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (dns_fd < 0) {
            std::cerr << "WARNING: failed to create DNS UDP socket; disabling DNS forwarder" << std::endl;
            dns_fd = -1;
        } else {
            sockaddr_in a;
            std::memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            (void)::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
            a.sin_port = htons(args.dns_listen_port);
            if (::bind(dns_fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
                std::cerr << "WARNING: failed to bind DNS UDP socket on 127.0.0.1:" << args.dns_listen_port
                          << "; disabling DNS forwarder" << std::endl;
                ::close(dns_fd);
                dns_fd = -1;
            }
        }

        if (dns_fd >= 0) {
            dns_thread = std::thread([&]() {
                std::string buf;
                buf.resize(64 * 1024);
                while (!g_stop.load()) {
                    struct pollfd pfd;
                    pfd.fd = dns_fd;
                    pfd.events = POLLIN;
                    pfd.revents = 0;
                    const int rc = ::poll(&pfd, 1, 100);
                    if (rc < 0) {
                        if (errno == EINTR) continue;
                        break;
                    }
                    if (rc == 0) continue;
                    if (!(pfd.revents & POLLIN)) continue;

                    sockaddr_storage src;
                    socklen_t slen = sizeof(src);
                    const ssize_t n = ::recvfrom(dns_fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&src), &slen);
                    if (n <= 0) continue;

                    // Key = ip:port (IPv4 only for local bind; still handle generically).
                    char ipbuf[INET6_ADDRSTRLEN];
                    uint16_t sport = 0;
                    std::string key;
                    if (src.ss_family == AF_INET) {
                        const auto* in = reinterpret_cast<const sockaddr_in*>(&src);
                        (void)::inet_ntop(AF_INET, &in->sin_addr, ipbuf, sizeof(ipbuf));
                        sport = ntohs(in->sin_port);
                        key = std::string(ipbuf) + ":" + std::to_string(sport);
                    } else if (src.ss_family == AF_INET6) {
                        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&src);
                        (void)::inet_ntop(AF_INET6, &in6->sin6_addr, ipbuf, sizeof(ipbuf));
                        sport = ntohs(in6->sin6_port);
                        key = std::string(ipbuf) + ":" + std::to_string(sport);
                    } else {
                        continue;
                    }

                    uint32_t sid = 0;
                    {
                        std::lock_guard<std::mutex> lk(udp_mu);
                        auto it = udp_by_client.find(key);
                        if (it != udp_by_client.end()) {
                            sid = it->second;
                            auto it2 = udp_by_stream.find(sid);
                            if (it2 != udp_by_stream.end()) {
                                it2->second.client_addr = src;
                                it2->second.client_len = slen;
                                it2->second.last_used = Clock::now();
                            }
                        } else {
                            sid = next_stream_id.fetch_add(1);
                            udp_by_client[key] = sid;
                            UdpFlow f;
                            f.stream_id = sid;
                            f.client_addr = src;
                            f.client_len = slen;
                            f.last_used = Clock::now();
                            udp_by_stream[sid] = f;
                        }
                    }

                    // Ensure the UDP exit flow exists (best-effort). We can send ENCAP each time; the gateway
                    // treats it as refresh/state update.
                    px->client_open_stream(args.gateway_peer_id, sid, "UDP_EXIT", args.dns_upstream_host, args.dns_upstream_port);
                    px->client_send_stream_data(args.gateway_peer_id, sid, std::string_view(buf.data(), static_cast<size_t>(n)));

                    // Best-effort GC for stale mappings.
                    {
                        std::lock_guard<std::mutex> lk(udp_mu);
                        const auto now = Clock::now();
                        for (auto it = udp_by_stream.begin(); it != udp_by_stream.end(); ) {
                            if (now - it->second.last_used > std::chrono::minutes(5)) {
                                const uint32_t dead = it->first;
                                for (auto it2 = udp_by_client.begin(); it2 != udp_by_client.end(); ) {
                                    if (it2->second == dead) it2 = udp_by_client.erase(it2);
                                    else ++it2;
                                }
                                it = udp_by_stream.erase(it);
                            } else {
                                ++it;
                            }
                        }
                    }
                }
            });
        }
    }

    while (!g_stop.load()) {
        struct pollfd pfd;
        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int rc = ::poll(&pfd, 1, 100);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc == 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        const int cfd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&cli), &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }

#ifdef SO_NOSIGPIPE
        {
            int one = 1;
            (void)::setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        }
#endif

        std::thread([&, cfd]() {
            std::string host;
            uint16_t port = 0;
            if (!socks5_handshake_and_get_dest(cfd, host, port)) {
                (void)socks5_send_reply(cfd, 0x01); // general failure
                ::close(cfd);
                return;
            }

            const uint32_t sid = next_stream_id.fetch_add(1);
            auto conn = std::make_shared<TcpConn>();
            conn->client_fd = cfd;
            conn->stream_id = sid;

            {
                std::lock_guard<std::mutex> lk(conns_mu);
                conns[sid] = conn;
            }

            // Ask gateway to open an INET/TCP exit flow.
            px->client_open_stream(args.gateway_peer_id, sid, "TCP_EXIT", host, port);

            // Small grace window: if the gateway immediately fails to connect, it should send a close.
            {
                std::unique_lock<std::mutex> lk(conn->state_mu);
                auto deadline = Clock::now() + std::chrono::milliseconds(300);
                while (!conn->remote_closed && Clock::now() < deadline) {
                    lk.unlock();
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    lk.lock();
                }
                if (conn->remote_closed) {
                    (void)socks5_send_reply(cfd, 0x05); // connection refused
                    {
                        std::lock_guard<std::mutex> lk2(conns_mu);
                        conns.erase(sid);
                    }
                    ::close(cfd);
                    return;
                }
            }

            if (!socks5_send_reply(cfd, 0x00)) {
                px->client_close_stream(args.gateway_peer_id, sid, "socks_reply_failed");
                {
                    std::lock_guard<std::mutex> lk(conns_mu);
                    conns.erase(sid);
                }
                ::close(cfd);
                return;
            }

            conn->reader = std::thread([&, conn]() {
                std::string buf;
                buf.resize(32 * 1024);
                while (!conn->stop.load() && !g_stop.load()) {
                    const ssize_t r = ::recv(conn->client_fd, buf.data(), buf.size(), 0);
                    if (r > 0) {
                        px->client_send_stream_data(args.gateway_peer_id, conn->stream_id,
                                                    std::string_view(buf.data(), static_cast<size_t>(r)));
                        continue;
                    }
                    if (r == 0) {
                        break;
                    }
                    if (r < 0 && errno == EINTR) {
                        continue;
                    }
                    break;
                }

                // Local side closed; signal proxy flow close.
                conn->request_stop();
                px->client_close_stream(args.gateway_peer_id, conn->stream_id, "local_closed");
            });

            conn->writer = std::thread([&, conn]() {
                for (;;) {
                    std::string chunk;
                    {
                        std::unique_lock<std::mutex> lk(conn->in_mu);
                        conn->in_cv.wait_for(lk, std::chrono::milliseconds(100), [&] {
                            return conn->stop.load() || g_stop.load() || !conn->in_q.empty();
                        });
                        if ((conn->stop.load() || g_stop.load()) && conn->in_q.empty()) {
                            break;
                        }
                        if (!conn->in_q.empty()) {
                            chunk = std::move(conn->in_q.front());
                            conn->in_q.pop_front();
                        }
                    }

                    if (!chunk.empty()) {
                        if (!send_all(conn->client_fd, chunk.data(), chunk.size())) {
                            conn->request_stop();
                            break;
                        }
                    }
                }

                if (conn->client_fd >= 0) {
                    ::shutdown(conn->client_fd, SHUT_RDWR);
                }
            });

            if (conn->reader.joinable()) conn->reader.join();
            if (conn->writer.joinable()) conn->writer.join();

            {
                std::lock_guard<std::mutex> lk(conns_mu);
                conns.erase(conn->stream_id);
            }

            if (conn->client_fd >= 0) {
                ::close(conn->client_fd);
                conn->client_fd = -1;
            }
        }).detach();
    }

    ::close(listen_fd);
    if (dns_fd >= 0) {
        ::close(dns_fd);
        dns_fd = -1;
    }
    if (dns_thread.joinable()) dns_thread.join();
    g_stop.store(true);
    sm.stop();
    return 0;
#endif
}
