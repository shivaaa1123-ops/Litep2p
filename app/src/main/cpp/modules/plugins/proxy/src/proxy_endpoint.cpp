#include "proxy_endpoint.h"

#include "logger.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace proxy {

namespace {
    struct ScopedFd {
        int fd{-1};
        ~ScopedFd() {
            if (fd >= 0) {
                ::close(fd);
            }
        }
        ScopedFd() = default;
        explicit ScopedFd(int f) : fd(f) {}
        ScopedFd(const ScopedFd&) = delete;
        ScopedFd& operator=(const ScopedFd&) = delete;
        ScopedFd(ScopedFd&& o) noexcept : fd(o.fd) { o.fd = -1; }
        ScopedFd& operator=(ScopedFd&& o) noexcept {
            if (this != &o) {
                if (fd >= 0) ::close(fd);
                fd = o.fd;
                o.fd = -1;
            }
            return *this;
        }
        int release() {
            const int out = fd;
            fd = -1;
            return out;
        }
    };

    inline void write_u32_be(std::string& out, uint32_t v) {
        out.push_back(static_cast<char>((v >> 24) & 0xFF));
        out.push_back(static_cast<char>((v >> 16) & 0xFF));
        out.push_back(static_cast<char>((v >> 8) & 0xFF));
        out.push_back(static_cast<char>(v & 0xFF));
    }

    inline void write_u16_be(std::string& out, uint16_t v) {
        out.push_back(static_cast<char>((v >> 8) & 0xFF));
        out.push_back(static_cast<char>(v & 0xFF));
    }

    inline bool read_u32_be(std::string_view in, uint32_t& v) {
        if (in.size() < 4) return false;
        v = (static_cast<uint32_t>(static_cast<uint8_t>(in[0])) << 24) |
            (static_cast<uint32_t>(static_cast<uint8_t>(in[1])) << 16) |
            (static_cast<uint32_t>(static_cast<uint8_t>(in[2])) << 8) |
            static_cast<uint32_t>(static_cast<uint8_t>(in[3]));
        return true;
    }

    inline bool read_u16_be(std::string_view in, uint16_t& v) {
        if (in.size() < 2) return false;
        v = (static_cast<uint16_t>(static_cast<uint8_t>(in[0])) << 8) |
            static_cast<uint16_t>(static_cast<uint8_t>(in[1]));
        return true;
    }

    // LPX1 framing: hop-local encapsulation for dumb-proxy mode.
    // Payload starts with magic "LPX1".
    // Layout:
    //   magic[4] = 'L','P','X','1'
    //   kind[u8] = 1 (ENCAP) or 2 (TUNNEL)
    //   flags[u8] (bit0=close)
    //   flow_id[u32be]
    //   if kind==ENCAP:
    //      dst_type[u8] = 1 (PEER) or 2 (INET)
    //      if PEER: peer_len[u16be] peer_id[peer_len]
    //      if INET: host_len[u16be] host[host_len] port[u16be] proto[u8] (1=TCP)
    //   payload_bytes[...]
    inline constexpr char kLpxMagic[4] = {'L', 'P', 'X', '1'};
    enum class LpxKind : uint8_t { ENCAP = 1, TUNNEL = 2 };
    enum class LpxDstType : uint8_t { PEER = 1, INET = 2 };
    inline constexpr uint8_t kLpxFlagClose = 0x01;
    inline constexpr uint8_t kLpxInetProtoTcp = 0x01;
    inline constexpr uint8_t kLpxInetProtoUdp = 0x02;

    struct ParsedLpx {
        LpxKind kind{LpxKind::TUNNEL};
        uint8_t flags{0};
        uint32_t flow_id{0};
        std::optional<LpxDstType> dst_type;
        std::string peer_id;
        std::string host;
        uint16_t port{0};
        uint8_t inet_proto{0};
        std::string_view payload;
    };

    bool parse_lpx(std::string_view payload, ParsedLpx& out) {
        if (payload.size() < 4 + 1 + 1 + 4) {
            return false;
        }
        if (std::memcmp(payload.data(), kLpxMagic, 4) != 0) {
            return false;
        }
        const uint8_t kind_u8 = static_cast<uint8_t>(payload[4]);
        const uint8_t flags = static_cast<uint8_t>(payload[5]);
        uint32_t flow_id = 0;
        if (!read_u32_be(payload.substr(6), flow_id)) {
            return false;
        }
        size_t off = 10;

        ParsedLpx tmp;
        tmp.flags = flags;
        tmp.flow_id = flow_id;
        if (kind_u8 == static_cast<uint8_t>(LpxKind::ENCAP)) {
            tmp.kind = LpxKind::ENCAP;
            if (payload.size() < off + 1) return false;
            const uint8_t dst = static_cast<uint8_t>(payload[off++]);
            if (dst == static_cast<uint8_t>(LpxDstType::PEER)) {
                tmp.dst_type = LpxDstType::PEER;
                if (payload.size() < off + 2) return false;
                uint16_t n = 0;
                if (!read_u16_be(payload.substr(off), n)) return false;
                off += 2;
                if (payload.size() < off + n) return false;
                tmp.peer_id.assign(payload.substr(off, n));
                off += n;
            } else if (dst == static_cast<uint8_t>(LpxDstType::INET)) {
                tmp.dst_type = LpxDstType::INET;
                if (payload.size() < off + 2) return false;
                uint16_t hn = 0;
                if (!read_u16_be(payload.substr(off), hn)) return false;
                off += 2;
                if (payload.size() < off + hn + 2 + 1) return false;
                tmp.host.assign(payload.substr(off, hn));
                off += hn;
                uint16_t p = 0;
                if (!read_u16_be(payload.substr(off), p)) return false;
                off += 2;
                tmp.port = p;
                tmp.inet_proto = static_cast<uint8_t>(payload[off++]);
            } else {
                return false;
            }
        } else if (kind_u8 == static_cast<uint8_t>(LpxKind::TUNNEL)) {
            tmp.kind = LpxKind::TUNNEL;
        } else {
            return false;
        }
        tmp.payload = payload.substr(off);
        out = std::move(tmp);
        return true;
    }

    std::string encode_lpx_tunnel_payload(uint32_t flow_id, std::string_view data, uint8_t flags) {
        std::string payload;
        payload.reserve(4 + 1 + 1 + 4 + data.size());
        payload.append(kLpxMagic, 4);
        payload.push_back(static_cast<char>(static_cast<uint8_t>(LpxKind::TUNNEL)));
        payload.push_back(static_cast<char>(flags));
        write_u32_be(payload, flow_id);
        payload.append(data.data(), data.size());
        return payload;
    }

    enum class ClientDestKind : uint8_t { NONE = 0, PEER = 1, INET = 2 };

    std::string encode_lpx_encap_payload(uint32_t flow_id,
                                         ClientDestKind dst_kind,
                                         std::string_view peer_id,
                                         std::string_view host,
                                         int port,
                                         std::string_view proto,
                                         std::string_view data,
                                         uint8_t flags) {
        std::string payload;
        payload.append(kLpxMagic, 4);
        payload.push_back(static_cast<char>(static_cast<uint8_t>(LpxKind::ENCAP)));
        payload.push_back(static_cast<char>(flags));
        write_u32_be(payload, flow_id);
        if (dst_kind == ClientDestKind::PEER) {
            payload.push_back(static_cast<char>(static_cast<uint8_t>(LpxDstType::PEER)));
            const auto n = static_cast<uint16_t>(std::min<size_t>(peer_id.size(), 0xFFFF));
            write_u16_be(payload, n);
            payload.append(peer_id.data(), n);
        } else if (dst_kind == ClientDestKind::INET) {
            payload.push_back(static_cast<char>(static_cast<uint8_t>(LpxDstType::INET)));
            const auto hn = static_cast<uint16_t>(std::min<size_t>(host.size(), 0xFFFF));
            write_u16_be(payload, hn);
            payload.append(host.data(), hn);
            const uint16_t p = static_cast<uint16_t>(std::max(0, std::min(port, 65535)));
            write_u16_be(payload, p);
            const uint8_t proto_u8 = (proto == "UDP") ? kLpxInetProtoUdp : kLpxInetProtoTcp;
            payload.push_back(static_cast<char>(proto_u8));
        } else {
            // No destination; encode as TUNNEL-like.
            payload.push_back(static_cast<char>(static_cast<uint8_t>(LpxDstType::PEER)));
            write_u16_be(payload, 0);
        }
        payload.append(data.data(), data.size());
        return payload;
    }

    ScopedFd connect_tcp_blocking(const std::string& host, int port, int timeout_ms) {
        if (port <= 0 || port > 65535) {
            return ScopedFd{};
        }

        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo* res = nullptr;
        const std::string port_str = std::to_string(port);
        const int gai = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (gai != 0 || !res) {
            return ScopedFd{};
        }

        ScopedFd out;
        for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) {
                continue;
            }

#ifdef SO_NOSIGPIPE
            {
                const int one = 1;
                (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
            }
#endif
            // Best-effort connect with poll-based timeout.
            int flags = ::fcntl(fd, F_GETFL, 0);
            if (flags >= 0) {
                ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }

            int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
            if (rc == 0) {
                out = ScopedFd(fd);
                break;
            }
            if (rc < 0 && errno != EINPROGRESS) {
                ::close(fd);
                continue;
            }

            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            rc = ::poll(&pfd, 1, timeout_ms);
            if (rc == 1 && (pfd.revents & POLLOUT)) {
                int err = 0;
                socklen_t errlen = sizeof(err);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0 && err == 0) {
                    out = ScopedFd(fd);
                    break;
                }
            }

            ::close(fd);
        }

        ::freeaddrinfo(res);

        if (out.fd >= 0) {
            // Switch back to blocking for simplicity in the IO loop.
            int flags = ::fcntl(out.fd, F_GETFL, 0);
            if (flags >= 0) {
                ::fcntl(out.fd, F_SETFL, flags & ~O_NONBLOCK);
            }
        }
        return out;
    }

    ScopedFd connect_udp_best_effort(const std::string& host, int port) {
        if (port <= 0 || port > 65535) {
            return ScopedFd{};
        }

        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        struct addrinfo* res = nullptr;
        const std::string port_str = std::to_string(port);
        const int gai = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (gai != 0 || !res) {
            return ScopedFd{};
        }

        ScopedFd out;
        for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) {
                continue;
            }

            // For UDP, connect() just sets default remote; it does not handshake.
            if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
                // Best-effort non-blocking.
                const int flags = ::fcntl(fd, F_GETFL, 0);
                if (flags >= 0) {
                    (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                }

                out = ScopedFd(fd);
                break;
            }

            ::close(fd);
        }

        ::freeaddrinfo(res);
        return out;
    }
}

std::string encode_proxy_control_wire(const json& control) {
    return wire::encode_message(MessageType::PROXY_CONTROL, control.dump());
}

std::string encode_proxy_stream_data_wire(uint32_t stream_id, std::string_view data) {
    std::string payload;
    payload.reserve(4 + data.size());
    write_u32_be(payload, stream_id);
    payload.append(data.data(), data.size());
    return wire::encode_message(MessageType::PROXY_STREAM_DATA, payload);
}

bool decode_proxy_stream_data_payload(std::string_view payload, ProxyStreamDataView& out) {
    // LPX1 framing (dumb-proxy): expose flow_id as stream_id and strip routing metadata.
    ParsedLpx lpx;
    if (parse_lpx(payload, lpx)) {
        out.stream_id = lpx.flow_id;
        out.is_close = (lpx.flags & kLpxFlagClose) != 0;
        out.data = lpx.payload;
        return true;
    }

    uint32_t sid = 0;
    if (!read_u32_be(payload, sid)) {
        return false;
    }
    out.stream_id = sid;
    out.is_close = false;
    out.data = payload.substr(4);
    return true;
}

ProxyEndpoint::ProxyEndpoint(SendFn send_fn) : m_send(std::move(send_fn)) {
    if (!m_send) {
        throw std::invalid_argument("ProxyEndpoint: send_fn must be set");
    }
}

ProxyEndpoint::~ProxyEndpoint() {
    // Best-effort teardown of any active tunnels.
    for (auto& kv : m_streams) {
        if (!kv.second) {
            continue;
        }
        kv.second->stop.store(true);
        if (kv.second->tcp_fd >= 0) {
            ::shutdown(kv.second->tcp_fd, SHUT_RDWR);
            ::close(kv.second->tcp_fd);
            kv.second->tcp_fd = -1;
        }
        if (kv.second->udp_fd >= 0) {
            ::close(kv.second->udp_fd);
            kv.second->udp_fd = -1;
        }
    }
    for (auto& kv : m_streams) {
        if (!kv.second) {
            continue;
        }
        if (kv.second->io_thread.joinable()) {
            kv.second->io_thread.join();
        }
    }
}

void ProxyEndpoint::set_connect_callback(ConnectFn connect_fn) {
    m_connect = std::move(connect_fn);
}

void ProxyEndpoint::configure(ProxySettings settings) {
    LOG_INFO("PROXY: configure called - gateway=" + std::string(settings.enable_gateway ? "true" : "false") +
             " client=" + std::string(settings.enable_client ? "true" : "false") +
             " test_echo=" + std::string(settings.enable_test_echo ? "true" : "false"));
    m_settings = settings;
}

ProxySettings ProxyEndpoint::settings() const {
    return m_settings;
}

json ProxyEndpoint::make_hello(std::string_view role, int version) {
    json j;
    j["type"] = kProxyHello;
    j["version"] = version;
    j["role"] = std::string(role);
    return j;
}

json ProxyEndpoint::make_open_stream(uint32_t stream_id, std::string_view protocol,
                                     std::string_view host, int port,
                                     const std::vector<std::string>& route) {
    json j;
    j["type"] = kProxyOpenStream;
    j["stream_id"] = stream_id;
    j["protocol"] = std::string(protocol);
    j["host"] = std::string(host);
    j["port"] = port;
    if (!route.empty()) {
        j["route"] = route;
    }
    return j;
}

json ProxyEndpoint::make_close_stream(uint32_t stream_id, std::string_view reason) {
    json j;
    j["type"] = kProxyCloseStream;
    j["stream_id"] = stream_id;
    j["reason"] = std::string(reason);
    return j;
}

void ProxyEndpoint::on_control(const std::string& from_peer_id, std::string_view payload) {
    LOG_INFO("PROXY: on_control from " + from_peer_id + " payload_len=" + std::to_string(payload.size()) +
             " gateway=" + (m_settings.enable_gateway ? "true" : "false") +
             " client=" + (m_settings.enable_client ? "true" : "false"));
    
    json msg;
    try {
        msg = json::parse(payload);
    } catch (const std::exception& e) {
        LOG_WARN(std::string("PROXY: control parse failed: ") + e.what());
        return;
    }

    if (m_control_cb) {
        m_control_cb(from_peer_id, msg);
    }

    const std::string type = msg.value("type", "");
    LOG_INFO("PROXY: control type=" + type + " from " + from_peer_id);
    // Legacy control types are intentionally ignored.
    // Target behavior: a dumb proxy does not participate in proxy-level handshakes.
    if (type == kProxyHello || type == kProxyAccept) {
        return;
    }
    if (type == kProxyOpenStream) {
        handle_open_stream_(from_peer_id, msg);
        return;
    }
    if (type == kProxyCloseStream) {
        handle_close_stream_(from_peer_id, msg);
        return;
    }

    LOG_WARN("PROXY: unknown control type from " + from_peer_id + ": " + type);
}

void ProxyEndpoint::on_stream_data(const std::string& from_peer_id, std::string_view payload) {
    // LPX1 (dumb-proxy) framing.
    ParsedLpx lpx;
    if (parse_lpx(payload, lpx)) {
        const uint32_t flow_id = lpx.flow_id;
        const StreamKey k{from_peer_id, flow_id};

        if (lpx.kind == LpxKind::ENCAP) {
            if (!m_settings.enable_gateway) {
                return;
            }

            // Create/update upstream flow.
            StreamKey up_key{from_peer_id, flow_id};
            auto& sp = m_streams[up_key];
            if (!sp) sp = std::make_unique<Stream>();
            Stream& s = *sp;
            s.upstream_peer_id = from_peer_id;
            s.upstream_stream_id = flow_id;
            s.open = true;
            s.use_lpx = true;

            // Close flag: teardown.
            if (lpx.flags & kLpxFlagClose) {
                close_stream_(s, "lpx_close");
                if (!s.downstream_peer_id.empty() && s.downstream_stream_id != 0u) {
                    m_downstream_to_upstream.erase(StreamKey{s.downstream_peer_id, s.downstream_stream_id});
                }
                m_streams.erase(up_key);
                return;
            }

            if (!lpx.dst_type.has_value()) {
                return;
            }

            if (*lpx.dst_type == LpxDstType::PEER) {
                if (lpx.peer_id.empty()) {
                    return;
                }
                s.is_chain_hop = true;
                s.downstream_peer_id = lpx.peer_id;
                s.downstream_stream_id = flow_id;
                m_downstream_to_upstream[StreamKey{s.downstream_peer_id, s.downstream_stream_id}] = up_key;

                // Ensure the gateway actually has a session to the downstream hop.
                // Without this, the LPX tunnel frames would be dropped because peer_b is unknown
                // or disconnected on the gateway. Debouncing is handled inside SessionManager.
                if (m_connect) {
                    LOG_INFO("PROXY: LPX gateway connecting to downstream peer: " + s.downstream_peer_id);
                    m_connect(s.downstream_peer_id);
                }

                // Forward payload downstream.
                std::string tunnel_payload = encode_lpx_tunnel_payload(flow_id, lpx.payload, 0);
                m_send(s.downstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
                return;
            }

            if (*lpx.dst_type == LpxDstType::INET) {
                    if (lpx.host.empty() || lpx.port == 0 || (lpx.inet_proto != kLpxInetProtoTcp && lpx.inet_proto != kLpxInetProtoUdp)) {
                    return;
                }

                    if (lpx.inet_proto == kLpxInetProtoTcp) {
                        s.is_tcp_exit = true;
                        s.is_udp_exit = false;
                    } else {
                        s.is_tcp_exit = false;
                        s.is_udp_exit = true;
                    }
                s.dest_host = lpx.host;
                s.dest_port = static_cast<int>(lpx.port);
                    s.protocol = (lpx.inet_proto == kLpxInetProtoUdp) ? "UDP_EXIT" : "TCP_EXIT";

                // Start IO thread if not running.
                if (!s.io_thread.joinable()) {
                    s.io_thread = std::thread([this, up_key]() {
                        auto it2 = m_streams.find(up_key);
                        if (it2 == m_streams.end()) return;
                        if (!it2->second) return;
                        Stream& st = *it2->second;

                            if (st.is_tcp_exit) {
                                ScopedFd fd = connect_tcp_blocking(st.dest_host, st.dest_port, 3000);
                                if (fd.fd < 0) {
                                    // Connection failed: signal closure upstream.
                                    {
                                        const std::string close_payload = encode_lpx_tunnel_payload(
                                            st.upstream_stream_id,
                                            std::string_view{},
                                            kLpxFlagClose);
                                        m_send(st.upstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, close_payload));
                                    }
                                    st.open = false;
                                    return;
                                }

                                st.tcp_fd = fd.release();

                                std::string inbuf;
                                inbuf.resize(16 * 1024);
                                while (!st.stop.load()) {
                                    // Flush pending writes.
                                    {
                                        std::lock_guard<std::mutex> lk(st.out_mu);
                                        while (!st.out_q.empty()) {
                                            std::string& front = st.out_q.front();
                                            if (front.empty()) {
                                                st.out_q.pop_front();
                                                continue;
                                            }
                                            const ssize_t n = ::send(st.tcp_fd, front.data(), front.size(), 0);
                                            if (n < 0) {
                                                if (errno == EINTR) {
                                                    continue;
                                                }
                                                st.stop.store(true);
                                                break;
                                            }
                                            if (n == 0) {
                                                st.stop.store(true);
                                                break;
                                            }
                                            front.erase(0, static_cast<size_t>(n));
                                            if (front.empty()) {
                                                st.out_q.pop_front();
                                            } else {
                                                break;
                                            }
                                        }
                                    }

                                    // Read from socket.
                                    const ssize_t r = ::recv(st.tcp_fd, inbuf.data(), inbuf.size(), 0);
                                    if (r > 0) {
                                        const std::string tunnel_payload = encode_lpx_tunnel_payload(
                                            st.upstream_stream_id,
                                            std::string_view(inbuf.data(), static_cast<size_t>(r)),
                                            0);
                                        m_send(st.upstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
                                        continue;
                                    }
                                    if (r == 0) {
                                        break;
                                    }
                                    if (r < 0 && errno == EINTR) {
                                        continue;
                                    }
                                    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                                        std::this_thread::sleep_for(std::chrono::milliseconds(5));
                                        continue;
                                    }
                                    break;
                                }

                                // Best-effort signal upstream that the egress side is closed.
                                {
                                    const std::string close_payload = encode_lpx_tunnel_payload(
                                        st.upstream_stream_id,
                                        std::string_view{},
                                        kLpxFlagClose);
                                    m_send(st.upstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, close_payload));
                                }

                                st.open = false;
                                return;
                            }

                            if (st.is_udp_exit) {
                                ScopedFd fd = connect_udp_best_effort(st.dest_host, st.dest_port);
                                if (fd.fd < 0) {
                                    {
                                        const std::string close_payload = encode_lpx_tunnel_payload(
                                            st.upstream_stream_id,
                                            std::string_view{},
                                            kLpxFlagClose);
                                        m_send(st.upstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, close_payload));
                                    }
                                    st.open = false;
                                    return;
                                }
                                st.udp_fd = fd.release();

                                std::string inbuf;
                                inbuf.resize(64 * 1024);
                                while (!st.stop.load()) {
                                    // Flush pending datagrams.
                                    {
                                        std::lock_guard<std::mutex> lk(st.out_mu);
                                        while (!st.out_q.empty()) {
                                            std::string& front = st.out_q.front();
                                            const ssize_t n = ::send(st.udp_fd, front.data(), front.size(), 0);
                                            if (n < 0) {
                                                if (errno == EINTR) {
                                                    continue;
                                                }
                                                st.stop.store(true);
                                                break;
                                            }
                                            st.out_q.pop_front();
                                        }
                                    }

                                    struct pollfd pfd;
                                    pfd.fd = st.udp_fd;
                                    pfd.events = POLLIN;
                                    pfd.revents = 0;
                                    const int rc = ::poll(&pfd, 1, 10);
                                    if (rc == 1 && (pfd.revents & POLLIN)) {
                                        const ssize_t r = ::recv(st.udp_fd, inbuf.data(), inbuf.size(), 0);
                                        if (r > 0) {
                                            const std::string tunnel_payload = encode_lpx_tunnel_payload(
                                                st.upstream_stream_id,
                                                std::string_view(inbuf.data(), static_cast<size_t>(r)),
                                                0);
                                            m_send(st.upstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
                                        }
                                    }
                                }

                                // Best-effort signal upstream that this flow is closed.
                                {
                                    const std::string close_payload = encode_lpx_tunnel_payload(
                                        st.upstream_stream_id,
                                        std::string_view{},
                                        kLpxFlagClose);
                                    m_send(st.upstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, close_payload));
                                }

                                st.open = false;
                                return;
                            }
                    });
                }

                // Enqueue upstream bytes to socket.
                if (!lpx.payload.empty()) {
                    std::lock_guard<std::mutex> lk(s.out_mu);
                    s.out_q.emplace_back(lpx.payload.data(), lpx.payload.size());
                }
                return;
            }
            return;
        }

        // TUNNEL frames.
        // 1) Normal upstream flow.
        auto it = m_streams.find(k);
        if (it != m_streams.end() && it->second) {
            Stream& s = *it->second;
            if (!s.open) {
                return;
            }
            if (lpx.flags & kLpxFlagClose) {
                close_stream_(s, "lpx_close");
                if (!s.downstream_peer_id.empty() && s.downstream_stream_id != 0u) {
                    m_downstream_to_upstream.erase(StreamKey{s.downstream_peer_id, s.downstream_stream_id});
                }
                m_streams.erase(it);
                return;
            }

            // Chain hop: forward upstream -> downstream.
            if (s.is_chain_hop) {
                if (!s.downstream_peer_id.empty() && s.downstream_stream_id != 0u) {
                    const std::string tunnel_payload = encode_lpx_tunnel_payload(s.downstream_stream_id, lpx.payload, 0);
                    m_send(s.downstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
                }
                return;
            }

            // TCP exit: enqueue bytes.
            if (s.is_tcp_exit) {
                std::lock_guard<std::mutex> lk(s.out_mu);
                s.out_q.emplace_back(lpx.payload.data(), lpx.payload.size());
                return;
            }

            // Deterministic test mode: echo back.
            if (m_settings.enable_test_echo) {
                const std::string tunnel_payload = encode_lpx_tunnel_payload(flow_id, lpx.payload, 0);
                m_send(from_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
            }
            return;
        }

        // 2) Downstream flow: map back to upstream.
        auto map_it = m_downstream_to_upstream.find(k);
        if (map_it == m_downstream_to_upstream.end()) {
            // Implicit flow creation for test/echo endpoints.
            if (m_settings.enable_test_echo) {
                StreamKey up_key{from_peer_id, flow_id};
                auto& sp = m_streams[up_key];
                if (!sp) sp = std::make_unique<Stream>();
                Stream& s = *sp;
                s.upstream_peer_id = from_peer_id;
                s.upstream_stream_id = flow_id;
                s.open = true;
                s.use_lpx = true;

                if (!(lpx.flags & kLpxFlagClose)) {
                    const std::string tunnel_payload = encode_lpx_tunnel_payload(flow_id, lpx.payload, 0);
                    m_send(from_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
                }
                return;
            }
            if (m_stream_data_cb) {
                m_stream_data_cb(from_peer_id, flow_id, lpx.payload, (lpx.flags & kLpxFlagClose) != 0);
                return;
            }
            return;
        }

        const StreamKey up_key = map_it->second;
        auto up_it = m_streams.find(up_key);
        if (up_it == m_streams.end() || !up_it->second || !up_it->second->open) {
            return;
        }
        Stream& up = *up_it->second;
        const std::string tunnel_payload = encode_lpx_tunnel_payload(up.upstream_stream_id, lpx.payload, 0);
        m_send(up.upstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
        return;
    }

    ProxyStreamDataView view;
    if (!decode_proxy_stream_data_payload(payload, view)) {
        LOG_WARN("PROXY: malformed stream data payload from " + from_peer_id);
        return;
    }

    const StreamKey k{from_peer_id, view.stream_id};

    // 1) Normal upstream flow: from upstream peer to this endpoint.
    auto it = m_streams.find(k);
    if (it != m_streams.end()) {
        Stream& s = *it->second;
        if (!s.open) {
            LOG_WARN("PROXY: stream data for closed stream " + std::to_string(view.stream_id) + " from " + from_peer_id);
            return;
        }

        // Chain hop: forward upstream -> downstream.
        if (s.is_chain_hop) {
            if (!s.downstream_peer_id.empty() && s.downstream_stream_id != 0u) {
                send_stream_data_(s.downstream_peer_id, s.downstream_stream_id, view.data);
            }
            return;
        }

        // TCP exit: enqueue upstream bytes to socket writer.
        if (s.is_tcp_exit) {
            std::lock_guard<std::mutex> lk(s.out_mu);
            s.out_q.emplace_back(view.data.data(), view.data.size());
            return;
        }

        // Deterministic test mode: echo back to upstream.
        if (m_settings.enable_test_echo) {
            send_stream_data_(from_peer_id, view.stream_id, view.data);
        }
        return;
    }

    // 2) Downstream flow: from a downstream peer back to us.
    auto map_it = m_downstream_to_upstream.find(k);
    if (map_it == m_downstream_to_upstream.end()) {
        // Client-side: we may intentionally not track stream state locally.
        // Allow a consumer (e.g. benchmark tooling) to observe bytes without treating it as an error.
        if (m_stream_data_cb) {
            m_stream_data_cb(from_peer_id, view.stream_id, view.data, view.is_close);
            return;
        }
        LOG_WARN("PROXY: stream data for unknown stream " + std::to_string(view.stream_id) + " from " + from_peer_id);
        return;
    }

    const StreamKey up_key = map_it->second;
    auto up_it = m_streams.find(up_key);
    if (up_it == m_streams.end() || !up_it->second || !up_it->second->open) {
        return;
    }
    Stream& up = *up_it->second;
    // Forward downstream -> upstream.
    send_stream_data_(up.upstream_peer_id, up.upstream_stream_id, view.data);
}

void ProxyEndpoint::client_send_hello(const std::string& gateway_peer_id, int version) {
    (void)gateway_peer_id;
    (void)version;
    // Deprecated: dumb-proxy mode has no proxy-level HELLO handshake.
}

void ProxyEndpoint::client_open_stream(const std::string& gateway_peer_id, uint32_t stream_id,
                                       std::string_view protocol, std::string_view host, int port) {
    if (!m_settings.enable_client) {
        LOG_WARN("PROXY: client_open_stream called but client mode disabled");
        return;
    }
    ClientDest dst;
    if (protocol == "TCP_EXIT" || protocol == "UDP_EXIT" || (!host.empty() && port > 0)) {
        dst.kind = ClientDest::Kind::INET;
        dst.host = std::string(host);
        dst.port = port;
        dst.proto = (protocol == "UDP_EXIT") ? "UDP" : "TCP";
    } else {
        // Unknown without route; keep legacy behavior.
        send_control_(gateway_peer_id, make_open_stream(stream_id, protocol, host, port));
        return;
    }

    m_client_dests[stream_id] = dst;
    const std::string encap_payload = encode_lpx_encap_payload(
        stream_id,
        ClientDestKind::INET,
        std::string_view{},
        dst.host,
        dst.port,
        dst.proto,
        std::string_view{},
        0);
    m_send(gateway_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, encap_payload));
}

void ProxyEndpoint::client_open_stream(const std::string& gateway_peer_id, uint32_t stream_id,
                                       std::string_view protocol, std::string_view host, int port,
                                       const std::vector<std::string>& route) {
    if (!m_settings.enable_client) {
        LOG_WARN("PROXY: client_open_stream(route) called but client mode disabled");
        return;
    }
    // Multi-hop chaining requires a proxy-level OPEN_STREAM so gateways can forward the remaining route.
    // Keep the existing single-hop dumb-proxy fast-path for backward compatibility.
    if (route.size() > 1) {
        send_control_(gateway_peer_id, make_open_stream(stream_id, protocol, host, port, route));
        return;
    }

    if (!route.empty()) {
        ClientDest dst;
        dst.kind = ClientDest::Kind::PEER;
        dst.peer_id = route.front();
        m_client_dests[stream_id] = dst;
        const std::string encap_payload = encode_lpx_encap_payload(
            stream_id,
            ClientDestKind::PEER,
            dst.peer_id,
            std::string_view{},
            0,
            std::string_view{},
            std::string_view{},
            0);
        m_send(gateway_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, encap_payload));
        return;
    }
    // Fallback to legacy OPEN_STREAM if no route provided.
    send_control_(gateway_peer_id, make_open_stream(stream_id, protocol, host, port, route));
}

void ProxyEndpoint::set_stream_data_callback(StreamDataCallback cb) {
    m_stream_data_cb = std::move(cb);
}

void ProxyEndpoint::set_control_callback(ControlCallback cb) {
    m_control_cb = std::move(cb);
}

void ProxyEndpoint::client_send_stream_data(const std::string& gateway_peer_id, uint32_t stream_id, std::string_view data) {
    if (!m_settings.enable_client) {
        LOG_WARN("PROXY: client_send_stream_data called but client mode disabled");
        return;
    }
    auto it = m_client_dests.find(stream_id);
    if (it != m_client_dests.end()) {
        const ClientDest& dst = it->second;
        const std::string encap_payload = encode_lpx_encap_payload(
            stream_id,
            (dst.kind == ClientDest::Kind::PEER) ? ClientDestKind::PEER : ClientDestKind::INET,
            dst.peer_id,
            dst.host,
            dst.port,
            dst.proto,
            data,
            0);
        m_send(gateway_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, encap_payload));
        return;
    }
    // Backward compatibility.
    send_stream_data_(gateway_peer_id, stream_id, data);
}

void ProxyEndpoint::client_close_stream(const std::string& gateway_peer_id, uint32_t stream_id, std::string_view reason) {
    if (!m_settings.enable_client) {
        LOG_WARN("PROXY: client_close_stream called but client mode disabled");
        return;
    }
    (void)reason;
    auto it = m_client_dests.find(stream_id);
    if (it != m_client_dests.end()) {
        const ClientDest& dst = it->second;
        const std::string encap_payload = encode_lpx_encap_payload(
            stream_id,
            (dst.kind == ClientDest::Kind::PEER) ? ClientDestKind::PEER : ClientDestKind::INET,
            dst.peer_id,
            dst.host,
            dst.port,
            dst.proto,
            std::string_view{},
            kLpxFlagClose);
        m_send(gateway_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, encap_payload));
        m_client_dests.erase(it);
        return;
    }
    // Backward compatibility.
    send_control_(gateway_peer_id, make_close_stream(stream_id, reason));
}

void ProxyEndpoint::handle_open_stream_(const std::string& from_peer_id, const json& msg) {
    if (!m_settings.enable_gateway) {
        // Dumb-proxy mode: no proxy-level rejects/acks.
        return;
    }

    const uint32_t stream_id = msg.value("stream_id", 0u);
    if (stream_id == 0u) {
        return;
    }

    const std::string protocol = msg.value("protocol", "");
    const std::string host = msg.value("host", "");
    const int port = msg.value("port", 0);

    std::vector<std::string> route;
    if (msg.contains("route") && msg["route"].is_array()) {
        for (const auto& hop : msg["route"]) {
            if (hop.is_string()) {
                route.push_back(hop.get<std::string>());
            }
        }
    }

    StreamKey up_key{from_peer_id, stream_id};
    auto& sp = m_streams[up_key];
    if (!sp) {
        sp = std::make_unique<Stream>();
    }
    Stream& s = *sp;
    s.upstream_peer_id = from_peer_id;
    s.upstream_stream_id = stream_id;
    s.protocol = protocol;
    s.dest_host = host;
    s.dest_port = port;
    s.route = route;
    s.open = true;

    // Chaining: if a route is provided, forward to the next hop.
    if (!route.empty()) {
        s.is_chain_hop = true;
        s.downstream_peer_id = route.front();
        s.downstream_stream_id = ++m_next_local_stream_id;
        s.downstream_open = false;

        // Record mapping for downstream -> upstream forwarding.
        m_downstream_to_upstream[StreamKey{s.downstream_peer_id, s.downstream_stream_id}] = up_key;

        // Exit-node proxy model: The gateway must connect to the downstream peer.
        // This allows peer_a to reach peer_b through Android without peer_b connecting to Android.
        // Android will "exit" traffic to peer_b, appearing as the sender.
        if (m_connect) {
            LOG_INFO("PROXY: Gateway connecting to downstream peer: " + s.downstream_peer_id);
            m_connect(s.downstream_peer_id);
        }

        // Build remaining route and forward OPEN_STREAM downstream.
        std::vector<std::string> remaining(route.begin() + 1, route.end());
        send_control_(s.downstream_peer_id, make_open_stream(s.downstream_stream_id, protocol, host, port, remaining));
        return;
    }

    // TCP exit: connect to host:port and start IO loop.
    // IMPORTANT: keep legacy behavior stable. The existing tests (and the original proxy.md scope)
    // treated "TCP" as a logical protocol label for deterministic echo, not a real outbound connect.
    // Real TCP tunneling is gated behind a dedicated protocol string.
    if (protocol == "TCP_EXIT") {
        if (host.empty() || port <= 0) {
            m_streams.erase(up_key);
            return;
        }

        s.is_tcp_exit = true;
        // Start IO thread that connects and then pumps data.
        s.io_thread = std::thread([this, up_key]() {
            auto it2 = m_streams.find(up_key);
            if (it2 == m_streams.end()) return;
            if (!it2->second) return;
            Stream& st = *it2->second;

            ScopedFd fd = connect_tcp_blocking(st.dest_host, st.dest_port, 3000);
            if (fd.fd < 0) {
                st.open = false;
                return;
            }

            st.tcp_fd = fd.release();

            // Simple pump loop: read from socket, write queued upstream->socket, forward socket->upstream.
            std::string inbuf;
            inbuf.resize(16 * 1024);
            while (!st.stop.load()) {
                // Flush pending writes.
                {
                    std::lock_guard<std::mutex> lk(st.out_mu);
                    while (!st.out_q.empty()) {
                        std::string& front = st.out_q.front();
                        if (front.empty()) {
                            st.out_q.pop_front();
                            continue;
                        }
                        const ssize_t n = ::send(st.tcp_fd, front.data(), front.size(), 0);
                        if (n < 0) {
                            if (errno == EINTR) {
                                continue;
                            }
                            // Give up.
                            st.stop.store(true);
                            break;
                        }
                        if (n == 0) {
                            st.stop.store(true);
                            break;
                        }
                        front.erase(0, static_cast<size_t>(n));
                        if (front.empty()) {
                            st.out_q.pop_front();
                        } else {
                            break;
                        }
                    }
                }

                // Read from socket.
                const ssize_t r = ::recv(st.tcp_fd, inbuf.data(), inbuf.size(), 0);
                if (r > 0) {
                    send_stream_data_(st.upstream_peer_id, st.upstream_stream_id, std::string_view(inbuf.data(), static_cast<size_t>(r)));
                    continue;
                }
                if (r == 0) {
                    // Remote closed.
                    break;
                }
                if (r < 0 && errno == EINTR) {
                    continue;
                }
                if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    continue;
                }
                // Other error.
                break;
            }

            st.open = false;
        });
        return;
    }

    // Default deterministic behavior (ECHO mode). This keeps tests stable.
    return;
}

void ProxyEndpoint::handle_close_stream_(const std::string& from_peer_id, const json& msg) {
    const uint32_t stream_id = msg.value("stream_id", 0u);
    if (stream_id == 0u) {
        return;
    }

    StreamKey up_key{from_peer_id, stream_id};
    auto it = m_streams.find(up_key);
    if (it == m_streams.end()) return;

    if (!it->second) return;
    Stream& s = *it->second;
    if (s.upstream_peer_id != from_peer_id) return;

    close_stream_(s, msg.value("reason", "closed"));

    // Remove any downstream mapping.
    if (!s.downstream_peer_id.empty() && s.downstream_stream_id != 0u) {
        m_downstream_to_upstream.erase(StreamKey{s.downstream_peer_id, s.downstream_stream_id});
    }

    m_streams.erase(it);
}

void ProxyEndpoint::close_stream_(Stream& s, std::string_view reason) {
    (void)reason;
    s.stop.store(true);

    if (s.is_chain_hop && !s.downstream_peer_id.empty() && s.downstream_stream_id != 0u) {
        if (s.use_lpx) {
            const std::string tunnel_payload = encode_lpx_tunnel_payload(s.downstream_stream_id, std::string_view{}, kLpxFlagClose);
            m_send(s.downstream_peer_id, wire::encode_message(MessageType::PROXY_STREAM_DATA, tunnel_payload));
        } else {
            send_control_(s.downstream_peer_id, make_close_stream(s.downstream_stream_id, "upstream_closed"));
        }
    }

    if (s.tcp_fd >= 0) {
        ::shutdown(s.tcp_fd, SHUT_RDWR);
        ::close(s.tcp_fd);
        s.tcp_fd = -1;
    }

    if (s.udp_fd >= 0) {
        ::close(s.udp_fd);
        s.udp_fd = -1;
    }

    if (s.io_thread.joinable()) {
        s.io_thread.join();
    }
    s.open = false;
}

void ProxyEndpoint::send_control_(const std::string& peer_id, const json& control) {
    LOG_INFO("PROXY: send_control_ to " + peer_id + " type=" + control.value("type", "?"));
    m_send(peer_id, encode_proxy_control_wire(control));
}

void ProxyEndpoint::send_stream_data_(const std::string& peer_id, uint32_t stream_id, std::string_view data) {
    m_send(peer_id, encode_proxy_stream_data_wire(stream_id, data));
}

} // namespace proxy
