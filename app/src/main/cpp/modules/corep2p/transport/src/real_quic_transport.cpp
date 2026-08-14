#include "real_quic_transport.h"

#if defined(LITEP2P_ENABLE_REAL_QUIC)

#include "logger.h"

#include <picoquic.h>
#include <picoquic_packet_loop.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

namespace {

constexpr char kAlpn[] = "litep2p";
constexpr size_t kMaxDatagram = 1200;            // announced max_datagram_frame_size
constexpr size_t kMaxPendingDatagrams = 64;      // per peer, before connection ready
constexpr int64_t kTimeCheckIntervalUs = 200000; // loop wakes >= every 200ms

// ---------------------------------------------------------------------------
// Cert resolution (demo self-signed cert shipped with picoquic).
// ---------------------------------------------------------------------------

bool file_exists(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

std::string resolve_cert_path(const char* leaf) {
    static const char* kPrefixes[] = {
        "",
        "../",
        "../../",
        "../../../",
        "third_party/picoquic/",
        "../third_party/picoquic/",
        "../../third_party/picoquic/",
        "../../../third_party/picoquic/",
    };
    for (const char* prefix : kPrefixes) {
        std::string candidate = std::string(prefix) + leaf;
        if (file_exists(candidate)) {
            return candidate;
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

// Format a sockaddr as a network_id string: "a.b.c.d:port" for IPv4,
// "[v6]:port" for IPv6. IPv4-mapped IPv6 addresses are normalized to IPv4.
std::string format_sockaddr(const struct sockaddr* sa) {
    char host[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(sa);
        inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
        port = ntohs(sin->sin_port);
        return std::string(host) + ":" + std::to_string(port);
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* sin6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        port = ntohs(sin6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            struct in_addr v4;
            std::memcpy(&v4, reinterpret_cast<const uint8_t*>(&sin6->sin6_addr) + 12, 4);
            inet_ntop(AF_INET, &v4, host, sizeof(host));
            return std::string(host) + ":" + std::to_string(port);
        }
        inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
        return "[" + std::string(host) + "]:" + std::to_string(port);
    }
    return {};
}

// Resolve host:port with IPv6 preference (prefer AAAA over A records).
bool resolve_prefer_ipv6(const std::string& host, uint16_t port,
                         struct sockaddr_storage& out) {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port_str, &hints, &res) != 0) {
        return false;
    }

    const struct addrinfo* v6 = nullptr;
    const struct addrinfo* v4 = nullptr;
    const struct addrinfo* any = nullptr;
    for (const struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        if (any == nullptr) any = ai;
        if (ai->ai_family == AF_INET6 && v6 == nullptr) v6 = ai;
        if (ai->ai_family == AF_INET && v4 == nullptr) v4 = ai;
    }

    const struct addrinfo* chosen = (v6 != nullptr) ? v6 : ((v4 != nullptr) ? v4 : any);
    if (chosen == nullptr) {
        freeaddrinfo(res);
        return false;
    }
    std::memcpy(&out, chosen->ai_addr, chosen->ai_addrlen);
    freeaddrinfo(res);
    return true;
}

// ---------------------------------------------------------------------------
// Peer state
// ---------------------------------------------------------------------------

struct PeerState {
    void* owner = nullptr; // RealQuicTransport::Impl* (opaque to avoid private access)
    std::string peer_id;
    bool ready = false;
    bool closed = false;
    std::deque<std::string> pending_datagrams; // queued before the handshake completes
};

} // namespace

struct RealQuicTransport::Impl {
    picoquic_quic_t* quic = nullptr;
    picoquic_network_thread_ctx_t* thread_ctx = nullptr;
    picoquic_packet_loop_param_t loop_param;
    std::atomic<bool> running{false};

    OnDataCb on_data;
    OnReadyCb on_ready;
    OnDisconnectCb on_disconnect;

    std::mutex mu;
    std::map<std::string, picoquic_cnx_t*> cnx_by_peer;
    std::map<picoquic_cnx_t*, PeerState*> state_by_cnx;
    std::vector<PeerState*> zombies;
    std::atomic<uint64_t> incoming_seq{0};

    struct PendingConnect {
        std::string peer_id;
        std::string host;
        uint16_t port;
    };
    std::vector<PendingConnect> pending_connects;

    // Outgoing datagrams queued by other threads; flushed by the packet loop
    // thread (picoquic connections are single-threaded objects).
    struct OutgoingDatagram {
        picoquic_cnx_t* cnx;
        std::string data;
    };
    std::vector<OutgoingDatagram> outgoing_datagrams;

    // ------------------------------------------------------------------
    // Connection lifecycle helpers
    // ------------------------------------------------------------------

    void on_connection_ready(picoquic_cnx_t* cnx, PeerState* st) {
        st->ready = true;

        // Diagnostic: confirm the peer announced datagram support.
        const picoquic_tp_t* remote_tp = picoquic_get_transport_parameters(cnx, 0 /* remote */);
        if (remote_tp != nullptr) {
            LOG_DEBUG("QUIC: peer " + st->peer_id + " remote max_datagram_frame_size=" +
                      std::to_string(remote_tp->max_datagram_frame_size));
        } else {
            LOG_WARN("QUIC: could not read remote transport parameters for " + st->peer_id);
        }

        // Flush datagrams queued before the handshake completed.
        std::vector<std::string> to_send;
        {
            std::lock_guard<std::mutex> lock(mu);
            to_send.assign(st->pending_datagrams.begin(), st->pending_datagrams.end());
            st->pending_datagrams.clear();
        }
        for (const auto& data : to_send) {
            if (data.size() <= kMaxDatagram) {
                picoquic_queue_datagram_frame(cnx, data.size(),
                                              reinterpret_cast<const uint8_t*>(data.data()));
            }
        }

        if (on_ready) {
            on_ready(st->peer_id);
        }
        LOG_INFO("QUIC: connection ready for peer " + st->peer_id);
    }

    void on_connection_closed(picoquic_cnx_t* cnx, PeerState* st) {
        if (st == nullptr || st->closed) return;
        st->closed = true;

        {
            std::lock_guard<std::mutex> lock(mu);
            state_by_cnx.erase(cnx);
            for (auto it = cnx_by_peer.begin(); it != cnx_by_peer.end(); ++it) {
                if (it->second == cnx) {
                    cnx_by_peer.erase(it);
                    break;
                }
            }
            zombies.push_back(st);
        }

        if (on_disconnect) {
            on_disconnect(st->peer_id);
        }
        LOG_INFO("QUIC: connection closed for peer " + st->peer_id);
    }

    void drain_pending_connects() {
        std::vector<PendingConnect> batch;
        {
            std::lock_guard<std::mutex> lock(mu);
            batch.swap(pending_connects);
        }

        for (const auto& pc : batch) {
            struct sockaddr_storage addr_storage {};
            if (!resolve_prefer_ipv6(pc.host, pc.port, addr_storage)) {
                LOG_WARN("QUIC: failed to resolve " + pc.host);
                continue;
            }

            auto* st = new PeerState{this, pc.peer_id, false, false, {}};
            const uint64_t now = picoquic_current_time();
            picoquic_cnx_t* cnx = picoquic_create_client_cnx(
                quic, reinterpret_cast<struct sockaddr*>(&addr_storage), now,
                0 /* preferred version */, pc.host.c_str(), kAlpn,
                &Impl::peer_callback, st);

            if (cnx == nullptr) {
                LOG_WARN("QUIC: failed to create client connection for " + pc.peer_id);
                delete st;
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(mu);
                cnx_by_peer[pc.peer_id] = cnx;
                state_by_cnx[cnx] = st;
            }

            LOG_INFO("QUIC: starting client connection to " + pc.peer_id +
                     " (" + pc.host + ")");
            picoquic_start_client_cnx(cnx);
        }
    }

    void drain_zombies() {
        std::vector<PeerState*> batch;
        {
            std::lock_guard<std::mutex> lock(mu);
            batch.swap(zombies);
        }
        for (PeerState* st : batch) {
            delete st;
        }
    }

    // Called on the packet loop thread: send all queued datagrams.
    void drain_outgoing_datagrams() {
        std::vector<OutgoingDatagram> batch;
        {
            std::lock_guard<std::mutex> lock(mu);
            batch.swap(outgoing_datagrams);
        }
        for (const auto& dg : batch) {
            const int rc = picoquic_queue_datagram_frame(
                dg.cnx, dg.data.size(), reinterpret_cast<const uint8_t*>(dg.data.data()));
            if (rc != 0) {
                LOG_WARN("QUIC: queue_datagram_frame failed rc=" + std::to_string(rc));
            }
        }
    }

    // ------------------------------------------------------------------
    // Callbacks
    // ------------------------------------------------------------------

    // Default callback: used for *incoming* connections before we install a
    // per-connection callback.
    static int default_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes,
                                size_t length, picoquic_call_back_event_t fin_or_event,
                                void* callback_ctx, void* v_stream_ctx) {
        (void)stream_id;
        (void)bytes;
        (void)length;
        (void)v_stream_ctx;

        Impl* impl = static_cast<Impl*>(callback_ctx);
        if (impl == nullptr) return 0;

        switch (fin_or_event) {
        case picoquic_callback_ready: {
            // New incoming peer: install a per-connection callback with fresh state.
            struct sockaddr* peer_addr = nullptr;
            picoquic_get_peer_addr(cnx, &peer_addr);
            const std::string peer_id =
                peer_addr ? format_sockaddr(peer_addr)
                          : ("quic-incoming-" + std::to_string(++impl->incoming_seq));

            auto* st = new PeerState{impl, peer_id, false, false, {}};
            picoquic_set_callback(cnx, &Impl::peer_callback, st);
            {
                std::lock_guard<std::mutex> lock(impl->mu);
                impl->state_by_cnx[cnx] = st;
                impl->cnx_by_peer[peer_id] = cnx;
            }
            impl->on_connection_ready(cnx, st);
            return 0;
        }
        case picoquic_callback_close:
        case picoquic_callback_application_close: {
            PeerState* st = nullptr;
            {
                std::lock_guard<std::mutex> lock(impl->mu);
                auto it = impl->state_by_cnx.find(cnx);
                if (it != impl->state_by_cnx.end()) st = it->second;
            }
            impl->on_connection_closed(cnx, st);
            return 0;
        }
        default:
            return 0;
        }
    }

    // Per-connection callback: installed for outgoing client connections at
    // creation time and for incoming connections on `ready`.
    static int peer_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes,
                             size_t length, picoquic_call_back_event_t fin_or_event,
                             void* callback_ctx, void* v_stream_ctx) {
        (void)stream_id;
        (void)v_stream_ctx;

        PeerState* st = static_cast<PeerState*>(callback_ctx);
        if (st == nullptr || st->owner == nullptr) return 0;
        Impl* impl = static_cast<Impl*>(st->owner);

        switch (fin_or_event) {
        case picoquic_callback_ready:
            impl->on_connection_ready(cnx, st);
            return 0;
        case picoquic_callback_datagram:
            if (impl->on_data && bytes != nullptr && length > 0) {
                LOG_DEBUG("QUIC: datagram received from " + st->peer_id + " len=" +
                          std::to_string(length));
                impl->on_data(st->peer_id, std::string(reinterpret_cast<char*>(bytes), length));
            }
            return 0;
        case picoquic_callback_close:
        case picoquic_callback_application_close:
            impl->on_connection_closed(cnx, st);
            return 0;
        default:
            return 0;
        }
    }

    // Packet loop callback: drives pending connects and zombie cleanup.
    static int loop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
                             void* callback_ctx, void* callback_argv) {
        (void)quic;
        Impl* impl = static_cast<Impl*>(callback_ctx);
        if (impl == nullptr) return 0;

        switch (cb_mode) {
        case picoquic_packet_loop_ready: {
            auto* options = static_cast<picoquic_packet_loop_options_t*>(callback_argv);
            if (options != nullptr) {
                options->do_time_check = 1;
            }
            return 0;
        }
        case picoquic_packet_loop_wake_up:
            // Another thread posted work (connect/send): process it here,
            // in the network thread, where picoquic APIs are safe to call.
            impl->drain_pending_connects();
            impl->drain_outgoing_datagrams();
            impl->drain_zombies();
            return 0;
        case picoquic_packet_loop_time_check: {
            impl->drain_pending_connects();
            impl->drain_outgoing_datagrams();
            impl->drain_zombies();

            // Cap the loop sleep so shutdown and pending work stay responsive.
            auto* arg = static_cast<packet_loop_time_check_arg_t*>(callback_argv);
            if (arg != nullptr && arg->delta_t > kTimeCheckIntervalUs) {
                arg->delta_t = kTimeCheckIntervalUs;
            }
            return 0;
        }
        default:
            return 0;
        }
    }
};

// ============================================================================
// Public API
// ============================================================================

bool RealQuicTransport::available() {
    return true;
}

RealQuicTransport::RealQuicTransport() : m_impl(std::make_unique<Impl>()) {
}

RealQuicTransport::~RealQuicTransport() {
    stop();
}

bool RealQuicTransport::start(uint16_t port, OnDataCb on_data, OnReadyCb on_ready,
                              OnDisconnectCb on_disconnect) {
    if (m_impl->running.load()) {
        LOG_WARN("QUIC: transport already running");
        return false;
    }

    const std::string cert_file = resolve_cert_path("certs/secp256r1-pkcs8/cert.pem");
    const std::string key_file = resolve_cert_path("certs/secp256r1-pkcs8/key.pem");
    if (cert_file.empty() || key_file.empty()) {
        LOG_ERROR("QUIC: TLS certificate/key not found (expected picoquic EC P-256 PKCS8 demo certs in "
                  "third_party/picoquic/certs/secp256r1-pkcs8). Real QUIC unavailable.");
        return false;
    }

    m_impl->on_data = std::move(on_data);
    m_impl->on_ready = std::move(on_ready);
    m_impl->on_disconnect = std::move(on_disconnect);

    const uint64_t now = picoquic_current_time();
    m_impl->quic = picoquic_create(
        64 /* max connections */, cert_file.c_str(), key_file.c_str(),
        nullptr /* cert root */, kAlpn,
        &Impl::default_callback, m_impl.get(),
        nullptr, nullptr, nullptr,
        now, nullptr, nullptr, nullptr, 0);

    if (m_impl->quic == nullptr) {
        LOG_ERROR("QUIC: picoquic_create failed");
        return false;
    }

    // Beta transport: both peers present the same self-signed cert; skip
    // certificate verification (see security note in the header).
    picoquic_set_null_verifier(m_impl->quic);

    // Announce datagram support and a generous idle timeout.
    picoquic_set_default_tp_value(m_impl->quic, picoquic_tp_max_datagram_frame_size,
                                  kMaxDatagram);
    picoquic_set_default_tp_value(m_impl->quic, picoquic_tp_idle_timeout,
                                  300000 /* 5 min, milliseconds */);

    // AF_INET6: dual-stack socket (picoquic clears IPV6_V6ONLY), so both
    // IPv6 and IPv4 (v4-mapped) peers are accepted - IPv6 preferred.
    memset(&m_impl->loop_param, 0, sizeof(m_impl->loop_param));
    m_impl->loop_param.local_port = port;
    m_impl->loop_param.local_af = AF_INET6;

    m_impl->running.store(true);
    int start_ret = 0;
    m_impl->thread_ctx = picoquic_start_network_thread(
        m_impl->quic, &m_impl->loop_param, &Impl::loop_callback, m_impl.get(), &start_ret);
    if (m_impl->thread_ctx == nullptr) {
        LOG_ERROR("QUIC: failed to start network thread (ret=" + std::to_string(start_ret) + ")");
        m_impl->running.store(false);
        return false;
    }

    LOG_INFO("QUIC: real QUIC transport listening on port " + std::to_string(port) +
             " (IPv6 dual-stack)");
    return true;
}

void RealQuicTransport::stop() {
    if (!m_impl->running.exchange(false)) {
        return;
    }
    // Closes the packet loop (joins the network thread) and frees the thread
    // context.
    if (m_impl->thread_ctx != nullptr) {
        picoquic_delete_network_thread(m_impl->thread_ctx);
        m_impl->thread_ctx = nullptr;
    }
    if (m_impl->quic != nullptr) {
        picoquic_free(m_impl->quic);
        m_impl->quic = nullptr;
    }
    m_impl->drain_zombies();
    LOG_INFO("QUIC: transport stopped");
}

bool RealQuicTransport::connect(const std::string& peer_id, const std::string& host,
                                uint16_t port) {
    if (!m_impl->running.load()) return false;
    {
        std::lock_guard<std::mutex> lock(m_impl->mu);
        m_impl->pending_connects.push_back({peer_id, host, port});
    }
    if (m_impl->thread_ctx != nullptr) {
        picoquic_wake_up_network_thread(m_impl->thread_ctx);
    }
    return true;
}

bool RealQuicTransport::send(const std::string& peer_id, const std::string& data) {
    if (!m_impl->running.load()) return false;
    if (data.size() > kMaxDatagram) {
        LOG_WARN("QUIC: refusing to send datagram of " + std::to_string(data.size()) +
                 " bytes (max " + std::to_string(kMaxDatagram) + ")");
        return false;
    }

    // picoquic connections are single-threaded objects owned by the packet
    // loop thread: queue here and let the loop flush (see drain_outgoing_datagrams).
    std::lock_guard<std::mutex> lock(m_impl->mu);
    auto it = m_impl->cnx_by_peer.find(peer_id);
    if (it == m_impl->cnx_by_peer.end()) return false;
    picoquic_cnx_t* cnx = it->second;
    auto sit = m_impl->state_by_cnx.find(cnx);
    if (sit == m_impl->state_by_cnx.end()) return false;
    PeerState* st = sit->second;

    if (!st->ready) {
        if (st->pending_datagrams.size() >= kMaxPendingDatagrams) {
            LOG_WARN("QUIC: pending datagram queue full for " + peer_id);
            return false;
        }
        st->pending_datagrams.push_back(data);
        return true;
    }

    m_impl->outgoing_datagrams.push_back({cnx, data});
    if (m_impl->thread_ctx != nullptr) {
        picoquic_wake_up_network_thread(m_impl->thread_ctx);
    }
    return true;
}

bool RealQuicTransport::is_connected(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_impl->mu);
    auto it = m_impl->cnx_by_peer.find(peer_id);
    if (it == m_impl->cnx_by_peer.end()) return false;
    auto sit = m_impl->state_by_cnx.find(it->second);
    return sit != m_impl->state_by_cnx.end() && sit->second->ready;
}

#else // !LITEP2P_ENABLE_REAL_QUIC

// Stub implementations so callers can link unconditionally when real QUIC is
// not compiled in.

struct RealQuicTransport::Impl {};

bool RealQuicTransport::available() { return false; }
RealQuicTransport::RealQuicTransport() : m_impl(std::make_unique<Impl>()) {}
RealQuicTransport::~RealQuicTransport() = default;
bool RealQuicTransport::start(uint16_t, OnDataCb, OnReadyCb, OnDisconnectCb) { return false; }
void RealQuicTransport::stop() {}
bool RealQuicTransport::connect(const std::string&, const std::string&, uint16_t) { return false; }
bool RealQuicTransport::send(const std::string&, const std::string&) { return false; }
bool RealQuicTransport::is_connected(const std::string&) const { return false; }

#endif // LITEP2P_ENABLE_REAL_QUIC
