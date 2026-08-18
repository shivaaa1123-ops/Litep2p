#include "session_manager_p.h"
#include "anomaly_reporter.h"
#include "../../../corep2p/transport/include/quic_connection_manager.h"
#include "../../../corep2p/transport/include/udp_connection_manager.h"
#include "../../../corep2p/core/include/config_manager.h"
#include "../../../corep2p/core/include/telemetry.h"
#include "../../../corep2p/core/include/device_utils.h"
#include "../../../corep2p/crypto/include/crypto_utils.h"
#include "../../routing/include/upnp_controller.h"
#include "../../discovery/include/signaling_client.h"
#include "../../discovery/include/discovery.h"
#include "unified_event_loop.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <algorithm>
#include <random>
#include <cstdlib>
#include <cerrno>
#include <filesystem>
#include <sys/select.h>
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <cstring>
#endif

#if HAVE_JNI
#include <android/log.h>
// Avoid shipping extremely chatty native traces by default.
// Enable by building with -DLITEP2P_NATIVE_TRACE=1.
#if defined(LITEP2P_NATIVE_TRACE) && LITEP2P_NATIVE_TRACE
#define NATIVELOGW(msg) __android_log_write(ANDROID_LOG_WARN, "Litep2p", msg)
#else
#define NATIVELOGW(msg) do { } while (0)
#endif
#else
#define NATIVELOGW(msg) do { } while (0)
#endif

namespace {
inline int64_t system_now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

inline int64_t steady_now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

inline std::string get_executable_dir_best_effort() {
#if defined(__APPLE__)
    uint32_t size = 0;
    if (_NSGetExecutablePath(nullptr, &size) != -1 || size == 0) {
        // size now contains required buffer length
    }
    std::string buffer(size, '\0');
    if (_NSGetExecutablePath(buffer.data(), &size) == 0) {
        buffer.resize(std::strlen(buffer.c_str()));
        try {
            return std::filesystem::path(buffer).parent_path().string();
        } catch (...) {
            return {};
        }
    }
    return {};
#elif defined(__linux__)
    char buf[PATH_MAX];
    ssize_t len = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        try {
            return std::filesystem::path(buf).parent_path().string();
        } catch (...) {
            return {};
        }
    }
    return {};
#else
    return {};
#endif
}

inline std::string join_path_best_effort(const std::string& dir, const std::string& leaf) {
    if (dir.empty()) return leaf;
    try {
        return (std::filesystem::path(dir) / leaf).string();
    } catch (...) {
        return dir + "/" + leaf;
    }
}

inline bool is_single_thread_mode() {
    static const bool enabled = []() {
#if defined(LITEP2P_SINGLE_THREAD_MODE_COMPILE) && LITEP2P_SINGLE_THREAD_MODE_COMPILE
        return true;  // Compile-time enabled
#else
        const char* v = std::getenv("LITEP2P_SINGLE_THREAD_MODE");
        if (!v) return false;
        return std::string(v) != "0";
#endif
    }();
    return enabled;
}

// True when some OTHER process on this host already holds `port` on a UDP
// socket. This is how we detect same-device multi-app coexistence: with
// SO_REUSEPORT a second bind() on the same port succeeds and the kernel then
// load-balances inbound unicast datagrams between the two sockets, so neither
// app reliably receives its handshake/message traffic.
//
// The probe deliberately binds WITHOUT SO_REUSEADDR/SO_REUSEPORT so it is
// rejected (EADDRINUSE) whenever ANY other socket already holds the port.
// (Binding with SO_REUSEADDR here would be wrong: on Linux two UDP sockets can
// share an addr:port when BOTH set SO_REUSEADDR — the engine's own data socket
// binds with SO_REUSEADDR+SO_REUSEPORT, so a reuseaddr probe would silently
// succeed against it and the coexistence fallback below would never engage.)
bool udp_port_held_by_other_process(int port) {
    if (port <= 0 || port > 65535) return false;
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    const bool held = (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0);
    ::close(fd);
    return held;
}
} // namespace

// ============================================================================
// PIMPL FORWARDING
// ============================================================================

SessionManager::SessionManager(std::shared_ptr<ISessionDependenciesFactory> factory) : m_impl(std::make_unique<Impl>(factory)) {}
SessionManager::~SessionManager() = default;

void SessionManager::start(int port, std::function<void(const std::vector<Peer>&)> cb, const std::string& comms_mode, const std::string& peer_id) {
    m_impl->start(port, cb, comms_mode, peer_id);
}

void SessionManager::stop() {
    m_impl->stop();
}

std::future<void> SessionManager::stopAsync() {
    return m_impl->stopAsync();
}

void SessionManager::setMessageReceivedCallback(std::function<void(const std::string&, const std::string&)> cb) {
    m_impl->setMessageReceivedCallback(cb);
}

#if ENABLE_PROXY_MODULE
proxy::ProxyEndpoint* SessionManager::get_proxy_endpoint() {
    return m_impl->m_proxy_endpoint.get();
}

void SessionManager::configure_proxy(const proxy::ProxySettings& settings) {
    if (m_impl->m_proxy_endpoint) {
        m_impl->m_proxy_endpoint->configure(settings);
    }
}
#endif

#if ENABLE_OVERLAY_MODULE
void SessionManager::set_overlay_relay_enabled(bool enabled) {
    if (m_impl->m_overlay_router) {
        m_impl->m_overlay_router->set_relay_enabled(enabled);
    }
}

std::string SessionManager::send_overlay(const std::string& peer_id, const std::string& payload,
                                         bool want_ack, bool via_mailbox) {
    if (!m_impl->m_overlay_router) return {};
    std::string frame_id;
    const auto rc = m_impl->m_overlay_router->send(peer_id, payload, want_ack,
                                                   via_mailbox, frame_id);
    return rc == overlay::OverlayRouter::SendResult::Ok ? frame_id : std::string{};
}

int SessionManager::send_overlay_ex(const std::string& peer_id, const std::string& payload,
                                    bool want_ack, bool via_mailbox, std::string& out_frame_id) {
    out_frame_id.clear();
    if (!m_impl->m_overlay_router) return static_cast<int>(overlay::OverlayRouter::SendResult::Internal);
    return static_cast<int>(m_impl->m_overlay_router->send(peer_id, payload, want_ack,
                                                           via_mailbox, out_frame_id));
}

void SessionManager::set_overlay_delivery_cb(
    std::function<void(const std::string&, bool)> cb) {
    if (!m_impl->m_overlay_router) return;
    m_impl->m_overlay_router->set_delivery_cb(
        [cb](const std::string& frame_id, overlay::OverlayRouter::DeliveryStatus st) {
            if (cb) cb(frame_id, st == overlay::OverlayRouter::DeliveryStatus::Delivered);
        });
}

void SessionManager::overlay_pickup_mailbox(const std::string& relay_peer_id) {
    if (m_impl->m_overlay_router) {
        m_impl->m_overlay_router->pickup_mailbox(relay_peer_id);
    }
}

void SessionManager::overlay_register_relay(const std::string& peer_id, int capacity,
                                            int max_hops, bool persistent) {
    if (peer_id.empty() || !m_impl->m_overlay_router) return;
    if (capacity <= 0 || capacity > 65535) capacity = 32;
    if (max_hops <= 0 || max_hops > 8) max_hops = 4;
    m_impl->m_overlay_router->register_relay_candidate(
        peer_id, static_cast<uint16_t>(capacity), static_cast<uint8_t>(max_hops), persistent);
}

void SessionManager::overlay_register_peer_signing_key(const std::string& peer_id,
                                                       const std::vector<uint8_t>& public_key) {
#if HAVE_NOISE_PROTOCOL
    if (peer_id.empty() || public_key.size() != 32) return;
    if (m_impl->m_noise_key_store) {
        m_impl->m_noise_key_store->register_peer_signing_key(peer_id, public_key);
    }
#else
    (void)peer_id;
    (void)public_key;
#endif
}

std::string SessionManager::overlay_stats_json() const {
    return m_impl->m_overlay_router ? m_impl->m_overlay_router->stats_json() : std::string("{}");
}
#endif

void SessionManager::connectToPeer(const std::string& peer_id) {
    // "user_api" source marks this as an explicit user request (clears any
    // user-disconnect suppression); internal reconnect paths use "api".
    m_impl->connectToPeer(peer_id, false, "user_api");
}

void SessionManager::connectToPeer(const std::string& peer_id, bool bypass_reconnect_policy) {
    // Public API: keep behavior identical unless the caller explicitly requests bypass.
    // Source tag helps triage logs when this path is used.
    m_impl->connectToPeer(peer_id, bypass_reconnect_policy,
                          bypass_reconnect_policy ? "user_api_bypass" : "user_api");
}

bool SessionManager::disconnectFromPeer(const std::string& peer_id) {
    return m_impl->disconnectFromPeer(peer_id);
}

void SessionManager::addPeer(const std::string& peer_id, const std::string& network_id) {
    m_impl->handlePeerDiscovered(network_id, peer_id);
}

void SessionManager::sendMessageToPeer(const std::string& peer_id, const std::string& message) {
    m_impl->sendMessageToPeer(peer_id, message);
}

int SessionManager::pendingSendCount() const {
    return m_impl->pending_send_count();
}

bool SessionManager::isPeerConnected(const std::string& peer_id) const {
    return m_impl->isPeerConnected(peer_id);
}

std::string SessionManager::getPeerFsmState(const std::string& peer_id) const {
    return m_impl->getPeerFsmState(peer_id);
}

std::string SessionManager::getPeerConnectionType(const std::string& peer_id) const {
    return m_impl->getPeerConnectionType(peer_id);
}

void SessionManager::set_battery_level(int batteryPercent, bool isCharging) {
    m_impl->set_battery_level_public(batteryPercent, isCharging);
}

void SessionManager::set_network_info(bool isWiFi, bool isNetworkAvailable) {
    m_impl->set_network_info_public(isWiFi, isNetworkAvailable);
}

void SessionManager::set_reconnect_mode(const std::string& mode) {
    m_impl->set_reconnect_mode_public(mode);
}

std::string SessionManager::get_reconnect_status_json() const {
    return m_impl->get_reconnect_status_json_public();
}

// ============================================================================
// v0.4 public wrappers (ask.md §1/§2/§3/§5)
// ============================================================================
bool SessionManager::send_reliable(const std::string& peer_id, const std::string& msg_id,
                                   const std::string& payload, int max_retries,
                                   uint32_t retry_timeout_ms) {
    return m_impl->send_reliable(peer_id, msg_id, payload, max_retries, retry_timeout_ms);
}

bool SessionManager::reliable_outbox_full() const {
    return m_impl->reliable_outbox_full();
}

size_t SessionManager::reliable_pending_count() const {
    return m_impl->reliable_pending_count();
}

bool SessionManager::cancel_reliable(const std::string& msg_id) {
    return m_impl->cancel_reliable(msg_id);
}

void SessionManager::set_delivery_status_callback(DeliveryStatusCallback cb) {
    m_impl->set_delivery_status_callback(std::move(cb));
}

void SessionManager::set_ping_result_callback(PingResultCallback cb) {
    m_impl->set_ping_result_callback(std::move(cb));
}

bool SessionManager::ping_peer(const std::string& peer_id, uint32_t timeout_ms) {
    return m_impl->ping_peer(peer_id, timeout_ms);
}

void SessionManager::set_presence_callback(PresenceCallback cb) {
    m_impl->set_presence_callback(std::move(cb));
}

bool SessionManager::subscribe_presence(const std::vector<std::string>& peer_ids) {
    return m_impl->subscribe_presence(peer_ids);
}

int64_t SessionManager::get_peer_last_seen_ms(const std::string& peer_id) const {
    return m_impl->get_peer_last_seen_ms(peer_id);
}

void SessionManager::set_lookup_result_callback(LookupResultCallback cb) {
    m_impl->set_lookup_result_callback(std::move(cb));
}

void SessionManager::set_invite_callback(InviteCallback cb) {
    m_impl->set_invite_callback(std::move(cb));
}

bool SessionManager::register_alias(const std::string& alias_hash) {
    return m_impl->register_alias(alias_hash);
}

bool SessionManager::lookup_peer(const std::string& alias_hash) {
    return m_impl->lookup_peer(alias_hash);
}

bool SessionManager::invite_peer(const std::string& peer_id) {
    return m_impl->invite_peer(peer_id);
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

SessionManager::Impl::Impl(std::shared_ptr<ISessionDependenciesFactory> factory)
    : m_stopped(false),
      m_shutting_down(false),
      m_running(false),
      m_factory(factory ? factory : std::make_shared<DefaultSessionDependenciesFactory>()),
      m_peer_tier_manager(nullptr),
      m_broadcast_discovery(nullptr),
      m_use_noise_protocol(false),
      m_noise_nk_enabled(false) {

    // Process-lifetime boot id used to detect peer restarts even when persistent static keys are reused.
    // Must be non-zero to enable change detection.
    {
        std::random_device rd;
        const uint64_t hi = static_cast<uint64_t>(rd());
        const uint64_t lo = static_cast<uint64_t>(rd());
        m_local_boot_id = (hi << 32) ^ lo;
        if (m_local_boot_id == 0) {
            m_local_boot_id = 1;
        }
        LOG_INFO("SM: Local boot id=" + std::to_string(m_local_boot_id));
    }
    
    // Initialize dependent members after m_factory is initialized
    m_peer_index = m_factory->createPeerIndex();
    m_battery_optimizer = m_factory->createBatteryOptimizer();
    m_session_cache = m_factory->createSessionCache();
    m_message_batcher = m_factory->createMessageBatcher(100, 10);  // Using default values
    m_failsafe = m_factory->createTierSystemFailsafe();
    m_file_transfer_manager = m_factory->createFileTransferManager();
    wire_file_transfer_manager();
    m_event_manager = m_factory->createEventManager();
    LOG_INFO("SM: Creating TCP connection manager...");
    m_tcpConnectionManager = m_factory->createTcpConnectionManager();
    LOG_INFO("SM: TCP connection manager created");

    LOG_INFO("SM: Creating UDP connection manager...");
    m_udpConnectionManager = m_factory->createUdpConnectionManager();
    LOG_INFO("SM: UDP connection manager created");
    
    if (m_udpConnectionManager) {
        LOG_INFO("SM: Registering UDP connection manager with NATTraversal...");
        NATTraversal::getInstance().setConnectionManager(m_udpConnectionManager.get());
        LOG_INFO("SM: NATTraversal connection manager registration complete");
    }

    // Initialize UPnP Controller (Disabled for current version)
    // auto upnp_controller = std::make_shared<UpnpController>();
    // NATTraversal::getInstance().setUpnpController(upnp_controller);
    
    m_message_handler = std::make_unique<detail::MessageHandler>(this);
    m_peer_lifecycle_manager = std::make_unique<detail::PeerLifecycleManager>(this);
    m_maintenance_manager = std::make_unique<detail::MaintenanceManager>(this);
    
    // Initialize Rugged Recovery Manager for automatic failure recovery
    m_recovery_manager = std::make_unique<recovery::RuggedRecoveryManager>();
    LOG_INFO("SM: Rugged Recovery Manager created");

#if ENABLE_PROXY_MODULE
    // Proxy module is compile-time optional; runtime behavior is enabled by default.
    m_proxy_endpoint = std::make_unique<proxy::ProxyEndpoint>(
        [this](const std::string& peer_id, const std::string& wire_message) {
            // Send pre-encoded wire frames via the existing session send path.
            this->sendMessageToPeer(peer_id, wire_message);
        }
    );
    // Exit-node proxy model: Gateway must connect to downstream peers when forwarding traffic.
    m_proxy_endpoint->set_connect_callback(
        [this](const std::string& peer_id) {
            LOG_INFO("SM: Proxy gateway requesting connection to downstream peer: " + peer_id);
            this->connectToPeer(peer_id);
        }
    );

    // SECURITY: The gateway role turns this node into a forwarding/egress point for
    // other peers. It is OFF by default and must be explicitly opted into, because a
    // default-on gateway lets any peer that can reach us relay traffic through this
    // device (including toward hosts only reachable from our network position).
    //
    // Client role is safe by default: it only lets *this* node originate proxied
    // streams through a gateway we chose. It never forwards traffic on behalf of others.
    //
    // Opt in via config.json:
    //   "proxy": { "enable_gateway": true, "enable_client": true }
    // or at runtime via the authenticated SET_PROXY_SETTINGS admin command.
    // NOTE: enable_test_echo must remain false for non-test deployments.
    {
        proxy::ProxySettings proxy_settings{};
        proxy_settings.enable_gateway = false;  // secure default: never forward for others
        proxy_settings.enable_client = true;
        proxy_settings.enable_test_echo = false;

        try {
            const json cfg = ConfigManager::getInstance().getConfigSnapshot();
            auto pit = cfg.find("proxy");
            if (pit != cfg.end() && pit->is_object()) {
                const json& p = *pit;
                auto read_bool = [&p](const char* key, bool& field) {
                    auto it = p.find(key);
                    if (it != p.end() && it->is_boolean()) {
                        field = it->get<bool>();
                    }
                };
                read_bool("enable_gateway", proxy_settings.enable_gateway);
                read_bool("enable_client", proxy_settings.enable_client);
                read_bool("enable_test_echo", proxy_settings.enable_test_echo);
            }
        } catch (const std::exception& e) {
            // Fail closed: a malformed proxy config must not silently enable forwarding.
            LOG_WARN(std::string("SM: Failed to read proxy config, using secure defaults: ") + e.what());
            proxy_settings = proxy::ProxySettings{};
            proxy_settings.enable_client = true;
        }

        if (proxy_settings.enable_gateway) {
            LOG_WARN("SM: Proxy GATEWAY role is ENABLED by configuration. This node will "
                     "forward traffic on behalf of other peers. Ensure peer authorization "
                     "and destination policy are appropriate for this deployment.");
        }
        if (proxy_settings.enable_test_echo) {
            LOG_WARN("SM: Proxy test echo is ENABLED. This is a test-harness-only mode and "
                     "must not be used in production deployments.");
        }

        m_proxy_endpoint->configure(proxy_settings);
        LOG_INFO(std::string("SM: Proxy configured - gateway=") +
                 (proxy_settings.enable_gateway ? "on" : "off") +
                 " client=" + (proxy_settings.enable_client ? "on" : "off"));
    }
#endif

#if ENABLE_OVERLAY_MODULE
    // Multi-hop overlay router (LPX2). SECURITY: the relay role (forwarding
    // frames for others + holding mailboxes) is opt-in — default off — matching
    // the proxy-gateway policy. Origin/destination roles need no opt-in; they
    // only ever act for THIS node.
    {
        overlay::OverlayRouter::Config ovl_cfg{};
        bool relay_default = false;
        std::vector<std::string> relay_peers_cfg;  // persistent bootstrap relays
        try {
            const json cfg = ConfigManager::getInstance().getConfigSnapshot();
            auto oit = cfg.find("overlay");
            if (oit != cfg.end() && oit->is_object()) {
                if (oit->contains("relay_enabled") && (*oit)["relay_enabled"].is_boolean()) {
                    relay_default = (*oit)["relay_enabled"].get<bool>();
                }
                if (oit->contains("default_hops") && (*oit)["default_hops"].is_number_integer()) {
                    const int hops = (*oit)["default_hops"].get<int>();
                    if (hops >= 0 && hops <= 3) ovl_cfg.default_hops = static_cast<uint8_t>(hops);
                }
                // Bootstrap relay list: persistent candidates so overlay works
                // out of the box even before any adverts are heard.
                if (oit->contains("relay_peers") && (*oit)["relay_peers"].is_array()) {
                    for (const auto& rp : (*oit)["relay_peers"]) {
                        if (rp.is_string()) relay_peers_cfg.push_back(rp.get<std::string>());
                    }
                }
                // Phase B (censorship resistance) knobs.
                if (oit->contains("padding_bucket") && (*oit)["padding_bucket"].is_number_integer()) {
                    const int b = (*oit)["padding_bucket"].get<int>();
                    if (b >= 0 && b <= 4096) ovl_cfg.padding_bucket = static_cast<size_t>(b);
                }
                if (oit->contains("obfuscate_transport") && (*oit)["obfuscate_transport"].is_boolean()) {
                    ovl_cfg.obfuscate_transport = (*oit)["obfuscate_transport"].get<bool>();
                }
                if (oit->contains("cover_interval_ms") && (*oit)["cover_interval_ms"].is_number_integer()) {
                    const auto c = (*oit)["cover_interval_ms"].get<int64_t>();
                    if (c >= 0) ovl_cfg.cover_interval_ms = static_cast<uint64_t>(c);
                }
                if (oit->contains("pex_interval_ms") && (*oit)["pex_interval_ms"].is_number_integer()) {
                    const auto p = (*oit)["pex_interval_ms"].get<int64_t>();
                    if (p >= 0) ovl_cfg.pex_interval_ms = static_cast<uint64_t>(p);
                }
                if (oit->contains("require_origin_auth") && (*oit)["require_origin_auth"].is_boolean()) {
                    ovl_cfg.require_origin_auth = (*oit)["require_origin_auth"].get<bool>();
                }
            }
        } catch (...) {
            // Config not loaded yet — defaults apply.
        }
        ovl_cfg.relay_enabled = relay_default;

        m_overlay_router = std::make_unique<overlay::OverlayRouter>(ovl_cfg);
        for (const auto& rp : relay_peers_cfg) {
            if (!rp.empty()) {
                m_overlay_router->register_relay_candidate(rp, 32, ovl_cfg.max_hops, true);
            }
        }
        if (!relay_peers_cfg.empty()) {
            LOG_INFO(std::string("SM: Overlay bootstrap relays registered: ") +
                     std::to_string(relay_peers_cfg.size()));
        }
        m_overlay_router->set_send_fn(
            [this](const std::string& peer_id, const std::string& wire_message) {
                this->sendMessageToPeer(peer_id, wire_message);
                return true;
            });
        m_overlay_router->set_connect_fn(
            [this](const std::string& peer_id) {
                this->connectToPeer(peer_id, true, "overlay");
            });
        m_overlay_router->set_is_connected_fn(
            [this](const std::string& peer_id) {
                return this->isPeerConnected(peer_id);
            });
        m_overlay_router->set_deliver_fn(
            [this](const std::string& origin_peer_id, const std::string& payload) {
                // Overlay-delivered messages surface through the normal
                // application message callback, tagged with the ORIGIN's id.
                if (m_message_received_cb) {
                    m_message_received_cb(origin_peer_id, payload);
                }
            });
#if HAVE_NOISE_PROTOCOL
        // Static keys from the Noise key store drive LPX2 sealing.
        m_overlay_router->set_peer_key_fn(
            [this](const std::string& peer_id) -> std::vector<uint8_t> {
                if (!m_noise_key_store) return {};
                return m_noise_key_store->get_peer_key(peer_id);
            });
        // Phase B: origin authentication — our Ed25519 signing keypair signs
        // every overlay payload; peer signing keys bind origins to identity.
        m_overlay_router->set_peer_signing_key_fn(
            [this](const std::string& peer_id) -> std::vector<uint8_t> {
                if (!m_noise_key_store) return {};
                return m_noise_key_store->get_peer_signing_key(peer_id);
            });
#endif
        LOG_INFO(std::string("SM: Overlay router created (relay=") +
                 (relay_default ? "on" : "off") + ")");
    }
#endif

    m_battery_optimizer->set_optimization_level(BatteryOptimizer::OptimizationLevel::BALANCED);
    LOG_INFO("SM: Battery optimization enabled (BALANCED mode)");
    
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.initialize(100, true);
    LOG_INFO("SM: Reconnect policy initialized");
    
#if HAVE_NOISE_PROTOCOL
    m_use_noise_protocol = true;
    m_secure_session_manager = m_factory->createSecureSessionManager();
    if (m_secure_session_manager) {
        LOG_INFO("SM: SecureSessionManager created successfully");
    } else {
        LOG_WARN("SM: SecureSessionManager creation FAILED (returned null)");
    }
    m_noise_nk_manager = m_factory->createNoiseNKManager();
    m_noise_key_store = m_factory->createNoiseKeyStore();
    m_noise_key_store->initialize();
    if (m_secure_session_manager && m_noise_nk_manager && m_noise_key_store) {
        m_secure_session_manager->set_noise_backend(m_noise_nk_manager.get(), m_noise_key_store.get());
    }
    LOG_INFO("SM: Noise Protocol support enabled");
#else
    LOG_INFO("SM: Noise Protocol not available");
#endif
}

std::string SessionManager::Impl::state_to_string(PeerState state) const {
    switch (state) {
        case PeerState::UNKNOWN: return "UNKNOWN";
        case PeerState::DISCOVERED: return "DISCOVERED";
        case PeerState::CONNECTING: return "CONNECTING";
        case PeerState::CONNECTED: return "CONNECTED";
        case PeerState::HANDSHAKING: return "HANDSHAKING";
        case PeerState::READY: return "READY";
        case PeerState::DEGRADED: return "DEGRADED";
        case PeerState::DISCONNECTED: return "DISCONNECTED";
        case PeerState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

SessionManager::Impl::~Impl() {
    // Ensure clean shutdown
    if (m_running.load()) {
        stop();
    }

    // If this instance constructed a UDP manager, make sure NATTraversal does not retain
    // a dangling raw pointer after we are destroyed (e.g., when a SessionManager is
    // constructed but never started).
    NATTraversal::getInstance().setConnectionManager(nullptr);
}

void SessionManager::Impl::load_remote_control_config() {
    m_remote_control_enabled = false;
    m_remote_control_allowed_senders.clear();

    json cfg;
    try {
        cfg = ConfigManager::getInstance().getConfigSnapshot();
    } catch (...) {
        return;
    }

    auto it = cfg.find("remote_control");
    if (it == cfg.end() || !it->is_object()) {
        return;
    }
    const json& rc = *it;
    m_remote_control_enabled = rc.value("enabled", false);
    if (!m_remote_control_enabled) {
        return;
    }

    auto allow_it = rc.find("allowed_senders");
    if (allow_it != rc.end() && allow_it->is_array()) {
        for (const auto& v : *allow_it) {
            if (v.is_string()) {
                const std::string pid = v.get<std::string>();
                if (!pid.empty()) {
                    m_remote_control_allowed_senders.insert(pid);
                }
            }
        }
    }

    LOG_INFO("SM: Remote control enabled=" + std::string(m_remote_control_enabled ? "true" : "false") +
             " allowed_senders=" + std::to_string(m_remote_control_allowed_senders.size()));
    if (m_remote_control_allowed_senders.empty()) {
        LOG_WARN("SM: Remote control enabled but allowed_senders is empty; all LP_ADMIN commands will be rejected");
    }
}

void SessionManager::Impl::send_admin_ack_(const std::string& to_peer_id,
                                          const std::string& request_id,
                                          bool ok,
                                          const std::string& message,
                                          const std::string& applied_settings_json) {
    json ack;
    ack["type"] = "LP_ADMIN_ACK";
    ack["ok"] = ok;
    if (!request_id.empty()) {
        ack["request_id"] = request_id;
    }
    ack["message"] = message;
    if (!applied_settings_json.empty()) {
        try {
            ack["applied_settings"] = json::parse(applied_settings_json);
        } catch (...) {
            ack["applied_settings_raw"] = applied_settings_json;
        }
    }

    try {
        sendMessageToPeer(to_peer_id, ack.dump());
    } catch (...) {
        // Best-effort.
    }
}

bool SessionManager::Impl::handle_admin_command_message(const std::string& from_peer_id, const std::string& payload) {
    json msg;
    try {
        msg = json::parse(payload);
    } catch (...) {
        return false;
    }

    const std::string type = msg.value("type", "");
    if (type != "LP_ADMIN") {
        return false;
    }

    const std::string request_id = msg.value("request_id", "");

    // Never forward admin commands; only act on those explicitly targeting this peer.
    const std::string target_peer_id = msg.value("target_peer_id", "");
    if (!target_peer_id.empty() && target_peer_id != m_localPeerId && target_peer_id != "*") {
        send_admin_ack_(from_peer_id, request_id, false, "target_peer_id does not match this peer", "");
        return true;
    }

    if (!m_remote_control_enabled) {
        send_admin_ack_(from_peer_id, request_id, false, "remote_control disabled", "");
        return true;
    }

    if (m_remote_control_allowed_senders.find(from_peer_id) == m_remote_control_allowed_senders.end()) {
        send_admin_ack_(from_peer_id, request_id, false, "sender not authorized", "");
        return true;
    }

    const std::string cmd = msg.value("cmd", "");
    if (cmd.empty()) {
        send_admin_ack_(from_peer_id, request_id, false, "missing cmd", "");
        return true;
    }

    if (cmd == "GET_PROXY_SETTINGS") {
#if ENABLE_PROXY_MODULE
        if (m_proxy_endpoint) {
            const proxy::ProxySettings s = m_proxy_endpoint->settings();
            json applied;
            applied["enable_gateway"] = s.enable_gateway;
            applied["enable_client"] = s.enable_client;
            applied["enable_test_echo"] = s.enable_test_echo;
            send_admin_ack_(from_peer_id, request_id, true, "ok", applied.dump());
            return true;
        }
        send_admin_ack_(from_peer_id, request_id, false, "proxy module not initialized", "");
        return true;
#else
        send_admin_ack_(from_peer_id, request_id, false, "proxy module not compiled", "");
        return true;
#endif
    }

    if (cmd == "SET_PROXY_SETTINGS") {
#if ENABLE_PROXY_MODULE
        if (!m_proxy_endpoint) {
            send_admin_ack_(from_peer_id, request_id, false, "proxy module not initialized", "");
            return true;
        }

        proxy::ProxySettings s = m_proxy_endpoint->settings();
        auto sit = msg.find("settings");
        if (sit != msg.end() && sit->is_object()) {
            const json& settings = *sit;
            auto set_bool_if_present = [&](const char* key, bool& field) {
                auto it2 = settings.find(key);
                if (it2 != settings.end() && it2->is_boolean()) {
                    field = it2->get<bool>();
                }
            };
            set_bool_if_present("enable_gateway", s.enable_gateway);
            set_bool_if_present("enable_client", s.enable_client);
            set_bool_if_present("enable_test_echo", s.enable_test_echo);
        }

        // Convenience alias: setting role="exit" means enable_gateway and disable test_echo.
        const std::string role = msg.value("role", "");
        if (role == "exit") {
            s.enable_gateway = true;
            s.enable_test_echo = false;
        } else if (role == "gateway") {
            s.enable_gateway = true;
            s.enable_test_echo = false;
        } else if (role == "client") {
            s.enable_client = true;
        } else if (role == "off") {
            s.enable_gateway = false;
            s.enable_client = false;
            s.enable_test_echo = false;
        }

        m_proxy_endpoint->configure(s);
        json applied;
        applied["enable_gateway"] = s.enable_gateway;
        applied["enable_client"] = s.enable_client;
        applied["enable_test_echo"] = s.enable_test_echo;
        send_admin_ack_(from_peer_id, request_id, true, "applied", applied.dump());
        return true;
#else
        send_admin_ack_(from_peer_id, request_id, false, "proxy module not compiled", "");
        return true;
#endif
    }

    send_admin_ack_(from_peer_id, request_id, false, "unknown cmd", "");
    return true;
}

void SessionManager::Impl::start(int port, std::function<void(const std::vector<Peer>&)> cb, 
                                 const std::string& comms_mode, const std::string& peer_id) {
    std::lock_guard<std::mutex> lifecycle_lock(m_lifecycle_mutex);
    if (m_running) {
        LOG_WARN("SM: Session manager already running, ignoring start request.");
        return;
    }

    // Record runtime parameters early so recovery paths (signaling reconnect, NAT refresh)
    // have stable access even during early startup.
    m_listen_port = port;
    m_comms_mode = comms_mode;
    m_localPeerId = peer_id;
    m_network_available.store(true, std::memory_order_release);

    // Same-device coexistence (v0.4): when another process on this host — e.g. a
    // second app built on this SDK, or a desktop node — already holds the
    // configured UDP port, a second bind() succeeds thanks to SO_REUSEPORT, but
    // the kernel then load-balances inbound unicast datagrams between the two
    // sockets, so neither engine reliably receives its handshake/message traffic
    // and connections never complete (peers still show up via broadcast).
    //
    // Censorship resistance (v0.4): when network.port_range is configured, we
    // pick a random free port in that range at startup, so a static port
    // blocklist cannot pin us to a fixed listener port.
    //
    // Either way the real bound port is advertised through discovery +
    // signaling so the mesh still reaches this node; if everything is held we
    // fall back to an OS-assigned ephemeral port.
    int resolved_port = port;
    {
        int lo = 0, hi = 0;
        const bool range_configured = ConfigManager::getInstance().getDataPortRange(lo, hi);
        if (range_configured) {
            std::mt19937 rng(std::random_device{}());
            std::uniform_int_distribution<int> dist(lo, hi);
            resolved_port = 0;
            for (int attempt = 0; attempt < 24; ++attempt) {
                const int candidate = dist(rng);
                if (!udp_port_held_by_other_process(candidate)) {
                    resolved_port = candidate;
                    break;
                }
            }
            LOG_INFO("SM: Dynamic data port selected " + std::to_string(resolved_port) +
                     " from range [" + std::to_string(lo) + "," + std::to_string(hi) + "]");
        } else if (port != 0 && udp_port_held_by_other_process(port)) {
            resolved_port = 0;
            LOG_WARN("SM: Port " + std::to_string(port) +
                     " is already held by another process on this device; falling back "
                     "to an ephemeral port (same-device multi-app coexistence)");
        }
    }

    // Telemetry (local-only, no network). Safe to call multiple times.
    {
        auto& cfg = ConfigManager::getInstance();
        Telemetry::Config tc;
        tc.enabled = cfg.isTelemetryEnabled();
        tc.log_json = cfg.isTelemetryLogEnabled();
        tc.flush_interval_ms = cfg.getTelemetryFlushIntervalMs();
        tc.file_path = cfg.getTelemetryFilePath();
        tc.include_peer_ids = cfg.telemetryIncludePeerIds();
        Telemetry::getInstance().initialize(peer_id, tc);
        Telemetry::getInstance().inc_counter("engine_start_total");
    }

    // AnomalyReporter (v0.4 field diagnostics): write an incident file for every
    // anomaly (disconnect, connect failure, stall, runtime error) and optionally
    // upload it to a collector server in production. Incidents land in
    // <base_dir>/anomalies/ so they can be inspected via terminal / adb.
    {
        auto& cfg = ConfigManager::getInstance();
        const auto engine_start_steady = std::chrono::steady_clock::now();

        // Base dir: next to config.json (Android: filesDir; desktop: repo root),
        // else next to the executable, else CWD (mirrors the peer-DB default).
        std::string base_dir;
        const std::string config_path = cfg.getConfigPath();
        if (!config_path.empty()) {
            try {
                base_dir = std::filesystem::path(config_path).parent_path().string();
            } catch (...) {
                base_dir.clear();
            }
        }
        if (base_dir.empty()) base_dir = get_executable_dir_best_effort();
        if (base_dir.empty()) {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != nullptr) base_dir = cwd;
        }

        AnomalyReporter::Config acfg;
        acfg.enabled = cfg.isAnomalyReporterEnabled();
        acfg.base_dir = base_dir;
        acfg.subdir = cfg.getAnomalyDirectory();
        acfg.max_files = cfg.getAnomalyMaxFiles();
        acfg.upload_enabled = cfg.isAnomalyUploadEnabled();
        acfg.upload_url = cfg.getAnomalyUploadUrl();
        acfg.upload_interval_ms = cfg.getAnomalyUploadIntervalMs();
        acfg.include_telemetry = cfg.anomalyIncludeTelemetry();
        acfg.min_interval_ms = cfg.getAnomalyMinIntervalMs();
        acfg.max_per_type_per_hour = cfg.getAnomalyMaxPerTypePerHour();
#ifdef LITEP2P_VERSION_STRING
        acfg.engine_version = LITEP2P_VERSION_STRING;
#else
        acfg.engine_version = "0.4.0";
#endif
        acfg.peer_id = peer_id;
        AnomalyReporter::getInstance().configure(acfg);
        AnomalyReporter::getInstance().setUptimeProvider([engine_start_steady]() {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - engine_start_steady)
                .count();
        });
        if (AnomalyReporter::getInstance().isEnabled()) {
            LOG_INFO("SM: AnomalyReporter enabled (dir=" + AnomalyReporter::getInstance().directory() + ")");
        }
    }

    // Variable to hold signaling FD for single-thread mode registration
    int single_thread_signaling_fd = -1;

    // Signaling (optional; controlled by config.json signaling.enabled).
    // On-demand policy: we only connect/list peers when the local peer DB is empty or exhausted.
    m_signaling_registered.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
        m_pending_signaling_network_id.clear();
    }

    const bool signaling_enabled = ConfigManager::getInstance().isSignalingEnabled();
    m_signaling_enabled = signaling_enabled;
    m_signaling_url = signaling_enabled ? ConfigManager::getInstance().getSignalingUrl() : std::string{};
    m_signaling_client.reset();
    m_signaling_bootstrap_requested.store(false, std::memory_order_release);
    m_signaling_persistent_after_db_exhausted.store(false, std::memory_order_release);

    if (signaling_enabled) {
        LOG_INFO("SM: Signaling configured (on-demand): " + m_signaling_url);
    } else {
        LOG_INFO("SM: Signaling disabled by config");
    }
    
    // Reset shutdown flag when starting
    m_shutting_down.store(false, std::memory_order_release);
    m_running = true;
    m_peer_update_cb = cb;
    m_comms_mode = comms_mode;
    m_localPeerId = peer_id;

    // v0.4: reliable-send manager (persistent outbox + retry + offline store).
    // Re-created on every start so config changes take effect; the outbox file
    // survives across stop()/start() and process restart.
    {
        auto& cfg = ConfigManager::getInstance();
        m_reliable_send_manager = std::make_unique<ReliableSendManager>();
        m_reliable_send_manager->configure(cfg.getReliableOutboxDir(),
                                           cfg.isOfflineQueueEnabled(),
                                           cfg.getOfflineQueueMaxMessages(),
                                           cfg.getOfflineQueueTtlMs());
        m_reliable_send_manager->set_callbacks(
            // status -> delivery-status callback
            [this](const std::string& msg_id, int status, const std::string& reason) {
                SessionManager::DeliveryStatusCallback cb2;
                {
                    std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
                    cb2 = m_delivery_status_cb;
                }
                if (cb2) cb2(msg_id, status, reason);
            },
            // send -> session send path (raw payload; handleSendMessage wraps it)
            [this](const std::string& peer_id, const std::string& wire_message) {
                this->sendMessageToPeer(peer_id, wire_message);
            },
            // is_connected -> peer session state
            [this](const std::string& peer_id) {
                return this->isPeerConnected(peer_id);
            },
            // offline store -> signaling server
            [this](const std::string& peer_id, const std::string& msg_id,
                   const std::string& payload_b64) {
                if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) {
                    return false;
                }
                signaling_send_store(peer_id, msg_id, payload_b64);
                return true;
            });
        LOG_INFO("SM: ReliableSendManager configured (offline_queue=" +
                 std::string(cfg.isOfflineQueueEnabled() ? "on" : "off") + ")");
    }

#if ENABLE_OVERLAY_MODULE && HAVE_NOISE_PROTOCOL
    // Start the overlay router once identity and keys are available. Keys are
    // generated lazily by the key store on first handshake; ensure they exist
    // now so LPX2 sealing works from the first overlay send.
    if (m_overlay_router && m_noise_key_store) {
        if (!m_noise_key_store->has_local_static_key()) {
            m_noise_key_store->generate_and_store_local_key();
        }
        // Phase B: origin authentication signing keypair.
        if (!m_noise_key_store->has_local_signing_keys()) {
            m_noise_key_store->generate_and_store_local_signing_keys();
        }
        m_overlay_router->set_local_identity(
            m_localPeerId,
            m_noise_key_store->get_local_static_public_key(),
            m_noise_key_store->get_local_static_private_key());
        m_overlay_router->set_local_signing_keys(
            m_noise_key_store->get_local_signing_public_key(),
            m_noise_key_store->get_local_signing_private_key());
        m_overlay_router->start();
    }
#endif

    // Read the communication mode (homogeneous/heterogeneous) from the effective config.
    // In heterogeneous mode the engine listens on and accepts BOTH UDP and TCP.
    m_comms_heterogeneous = (ConfigManager::getInstance().getCommsMode() == "HETEROGENEOUS");
    if (m_comms_heterogeneous) {
        LOG_INFO("SM: Communication mode = HETEROGENEOUS (accept UDP + TCP connections)");
    } else {
        LOG_INFO("SM: Communication mode = HOMOGENEOUS (only " + m_comms_mode + " connections)");
    }

    // stop() clears NATTraversal's connection manager pointer. Re-register on every start so
    // bound-socket STUN probing and hole punching remain functional across engine restarts.
    ensure_nat_connection_manager_registered_();

    // Wire NAT hole-punch completion (success/failure) into peer lifecycle.
    // This prevents peers from staying CONNECTING indefinitely after punch retries are exhausted.
    ensure_nat_punch_observer_registered_();

    // Optional: initialize local peer DB now that we know our local peer id and config.
    maybe_init_peer_db_();

    // Load remote control allowlist (safe-by-default: disabled unless explicitly enabled in config).
    load_remote_control_config();
    
    // Re-initialize components if they were destroyed in stop()
    if (!m_peer_index) m_peer_index = m_factory->createPeerIndex();
    if (!m_battery_optimizer) {
        m_battery_optimizer = m_factory->createBatteryOptimizer();
        m_battery_optimizer->set_optimization_level(BatteryOptimizer::OptimizationLevel::BALANCED);
    }
    if (!m_session_cache) m_session_cache = m_factory->createSessionCache();
    if (!m_message_batcher) m_message_batcher = m_factory->createMessageBatcher(100, 10);
    if (!m_file_transfer_manager) {
        m_file_transfer_manager = m_factory->createFileTransferManager();
        wire_file_transfer_manager();
    }

#if HAVE_NOISE_PROTOCOL
    if (!m_secure_session_manager) {
        m_secure_session_manager = m_factory->createSecureSessionManager();
        if (m_secure_session_manager) {
            LOG_INFO("SM: SecureSessionManager re-created successfully");
        } else {
            LOG_WARN("SM: SecureSessionManager re-creation FAILED");
        }
    }
    if (!m_noise_nk_manager) m_noise_nk_manager = m_factory->createNoiseNKManager();
    if (!m_noise_key_store) {
        m_noise_key_store = m_factory->createNoiseKeyStore();
        m_noise_key_store->initialize();
    }
    
    if (m_secure_session_manager && m_noise_nk_manager && m_noise_key_store) {
        m_secure_session_manager->set_noise_backend(m_noise_nk_manager.get(), m_noise_key_store.get());
    }
#endif

    m_peer_tier_manager = m_factory->createPeerTierManager();
    // Initialize peer tier manager
    if (m_peer_tier_manager) {
        if (!m_peer_tier_manager->initialize()) {
            LOG_WARN("SM: Failed to initialize peer tier manager: " + m_peer_tier_manager->get_last_error());
            m_peer_tier_manager.reset();
        } else {
            LOG_INFO("SM: Peer tier manager initialized successfully");
        }
    }
    m_broadcast_discovery = m_factory->createBroadcastDiscoveryManager();
    
    // Initialize broadcast discovery manager
    if (!m_broadcast_discovery->initialize()) {
        LOG_WARN("SM: Failed to initialize broadcast discovery manager");
    } else {
        LOG_INFO("SM: Broadcast discovery manager initialized successfully");
    }
    
    // Clear peer contexts when starting
    m_peer_contexts.clear();
    
    // Check for single-thread mode
    const bool single_thread = is_single_thread_mode();
    if (single_thread) {
        LOG_INFO("SM: *** SINGLE-THREAD MODE ENABLED ***");
    }
    
    Discovery* discovery = getGlobalDiscoveryInstance();
    discovery->setCallback([this](const std::string& network_id, const std::string& peer_id) {
        if (m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }
        handlePeerDiscovered(network_id, peer_id);
    });
    
    LOG_INFO("SM: Starting session manager on port " + std::to_string(port));
    LOG_INFO("SM: Comms mode: " + comms_mode);
    
    initializeTierSystemCallbacks();
    
    // Variables to hold FDs for single-thread mode registration
    int single_thread_discovery_fd = -1;
    int single_thread_udp_fd = -1;
    // single_thread_signaling_fd is declared earlier when signaling client connects
    UdpConnectionManager* single_thread_udp_mgr = nullptr;

    auto event_handler = [this](const SessionEvent& event) {
        // LOG_INFO("SM: Event dispatcher called - processing event");
        try {
            if (auto* e = std::get_if<PeerDiscoveredEvent>(&event)) {
                LOG_INFO("SM: Event type = PeerDiscoveredEvent");
                m_peer_lifecycle_manager->handlePeerDiscovered(*e);
            } else if (auto* e = std::get_if<DataReceivedEvent>(&event)) {
                LOG_INFO("SM: Event type = DataReceivedEvent from network_id " + e->network_id + ", data_len=" + std::to_string(e->data.length()));
                m_message_handler->handleDataReceived(*e);
            } else if (auto* e = std::get_if<PeerDisconnectEvent>(&event)) {
                LOG_INFO("SM: Event type = PeerDisconnectEvent");
                m_peer_lifecycle_manager->handlePeerDisconnect(*e);
            } else if (auto* e = std::get_if<ConnectToPeerEvent>(&event)) {
                LOG_INFO("SM: Event type = ConnectToPeerEvent");
                m_peer_lifecycle_manager->handleConnectToPeer(*e);
            } else if (auto* e = std::get_if<SendMessageEvent>(&event)) {
                LOG_INFO("SM: Event type = SendMessageEvent for peer " + e->peerId);
                LOG_INFO("SM: SendMessageEvent dispatched to message handler for peer " + e->peerId);
                // v0.4 backpressure: this send event is leaving the queue.
                m_pending_sends.fetch_sub(1, std::memory_order_relaxed);
                m_message_handler->handleSendMessage(*e);
            } else if (auto* e = std::get_if<TimerTickEvent>(&event)) {
                LOG_DEBUG("SM: Event type = TimerTickEvent");
                m_maintenance_manager->handleTimerTick(*e);
                // v0.4: drive the reliable-send retry/offline-store loop.
                if (m_reliable_send_manager) {
                    m_reliable_send_manager->tick();
                }
                // v0.4: expire app-level pings that never got a PONG.
                check_ping_timeouts_();
            } else if (auto* e = std::get_if<DiscoveryInitiatedEvent>(&event)) {
                LOG_DEBUG("SM: Event type = DiscoveryInitiatedEvent");
                // Handle discovery initiation (queued from handleSendMessageEvent)
                if (m_broadcast_discovery && m_broadcast_discovery->is_running()) {
                    m_broadcast_discovery->discover_peer(e->peerId,
                        [this](const DiscoveryResponse& response) {
                            // IMPORTANT: Use the full response including local IP/port
                            handleDiscoveryResponseWithEndpoint(
                                response.responder_peer_id,
                                response.responder_ip,
                                response.responder_port,
                                response.latency_ms);
                        });
                }
            } else if (auto* e = std::get_if<LanDiscoveryResultEvent>(&event)) {
                LOG_INFO("SM: Event type = LanDiscoveryResultEvent for peer " + e->peerId);
                handleLanDiscoveryResult(*e);
            } else if (auto* e = std::get_if<MessageSendCompleteEvent>(&event)) {
                LOG_DEBUG("SM: Event type = MessageSendCompleteEvent");
                handleMessageSendComplete(*e);
            } else if (auto* e = std::get_if<FSMEvent>(&event)) {
                LOG_DEBUG("SM: Event type = FSMEvent");
                handleFSMEvent(*e);
            } else {
                LOG_WARN("SM: Unknown event type received - not handled");
            }
        } catch (const std::exception& e) {
            LOG_WARN("SM: Error processing event: " + std::string(e.what()));
        }
    };
    
    if (single_thread) {
        // ================================================================
        // SINGLE-THREADED MODE: Use event-loop for all I/O
        // ================================================================
        
        // Discovery is started after the listeners bind (below) so it can
        // advertise the real (possibly ephemeral) listener port.
        
        // Start UDP in event-loop mode (no listener thread)
        // Start UDP in event-loop mode (no listener thread). In heterogeneous mode we
        // start UDP regardless of the primary protocol, then also open the TCP listener.
        if (comms_mode != "TCP" || m_comms_heterogeneous) {
            // Cast to concrete type to access event-loop methods
            single_thread_udp_mgr = dynamic_cast<UdpConnectionManager*>(m_udpConnectionManager.get());
            if (single_thread_udp_mgr) {
                single_thread_udp_mgr->startServerEventLoop(resolved_port,
                    [this](const std::string& id, const std::string& data) {
                        note_inbound_transport(id, "UDP");
                        onData(id, data);
                    },
                    [this](const std::string& id) { onDisconnect(id); });
                single_thread_udp_fd = single_thread_udp_mgr->getSocketFd();
                LOG_INFO("SM: UDP started in event-loop mode, fd=" + std::to_string(single_thread_udp_fd));
            }
        } else {
            // TCP not supported in single-thread mode yet
            m_tcpConnectionManager->startServer(resolved_port, 
                [this](const std::string& id, const std::string& data) {
                    note_inbound_transport(id, "TCP");
                    onData(id, data);
                },
                [this](const std::string& id) { onDisconnect(id); });
        }

        // Heterogeneous mode: also accept TCP connections alongside the UDP socket.
        if (m_comms_heterogeneous) {
            m_tcpConnectionManager->startServer(resolved_port,
                [this](const std::string& id, const std::string& data) {
                    note_inbound_transport(id, "TCP");
                    onData(id, data);
                },
                [this](const std::string& id) { onDisconnect(id); });
            LOG_INFO("SM: TCP listener started additionally (heterogeneous mode)");
        }

        // Resolve the real bound port (ephemeral when the configured port was
        // contended by another process on this device) and advertise it via
        // discovery so peers connect to the actual listener.
        int actual_port = resolved_port;
        if (single_thread_udp_mgr) {
            const int p = single_thread_udp_mgr->getBoundPort();
            if (p > 0) actual_port = p;
        }
        m_listen_port = actual_port;
        if (resolved_port == 0) {
            LOG_WARN("SM: Using ephemeral listener port " + std::to_string(actual_port) + " (same-device coexistence)");
        }
        discovery->setConnectionPort(actual_port);
        single_thread_discovery_fd = discovery->startEventLoop(actual_port, peer_id);
        if (single_thread_discovery_fd < 0) {
            LOG_WARN("SM: Failed to start discovery in event-loop mode");
        } else {
            LOG_INFO("SM: Discovery started in event-loop mode, fd=" + std::to_string(single_thread_discovery_fd));
        }
        
        // Do NAT detection synchronously at startup (no thread)
        if (comms_mode != "TCP") {
            NATTraversal& nat = NATTraversal::getInstance();
            nat.initialize(static_cast<uint16_t>(actual_port));

            // Single-thread mode: NATTraversal's bound-socket STUN path relies on STUN responses
            // being processed by the UDP transport while detectNATType() is blocked waiting.
            // Since we intentionally don't run the full UnifiedEventLoop until after startup,
            // temporarily pump the UDP socket on a dedicated thread during detection.
            std::atomic<bool> stun_pump_stop{false};
            std::thread stun_pump_thread;
            if (single_thread_udp_mgr && single_thread_udp_fd >= 0) {
                stun_pump_thread = std::thread([&]() {
                    while (!stun_pump_stop.load(std::memory_order_acquire)) {
                        fd_set read_fds;
                        FD_ZERO(&read_fds);
                        FD_SET(single_thread_udp_fd, &read_fds);
                        timeval tv;
                        tv.tv_sec = 0;
                        tv.tv_usec = 100 * 1000; // 100ms

                        int res = select(single_thread_udp_fd + 1, &read_fds, nullptr, nullptr, &tv);
                        if (res < 0) {
                            if (errno == EINTR) {
                                continue;
                            }
                            // Avoid spamming logs in a tight loop; just sleep a bit.
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        }

                        if (res > 0 && FD_ISSET(single_thread_udp_fd, &read_fds)) {
                            // Drain a few packets quickly (processIncomingData reads one packet).
                            for (int i = 0; i < 16; ++i) {
                                single_thread_udp_mgr->processIncomingData();
                            }
                        }
                    }
                });
            }

            NATInfo info = nat.detectNATType();

            stun_pump_stop.store(true, std::memory_order_release);
            if (stun_pump_thread.joinable()) {
                stun_pump_thread.join();
            }
            
            if (!info.external_ip.empty() && info.external_port != 0) {
                const std::string network_id = info.external_ip + ":" + std::to_string(info.external_port);
                {
                    std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
                    m_pending_signaling_network_id = network_id;
                }
                LOG_INFO("SM: NAT detected external address: " + network_id);
                
                // Send signaling UPDATE with our external address so other peers can connect to us
                if (m_signaling_registered.load(std::memory_order_acquire) && m_signaling_client) {
                    m_signaling_client->sendUpdateNetworkId(network_id);
                    LOG_INFO("SM: Sent signaling UPDATE with network_id: " + network_id);
                }
            }
        }
        
    } else {
        // ================================================================
        // MULTI-THREADED MODE (Legacy)
        // ================================================================
        
        // Discovery is started after the listeners bind (below) so it can
        // advertise the real (possibly ephemeral) listener port.

        // Per-transport inbound data callbacks. In heterogeneous mode both UDP and
        // TCP listeners feed the same message pipeline, so we first record which
        // transport each peer came in on (Peer::transport) to route replies back on
        // the same protocol.
        auto udp_on_data = [this](const std::string& id, const std::string& data) {
            note_inbound_transport(id, "UDP");
            onData(id, data);
        };
        auto tcp_on_data = [this](const std::string& id, const std::string& data) {
            note_inbound_transport(id, "TCP");
            onData(id, data);
        };
        auto on_disc = [this](const std::string& id) { onDisconnect(id); };
        const bool comms_hetero = m_comms_heterogeneous;

        if (comms_mode == "TCP") {
            if (comms_hetero) {
                // Heterogeneous: accept TCP and UDP connections.
                m_tcpConnectionManager->startServer(resolved_port, tcp_on_data, on_disc);
                m_udpConnectionManager->startServer(resolved_port, udp_on_data, on_disc);
            } else {
                // Homogeneous TCP: only accept TCP connections.
                m_tcpConnectionManager->startServer(resolved_port, tcp_on_data, on_disc);
            }
        } else if (comms_mode == "QUIC") {
            LOG_INFO("SM: Switching to QUIC protocol");
            NATTraversal::getInstance().setConnectionManager(nullptr);
            auto ptr = std::make_unique<QuicConnectionManager>();
            m_udpConnectionManager = std::move(ptr);
            NATTraversal::getInstance().setConnectionManager(m_udpConnectionManager.get());
            m_udpConnectionManager->startServer(resolved_port, udp_on_data, on_disc);
        } else {
            // UDP (homogeneous UDP, or the UDP half of heterogeneous mode).
            m_udpConnectionManager->startServer(resolved_port, udp_on_data, on_disc);
            if (comms_hetero) {
                m_tcpConnectionManager->startServer(resolved_port, tcp_on_data, on_disc);
            }
        }

        // Resolve the real bound port (ephemeral when the configured port was
        // contended by another process on this device) and advertise it via
        // discovery so peers connect to the actual listener.
        int actual_port = resolved_port;
        if (m_udpConnectionManager) {
            const int p = m_udpConnectionManager->getBoundPort();
            if (p > 0) actual_port = p;
        }
        m_listen_port = actual_port;
        if (resolved_port == 0) {
            LOG_WARN("SM: Using ephemeral listener port " + std::to_string(actual_port) + " (same-device coexistence)");
        }
        discovery->setConnectionPort(actual_port);
        // LAN discovery is optional (network.discovery_enabled). When disabled
        // the engine runs purely on signaling/peer-DB/direct endpoints — also
        // the hermetic-test path (no socket, no foreign announcements).
        if (ConfigManager::getInstance().isDiscoveryEnabled()) {
            discovery->start(actual_port, peer_id);
        } else {
            LOG_INFO("SM: LAN discovery disabled by config");
        }

        // NAT detection in separate thread (multi-threaded mode)
        if (comms_mode != "TCP") {
            if (m_nat_detect_thread.joinable()) {
                m_nat_detect_thread.join();
            }
            m_nat_detect_in_progress.store(true, std::memory_order_release);
            m_nat_detect_thread = std::thread([this, actual_port]() {
                struct Guard {
                    std::atomic<bool>& flag;
                    ~Guard() { flag.store(false, std::memory_order_release); }
                } guard{m_nat_detect_in_progress};

                if (m_shutting_down.load(std::memory_order_acquire)) {
                    return;
                }

                NATTraversal& nat = NATTraversal::getInstance();
                nat.initialize(static_cast<uint16_t>(actual_port));
                NATInfo info = nat.detectNATType();

                if (m_shutting_down.load(std::memory_order_acquire)) {
                    return;
                }

                if (info.external_ip.empty() || info.external_port == 0) {
                    return;
                }

                const std::string network_id = info.external_ip + ":" + std::to_string(info.external_port);
                {
                    std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
                    m_pending_signaling_network_id = network_id;
                }

                if (m_signaling_registered.load(std::memory_order_acquire) && m_signaling_client) {
                    m_signaling_client->sendUpdateNetworkId(network_id);
                }
            });
        }
    }
    
    // Re-create EventManager if it was destroyed during stop()
    if (!m_event_manager) {
        m_event_manager = m_factory->createEventManager();
    }

    // Start the EventManager with our event handler
    if (m_event_manager) {
        m_event_manager->startEventProcessing(event_handler);

        // In single-thread mode, register I/O FDs with the UnifiedEventLoop
        if (single_thread) {
            UnifiedEventLoop* loop = m_event_manager->getUnifiedEventLoop();
            if (loop) {
                // Set up read callback for UDP, Discovery, and Signaling sockets
                loop->setReadCallback([this, single_thread_udp_mgr, discovery](int fd, const std::string& peer_id) {
                    (void)peer_id;
                    // UDP socket
                    if (single_thread_udp_mgr && fd == single_thread_udp_mgr->getSocketFd()) {
                        single_thread_udp_mgr->processIncomingData();
                    }
                    // Discovery socket
                    if (discovery && fd == discovery->getSocketFd()) {
                        discovery->processIncoming();
                    }
                    // Signaling socket (TCP for WebSocket)
                    if (m_signaling_client && fd == m_signaling_client->getSocketFd()) {
                        m_signaling_client->processIncoming();
                    }
                });

                // Register UDP socket
                if (single_thread_udp_fd >= 0) {
                    loop->registerFd(single_thread_udp_fd, UnifiedEventLoop::FdType::UDP_SOCKET, "udp_server");
                    LOG_INFO("SM: Registered UDP fd=" + std::to_string(single_thread_udp_fd) + " with UnifiedEventLoop");
                }

                // Register Discovery socket
                if (single_thread_discovery_fd >= 0) {
                    loop->registerFd(single_thread_discovery_fd, UnifiedEventLoop::FdType::UDP_SOCKET, "discovery");
                    LOG_INFO("SM: Registered Discovery fd=" + std::to_string(single_thread_discovery_fd) + " with UnifiedEventLoop");
                }

                // Register Signaling socket (TCP for WebSocket)
                if (single_thread_signaling_fd >= 0) {
                    loop->registerFd(single_thread_signaling_fd, UnifiedEventLoop::FdType::TCP_CLIENT, "signaling");
                    LOG_INFO("SM: Registered Signaling fd=" + std::to_string(single_thread_signaling_fd) + " with UnifiedEventLoop");
                }

                LOG_INFO("SM: Single-thread mode I/O registration complete");
            } else {
                LOG_WARN("SM: Single-thread mode but UnifiedEventLoop is null!");
            }
        }
    }

    // After the event system is running, bootstrap peers from the local DB.
    // This allows DB-first peer list population and best-effort reconnect attempts even without signaling.
    bootstrap_peers_from_db_();
    
    // Initialize Rugged Recovery Manager with callbacks
    if (m_recovery_manager) {
        m_recovery_manager->initialize(
            // Send direct callback
            [this](const std::string& network_id, const std::string& message) {
                send_message_to_peer(network_id, message);
            },
            // Send relay callback
            [this](const std::string& peer_id, const std::string& message) {
                if (m_signaling_client && m_signaling_client->isConnected()) {
                    m_signaling_client->sendRelayMessage(peer_id, message);
                }
            },
            // Restart socket callback
            [this]() -> bool {
                if (m_udpConnectionManager) {
                    return m_udpConnectionManager->restartSocket();
                }
                return false;
            },
            // Reconnect peer callback
            [this](const std::string& peer_id) {
                connectToPeer(peer_id, true, "rugged_recovery");
            },
            // Get network ID callback
            [this](const std::string& peer_id) -> std::string {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                auto it = m_peers.find(peer_id);
                if (it != m_peers.end()) {
                    return it->second.network_id;
                }
                return "";
            }
        );
        LOG_INFO("SM: Rugged Recovery Manager initialized with callbacks");
    }
    
    // Proactively connect to signaling at startup (even if we have peers in DB).
    // This ensures we are registered and can receive CONNECT_REQUEST messages from other peers.
    // Without this, a restarting peer may try to connect via cached DB data while the remote
    // peer hasn't registered with signaling yet, causing connection failures.
    if (m_signaling_enabled && !single_thread) {
        LOG_INFO("SM: Proactively connecting to signaling at startup");
        ensure_signaling_connected_async(true);
    }
    
    LOG_INFO("SM: Session manager started successfully");

    // Start timer thread only in multi-threaded mode
    // (In single-thread mode, EventManager's UnifiedEventLoop handles timers)
    if (!single_thread) {
        m_timer_thread = std::thread(&SessionManager::Impl::timerLoop, this);
    }
    
    // PRODUCTION-READY: Start IP change monitoring
    start_ip_monitor();
}

void SessionManager::Impl::maybe_init_peer_db_() {
    // Shutdown guard
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }

    // Already initialized
    if (m_local_peer_db && m_local_peer_db->is_open()) {
        return;
    }

    ConfigManager& cfg = ConfigManager::getInstance();
    if (!cfg.isPeerDbEnabled()) {
        return;
    }

    std::string path = cfg.getPeerDbPath();
    if (path.empty()) {
        // Default: next to config.json (if known), else next to the executable, else CWD.
        std::string base_dir;
        const std::string config_path = cfg.getConfigPath();
        if (!config_path.empty()) {
            try {
                base_dir = std::filesystem::path(config_path).parent_path().string();
            } catch (...) {
                base_dir.clear();
            }
        }
        if (base_dir.empty()) {
            base_dir = get_executable_dir_best_effort();
        }
        if (base_dir.empty()) {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                base_dir = cwd;
            }
        }
        path = join_path_best_effort(base_dir, "litep2p_peers.sqlite");
    }

    auto db = std::make_unique<LocalPeerDb>();
    LocalPeerDb::Options opt;
    opt.enable = true;
    opt.path = path;
    opt.default_candidate_limit = cfg.getPeerDbReconnectCandidateLimit();

    if (!db->open(opt)) {
        LOG_INFO("SM: Local peer DB disabled (open failed)");
        return;
    }

    m_local_peer_db = std::move(db);
}

void SessionManager::Impl::bootstrap_peers_from_db_() {
    if (m_peer_db_bootstrapped) {
        return;
    }
    m_peer_db_bootstrapped = true;

    if (!m_local_peer_db || !m_local_peer_db->is_open()) {
        return;
    }

    ConfigManager& cfg = ConfigManager::getInstance();
    const int candidate_limit = cfg.getPeerDbReconnectCandidateLimit();
    const auto candidates = m_local_peer_db->get_reconnect_candidates(candidate_limit);
    if (candidates.empty()) {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    std::vector<std::string> to_connect;
    std::vector<std::pair<std::string, std::string>> index_adds;
    int inserted = 0;

    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        for (const auto& rec : candidates) {
            if (rec.peer_id.empty()) continue;
            if (!m_localPeerId.empty() && rec.peer_id == m_localPeerId) continue;

            auto it = m_peers.find(rec.peer_id);
            if (it == m_peers.end()) {
                Peer p;
                p.id = rec.peer_id;
                p.network_id = rec.network_id;
                p.advertised_network_id = rec.network_id;
                p.ip = rec.ip;
                p.port = rec.port;
                p.connected = false;
                p.last_seen = now;
                p.last_discovery_seen = now;
                p.latency = -1;
                p.tier = (m_peer_tier_manager) ? m_peer_tier_manager->get_peer_tier(rec.peer_id) : PeerTier::TIER_1;

                m_peers[rec.peer_id] = p;
                if (!p.network_id.empty()) {
                    index_adds.emplace_back(rec.peer_id, p.network_id);
                }

                PeerContext ctx{rec.peer_id, p.network_id};
                ctx.state = PeerState::DISCOVERED;
                m_peer_contexts[rec.peer_id] = std::move(ctx);
                inserted++;
            }

            if (rec.connectable && !rec.network_id.empty()) {
                to_connect.push_back(rec.peer_id);
            }
        }
    }

    // Apply network index updates outside m_peers_mutex to avoid lock inversion.
    for (const auto& item : index_adds) {
        add_peer_to_network_index(item.first, item.second);
    }

    if (inserted > 0) {
        LOG_INFO("SM: Bootstrapped " + std::to_string(inserted) + " peers from local DB");
        notifyPeerUpdate();
    }

    // Queue reconnect attempts. We intentionally do not start many outbound connects at once.
    // The MaintenanceManager will drive paced attempts and trigger signaling only if DB is exhausted.
    if (!to_connect.empty()) {
        m_db_reconnect_queue.clear();
        for (const auto& pid : to_connect) {
            m_db_reconnect_queue.push_back(pid);
        }
        m_last_db_candidate_reload = std::chrono::steady_clock::now();
        m_db_cycle_exhausted_at = std::chrono::steady_clock::time_point{};
    }
}

void SessionManager::Impl::db_first_connect_and_prune_tick_() {
    // Shutdown guard
    if (m_shutting_down.load(std::memory_order_acquire) || !m_running.load(std::memory_order_acquire)) {
        return;
    }

    auto request_signaling_peer_list_bootstrap = [&](const char* reason) {
        // DB exhausted/unavailable. Query signaling for peers (throttled).
        if (!m_signaling_enabled) {
            return;
        }

        constexpr auto kPeerListCooldown = std::chrono::seconds(30);
        const auto now_local = std::chrono::steady_clock::now();
        if (m_last_signaling_peer_list_request != std::chrono::steady_clock::time_point{} &&
            (now_local - m_last_signaling_peer_list_request) < kPeerListCooldown) {
            return;
        }
        m_last_signaling_peer_list_request = now_local;

        LOG_INFO(std::string("SM: Signaling peer list bootstrap requested (") + reason + ")");

        m_signaling_bootstrap_requested.store(true, std::memory_order_release);
        // Once we fall back to signaling (DB exhausted/empty/unavailable), keep signaling connected.
        m_signaling_persistent_after_db_exhausted.store(true, std::memory_order_release);

        // If signaling is already connected+registered, just request a peer list.
        if (m_signaling_client && m_signaling_client->isConnected() &&
            m_signaling_registered.load(std::memory_order_acquire)) {
            m_signaling_client->sendListPeers();
            return;
        }

        // Otherwise, connect and register; REGISTER_ACK handler will send LIST_PEERS.
        ensure_signaling_connected_async(true);
    };

    const bool peer_db_available = (m_local_peer_db && m_local_peer_db->is_open());
    if (!peer_db_available) {
        // If the DB can't be opened/used (e.g., missing sqlite runtime on a platform),
        // we must not block signaling discovery behind DB-first logic.
        request_signaling_peer_list_bootstrap("peer_db_unavailable");
        return;
    }

    const auto now = std::chrono::steady_clock::now();

    // Periodic DB maintenance: prune stale peers.
    {
        constexpr auto kPruneInterval = std::chrono::hours(1);
        if (m_last_peer_db_prune == std::chrono::steady_clock::time_point{} ||
            (now - m_last_peer_db_prune) >= kPruneInterval) {
            const int days = ConfigManager::getInstance().getPeerDbPruneAfterDays();
            m_local_peer_db->prune_stale_peers(days);
            m_last_peer_db_prune = now;
        }
    }

    // If we already have a connected peer, stop DB-first bootstrapping.
    // IMPORTANT: If we've already fallen back to signaling at least once (DB exhausted/empty),
    // keep a best-effort persistent signaling connection for ongoing peer updates.
    bool any_connected = false;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        for (const auto& kv : m_peers) {
            if (kv.second.connected) {
                any_connected = true;
                break;
            }
        }
    }
    if (any_connected) {
        m_db_reconnect_queue.clear();
        m_db_cycle_exhausted_at = std::chrono::steady_clock::time_point{};
        m_signaling_bootstrap_requested.store(false, std::memory_order_release);

        if (m_signaling_persistent_after_db_exhausted.load(std::memory_order_acquire)) {
            // Maintain signaling connection (no frequent LIST_PEERS) while peers are connected.
            ensure_signaling_connected_async(false);
        }
        return;
    }

    // Pace DB reconnect attempts (avoid flooding). The interval is mode-driven so
    // reliability/desktop scenarios can recover faster while mobile can stay conservative.
    const auto kAttemptInterval = std::chrono::milliseconds(
        std::max<uint32_t>(250, PeerReconnectPolicy::getInstance().get_reconnect_attempt_interval_ms()));
    constexpr auto kReloadInterval = std::chrono::seconds(30);
    constexpr auto kPostExhaustGrace = std::chrono::seconds(6);

    // If we have no queued candidates, refresh from DB occasionally.
    if (m_db_reconnect_queue.empty() &&
        (m_last_db_candidate_reload == std::chrono::steady_clock::time_point{} || (now - m_last_db_candidate_reload) >= kReloadInterval)) {
        m_last_db_candidate_reload = now;

        ConfigManager& cfg = ConfigManager::getInstance();
        const int candidate_limit = cfg.getPeerDbReconnectCandidateLimit();
        const auto candidates = m_local_peer_db->get_reconnect_candidates(candidate_limit);

        for (const auto& rec : candidates) {
            if (rec.peer_id.empty()) continue;
            if (!m_localPeerId.empty() && rec.peer_id == m_localPeerId) continue;
            if (!rec.connectable) continue;
            if (rec.network_id.empty()) continue;
            m_db_reconnect_queue.push_back(rec.peer_id);
        }

        if (!m_db_reconnect_queue.empty()) {
            m_db_cycle_exhausted_at = std::chrono::steady_clock::time_point{};
        } else {
            // No viable candidates in DB.
            if (m_db_cycle_exhausted_at == std::chrono::steady_clock::time_point{}) {
                m_db_cycle_exhausted_at = now;
            }
        }
    }

    if (!m_db_reconnect_queue.empty()) {
        if (m_last_db_reconnect_attempt != std::chrono::steady_clock::time_point{} &&
            (now - m_last_db_reconnect_attempt) < kAttemptInterval) {
            return;
        }
        // Pick an eligible peer according to per-peer backoff (avoid hot loops).
        PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
        const size_t scan_limit = std::min<size_t>(5, m_db_reconnect_queue.size());
        std::string pid;
        bool found = false;
        for (size_t i = 0; i < scan_limit; ++i) {
            const std::string cand = m_db_reconnect_queue.front();
            m_db_reconnect_queue.pop_front();

            // Respect explicit user disconnects: drop suppressed candidates.
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                if (m_user_disconnected_peers.count(cand)) {
                    continue;
                }
            }

            policy.track_peer(cand);
            if (!found && policy.should_reconnect_now(cand)) {
                pid = cand;
                found = true;
            } else {
                // Not eligible yet; rotate to back.
                m_db_reconnect_queue.push_back(cand);
            }
        }

        if (!found) {
            return;
        }

        m_last_db_reconnect_attempt = now;
        connectToPeer(pid);

        if (m_db_reconnect_queue.empty()) {
            m_db_cycle_exhausted_at = now;
        }
        return;
    }

    // DB exhausted (or empty). Only now do we query signaling for peers.
    if (!m_signaling_enabled) {
        return;
    }

    // Give in-flight DB connects time to succeed. If there were no DB connect attempts in this cycle
    // (e.g., DB is empty), we can skip the grace period and go straight to signaling.
    if (m_db_cycle_exhausted_at != std::chrono::steady_clock::time_point{} &&
        (now - m_db_cycle_exhausted_at) < kPostExhaustGrace) {
        const bool no_db_connects_in_this_cycle =
            (m_last_db_reconnect_attempt == std::chrono::steady_clock::time_point{} ||
             m_last_db_reconnect_attempt < m_db_cycle_exhausted_at);
        if (!no_db_connects_in_this_cycle) {
            return;
        }
    }

    request_signaling_peer_list_bootstrap("db_exhausted_or_empty");
}

void SessionManager::Impl::stop() {
    std::lock_guard<std::mutex> lifecycle_lock(m_lifecycle_mutex);
    LOG_INFO("SM: Stopping session manager...");

    // Best-effort final telemetry flush before teardown starts.
    Telemetry::getInstance().inc_counter("engine_stop_total");
    Telemetry::getInstance().flush("shutdown");

    const auto stop_started_at = std::chrono::steady_clock::now();
    auto log_phase_ms = [&](const char* label, const std::chrono::steady_clock::time_point& started) {
        const auto now = std::chrono::steady_clock::now();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - started).count();
        LOG_INFO(std::string("SM: stop phase ") + label + " took " + std::to_string(ms) + "ms");
    };
    
    // Phase 1: RUNNING -> QUIESCING
    // Set shutdown flag first to prevent new work
    if (!m_running.exchange(false)) {
        LOG_WARN("SM: Session manager not running, ignoring stop request.");
        return;
    }

#if ENABLE_OVERLAY_MODULE
    // Stop the overlay router early: it joins its tick thread and must not
    // attempt further sends while transports are being torn down below.
    if (m_overlay_router) {
        m_overlay_router->stop();
    }
#endif

    // v0.4: flush the reliable-send outbox to disk so pending sends survive.
    if (m_reliable_send_manager) {
        m_reliable_send_manager->stop();
    }

    // Wake the SessionManager timer thread immediately (it may be waiting up to 100ms).
    m_timer_cv.notify_all();
    
    // Set the shutdown barrier flag to prevent new events
    m_shutting_down.store(true, std::memory_order_release);
    LOG_INFO("SM: Shutdown initiated");
    
    // Phase 1: STOPPING - Signal all components to stop gracefully
    LOG_INFO("SM: Phase 1 - STOPPING components");
    LOG_INFO("SM: Stopping session manager...");
    
    // Wake up any waiting threads
    m_eventCv.notify_all();
    
    auto phase = std::chrono::steady_clock::now();
    if (m_timer_thread.joinable()) {
        m_timer_thread.join();
    }
    log_phase_ms("join_timer_thread", phase);

    phase = std::chrono::steady_clock::now();

    // If a NAT/STUN detection thread is running, request cancellation BEFORE joining.
    // Without this, stop() can block for several seconds due to STUN retry/timeout cycles.
    if (m_comms_mode != "TCP") {
        NATTraversal::getInstance().requestCancel();
    }

    if (m_nat_detect_thread.joinable()) {
        m_nat_detect_thread.join();
    }
    log_phase_ms("join_nat_detect_thread", phase);

    phase = std::chrono::steady_clock::now();

    // Join signaling reconnect thread (if any) before tearing down the signaling client.
    if (m_signaling_reconnect_thread.joinable()) {
        m_signaling_reconnect_thread.join();
    }
    log_phase_ms("join_signaling_reconnect_thread", phase);

    phase = std::chrono::steady_clock::now();
    join_owned_recovery_workers_();
    log_phase_ms("join_owned_recovery_workers", phase);
    
    // PRODUCTION-READY: Stop IP monitoring
    stop_ip_monitor();

    phase = std::chrono::steady_clock::now();

    // Stop signaling client early to avoid it delivering callbacks during teardown.
    m_signaling_client.reset();
    log_phase_ms("stop_signaling_client", phase);

    phase = std::chrono::steady_clock::now();

    // Phase 2: QUIESCING - Stop processing new events
    // Stop the EventManager FIRST to prevent new events from being processed
    if (m_event_manager) {
        LOG_INFO("SM: Stopping event manager...");
        m_event_manager->stopEventProcessing();
        // EventManager must be destroyed immediately after stopping
        m_event_manager.reset();
        LOG_INFO("SM: Event manager stopped and destroyed");
    }
    log_phase_ms("stop_event_manager", phase);

    phase = std::chrono::steady_clock::now();
    
    // Clear any pending events in the legacy queue
    {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        while (!m_eventQueue.empty()) {
            m_eventQueue.pop();
        }
    }
    // v0.4 backpressure: all queued send events are gone after stop.
    m_pending_sends.store(0, std::memory_order_relaxed);
    
    // Stop the low-level UDP discovery service first to prevent blocking
    LOG_INFO("SM: Stopping discovery service...");
    Discovery* discovery = getGlobalDiscoveryInstance();
    // Clear the discovery callback to prevent it from firing after shutdown
    discovery->setCallback(nullptr);
    discovery->stop();
    LOG_INFO("SM: Discovery service stopped.");
    log_phase_ms("stop_discovery", phase);

    phase = std::chrono::steady_clock::now();
    
    // Stop network IO
    // Always unregister punch observers during teardown (no-op if not registered).
    unregister_nat_punch_observer_();
    if (m_comms_mode == "TCP") {
        LOG_INFO("SM: Stopping TCP connection manager...");
        m_tcpConnectionManager->stop();
        LOG_INFO("SM: TCP connection manager stopped.");

        // Even in TCP mode we construct a UDP manager (used for NAT/STUN and UDP sessions).
        // Ensure NATTraversal never holds a dangling raw pointer across SessionManager lifetimes.
        NATTraversal::getInstance().setConnectionManager(nullptr);

        // Heterogeneous mode started a UDP listener too; tear it down as well.
        if (m_comms_heterogeneous) {
            m_udpConnectionManager->stop();
            NATTraversal::getInstance().shutdown();
            LOG_INFO("SM: UDP connection manager stopped (heterogeneous mode teardown).");
        }
    } else {
        LOG_INFO("SM: Stopping UDP connection manager...");
        NATTraversal::getInstance().setConnectionManager(nullptr);
        m_udpConnectionManager->stop();
        NATTraversal::getInstance().shutdown();
        LOG_INFO("SM: UDP connection manager stopped.");

        // Heterogeneous mode started a TCP listener too; tear it down as well.
        if (m_comms_heterogeneous) {
            m_tcpConnectionManager->stop();
            LOG_INFO("SM: TCP connection manager stopped (heterogeneous mode teardown).");
        }
    }

    log_phase_ms("stop_network_io", phase);

    // PeerReconnectPolicy is a process-wide singleton. If the engine is stopped and
    // restarted within the same process (common on Android), stale per-peer state
    // (e.g., "connected=true") can incorrectly suppress new connect attempts after
    // restart. Clear policy tracking on stop so the next start begins clean.
    PeerReconnectPolicy::getInstance().shutdown();

    phase = std::chrono::steady_clock::now();
    
    // Avoid fixed long sleeps during stop(). If a short grace is needed for
    // platform-specific socket teardown, keep it minimal.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    log_phase_ms("post_network_grace", phase);

    phase = std::chrono::steady_clock::now();
    
    // Phase 3: STOPPED - Destroy resources in reverse order of dependency
    // Clear peer data and contexts
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        m_peers.clear();
        m_peer_contexts.clear();
    }

    // Clear network index and ephemeral mappings
    {
        std::lock_guard<std::mutex> index_lock(m_network_index_mutex);
        m_network_id_to_peer_id.clear();
        m_ephemeral_to_advertised_port_map.clear();
    }
    
    // Reset unique pointers to ensure clean state
    LOG_INFO("SM: Resetting unique pointers...");
    m_broadcast_discovery.reset();
    LOG_INFO("SM: broadcast_discovery reset");
    log_phase_ms("reset_broadcast_discovery", phase);

    phase = std::chrono::steady_clock::now();
    
    // Shutdown peer tier manager before resetting
    if (m_peer_tier_manager) {
        LOG_INFO("SM: Shutting down peer tier manager...");
        m_peer_tier_manager->shutdown();
        LOG_INFO("SM: Peer tier manager shutdown complete");
    }
    m_peer_tier_manager.reset();
    LOG_INFO("SM: peer_tier_manager reset");
    log_phase_ms("shutdown_peer_tier_manager", phase);
    
    m_file_transfer_manager.reset();
    LOG_INFO("SM: file_transfer_manager reset");
    m_session_cache.reset();
    LOG_INFO("SM: session_cache reset");
    m_message_batcher.reset();
    LOG_INFO("SM: message_batcher reset");
    m_peer_index.reset();
    LOG_INFO("SM: peer_index reset");
    m_battery_optimizer.reset();
    LOG_INFO("SM: battery_optimizer reset");
    
#if HAVE_NOISE_PROTOCOL
    m_secure_session_manager.reset();
    LOG_INFO("SM: secure_session_manager reset");
    m_noise_nk_manager.reset();
    LOG_INFO("SM: noise_nk_manager reset");
    m_noise_key_store.reset();
    LOG_INFO("SM: noise_key_store reset");
#endif
    
    LOG_INFO("SM: Session manager stopped");

    const auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - stop_started_at).count();
    LOG_INFO("SM: stop() total " + std::to_string(total_ms) + "ms");
}

void SessionManager::Impl::connectToPeer(const std::string& peer_id) {
    connectToPeer(peer_id, false, "api");
}

void SessionManager::Impl::connectToPeer(const std::string& peer_id, bool bypass_reconnect_policy, const char* source) {
    if (peer_id.empty()) {
        return;
    }

    // An explicit user-initiated connect clears any prior user-disconnect
    // suppression so the peer becomes eligible for reconnect again. Internal
    // reconnect attempts (maintenance/db) must NOT clear it.
    if (source && std::strncmp(source, "user_api", 8) == 0) {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        m_user_disconnected_peers.erase(peer_id);
    } else {
        // Centralized guard: internal auto-reconnect paths (network change,
        // discovery, endpoint change, recovery, maintenance) must not bypass
        // an explicit user disconnect. Only user_api connects may override.
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        if (m_user_disconnected_peers.count(peer_id)) {
            LOG_DEBUG("SM: connectToPeer suppressed for user-disconnected peer " + peer_id +
                      " (source=" + (source ? source : "?") + ")");
            return;
        }
    }

    const auto now = std::chrono::steady_clock::now();
    bool should_push = true;

    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = m_peer_contexts.find(peer_id);
        if (it == m_peer_contexts.end()) {
            // Create a context so we can debounce subsequent requests even if the peer
            // isn't fully discovered yet.
            it = m_peer_contexts.emplace(peer_id, PeerContext{peer_id, std::string{}}).first;
        }

        PeerContext& ctx = it->second;
        const auto elapsed = now - ctx.last_connect_attempt;

        // Debounce repeated connect triggers that commonly arise from discovery/signaling
        // races or reciprocal CONNECT_REQUEST loops.
        //
        // IMPORTANT: Do NOT update last_connect_attempt when suppressing; otherwise a
        // tight loop can extend suppression indefinitely.
        std::chrono::milliseconds debounce_ms{0};
        switch (ctx.state) {
            case PeerState::CONNECTING:
            case PeerState::CONNECTED:
                debounce_ms = std::chrono::milliseconds(2000);
                break;
            case PeerState::HANDSHAKING:
                debounce_ms = std::chrono::milliseconds(5000);
                break;
            case PeerState::READY:
                debounce_ms = std::chrono::milliseconds(10000);
                break;
            default:
                debounce_ms = std::chrono::milliseconds(0);
                break;
        }

        if (debounce_ms.count() > 0 &&
            ctx.last_connect_attempt != std::chrono::steady_clock::time_point{} &&
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed) < debounce_ms) {
            should_push = false;
        } else {
            ctx.last_connect_attempt = now;
        }
    }

    if (!should_push) {
        LOG_DEBUG("SM: connectToPeer debounced for " + peer_id);
        return;
    }

    LOG_INFO("SM: connectToPeer requested for peer: " + peer_id +
             (bypass_reconnect_policy ? " (bypass_policy=true)" : ""));
    pushEvent(ConnectToPeerEvent{peer_id, bypass_reconnect_policy, source ? std::string(source) : std::string{}});
}

bool SessionManager::Impl::disconnectFromPeer(const std::string& peer_id) {
    if (peer_id.empty()) {
        return false;
    }
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return false;
    }

    // Gather everything we need under the peers lock, then release it before
    // touching transports (their callbacks may re-enter the session layer).
    bool peer_known = false;
    bool has_fsm_context = false;
    uint64_t current_epoch = 0;
    std::vector<std::string> candidate_network_ids;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        Peer* peer = find_peer_by_id(peer_id);
        if (peer) {
            peer_known = true;
            if (!peer->network_id.empty()) candidate_network_ids.push_back(peer->network_id);
            if (!peer->advertised_network_id.empty() &&
                peer->advertised_network_id != peer->network_id) {
                candidate_network_ids.push_back(peer->advertised_network_id);
            }
        }
        auto ctx_it = m_peer_contexts.find(peer_id);
        if (ctx_it != m_peer_contexts.end()) {
            has_fsm_context = true;
            current_epoch = ctx_it->second.connect_epoch;
            if (!ctx_it->second.network_id.empty()) {
                candidate_network_ids.push_back(ctx_it->second.network_id);
            }
        }

        // Suppress automatic reconnects until the next explicit connect or an
        // inbound connection from this peer.
        m_user_disconnected_peers.insert(peer_id);
    }

    if (!peer_known) {
        LOG_WARN("SM: disconnectFromPeer - unknown peer: " + peer_id);
        return false;
    }

    // Include any ephemeral-port mappings that point at the candidate endpoints
    // (incoming connections may live on an ephemeral port).
    {
        std::lock_guard<std::mutex> index_lock(m_network_index_mutex);
        for (const auto& mapping : m_ephemeral_to_advertised_port_map) {
            for (const auto& nid : candidate_network_ids) {
                if (mapping.second == nid) {
                    candidate_network_ids.push_back(mapping.first);
                    break;
                }
            }
        }
    }

    LOG_INFO("SM: disconnectFromPeer requested for peer: " + peer_id);

    // Close transport connections best-effort. TCP closes the socket, which
    // triggers the normal on_disconnect teardown path. UDP/QUIC are
    // connectionless at this layer (disconnectPeer returns false); the FSM
    // event below handles their session state.
    for (const auto& nid : candidate_network_ids) {
        if (m_tcpConnectionManager) {
            m_tcpConnectionManager->disconnectPeer(nid);
        }
        if (m_udpConnectionManager) {
            m_udpConnectionManager->disconnectPeer(nid);
        }
    }

    // Stop reconnect-policy tracking so a user disconnect does not accumulate
    // backoff/failure stats, and drop any queued DB-first reconnect candidate.
    PeerReconnectPolicy::getInstance().untrack_peer(peer_id);
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = std::find(m_db_reconnect_queue.begin(), m_db_reconnect_queue.end(), peer_id);
        if (it != m_db_reconnect_queue.end()) {
            m_db_reconnect_queue.erase(it);
        }
    }

    // Drive the peer FSM to DISCONNECTED. This updates peer.connected,
    // telemetry, persistence and notifies listeners — the same path used for
    // transport-detected disconnects.
    if (has_fsm_context) {
        pushEvent(FSMEvent{peer_id, PeerEvent::DISCONNECT_DETECTED, current_epoch});
    } else {
        // No FSM context (peer known but never connected): update state directly.
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            Peer* peer = find_peer_by_id(peer_id);
            if (peer) {
                peer->connected = false;
                peer->active_connection_path = ConnectionPath::UNKNOWN;
            }
        }
        Telemetry::getInstance().set_peer_connection(peer_id, "UNKNOWN", false);
        notifyPeerUpdate();
    }

    return true;
}

void SessionManager::Impl::sendMessageToPeer(const std::string& peer_id, const std::string& message) {
    LOG_INFO("SM: sendMessageToPeer called - pushing SendMessageEvent for peer " + peer_id + ", msg_len=" + std::to_string(message.length()));
    pushEvent(SendMessageEvent{peer_id, message});
    LOG_INFO("SM: SendMessageEvent pushed to queue for peer " + peer_id);
}

void SessionManager::Impl::setMessageReceivedCallback(std::function<void(const std::string&, const std::string&)> cb) {
    LOG_INFO("SM: Message received callback registered");
    m_message_received_cb = cb;
}

void SessionManager::Impl::set_battery_level_public(int percent, bool is_charging) {
    set_battery_level(percent, is_charging);
}

void SessionManager::Impl::set_network_info_public(bool is_wifi, bool is_available) {
    set_network_info(is_wifi, is_available);
}

void SessionManager::Impl::set_reconnect_mode_public(const std::string& mode) {
    PeerReconnectPolicy::getInstance().set_reconnect_mode_string(mode);
}

std::string SessionManager::Impl::get_reconnect_status_json_public() const {
    return get_reconnect_status_json();
}

std::future<void> SessionManager::Impl::stopAsync() {
    return std::async(std::launch::async, [this]() {
        stop();
    });
}

#if HAVE_NOISE_PROTOCOL
void SessionManager::Impl::initializeNoiseHandshake(const std::string& peer_id) {
    if (!m_use_noise_protocol) {
        LOG_WARN("SM: Noise handshake requested but protocol disabled");
        return;
    }

    if (!m_secure_session_manager) {
        LOG_WARN("SM: Noise handshake requested but secure session manager unavailable");
        return;
    }

    std::string handshake_payload;
    {
        // IMPORTANT: SecureSession/Noise state is not thread-safe. Hold the mutex while
        // creating the session AND generating the first handshake message.
        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
        auto session = m_secure_session_manager->get_or_create_session(peer_id, NoiseNKSession::Role::INITIATOR);
        // Get current epoch for this peer
        uint64_t current_epoch = 0;
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            auto ctx_it = m_peer_contexts.find(peer_id);
            if (ctx_it != m_peer_contexts.end()) {
                current_epoch = ctx_it->second.connect_epoch;
            }
        }
        
        if (!session) {
            LOG_WARN("SM: Failed to create secure session for initiator " + peer_id);
            pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED, current_epoch});
            return;
        }

        // If a previous attempt left a half-initialized initiator session (handshake_initiated=true but not READY),
        // we must reset it; otherwise start_handshake() returns empty and we can get stuck retrying forever under loss.
        if (!session->is_ready() && session->handshake_initiated()) {
            LOG_WARN("SM: Resetting half-initialized Noise session for " + peer_id + " before initiating handshake");
            m_secure_session_manager->remove_session(peer_id);
            session = m_secure_session_manager->get_or_create_session(peer_id, NoiseNKSession::Role::INITIATOR);
            if (!session) {
                LOG_WARN("SM: Failed to recreate secure session for initiator " + peer_id);
                // Get current epoch
                uint64_t current_epoch = 0;
                {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    auto ctx_it = m_peer_contexts.find(peer_id);
                    if (ctx_it != m_peer_contexts.end()) {
                        current_epoch = ctx_it->second.connect_epoch;
                    }
                }
                pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED, current_epoch});
                return;
            }
        }

        if (session->is_ready()) {
            // Already ready; no need to re-initiate.
            return;
        }
        handshake_payload = session->start_handshake();
    }

    if (handshake_payload.empty()) {
        LOG_WARN("SM: Failed to start Noise handshake with " + peer_id);
        pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED});
        return;
    }

    LOG_INFO("SM: Initiating Noise handshake with " + peer_id + ", payload_len=" + std::to_string(handshake_payload.size()));
    sendNoiseHandshakeMessage(peer_id, handshake_payload);
}

std::string SessionManager::Impl::processNoiseHandshakeMessage(const std::string& peer_id, const std::string& message) {
    LOG_INFO("SM: Processing Noise handshake message from " + peer_id + ", payload_len=" + std::to_string(message.size()));

    if (message.empty()) {
        LOG_WARN("SM: Received empty handshake message for " + peer_id);
        return "";
    }

    // Check if this is a relay reconnect (peer lost direct path and is reconnecting via signaling)
    // Also check the cooldown to prevent infinite handshake loops
    bool is_relay_reconnect = false;
    bool within_cooldown = false;
    constexpr auto HANDSHAKE_COOLDOWN = std::chrono::seconds(5);  // Don't reset session if handshake completed within 5s
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto ctx_it = m_peer_contexts.find(peer_id);
        if (ctx_it != m_peer_contexts.end()) {
            is_relay_reconnect = ctx_it->second.is_relay_reconnect;
            ctx_it->second.is_relay_reconnect = false;  // Clear flag after reading
            
            // Check if handshake completed recently - if so, don't allow reset to prevent loops
            auto now = std::chrono::steady_clock::now();
            auto time_since_handshake = now - ctx_it->second.last_handshake_completed;
            if (ctx_it->second.last_handshake_completed != std::chrono::steady_clock::time_point{} &&
                time_since_handshake < HANDSHAKE_COOLDOWN) {
                within_cooldown = true;
            }
        }
    }

    std::string response;
    bool handshake_ready = false;
    std::vector<uint8_t> pending_send_key;
    std::vector<uint8_t> pending_recv_key;
    {
        // IMPORTANT: SecureSession/Noise state is not thread-safe. Hold the mutex while
        // checking readiness and processing the handshake message.
        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
        auto session = m_secure_session_manager->get_session(peer_id);

        // IMPORTANT: If a session is already READY, do not reset it just because a handshake
        // message arrived. During connect/handshake races, the peer may resend handshake frames,
        // and resetting here can create an endless loop where neither side can finish.
        // EXCEPTION: If this is a relay reconnect (peer lost direct path e.g. WiFi toggle),
        // allow resetting the session so the peer can re-establish connection.
        // HOWEVER: If handshake completed very recently (within cooldown), do NOT reset -
        // this prevents infinite handshake loops when both sides relay-reconnect simultaneously.
        if (session && session->is_ready()) {
            if (is_relay_reconnect && !within_cooldown) {
                LOG_INFO("SM: Relay reconnect from " + peer_id + " - resetting READY session to allow re-handshake");
                m_secure_session_manager->remove_session(peer_id);
                session = nullptr;
                // FSM will receive HANDSHAKE_SUCCESS after re-handshake completes.
                // The FSM now accepts HANDSHAKE_SUCCESS in READY state (idempotent).
            } else if (is_relay_reconnect && within_cooldown) {
                LOG_INFO("SM: Relay reconnect from " + peer_id + " within cooldown - ignoring to prevent handshake loop");
                return "";
            } else {
                LOG_INFO("SM: Received handshake message for READY session with " + peer_id + " - ignoring");
                return "";
            }
        }

        // Detect and resolve simultaneous handshake initiation (glare)
        // IMPORTANT: As an INITIATOR we will legitimately receive a responder handshake message.
        // Only treat this as glare when we are configured as INITIATOR but have *not yet* initiated
        // the handshake (i.e., we haven't sent msg1). That case means the peer initiated first.
        if (session && session->get_role() == NoiseNKSession::Role::INITIATOR && !session->handshake_initiated()) {
            // Tie-break using peer ID. Lower ID wins and stays Initiator.
            if (m_localPeerId < peer_id) {
                LOG_INFO("SM: Handshake glare with " + peer_id + " - I am Initiator (winner). Initiating handshake and ignoring inbound msg1");
                const std::string first = session->start_handshake();
                if (!first.empty()) {
                    sendNoiseHandshakeMessage(peer_id, first);
                } else {
                    LOG_WARN("SM: Failed to start handshake during glare resolution with " + peer_id);
                }
                return "";
            }

            LOG_INFO("SM: Handshake glare with " + peer_id + " - I am Initiator (loser), switching to Responder");
            m_secure_session_manager->remove_session(peer_id);
            session = nullptr;
        }

        if (!session) {
            if (!m_secure_session_manager) {
                LOG_WARN("SM: Secure session manager unavailable for responder handshake with " + peer_id);
                return "";
            }
            session = m_secure_session_manager->get_or_create_session(peer_id, NoiseNKSession::Role::RESPONDER);
        }

        if (!session) {
            LOG_WARN("SM: Unable to process handshake for " + peer_id + " - session unavailable");
            return "";
        }

        LOG_INFO("SM: About to call session->process_handshake for " + peer_id);
        try {
            response = session->process_handshake(message);
        } catch (const std::exception& e) {
            LOG_WARN("SM: Exception processing handshake: " + std::string(e.what()));
            return "";
        } catch (...) {
            LOG_WARN("SM: Unknown exception processing handshake");
            return "";
        }
        handshake_ready = session->is_ready();
        // Derive per-session transport keys, but DO NOT register them yet.
        // The handshake response (msg2) must still travel with the shared
        // network key because the peer only derives its own keys after
        // receiving it. Registration happens after the response is sent.
        if (handshake_ready && session) {
            session->get_transport_keys(pending_send_key, pending_recv_key);
        }
    }

    LOG_INFO("SM: Returned from session->process_handshake for " + peer_id + ", response size=" + std::to_string(response.size()));

    if (!response.empty()) {
        LOG_INFO("SM: Sending Noise handshake response to " + peer_id + ", payload_len=" + std::to_string(response.size()));
        sendNoiseHandshakeMessage(peer_id, response);
    }

    // Register per-session transport keys once the peer can decrypt them.
    // (After the response above has gone out with the shared network key.)
    if (handshake_ready && pending_send_key.size() == 32 && pending_recv_key.size() == 32) {
        set_peer_transport_keys(peer_id, pending_send_key.data(), pending_recv_key.data());
        // Also register under the active network_id so transports
        // (which only know ip:port) can find the key on receive.
        std::string net_id;
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            auto pit = m_peers.find(peer_id);
            if (pit != m_peers.end() && !pit->second.network_id.empty()) {
                net_id = pit->second.network_id;
            }
        }
        if (!net_id.empty()) {
            set_peer_transport_keys(net_id, pending_send_key.data(), pending_recv_key.data());
        }
        LOG_INFO("SM: Registered per-session transport keys for peer " + peer_id);
    }

    // Get current epoch for this peer and update handshake completion timestamp
    uint64_t current_epoch = 0;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto ctx_it = m_peer_contexts.find(peer_id);
        if (ctx_it != m_peer_contexts.end()) {
            current_epoch = ctx_it->second.connect_epoch;
            if (handshake_ready) {
                // Record when handshake completed - used for cooldown to prevent loops
                ctx_it->second.last_handshake_completed = std::chrono::steady_clock::now();
            }
        }
    }
    
    if (handshake_ready) {
        LOG_INFO("SM: Noise handshake completed with peer " + peer_id);
        pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_SUCCESS, current_epoch});
        flushQueuedMessages(peer_id);
    } else if (response.empty()) {
        LOG_WARN("SM: Noise handshake with peer " + peer_id + " did not progress - marking as failed");
        pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED, current_epoch});
    }

    return response;
}

void SessionManager::Impl::queueMessage(const std::string& peer_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    auto it = m_peer_contexts.find(peer_id);
    if (it != m_peer_contexts.end()) {
        if (it->second.pending_messages.size() >= MAX_QUEUED_MESSAGES) {
            it->second.pending_messages.pop_front();
        }
        it->second.pending_messages.push_back(message);
        LOG_DEBUG("SM: Queued application message for peer " + peer_id + ", queue_size=" + std::to_string(it->second.pending_messages.size()));
    }
}

void SessionManager::Impl::flushQueuedMessages(const std::string& peer_id) {
    std::deque<std::string> pending;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = m_peer_contexts.find(peer_id);
        if (it != m_peer_contexts.end()) {
            pending.assign(it->second.pending_messages.begin(), it->second.pending_messages.end());
            it->second.pending_messages.clear();
        }
    }

    if (pending.empty()) {
        return;
    }

    LOG_INFO("SM: Flushing " + std::to_string(pending.size()) + " queued messages for peer " + peer_id);
    for (const auto& msg : pending) {
        pushEvent(SendMessageEvent{peer_id, msg});
    }
}

void SessionManager::Impl::clearQueuedMessages(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    auto it = m_peer_contexts.find(peer_id);
    if (it != m_peer_contexts.end()) {
        size_t queue_size = it->second.pending_messages.size();
        it->second.pending_messages.clear();
        LOG_INFO("SM: Cleared " + std::to_string(queue_size) + " pending messages for peer " + peer_id + " (due to restart)");
    }
}

bool SessionManager::Impl::shouldInitiateNoiseHandshake(const std::string& peer_id) const {
    if (!m_use_noise_protocol) {
        LOG_INFO("SM: shouldInitiateNoiseHandshake: protocol disabled");
        return false;
    }
    if (m_localPeerId.empty() || peer_id.empty()) {
        LOG_INFO("SM: shouldInitiateNoiseHandshake: empty IDs (local=" + m_localPeerId + ", remote=" + peer_id + ")");
        return false;
    }
    bool result = m_localPeerId < peer_id;
    LOG_INFO("SM: shouldInitiateNoiseHandshake: " + m_localPeerId + " < " + peer_id + " = " + (result ? "true" : "false"));
    return result;
}

void SessionManager::Impl::sendNoiseHandshakeMessage(const std::string& peer_id, const std::string& handshake_payload) {
    if (handshake_payload.empty()) {
        return;
    }

    std::string network_id;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        const Peer* peer = find_peer_by_id(peer_id);
        if (peer) {
            network_id = peer->network_id;
        }
    }

    if (network_id.empty()) {
        LOG_WARN("SM: Cannot send handshake to " + peer_id + " - missing network ID");
        return;
    }

    const std::string encoded = wire::encode_message(MessageType::HANDSHAKE_NOISE, handshake_payload);
    send_message_to_peer(network_id, encoded);
    
    // SIGNALING RELAY FALLBACK: Also relay handshake via signaling for AP isolation scenarios.
    // This ensures handshakes can complete even when direct UDP is blocked on WiFi networks.
    // IMPORTANT: Only relay when the direct destination is NOT a private/LAN endpoint.
    // On the same LAN, direct UDP already delivers the handshake; duplicating it over the
    // signaling relay makes the responder process the handshake twice back-to-back. The
    // second (relayed) handshake generates a NEW ephemeral and re-keys the session on the
    // responder while the initiator keeps the first key set -> one-sided re-key -> every
    // subsequent application message fails with "auth tag mismatch".
    {
        std::string hs_ip;
        uint16_t hs_port = 0;
        bool hs_parsed = parse_network_id(network_id, hs_ip, hs_port);
        // Minimal RFC-1918 private-IPv4 check (10/8, 172.16/12, 192.168/16).
        const bool hs_is_lan = hs_parsed && (
            hs_ip.rfind("10.", 0) == 0 ||
            hs_ip.rfind("192.168.", 0) == 0 ||
            hs_ip.rfind("172.", 0) == 0);
        if (!hs_is_lan && m_signaling_client && m_signaling_registered.load(std::memory_order_acquire)) {
        // Base64 encode the handshake payload for signaling transport
        auto base64_encode = [](const std::string& data) -> std::string {
            static const char* base64_chars = 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string result;
            result.reserve(((data.size() + 2) / 3) * 4);
            
            unsigned int val = 0;
            int valb = -6;
            for (unsigned char c : data) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    result.push_back(base64_chars[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
            while (result.size() % 4) result.push_back('=');
            return result;
        };
        
        std::string encoded_payload = base64_encode(handshake_payload);
        std::string relay_msg = "HANDSHAKE_RELAY|" + encoded_payload;
        
        try {
            m_signaling_client->sendSignal(peer_id, relay_msg);
            LOG_INFO("SM: Sent HANDSHAKE_RELAY to " + peer_id + " via signaling (AP isolation fallback)");
            Telemetry::getInstance().inc_counter("handshake_relay_sent_total");
        } catch (const std::exception& e) {
            LOG_WARN("SM: Failed to relay handshake via signaling to " + peer_id + ": " + e.what());
        } catch (...) {
            LOG_WARN("SM: Failed to relay handshake via signaling to " + peer_id);
        }
    }
    }
}

void SessionManager::Impl::proactiveHandshakeRelay(const std::string& peer_id) {
    // PROACTIVE RELAY ESCALATION: Re-send the handshake via signaling relay when the
    // peer is stuck in HANDSHAKING state for too long. This handles cases where:
    // - UDP handshake packets are being dropped
    // - LAN connectivity hasn't fully established after WiFi re-enable
    // - AP isolation blocks direct device-to-device traffic
    
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) {
        return;
    }
    
    // Check if peer is still in HANDSHAKING state
    PeerState current_state = PeerState::UNKNOWN;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto ctx_it = m_peer_contexts.find(peer_id);
        if (ctx_it == m_peer_contexts.end()) {
            return;
        }
        current_state = ctx_it->second.state;
    }
    
    if (current_state != PeerState::HANDSHAKING) {
        return;
    }
    
    // Get session and re-generate handshake message
    std::string handshake_payload;
    {
        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
        auto session = m_secure_session_manager->get_session(peer_id);
        if (!session) {
            return;
        }
        
        if (session->is_ready()) {
            // Session already completed - handshake succeeded via another path
            return;
        }
        
        // For initiator sessions, start_handshake() returns the cached first message
        // if already initiated, so this is safe to call again
        handshake_payload = session->start_handshake();
    }
    
    if (handshake_payload.empty()) {
        // We're not the initiator or session is in unexpected state
        return;
    }
    
    // Base64 encode and send via relay
    auto base64_encode = [](const std::string& data) -> std::string {
        static const char* base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        result.reserve(((data.size() + 2) / 3) * 4);
        
        unsigned int val = 0;
        int valb = -6;
        for (unsigned char c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    };
    
    std::string encoded_payload = base64_encode(handshake_payload);
    std::string relay_msg = "HANDSHAKE_RELAY|" + encoded_payload;
    
    try {
        m_signaling_client->sendSignal(peer_id, relay_msg);
        LOG_INFO("SM: Proactive HANDSHAKE_RELAY sent to " + peer_id + " (escalation after UDP timeout)");
        Telemetry::getInstance().inc_counter("handshake_relay_escalation_total");
    } catch (const std::exception& e) {
        LOG_WARN("SM: Failed to send proactive relay to " + peer_id + ": " + e.what());
    } catch (...) {
        LOG_WARN("SM: Failed to send proactive relay to " + peer_id);
    }
}
#endif

void SessionManager::Impl::handleDiscoveryResponse(const std::string& discovered_peer_id) {
    // Shutdown guard - early return if shutting down
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    
    LOG_INFO("SM: Discovery response for " + discovered_peer_id);
    
    {
        std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
        m_peers_being_discovered.erase(discovered_peer_id);
    }
    
    m_peer_lifecycle_manager->handleConnectToPeer(ConnectToPeerEvent{discovered_peer_id});
}

void SessionManager::Impl::handleDiscoveryResponseWithEndpoint(
        const std::string& discovered_peer_id,
        const std::string& responder_ip,
        int responder_port,
        int latency_ms) {
    // Shutdown guard - early return if shutting down
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    
    // Validate peer_id to reject phantom/malformed entries like "TIMEOUT"
    if (discovered_peer_id.empty() || discovered_peer_id.length() < 3 || discovered_peer_id.length() > 128) {
        LOG_WARN("SM: Rejecting discovery response with invalid peer_id length: '" + discovered_peer_id + "'");
        Telemetry::getInstance().inc_counter("phantom_discovery_rejected_total");
        return;
    }
    
    // Reject common error strings that can appear due to parsing bugs
    static const std::vector<std::string> invalid_peer_ids = {
        "TIMEOUT", "timeout", "ERROR", "error", "NULL", "null",
        "undefined", "UNDEFINED", "none", "NONE", "unknown", "UNKNOWN"
    };
    for (const auto& invalid : invalid_peer_ids) {
        if (discovered_peer_id == invalid) {
            LOG_WARN("SM: Rejecting discovery response with phantom peer_id: '" + discovered_peer_id + "'");
            Telemetry::getInstance().inc_counter("phantom_discovery_rejected_total");
            return;
        }
    }
    
    // Validate endpoint - reject malformed responses (e.g., ":204338992" with empty IP)
    if (responder_ip.empty() || responder_port <= 0 || responder_port > 65535) {
        LOG_WARN("SM: Rejecting discovery response with invalid endpoint for " + discovered_peer_id +
                 ": ip='" + responder_ip + "' port=" + std::to_string(responder_port));
        Telemetry::getInstance().inc_counter("invalid_discovery_endpoint_rejected_total");
        return;
    }
    
    LOG_INFO("SM: Discovery response with endpoint for " + discovered_peer_id + 
             " at " + responder_ip + ":" + std::to_string(responder_port) +
             " (latency=" + std::to_string(latency_ms) + "ms)");
    
    {
        std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
        m_peers_being_discovered.erase(discovered_peer_id);
    }
    
    // If we have valid endpoint info, create a LAN discovery result event
    // This will properly update the peer with the local IP
    if (!responder_ip.empty() && responder_port > 0) {
        LanDiscoveryResultEvent lan_event;
        lan_event.peerId = discovered_peer_id;
        lan_event.lanIp = responder_ip;
        lan_event.lanPort = responder_port;
        lan_event.latencyMs = latency_ms;
        lan_event.hopCount = 1;
        
        // Process LAN discovery to update peer endpoint
        handleLanDiscoveryResult(lan_event);
    }
    
    // Always trigger connect attempt
    m_peer_lifecycle_manager->handleConnectToPeer(
        ConnectToPeerEvent{discovered_peer_id, false, "lan_discovery"});
}

void SessionManager::Impl::handleLanDiscoveryResult(const LanDiscoveryResultEvent& event) {
    // Delegate to peer lifecycle manager for proper endpoint handling
    m_peer_lifecycle_manager->handleLanDiscoveryResult(event);
}

void SessionManager::Impl::initializeTierSystemCallbacks() {
    if (!m_failsafe) return;
    
    m_failsafe->set_error_callback([this](const SystemError& error) {
        LOG_WARN("SM: Tier error - " + error.component + ": " + error.description);
        
        try {
            if (error.component == "BroadcastDiscovery") {
                std::lock_guard<std::mutex> lock(m_scheduledEventsMutex);
                m_peers_being_discovered.erase(error.context);
            }
        } catch (...) {}
    });
    
    m_failsafe->set_health_callback([](bool is_healthy) {
        if (!is_healthy) {
            LOG_WARN("SM: Tier system degraded");
        }
    });
    
    LOG_INFO("SM: Tier system callbacks initialized");
}

void SessionManager::Impl::notifyPeerUpdate() {
    if (m_peer_update_cb) {
        // Convert map to vector for callback compatibility
        std::vector<Peer> peer_list;
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            peer_list.reserve(m_peers.size());
            for (const auto& kv : m_peers) {
                peer_list.push_back(kv.second);
            }
        }
        
        // Do not create an unowned callback thread: UI/JNI teardown can otherwise
        // race a callback after SessionManager has stopped. The peer lock was
        // released above, so delivery cannot deadlock the peer store.
        auto cb = m_peer_update_cb;
        try {
            cb(peer_list);
        } catch (const std::exception& e) {
            LOG_WARN("SM: Peer update callback failed: " + std::string(e.what()));
        } catch (...) {
            LOG_WARN("SM: Peer update callback failed with an unknown exception");
        }
    }
}

void SessionManager::Impl::handleFSMEvent(const FSMEvent& event) {
    // Shutdown guard - early return if shutting down
    // FSM must be silenced during shutdown to prevent accessing destroyed resources
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    
    // Ignore FSM events for self (prevents infinite loops if self is accidentally added to peers)
    if (event.peerId == m_localPeerId) {
        LOG_WARN("SM: Ignoring FSM event for self: " + event.peerId);
        return;
    } else {
        LOG_WARN("SM: Handling FSM event for " + event.peerId + " (len=" + std::to_string(event.peerId.length()) + ") local: " + m_localPeerId + " (len=" + std::to_string(m_localPeerId.length()) + ")");
    }
    
    PeerState prev_state = PeerState::UNKNOWN;
    PeerState new_state = PeerState::UNKNOWN;
    std::chrono::steady_clock::time_point prev_enter{};
    FSMResult result{PeerState::UNKNOWN};
    {
        NATIVELOGW("SM_NATIVE: handleFSMEvent - acquiring peers_mutex");
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = m_peer_contexts.find(event.peerId);
        if (it == m_peer_contexts.end()) {
            NATIVELOGW("SM_NATIVE: handleFSMEvent - ctx not found");
            return;
        }
        PeerContext& ctx = it->second;

        // Do not let a pointer into m_peer_contexts escape this critical section:
        // concurrent removal/insertion can rehash the map and invalidate it.
        if (event.connect_epoch > 0 && ctx.connect_epoch > 0 &&
            event.connect_epoch != ctx.connect_epoch) {
            LOG_INFO("SM: Ignoring stale FSM event for " + event.peerId +
                     " (event_epoch=" + std::to_string(event.connect_epoch) +
                     ", current_epoch=" + std::to_string(ctx.connect_epoch) + ")");
            return;
        }

        prev_state = ctx.state;
        prev_enter = ctx.last_state_change;
        NATIVELOGW(("SM_NATIVE: handleFSMEvent - calling fsm.handle_event. Current State: " + std::to_string(static_cast<int>(ctx.state)) + ", Event: " + std::to_string(static_cast<int>(event.fsmEvent))).c_str());
        result = m_peer_fsm.handle_event(ctx, event.fsmEvent);
        new_state = ctx.state;
        NATIVELOGW("SM_NATIVE: handleFSMEvent - releasing peers_mutex");
    }
    const bool fsm_state_changed = (prev_state != new_state);

    // ---------------- Telemetry: FSM events + state durations ----------------
    {
        Telemetry& t = Telemetry::getInstance();
        t.inc_counter("fsm_event_total");
        switch (event.fsmEvent) {
            case PeerEvent::CONNECT_REQUESTED: t.inc_counter("connect_requested_total"); break;
            case PeerEvent::CONNECT_SUCCESS: t.inc_counter("connect_success_total"); break;
            case PeerEvent::CONNECT_FAILED: t.inc_counter("connect_failed_total"); break;
            case PeerEvent::HANDSHAKE_REQUIRED: t.inc_counter("handshake_required_total"); break;
            case PeerEvent::HANDSHAKE_SUCCESS: t.inc_counter("handshake_success_total"); break;
            case PeerEvent::HANDSHAKE_FAILED: t.inc_counter("handshake_failed_total"); break;
            case PeerEvent::DISCONNECT_DETECTED: t.inc_counter("disconnect_detected_total"); break;
            default: break;
        }

        if (prev_state != new_state) {
            t.inc_counter("state_transition_total");
            const auto now = std::chrono::steady_clock::now();
            const int64_t dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - prev_enter).count();
            t.observe_hist_ms(std::string("state_duration_ms.") + std::to_string(static_cast<int>(prev_state)), dur_ms);
        }
    }

    // Update UI-facing connected status based on FSM state transitions.
    // IMPORTANT:
    // - With Noise enabled, peers are only truly usable for app messages once the secure session is READY.
    //   Marking CONNECTED/HANDSHAKING as "connected" causes the UI to report connected while messages
    //   are still being queued awaiting handshake completion.
    // - With Noise disabled, CONNECTED is sufficient.
    bool peer_status_changed = false;
    bool should_persist_connected_state = false;
    bool new_connected_state = false;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = m_peers.find(event.peerId);
        if (it != m_peers.end()) {
            Peer& peer = it->second;

            const bool is_ready_for_messages = m_use_noise_protocol ? (new_state == PeerState::READY)
                                                                    : (new_state == PeerState::CONNECTED || new_state == PeerState::READY);
            const bool is_hard_disconnected = (new_state == PeerState::DISCONNECTED || new_state == PeerState::FAILED || new_state == PeerState::DEGRADED);

            if (is_ready_for_messages) {
                if (!peer.connected) {
                    peer.connected = true;
                    
                    // Determine and set the connection path based on how we connected
                    // Check if the peer context has is_relay_reconnect set (signaling relay)
                    auto ctx_it = m_peer_contexts.find(event.peerId);
                    if (ctx_it != m_peer_contexts.end() && ctx_it->second.is_relay_reconnect) {
                        peer.active_connection_path = ConnectionPath::SIGNALING_RELAY;
                    } else {
                        // Determine based on the endpoint type being used
                        const std::string& current_ip = peer.ip;
                        bool is_private_ip = false;
                        if (!current_ip.empty()) {
                            is_private_ip = (current_ip.rfind("10.", 0) == 0 ||
                                            current_ip.rfind("192.168.", 0) == 0 ||
                                            current_ip.rfind("127.", 0) == 0 ||
                                            current_ip.rfind("169.254.", 0) == 0);
                            // Check 172.16-31.x range
                            if (!is_private_ip && current_ip.rfind("172.", 0) == 0 && current_ip.size() > 4) {
                                size_t dot_pos = current_ip.find('.', 4);
                                if (dot_pos != std::string::npos) {
                                    int second_octet = std::stoi(current_ip.substr(4, dot_pos - 4));
                                    is_private_ip = (second_octet >= 16 && second_octet <= 31);
                                }
                            }
                        }
                        
                        if (is_private_ip) {
                            peer.active_connection_path = ConnectionPath::LAN_DIRECT;
                        } else {
                            // Check if we're using a RELAY endpoint candidate
                            bool using_relay = false;
                            for (const auto& candidate : peer.endpoint_candidates) {
                                if (candidate.type == EndpointType::RELAY &&
                                    candidate.ip == peer.ip) {
                                    using_relay = true;
                                    break;
                                }
                            }
                            peer.active_connection_path = using_relay ? ConnectionPath::WAN_TURN_RELAY 
                                                                      : ConnectionPath::WAN_HOLE_PUNCH;
                        }
                    }
                    
                    LOG_INFO("SM: Peer " + event.peerId + " is now CONNECTED (FSM state=" + 
                             std::to_string(static_cast<int>(new_state)) + ", path=" + 
                             connectionPathToString(peer.active_connection_path) + ")");
                    
                    // Report connection path to telemetry
                    Telemetry::getInstance().set_peer_connection(
                        event.peerId, 
                        connectionPathToString(peer.active_connection_path), 
                        true);
                    
                    peer_status_changed = true;
                    should_persist_connected_state = true;
                    new_connected_state = true;
                }
            } else if (is_hard_disconnected) {
                if (peer.connected) {
                    peer.connected = false;
                    peer.active_connection_path = ConnectionPath::UNKNOWN;  // Reset on disconnect
                    LOG_INFO("SM: Peer " + event.peerId + " is now DISCONNECTED (FSM state=" + std::to_string(static_cast<int>(new_state)) + ")");
                    
                    // Report disconnection to telemetry
                    Telemetry::getInstance().set_peer_connection(event.peerId, "UNKNOWN", false);
                    
                    peer_status_changed = true;
                    should_persist_connected_state = true;
                    new_connected_state = false;
                }
            } else {
                // Intermediate states (CONNECTING/HANDSHAKING/etc). For Noise-enabled sessions these should not
                // be treated as connected; keep current peer.connected value unless we need to drop it.
                if (m_use_noise_protocol && peer.connected) {
                    peer.connected = false;
                    peer.active_connection_path = ConnectionPath::UNKNOWN;  // Reset on leaving READY
                    LOG_INFO("SM: Peer " + event.peerId + " leaving READY; now not connected for messaging (FSM state=" + std::to_string(static_cast<int>(new_state)) + ")");
                    
                    // Report state change to telemetry
                    Telemetry::getInstance().set_peer_connection(event.peerId, "UNKNOWN", false);
                    
                    peer_status_changed = true;
                    should_persist_connected_state = true;
                    new_connected_state = false;
                }
            }
        }
    }
    
    if (peer_status_changed || fsm_state_changed) {
        notifyPeerUpdate();
    }

    // Best-effort persistence (avoid DB I/O while holding peer locks).
    if (should_persist_connected_state) {
        if (m_local_peer_db && m_local_peer_db->is_open()) {
            m_local_peer_db->set_peer_connected(event.peerId, new_connected_state, system_now_ms());
        }
    }

    // Feed the per-peer reconnect policy with outcome signals so it can apply backoff and avoid hot loops.
    // This is the core "never hang / never spin forever" safety net.
    {
        PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
        policy.track_peer(event.peerId);

        auto policy_method = m_comms_mode;
        if (policy_method == "QUIC") policy_method = "UDP";

        // Success: once the peer is usable for messaging, reset backoff.
        const bool ready_for_messages = m_use_noise_protocol ? (new_state == PeerState::READY)
                                                            : (new_state == PeerState::CONNECTED || new_state == PeerState::READY);
        if (prev_state != new_state && ready_for_messages) {
            uint32_t rtt_ms = 50;
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                auto it = m_peers.find(event.peerId);
                if (it != m_peers.end() && it->second.latency > 0) {
                    rtt_ms = static_cast<uint32_t>(it->second.latency);
                }
            }
            policy.on_connection_success(event.peerId, policy_method, rtt_ms);
        }

        // Failures / disconnects: schedule backoff with reason-aware classification
        if (event.fsmEvent == PeerEvent::CONNECT_FAILED) {
            policy.on_connection_failure(event.peerId, policy_method, 
                ConnectionFailureReason::TIMEOUT_CONNECT, 0.0f);
        } else if (event.fsmEvent == PeerEvent::HANDSHAKE_FAILED) {
            policy.on_connection_failure(event.peerId, "HANDSHAKE", 
                ConnectionFailureReason::TIMEOUT_HANDSHAKE, 0.0f);
        } else if (event.fsmEvent == PeerEvent::DISCONNECT_DETECTED) {
            policy.on_connection_failure(event.peerId, "DISCONNECT", 
                ConnectionFailureReason::NO_ROUTE, 0.0f);
        }
    }

    if (result.actions.empty()) {
        NATIVELOGW("SM_NATIVE: handleFSMEvent - no actions to process");
    } else {
        NATIVELOGW(("SM_NATIVE: Actions size: " + std::to_string(result.actions.size())).c_str());
        try {
            for (size_t i = 0; i < result.actions.size(); ++i) {
                PeerAction action = result.actions[i];
                NATIVELOGW(("SM_NATIVE: Processing action index " + std::to_string(i) + ": " + std::to_string(static_cast<int>(action))).c_str());
                switch (action) {

            case PeerAction::INITIATE_HANDSHAKE:
                NATIVELOGW("SM_NATIVE: Action INITIATE_HANDSHAKE");
#if HAVE_NOISE_PROTOCOL
                if (m_use_noise_protocol) {
                    NATIVELOGW("SM_NATIVE: Calling initializeNoiseHandshake");
                    initializeNoiseHandshake(event.peerId);
                } else {
                    NATIVELOGW("SM_NATIVE: Noise protocol disabled, skipping handshake");
                }
#endif
                break;

            case PeerAction::PROCESS_HANDSHAKE_MESSAGE:
                NATIVELOGW("SM_NATIVE: Action PROCESS_HANDSHAKE_MESSAGE");
                if (m_use_noise_protocol) {
                    NATIVELOGW("SM_NATIVE: m_use_noise_protocol = 1");
                } else {
                    NATIVELOGW("SM_NATIVE: m_use_noise_protocol = 0");
                }
#if HAVE_NOISE_PROTOCOL
                if (m_use_noise_protocol) {
                    NATIVELOGW("SM_NATIVE: Retrieving handshake message");
                    // Retrieve the handshake message from peer context and process it
                    std::string handshake_msg;
                    {
                        std::lock_guard<std::mutex> lock(m_peers_mutex);
                        auto it = m_peer_contexts.find(event.peerId);
                        if (it != m_peer_contexts.end()) {
                            handshake_msg = std::move(it->second.pending_handshake_message);
                            it->second.pending_handshake_message.clear();
                        }
                    }
                    NATIVELOGW("SM_NATIVE: Calling processNoiseHandshakeMessage");
                    processNoiseHandshakeMessage(event.peerId, handshake_msg);
                    NATIVELOGW("SM_NATIVE: Returned from processNoiseHandshakeMessage");
                }
#endif
                break;

            case PeerAction::RETRY_HANDSHAKE:
#if HAVE_NOISE_PROTOCOL
                if (m_use_noise_protocol) {
                    // If we are retrying, ensure we don't reuse a half-initialized SecureSession
                    // that refuses to start_handshake() again (m_handshake_initiated=true).
                    // This can happen under loss/jitter where handshake packets drop and the
                    // watchdog marks HANDSHAKE_FAILED. Without resetting, we can get stuck in
                    // "Handshake already initiated" and never recover.
                    {
                        std::lock_guard<std::mutex> ssl(m_secure_session_mutex);
                        if (m_secure_session_manager) {
                            m_secure_session_manager->remove_session(event.peerId);
                        }
                    }
                    initializeNoiseHandshake(event.peerId);
                }
#endif
                break;

            case PeerAction::FLUSH_QUEUED_MESSAGES:
#if HAVE_NOISE_PROTOCOL
                flushQueuedMessages(event.peerId);
#endif
                break;

            case PeerAction::CLEANUP_RESOURCES:
                clear_peer_transport_keys(event.peerId);
#if HAVE_NOISE_PROTOCOL
                {
                    std::lock_guard<std::mutex> ssl(m_secure_session_mutex);
                    m_secure_session_manager->remove_session(event.peerId);
                }
#endif
                break;

            case PeerAction::RECORD_METRICS: {
                // Record latency metrics through the peer tier manager
                if (m_peer_tier_manager) {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    auto it = m_peers.find(event.peerId);
                    if (it != m_peers.end()) {
                        const Peer& peer = it->second;
                        m_peer_tier_manager->record_latency(event.peerId, peer.latency);
                    }
                }
                break;
            }

            default:
                break;
            }
        }
        } catch (const std::exception& e) {
            NATIVELOGW(("SM_NATIVE: Exception in actions loop: " + std::string(e.what())).c_str());
        } catch (...) {
            NATIVELOGW("SM_NATIVE: Unknown exception in actions loop");
        }
    }
    NATIVELOGW("SM_NATIVE: handleFSMEvent - finished processing actions");
} 

void SessionManager::Impl::timerLoop() {
    constexpr auto kTick = std::chrono::milliseconds(100);
    while (m_running.load(std::memory_order_acquire)) {
        {
            std::unique_lock<std::mutex> lock(m_timer_mutex);
            (void)m_timer_cv.wait_for(lock, kTick, [this] {
                return !m_running.load(std::memory_order_acquire);
            });
        }

        if (m_running.load(std::memory_order_acquire)) {
            pushEvent(TimerTickEvent{});
        }
    }
}

void SessionManager::Impl::handleSendMessageWithRetry(const std::string& peer_id, const std::string& network_id, 
                                   const std::string& message, const std::string& message_id) {
    (void)message_id;
    LOG_INFO("SM: handleSendMessageWithRetry called - peer_id=" + peer_id + ", network_id=" + network_id + ", msg_len=" + std::to_string(message.length()));

    Telemetry::getInstance().inc_counter("tx_messages_total");
    Telemetry::getInstance().inc_counter("tx_bytes_total", static_cast<int64_t>(message.size()));
    
    // Shutdown guard - early return if shutting down
    if (m_shutting_down.load(std::memory_order_acquire)) {
        LOG_WARN("SM: Cannot send to " + peer_id + " - session is shutting down");
        return;
    }
    
    if (network_id.empty()) {
        LOG_WARN("SM: Cannot send to " + peer_id + " - network_id is empty");
        return;
    }

    // Record that we are actively writing to this peer. Used to gate the
    // "stale peer while CONNECTED -> force reconnect" path so a dense outbound
    // burst (which occupies the local event loop and delays inbound ACK/PONG
    // processing, making the peer look stale to ourselves) does not trigger a
    // destructive reconnect mid-burst. See handleSendMessage.
    note_outbound(peer_id);

    LOG_INFO("SM: Calling send_message_to_peer for network_id " + network_id);
    send_message_to_peer(network_id, message);
    LOG_INFO("SM: send_message_to_peer completed for network_id " + network_id);
}

void SessionManager::Impl::handleMessageSendComplete(const MessageSendCompleteEvent& event) {
    // This is where you would handle ACKs if you had a reliable messaging layer.
    // For now, we'll just log it.
    LOG_DEBUG("SM: Message send complete for " + event.peerId + ", success: " + (event.success ? "true" : "false"));
}

void SessionManager::Impl::set_battery_level(int percent, bool is_charging) {
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.set_battery_level(percent, is_charging);
    LOG_DEBUG("SM: Battery " + std::to_string(percent) + "%, charging: " + 
             (is_charging ? "true" : "false"));
}

void SessionManager::Impl::set_network_info(bool is_wifi, bool is_available) {
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    policy.set_network_type(is_wifi, is_available);
    LOG_INFO("SM: Network info update - WiFi: " + std::string(is_wifi ? "true" : "false") + 
             ", Available: " + std::string(is_available ? "true" : "false"));

    const bool was_available = m_network_available.exchange(is_available, std::memory_order_acq_rel);
    const bool was_wifi = m_is_wifi.exchange(is_wifi, std::memory_order_acq_rel);

    // Treat a WiFi<->cellular transition as a network change even if "available" stays true.
    // This is critical on Android: LTE -> WiFi often does NOT produce an "unavailable" gap,
    // but it *does* invalidate our NAT mapping + signaling-advertised network_id.
    const bool network_restored = (!was_available && is_available);
    const bool network_type_changed = (was_available && is_available && was_wifi != is_wifi);
    const bool switched_to_wifi = network_type_changed && is_wifi;
    if (network_restored || network_type_changed) {
        m_last_network_change_ms.store(steady_now_ms(), std::memory_order_release);
        Telemetry::getInstance().inc_counter("network_change_total");
        if (network_restored) Telemetry::getInstance().inc_counter("network_change_restored_total");
        if (network_type_changed) Telemetry::getInstance().inc_counter("network_change_type_total");
        LOG_INFO(std::string("SM: Network change detected (") +
                 (network_restored ? "restored" : "type_changed") +
                 ", wifi=" + (is_wifi ? "true" : "false") + "). Triggering rugged recovery.");

        // RUGGED RECOVERY: Delegate to the recovery manager for coordinated recovery
        // This handles socket restart, session invalidation, and parallel reconnects
        if (m_recovery_manager) {
            std::lock_guard<std::mutex> worker_lock(m_owned_recovery_workers_mutex);
            if (!m_shutting_down.load(std::memory_order_acquire)) {
                if (m_network_recovery_thread.joinable() &&
                    !m_network_recovery_in_progress.load(std::memory_order_acquire)) {
                    m_network_recovery_thread.join();
                }
                bool expected = false;
                if (m_network_recovery_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    m_network_recovery_thread = std::thread([this, is_wifi, is_available]() {
                        struct Guard {
                            std::atomic<bool>& flag;
                            ~Guard() { flag.store(false, std::memory_order_release); }
                        } guard{m_network_recovery_in_progress};
                        if (!m_shutting_down.load(std::memory_order_acquire) && m_recovery_manager) {
                            m_recovery_manager->handle_network_change(is_wifi, is_available);
                        }
                    });
                }
            }
        }

        // CRITICAL FIX: Restart UDP socket on network interface change.
        // On Android, when switching between WiFi and LTE, the old socket may remain
        // associated with the old network interface. This causes packets to be routed
        // through the wrong interface or dropped entirely. Restarting the socket forces
        // the kernel to bind to the new active interface.
        if (m_udpConnectionManager) {
            LOG_INFO("SM: Restarting UDP socket after network interface change");
            if (m_udpConnectionManager->restartSocket()) {
                LOG_INFO("SM: UDP socket restarted successfully");
                Telemetry::getInstance().inc_counter("network_change_socket_restart_success_total");
            } else {
                LOG_WARN("SM: Failed to restart UDP socket after network change");
                Telemetry::getInstance().inc_counter("network_change_socket_restart_failed_total");
                {
                    AnomalyReporter::Event ev;
                    ev.type = "runtime_error";
                    ev.severity = "critical";
                    ev.reason = "The engine's UDP listener could not be rebound after a network interface change; connectivity to existing peers is at risk";
                    ev.detail = "UDP socket failed to restart after a network interface change";
                    ev.extras.emplace_back("subsystem", "transport");
                    AnomalyReporter::getInstance().report(ev);
                }
            }
        }

        // Network transitions often invalidate NAT mappings and temporarily break handshakes.
        // Clear per-peer cooldown/backoff so recovery isn't blocked by stale suppression.
        policy.reset_all_peer_stats();
        Telemetry::getInstance().inc_counter("reconnect_policy_reset_total");

        // CRITICAL FIX: Invalidate ALL connected peer sessions on network type change.
        // When WiFi<->LTE transitions occur, the UDP "sessions" become stale - the peer
        // may still be listening on the same IP:port, but our source IP has changed and
        // they won't recognize our packets. We must force re-handshake on all peers.
        // This also clears any Noise sessions that are bound to the old network path.
        {
            std::vector<std::string> peers_to_invalidate;
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
            for (auto& kv : m_peers) {
                Peer& peer = kv.second;
                if (peer.connected) {
                    peers_to_invalidate.push_back(peer.id);
                    // Mark as disconnected so next connect attempt does full handshake
                    peer.connected = false;
                }
            }
            }
            
            // Clear Noise sessions for these peers so we re-handshake
            if (!peers_to_invalidate.empty()) {
                LOG_INFO("SM: Network change - invalidating " + std::to_string(peers_to_invalidate.size()) + 
                         " peer sessions for re-handshake");
                Telemetry::getInstance().inc_counter("network_change_session_invalidation_total");
                
                for (const auto& peer_id : peers_to_invalidate) {
                    // Clear any existing Noise session
#if HAVE_NOISE_PROTOCOL
                    if (m_secure_session_manager) {
                        std::lock_guard<std::mutex> noise_lock(m_secure_session_mutex);
                        m_secure_session_manager->remove_session(peer_id);
                    }
#endif
                    // Transition FSM state to DISCONNECTED
                    bool needs_disconnect_event = false;
                    {
                        std::lock_guard<std::mutex> lock(m_peers_mutex);
                        auto ctx_it = m_peer_contexts.find(peer_id);
                        needs_disconnect_event = ctx_it != m_peer_contexts.end() &&
                            (ctx_it->second.state == PeerState::READY || ctx_it->second.state == PeerState::CONNECTED);
                    }
                    if (needs_disconnect_event) {
                        pushEvent(FSMEvent{peer_id, PeerEvent::DISCONNECT_DETECTED});
                    }
                }
            }
        }

        // LAN IP OPTIMIZATION: When switching TO WiFi, broadcast updated LAN IP to ALL known
        // peers (even connected ones). This allows peers on the same LAN to discover each other
        // directly and bypass AP Isolation by exchanging LAN IPs via signaling.
        if (switched_to_wifi && m_signaling_enabled) {
            LOG_INFO("SM: Switched to WiFi - broadcasting updated LAN IP to all peers");
            schedule_lan_ip_broadcast_(std::chrono::milliseconds(300));
        }

        // SELF-HEALING OPTIMIZATION: Trigger immediate reconnect for all disconnected peers.
        // This bypasses all backoff timers to allow the fastest possible recovery after
        // WiFi<->LTE transitions. The maintenance manager will pick these up on the next
        // timer tick and attempt reconnection.
        policy.trigger_immediate_reconnect_all();
        Telemetry::getInstance().inc_counter("immediate_reconnect_trigger_total");
        
        // PRODUCTION-READY: Immediately start reconnect attempts for disconnected peers
        // Don't wait for maintenance tick - start reconnecting NOW
        {
            std::vector<std::string> disconnected_peers;
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
            for (const auto& kv : m_peers) {
                const Peer& peer = kv.second;
                if (!peer.connected) {
                    auto ctx_it = m_peer_contexts.find(peer.id);
                    if (ctx_it != m_peer_contexts.end()) {
                        PeerState state = ctx_it->second.state;
                        if (state == PeerState::DISCONNECTED || 
                            state == PeerState::DEGRADED || 
                            state == PeerState::FAILED) {
                            disconnected_peers.push_back(peer.id);
                        }
                    }
                }
            }
            }
            
            // connectToPeer only queues an event; calling it directly avoids
            // detached workers and preserves a single shutdown ownership model.
            constexpr size_t max_parallel = 5;
            for (size_t i = 0; i < std::min(max_parallel, disconnected_peers.size()); i++) {
                const std::string& peer_id = disconnected_peers[i];
                LOG_INFO("SM: Immediately reconnecting peer " + peer_id + " after network change");
                connectToPeer(peer_id, true, "network_change_immediate");
            }
            
            // Queue remaining peers for maintenance manager to handle
            for (size_t i = max_parallel; i < disconnected_peers.size(); i++) {
                const std::string& peer_id = disconnected_peers[i];
                policy.track_peer(peer_id);
            }
        }

        // Self-heal: make sure NATTraversal is still wired up to our UDP transport before
        // refreshing the external address (otherwise STUN can return an unusable ephemeral port).
        ensure_nat_connection_manager_registered_();

        // Reset hole punch failure counters so peers can get fresh attempts after network change.
        // This is critical because the NAT type may change (e.g., from Symmetric to Full Cone)
        // after switching networks, making hole punching viable again.
        NATTraversal::getInstance().resetHolePunchFailures();

        // Refresh external address and publish updated network_id to signaling (if registered).
        refresh_external_address_async(true);

        if (m_signaling_enabled) {
            // Network transitions can leave the signaling TCP socket "connected" but unusable
            // (stale route, stalled receive loop, captive portal, etc.). Force a full reconnect so
            // REGISTER_ACK timing is bounded and recovery is deterministic.
            m_force_signaling_reconnect_requested.store(true, std::memory_order_release);

            // Treat a network change as a recovery opportunity: ask signaling for a fresh peer list
            // and keep a best-effort persistent connection so future flaps can self-heal.
            m_signaling_bootstrap_requested.store(true, std::memory_order_release);
            m_signaling_persistent_after_db_exhausted.store(true, std::memory_order_release);

            // IMPORTANT:
            // Always run the signaling recovery path on network change. Sending LIST_PEERS on an
            // existing socket can look successful while the TCP route is stale (Android handoffs).
            // ensure_signaling_connected_async(true) will either force a full reconnect or at
            // least re-register, bounding recovery.
            ensure_signaling_connected_async(true);
        }
    }
}

// Broadcast updated LAN IP to all known peers via signaling.
// This is called when switching to WiFi to enable LAN discovery optimization.
void SessionManager::Impl::broadcastLanIpUpdate() {
    if (!m_signaling_enabled) return;
    
    // Get our current LAN IP
    Discovery* discovery = getGlobalDiscoveryInstance();
    if (!discovery) {
        LOG_WARN("SM: broadcastLanIpUpdate: No discovery instance");
        return;
    }
    
    std::string lan_ip = discovery->getLocalLanIP();
    if (lan_ip.empty()) {
        LOG_INFO("SM: broadcastLanIpUpdate: No LAN IP available");
        return;
    }
    
    LOG_INFO("SM: broadcastLanIpUpdate: Broadcasting LAN IP " + lan_ip + " to all peers");
    
    // Collect all known peer IDs
    std::vector<std::string> peer_ids;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        for (const auto& kv : m_peers) {
            peer_ids.push_back(kv.first);
        }
    }
    
    if (peer_ids.empty()) {
        LOG_INFO("SM: broadcastLanIpUpdate: No known peers to broadcast to");
        return;
    }
    
    // Build the LAN_IP_UPDATE message
    // Format: "LAN_IP_UPDATE|<lan_ip>|<connection_port>"
    std::string payload = "LAN_IP_UPDATE|" + lan_ip + "|" + std::to_string(m_listen_port);
    
    // Check signaling is ready
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) {
        LOG_WARN("SM: broadcastLanIpUpdate: Signaling not ready");
        return;
    }
    
    // Send to each peer via signaling
    for (const auto& peer_id : peer_ids) {
        try {
            m_signaling_client->sendSignal(peer_id, payload);
            LOG_INFO("SM: Sent LAN_IP_UPDATE to " + peer_id + " (LAN=" + lan_ip + ":" + std::to_string(m_listen_port) + ")");
        } catch (const std::exception& e) {
            LOG_WARN("SM: Failed to send LAN_IP_UPDATE to " + peer_id + ": " + std::string(e.what()));
        }
    }
    
    Telemetry::getInstance().inc_counter("lan_ip_update_broadcast_total");
}

void SessionManager::Impl::join_owned_recovery_workers_() {
    // stop() is the only caller. Joining before members are reset establishes a
    // clear lifetime barrier for all recovery lambdas that capture this.
    m_timer_cv.notify_all();
    std::lock_guard<std::mutex> worker_lock(m_owned_recovery_workers_mutex);
    if (m_lan_broadcast_thread.joinable()) {
        m_lan_broadcast_thread.join();
    }
    if (m_network_recovery_thread.joinable()) {
        m_network_recovery_thread.join();
    }
}

void SessionManager::Impl::schedule_lan_ip_broadcast_(std::chrono::milliseconds delay) {
    std::lock_guard<std::mutex> worker_lock(m_owned_recovery_workers_mutex);
    if (m_shutting_down.load(std::memory_order_acquire) || !m_running.load(std::memory_order_acquire)) {
        return;
    }
    if (m_lan_broadcast_thread.joinable() &&
        !m_lan_broadcast_in_progress.load(std::memory_order_acquire)) {
        m_lan_broadcast_thread.join();
    }

    bool expected = false;
    if (!m_lan_broadcast_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return; // A previous network transition already scheduled the broadcast.
    }

    m_lan_broadcast_thread = std::thread([this, delay]() {
        struct Guard {
            std::atomic<bool>& flag;
            ~Guard() { flag.store(false, std::memory_order_release); }
        } guard{m_lan_broadcast_in_progress};

        for (int attempt = 0; attempt < 10; ++attempt) {
            {
                std::unique_lock<std::mutex> lock(m_timer_mutex);
                if (m_timer_cv.wait_for(lock, delay, [this] {
                        return m_shutting_down.load(std::memory_order_acquire) ||
                               !m_running.load(std::memory_order_acquire);
                    })) {
                    return;
                }
            }
            if (m_signaling_registered.load(std::memory_order_acquire) && m_signaling_client) {
                broadcastLanIpUpdate();
                return;
            }
            LOG_INFO("SM: Waiting for signaling to be ready before LAN IP broadcast (attempt " +
                     std::to_string(attempt + 1) + "/10)");
        }
    });
}

std::string SessionManager::Impl::get_reconnect_status_json() const {
    PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
    return policy.get_status_json();
}

void SessionManager::Impl::setup_signaling_callbacks(SignalingClient& client) {
    client.setMessageCallback([this](const std::string& msg) {
        LOG_INFO("SM: Signaling message received: " + msg);

        // Shutdown guard
        if (m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        json data;
        try {
            data = json::parse(msg);
        } catch (const std::exception& e) {
            LOG_WARN(std::string("SM: Failed to parse signaling JSON: ") + e.what());
            return;
        }

        const std::string type = data.value("type", "");
        if (type.empty()) {
            return;
        }

        // Phase 1 (P0.4): Track signaling freshness so MaintenanceManager can detect
        // stalled-but-connected sockets and force a re-register.
        m_last_signaling_rx_ms.store(steady_now_ms(), std::memory_order_release);

        // v0.4 signaling protocol extensions (ask.md §2/§3/§5): offline mailbox
        // delivery, alias lookup results, invites, and server-assisted presence.
        if (type == "STORED_MESSAGES" || type == "LOOKUP_RESULT" ||
            type == "INVITE" || type == "PRESENCE") {
            handle_signaling_v04_message(data);
            return;
        }

        auto make_placeholder_network_id = [](std::string peer_id) {
            // Must NOT contain ':' unless it's truly ip:port; otherwise connect logic will try to parse it.
            std::replace(peer_id.begin(), peer_id.end(), ':', '_');
            std::replace(peer_id.begin(), peer_id.end(), '/', '_');
            return std::string("signaling-") + peer_id;
        };

        auto safe_string = [](const json& obj, const char* key) -> std::string {
            auto it = obj.find(key);
            if (it == obj.end() || it->is_null()) {
                return "";
            }
            if (!it->is_string()) {
                return "";
            }
            return it->get<std::string>();
        };

        if (type == "REGISTER_ACK") {
            LOG_INFO("SM: Processing REGISTER_ACK, setting m_signaling_registered=true");
            m_signaling_registered.store(true, std::memory_order_release);
            LOG_INFO("SM: m_signaling_registered stored as true");

            // v0.4: fetch any offline messages held for us (store-and-forward).
            signaling_send_fetch();

            // Network transitions can request a forced full reconnect. Once we are registered again,
            // clear that request so we don't churn the signaling socket.
            m_force_signaling_reconnect_requested.store(false, std::memory_order_release);

            // If we already discovered an external address, publish it now.
            std::string pending;
            {
                std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
                pending = m_pending_signaling_network_id;
            }
            if (!pending.empty() && m_signaling_client) {
                m_signaling_client->sendUpdateNetworkId(pending);
            }

            // If DB-first reconnect hasn't requested signaling bootstrap yet, a fresh restart can
            // end up with "signaling connected" but zero peers (no PEER_LIST/PEER_JOINED events),
            // especially if the local peer DB is empty or UI is showing cached peers.
            // Request a peer list once (throttled) when we currently know no peers.
            bool no_known_peers = false;
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                no_known_peers = m_peers.empty();
            }

            if (m_signaling_client) {
                // ALWAYS request peer list after REGISTER_ACK to ensure we discover peers that joined
                // before us. This is critical when a peer connects to signaling late (e.g., desktop-19
                // joining after Android already registered). Without this, the late-joining peer never
                // learns about existing peers via signaling and can only discover them through LAN.
                const bool bootstrapping = m_signaling_bootstrap_requested.load(std::memory_order_acquire);
                const auto kPeerListCooldown = bootstrapping ? std::chrono::seconds(5)
                                                             : std::chrono::seconds(10);
                const auto now_local = std::chrono::steady_clock::now();
                if (m_last_signaling_peer_list_request == std::chrono::steady_clock::time_point{} ||
                    (now_local - m_last_signaling_peer_list_request) >= kPeerListCooldown) {
                    m_last_signaling_peer_list_request = now_local;
                    const char* reason = bootstrapping ? "bootstrap" : 
                                         (no_known_peers ? "no_known_peers" : "late_join_sync");
                    LOG_INFO(std::string("SM: Requesting signaling PEER_LIST after REGISTER_ACK (") +
                             reason + ")");
                    m_signaling_client->sendListPeers();
                }
            }
            
            // INITIAL LAN IP BROADCAST: When we register with signaling while already on WiFi,
            // broadcast our LAN IP to all peers. This is essential for LAN-first connections.
            // Without this, peers only learn our WAN IP from PEER_JOINED and never get our LAN IP.
            if (m_is_wifi.load(std::memory_order_acquire)) {
                LOG_INFO("SM: On WiFi at REGISTER_ACK - scheduling initial LAN IP broadcast");
                schedule_lan_ip_broadcast_(std::chrono::milliseconds(500));
            }
            return;
        }

        if (type == "PEER_LIST") {
            if (!data.contains("peers") || !data["peers"].is_array()) {
                return;
            }

            const bool bootstrapping = m_signaling_bootstrap_requested.load(std::memory_order_acquire);

            auto is_connectable_ipv4_endpoint = [](const std::string& nid) {
                if (nid.empty()) return false;
                if (nid.rfind("signaling-", 0) == 0) return false;
                const size_t first = nid.find(':');
                if (first == std::string::npos) return false;
                // Reject IPv6 literals (they contain multiple ':' and require bracket syntax).
                if (nid.find(':', first + 1) != std::string::npos) return false;
                return true;
            };

            // When bootstrapping via signaling (common when peer DB is disabled/unavailable),
            // connect to all connectable peers, but avoid spamming CONNECT attempts for peers
            // that are already connected.
            std::unordered_set<std::string> already_connected;
            if (bootstrapping) {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                for (const auto& kv : m_peers) {
                    if (kv.second.connected) {
                        already_connected.insert(kv.first);
                    }
                }
            }

            std::vector<std::string> bootstrap_connect_peers;
            std::unordered_set<std::string> bootstrap_connect_seen;

            for (const auto& p : data["peers"]) {
                if (!p.is_object()) {
                    continue;
                }
                const std::string pid = p.value("peer_id", "");
                if (pid.empty()) {
                    continue;
                }
                std::string network_id = safe_string(p, "network_id");
                if (network_id.empty()) {
                    network_id = make_placeholder_network_id(pid);
                }
                handlePeerDiscovered(network_id, pid);

                if (bootstrapping && pid != m_localPeerId && is_connectable_ipv4_endpoint(network_id)) {
                    if (already_connected.find(pid) == already_connected.end() &&
                        bootstrap_connect_seen.insert(pid).second) {
                        bootstrap_connect_peers.push_back(pid);
                    }
                }
            }

            if (bootstrapping) {
                for (const auto& pid : bootstrap_connect_peers) {
                    connectToPeer(pid);
                }
            }
            return;
        }

        if (type == "PEER_JOINED") {
            if (!data.contains("peer") || !data["peer"].is_object()) {
                return;
            }
            const auto& p = data["peer"];
            const std::string pid = p.value("peer_id", "");
            if (pid.empty()) {
                return;
            }
            std::string network_id = safe_string(p, "network_id");
            if (network_id.empty()) {
                network_id = make_placeholder_network_id(pid);
            }
            handlePeerDiscovered(network_id, pid);

            // v0.4 presence: a peer registering with the server is online.
            note_peer_presence(pid, true);

            auto is_connectable_ipv4_endpoint = [](const std::string& nid) {
                if (nid.empty()) return false;
                if (nid.rfind("signaling-", 0) == 0) return false;
                const size_t first = nid.find(':');
                if (first == std::string::npos) return false;
                // Reject IPv6 literals (they contain multiple ':' and require bracket syntax).
                if (nid.find(':', first + 1) != std::string::npos) return false;
                return true;
            };

            if (m_signaling_bootstrap_requested.load(std::memory_order_acquire)) {
                if (network_id.find(':') != std::string::npos && network_id.rfind("signaling-", 0) != 0) {
                    if (pid != m_localPeerId &&
                        m_signaling_bootstrap_requested.load(std::memory_order_acquire)) {
                        connectToPeer(pid);
                    }
                }
            } else if (pid != m_localPeerId && is_connectable_ipv4_endpoint(network_id)) {
                // Not bootstrapping: only auto-connect for peers we already knew about.
                // This fixes local Wi-Fi -> 4G transitions where the remote peer updates its
                // WAN endpoint via signaling and we must proactively reconnect.
                bool known_peer = false;
                bool currently_connected = false;
                {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    auto it = m_peers.find(pid);
                    if (it != m_peers.end()) {
                        known_peer = true;
                        currently_connected = it->second.connected;
                    }
                }
                if (known_peer && !currently_connected) {
                    connectToPeer(pid);
                }
            }
            return;
        }

        if (type == "PEER_UPDATED") {
            if (!data.contains("peer") || !data["peer"].is_object()) {
                return;
            }
            const auto& p = data["peer"];
            const std::string pid = p.value("peer_id", "");
            if (pid.empty()) {
                return;
            }
            std::string network_id = safe_string(p, "network_id");
            if (network_id.empty()) {
                network_id = make_placeholder_network_id(pid);
            }
            
            // CRITICAL: Get old network_id BEFORE calling handlePeerDiscovered, which updates it.
            // We need to compare old vs new to detect endpoint changes for immediate reconnect.
            std::string old_network_id_for_change_detection;
            bool was_connected_for_change_detection = false;
            {
                std::lock_guard<std::mutex> lock(m_peers_mutex);
                auto it = m_peers.find(pid);
                if (it != m_peers.end()) {
                    old_network_id_for_change_detection = it->second.network_id;
                    was_connected_for_change_detection = it->second.connected;
                }
            }
            
            handlePeerDiscovered(network_id, pid);

            // P0.3: Update NAT registration when peer endpoint changes.
            // This ensures hole-punching targets the updated endpoint.
            {
                const size_t colon_pos = network_id.find(':');
                // Only update for valid IPv4 endpoints (single colon, not signaling-placeholder).
                if (colon_pos != std::string::npos &&
                    network_id.find(':', colon_pos + 1) == std::string::npos &&
                    network_id.rfind("signaling-", 0) != 0) {
                    const std::string ip = network_id.substr(0, colon_pos);
                    const std::string port_str = network_id.substr(colon_pos + 1);

                    // Safe parse (avoid exceptions on malformed signaling payloads).
                    char* end = nullptr;
                    errno = 0;
                    const long port_long = std::strtol(port_str.c_str(), &end, 10);
                    const bool parsed_ok = (errno == 0 && end && *end == '\0');

                    if (parsed_ok && port_long > 0 && port_long <= 65535) {
                        const int port = static_cast<int>(port_long);
                        PeerAddress pa;
                        pa.peer_id = pid;
                        pa.network_id = "wan";
                        pa.external_ip = ip;
                        pa.external_port = static_cast<uint16_t>(port);
                        pa.discovered_at_ms = system_now_ms();
                        NATTraversal::getInstance().registerPeer(pa);
                        LOG_INFO("SM: PEER_UPDATED: Updated NAT registration for " + pid + " -> " + ip + ":" + std::to_string(port));
                    }
                }
            }

            auto is_connectable_ipv4_endpoint = [](const std::string& nid) {
                if (nid.empty()) return false;
                if (nid.rfind("signaling-", 0) == 0) return false;
                const size_t first = nid.find(':');
                if (first == std::string::npos) return false;
                // Reject IPv6 literals (they contain multiple ':' and require bracket syntax).
                if (nid.find(':', first + 1) != std::string::npos) return false;
                return true;
            };

            // Log the decision path for debugging endpoint change detection
            const bool bootstrap_mode = m_signaling_bootstrap_requested.load(std::memory_order_acquire);
            LOG_INFO("SM: PEER_UPDATED endpoint check: peer=" + pid + 
                     " old_nid=" + old_network_id_for_change_detection +
                     " new_nid=" + network_id +
                     " was_connected=" + std::to_string(was_connected_for_change_detection) +
                     " bootstrap=" + std::to_string(bootstrap_mode));
            
            // CRITICAL FIX: ALWAYS check for endpoint changes, REGARDLESS of bootstrap mode.
            // When a connected peer's endpoint changes (e.g., Android switches from WiFi to LTE),
            // we must force an immediate disconnect and reconnect instead of waiting for heartbeat
            // timeout (which can take 20-30 seconds). This dramatically improves WiFi handoff recovery.
            if (pid != m_localPeerId && 
                was_connected_for_change_detection && 
                !old_network_id_for_change_detection.empty() && 
                old_network_id_for_change_detection != network_id &&
                is_connectable_ipv4_endpoint(network_id)) {
                
                // Same-NAT guard: when two peers share one router, the signaling
                // server periodically advertises the peer's STUN-discovered PUBLIC
                // endpoint, which equals OUR OWN public IP. Treating that as an
                // "endpoint change" and forcing a reconnect tears down a perfectly
                // healthy LAN/READY session and re-keys Noise on one side only
                // ("auth tag mismatch"), causing endless connect churn (observed in
                // the rugged soak: READY -> DISCONNECT_DETECTED -> CONNECTING -> ...).
                // Keep the working LAN connection; the secondary receive mapping
                // added above already accepts packets from the advertised WAN endpoint.
                bool same_nat_advertised = false;
                {
                    std::string adv_ip, our_ip;
                    uint16_t adv_port = 0, our_port = 0;
                    bool adv_ok = parse_network_id(network_id, adv_ip, adv_port);
                    std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
                    bool our_ok = parse_network_id(m_pending_signaling_network_id, our_ip, our_port);
                    same_nat_advertised = adv_ok && our_ok && !adv_ip.empty() && adv_ip == our_ip;
                }

                if (same_nat_advertised) {
                    LOG_INFO("SM: PEER_UPDATED: peer " + pid + " advertised endpoint " + network_id +
                             " equals our own public IP; same-NAT, keeping existing connection (old=" +
                             old_network_id_for_change_detection + ")");
                    return;
                }

                LOG_INFO("SM: PEER_UPDATED: Peer " + pid + " endpoint changed from " + 
                         old_network_id_for_change_detection + " to " + network_id + " - forcing immediate reconnect");
                
                // Get current epoch for FSM event
                uint64_t current_epoch = 0;
                {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    auto ctx_it = m_peer_contexts.find(pid);
                    if (ctx_it != m_peer_contexts.end()) {
                        current_epoch = ctx_it->second.connect_epoch;
                    }
                }
                
                // Force disconnect to invalidate stale session
                pushEvent(FSMEvent{pid, PeerEvent::DISCONNECT_DETECTED, current_epoch});
                
                // Update peer's network_id to new endpoint
                {
                    std::lock_guard<std::mutex> lock(m_peers_mutex);
                    auto it = m_peers.find(pid);
                    if (it != m_peers.end()) {
                        it->second.connected = false;
                        it->second.network_id = network_id;
                        // Parse IP:port
                        const size_t cpos = network_id.find(':');
                        if (cpos != std::string::npos) {
                            it->second.ip = network_id.substr(0, cpos);
                            it->second.port = static_cast<uint16_t>(std::strtol(
                                network_id.substr(cpos + 1).c_str(), nullptr, 10));
                        }
                    }
                }
                
                // Clear any stale Noise session
#if HAVE_NOISE_PROTOCOL
                if (m_secure_session_manager) {
                    std::lock_guard<std::mutex> noise_lock(m_secure_session_mutex);
                    m_secure_session_manager->remove_session(pid);
                }
#endif
                
                // Reset reconnect policy for this peer (clear backoff)
                PeerReconnectPolicy::getInstance().reset_peer_stats(pid);
                
                // Immediately attempt to connect to new endpoint
                connectToPeer(pid, true, "endpoint_change_reconnect");
                return;  // Don't fall through to bootstrap/reconnect logic
            }
            
            // Standard bootstrap/reconnect logic (only if not already handled above)
            if (bootstrap_mode) {
                if (network_id.find(':') != std::string::npos && network_id.rfind("signaling-", 0) != 0) {
                    if (pid != m_localPeerId &&
                        m_signaling_bootstrap_requested.load(std::memory_order_acquire)) {
                        connectToPeer(pid);
                    }
                }
            } else if (pid != m_localPeerId && is_connectable_ipv4_endpoint(network_id)) {
                // Not bootstrapping: reconnect only for peers we already knew about.
                const bool known_peer = !old_network_id_for_change_detection.empty() || was_connected_for_change_detection;
                if (known_peer && !was_connected_for_change_detection) {
                    connectToPeer(pid);
                }
            }
            return;
        }

        if (type == "PEER_LEFT") {
            const std::string pid = data.value("peer_id", "");
            if (pid.empty()) {
                return;
            }
            // v0.4 presence: peer dropped off the server.
            note_peer_presence(pid, false);
            handlePeerLeftFromSignaling(pid);
            return;
        }

        if (type == "SIGNAL") {
            const std::string source_peer_id = data.value("source_peer_id", "");
            const std::string payload = data.value("payload", "");
            if (source_peer_id.empty() || payload.empty()) {
                return;
            }

            // Ignore self-addressed signaling messages if the server echoes/broadcasts.
            if (source_peer_id == m_localPeerId) {
                return;
            }

            // Payload format (string, must be JSON-string-safe):
            //   CONNECT_REQUEST|<network_id>|<comms_mode>[|<lan_ip>|<lan_port>]
            // Example:
            //   CONNECT_REQUEST|110.235.237.26:30001|UDP
            //   CONNECT_REQUEST|110.235.237.26:30001|UDP|192.168.1.100|30001
            if (payload.rfind("CONNECT_REQUEST|", 0) == 0) {
                std::string rest = payload.substr(std::strlen("CONNECT_REQUEST|"));
                std::string their_network_id;
                std::string their_mode;
                std::string their_lan_ip;
                int their_lan_port = 0;
                
                // Parse: network_id|mode[|lan_ip|lan_port]
                std::vector<std::string> parts;
                size_t start = 0;
                size_t end = 0;
                while ((end = rest.find('|', start)) != std::string::npos) {
                    parts.push_back(rest.substr(start, end - start));
                    start = end + 1;
                }
                parts.push_back(rest.substr(start));  // Last part
                
                if (parts.size() >= 1) their_network_id = parts[0];
                if (parts.size() >= 2) their_mode = parts[1];
                if (parts.size() >= 3) their_lan_ip = parts[2];
                if (parts.size() >= 4) {
                    try {
                        their_lan_port = std::stoi(parts[3]);
                    } catch (...) {
                        their_lan_port = 0;
                    }
                }

                if (!their_network_id.empty()) {
                    LOG_INFO("SM: Received CONNECT_REQUEST from " + source_peer_id + " endpoint=" + their_network_id +
                             (their_mode.empty() ? std::string("") : (" mode=" + their_mode)) +
                             (!their_lan_ip.empty() ? (" lan=" + their_lan_ip + ":" + std::to_string(their_lan_port)) : ""));

                    // Ensure we have a peer entry with the provided endpoint.
                    handlePeerDiscovered(their_network_id, source_peer_id);

                    // If they provided a LAN IP and we're on WiFi, also try to discover/connect via LAN
                    // This is useful when AP isolation blocks broadcasts but we can reach them directly
                    if (!their_lan_ip.empty() && their_lan_port > 0 && m_is_wifi.load(std::memory_order_acquire)) {
                        // Check if their LAN IP is in our subnet (simple heuristic)
                        std::string our_lan_ip;
                        Discovery* discovery = getGlobalDiscoveryInstance();
                        if (discovery) {
                            our_lan_ip = discovery->getLocalLanIP();
                        }
                        
                        // If both are in private IP space, try direct probe and handlePeerDiscovered
                        if (!our_lan_ip.empty()) {
                            std::string lan_network_id = their_lan_ip + ":" + std::to_string(their_lan_port);
                            LOG_INFO("SM: Peer " + source_peer_id + " advertised LAN endpoint: " + lan_network_id);
                            
                            // Send direct discovery probe to bypass AP isolation
                            if (discovery) {
                                discovery->sendDirectProbe(their_lan_ip, their_lan_port);
                            }
                            
                            // Also register this as a LAN endpoint candidate
                            handlePeerDiscovered(lan_network_id, source_peer_id);
                        }
                    }

                    // Best-effort: initiate reciprocal connect to help NAT traversal.
                    connectToPeer(source_peer_id, true, "signaling_connect_request");
                }
                return;
            }

            // Handle LAN_IP_UPDATE: Peer is broadcasting their new LAN IP after WiFi handoff
            // Format: "LAN_IP_UPDATE|<lan_ip>|<lan_port>"
            if (payload.rfind("LAN_IP_UPDATE|", 0) == 0) {
                std::string rest = payload.substr(std::strlen("LAN_IP_UPDATE|"));
                // Parse: <lan_ip>|<lan_port>
                auto pipe_pos = rest.find('|');
                if (pipe_pos != std::string::npos) {
                    std::string their_lan_ip = rest.substr(0, pipe_pos);
                    int their_lan_port = 0;
                    try {
                        their_lan_port = std::stoi(rest.substr(pipe_pos + 1));
                    } catch (...) {}
                    
                    if (!their_lan_ip.empty() && their_lan_port > 0) {
                        // Debounce: Only process LAN_IP_UPDATE from each peer once per 5 seconds
                        // This prevents ping-pong loops where both sides keep sending updates
                        bool should_process = false;
                        {
                            std::lock_guard<std::mutex> lock(m_lan_ip_update_mutex);
                            auto now = std::chrono::steady_clock::now();
                            std::string key = "recv_" + source_peer_id;
                            auto it = m_last_lan_ip_update_sent.find(key);
                            if (it == m_last_lan_ip_update_sent.end() ||
                                std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() >= 5) {
                                should_process = true;
                                m_last_lan_ip_update_sent[key] = now;
                            }
                        }
                        
                        if (!should_process) {
                            LOG_DEBUG("SM: Ignoring duplicate LAN_IP_UPDATE from " + source_peer_id + " (debounced)");
                            return;
                        }
                        
                        LOG_INFO("SM: Received LAN_IP_UPDATE from " + source_peer_id + 
                                 " lan=" + their_lan_ip + ":" + std::to_string(their_lan_port));
                        
                        // If we're on WiFi, try to discover/connect via LAN
                        if (m_is_wifi.load(std::memory_order_acquire)) {
                            std::string our_lan_ip;
                            Discovery* discovery = getGlobalDiscoveryInstance();
                            if (discovery) {
                                our_lan_ip = discovery->getLocalLanIP();
                            }
                            
                            if (!our_lan_ip.empty()) {
                                std::string lan_network_id = their_lan_ip + ":" + std::to_string(their_lan_port);
                                LOG_INFO("SM: Peer " + source_peer_id + " now reachable on LAN: " + lan_network_id);
                                
                                // Send direct discovery probe to bypass AP isolation
                                if (discovery) {
                                    discovery->sendDirectProbe(their_lan_ip, their_lan_port);
                                }
                                
                                // Also register this as a LAN endpoint candidate
                                handlePeerDiscovered(lan_network_id, source_peer_id);
                                
                                // Send reciprocal LAN_IP_UPDATE so both sides know each other's LAN IPs
                                // But use debouncing to prevent ping-pong loops (both sides responding forever)
                                // Only send if we haven't sent one to this peer in the last 5 seconds
                                if (m_signaling_client && !our_lan_ip.empty()) {
                                    bool should_send = false;
                                    {
                                        std::lock_guard<std::mutex> lock(m_lan_ip_update_mutex);
                                        auto now = std::chrono::steady_clock::now();
                                        auto it = m_last_lan_ip_update_sent.find(source_peer_id);
                                        if (it == m_last_lan_ip_update_sent.end() ||
                                            std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() >= 5) {
                                            should_send = true;
                                            m_last_lan_ip_update_sent[source_peer_id] = now;
                                        }
                                    }
                                    
                                    if (should_send) {
                                        std::string our_update = "LAN_IP_UPDATE|" + our_lan_ip + "|" + std::to_string(m_listen_port);
                                        try {
                                            m_signaling_client->sendSignal(source_peer_id, our_update);
                                            LOG_INFO("SM: Sent reciprocal LAN_IP_UPDATE to " + source_peer_id + 
                                                     " (LAN=" + our_lan_ip + ":" + std::to_string(m_listen_port) + ")");
                                        } catch (...) {}
                                    } else {
                                        LOG_DEBUG("SM: Skipping reciprocal LAN_IP_UPDATE to " + source_peer_id + " (debounced)");
                                    }
                                }
                                
                                Telemetry::getInstance().inc_counter("lan_ip_update_received_total");
                            }
                        }
                    }
                }
                return;
            }

            // Handle HANDSHAKE_RELAY: Relay handshake messages through signaling for AP isolation scenarios
            // Format: "HANDSHAKE_RELAY|<base64_handshake_payload>"
            // This allows handshakes to complete even when direct UDP is blocked by AP isolation
            if (payload.rfind("HANDSHAKE_RELAY|", 0) == 0) {
                std::string rest = payload.substr(std::strlen("HANDSHAKE_RELAY|"));
                if (!rest.empty()) {
                    LOG_INFO("SM: Received HANDSHAKE_RELAY from " + source_peer_id + 
                             " payload_len=" + std::to_string(rest.length()));
                    
                    // Decode Base64 payload
                    // Simple Base64 decode inline
                    auto base64_decode = [](const std::string& encoded) -> std::string {
                        static const std::string base64_chars =
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                        std::string decoded;
                        std::vector<int> T(256, -1);
                        for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
                        
                        int val = 0, valb = -8;
                        for (unsigned char c : encoded) {
                            if (T[c] == -1) continue;
                            val = (val << 6) + T[c];
                            valb += 6;
                            if (valb >= 0) {
                                decoded.push_back(char((val >> valb) & 0xFF));
                                valb -= 8;
                            }
                        }
                        return decoded;
                    };
                    
                    std::string handshake_payload = base64_decode(rest);
                    if (!handshake_payload.empty()) {
                        LOG_INFO("SM: Processing relayed handshake from " + source_peer_id + 
                                 " decoded_len=" + std::to_string(handshake_payload.size()));
                        
                        // Set pending handshake message and trigger FSM event
                        // Mark as relay reconnect to allow resetting READY sessions
                        uint64_t current_epoch = 0;
                        {
                            std::lock_guard<std::mutex> lock(m_peers_mutex);
                            auto ctx_it = m_peer_contexts.find(source_peer_id);
                            if (ctx_it != m_peer_contexts.end()) {
                                ctx_it->second.pending_handshake_message = handshake_payload;
                                ctx_it->second.is_relay_reconnect = true;  // Allow session reset
                                current_epoch = ctx_it->second.connect_epoch;
                            } else {
                                // Create context if needed
                                auto& ctx = m_peer_contexts[source_peer_id];
                                ctx.pending_handshake_message = handshake_payload;
                                ctx.is_relay_reconnect = true;  // Allow session reset
                            }
                        }
                        
                        pushEvent(FSMEvent{source_peer_id, PeerEvent::HANDSHAKE_MESSAGE_RECEIVED, current_epoch});
                        Telemetry::getInstance().inc_counter("handshake_relay_received_total");
                    }
                }
                return;
            }

            // Other signaling payloads are ignored for now.
            return;
        }
    });
}

void SessionManager::Impl::ensure_signaling_connected_async(bool force) {
    if (!m_signaling_enabled) {
        return;
    }
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }
    if (!m_network_available.load(std::memory_order_acquire) && !force) {
        return;
    }

    // Join any completed reconnect thread to free its handle.
    if (m_signaling_reconnect_thread.joinable() &&
        !m_signaling_reconnect_in_progress.load(std::memory_order_acquire)) {
        m_signaling_reconnect_thread.join();
    }

    bool force_reconnect = force && m_force_signaling_reconnect_requested.load(std::memory_order_acquire);
    if (force_reconnect) {
        const int64_t change_ms = m_last_network_change_ms.load(std::memory_order_acquire);
        const int64_t last_forced_ms = m_last_forced_signaling_reconnect_change_ms.load(std::memory_order_acquire);
        if (change_ms > 0 && last_forced_ms == change_ms) {
            // We already initiated a forced reconnect for this network change; don't churn.
            force_reconnect = false;
        } else if (change_ms > 0) {
            m_last_forced_signaling_reconnect_change_ms.store(change_ms, std::memory_order_release);
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_signaling_lifecycle_mutex);
        if (!force_reconnect && m_signaling_client && m_signaling_client->isConnected()) {
            // We can be TCP-connected but not registered (e.g., server restart, late start, or a
            // previous reconnect swap). In that state we will never receive PEER_LIST/updates.
            const bool registered = m_signaling_registered.load(std::memory_order_acquire);
            const bool want_register = (!registered) &&
                (force ||
                 m_signaling_bootstrap_requested.load(std::memory_order_acquire) ||
                 m_signaling_persistent_after_db_exhausted.load(std::memory_order_acquire));

            // IMPORTANT:
            // On network transitions (especially in single-thread/event-loop mode), the signaling TCP
            // socket can become "stalled" without producing readable EOF/HUP events immediately.
            // In that case `isConnected()` may still be true and `registered` may still be true,
            // but we will never receive peer updates again.
            //
            // When `force==true`, proactively re-register even if we *think* we're registered.
            // This acts as a cheap keepalive and refreshes server-side state. If the socket is
            // actually dead, the send will fail and SignalingClient will mark itself disconnected,
            // allowing the reconnect path to run on the next call.
            const bool force_reregister = force && registered;

            if (want_register || force_reregister) {
                const std::string local_peer_id = m_localPeerId;
                if (!local_peer_id.empty()) {
                    std::string local_network_id;
                    {
                        std::lock_guard<std::mutex> lock2(m_signaling_update_mutex);
                        local_network_id = m_pending_signaling_network_id;
                    }
                    LOG_INFO(std::string("SM: Signaling: sending REGISTER") +
                             (want_register ? " (want_register)" : " (force_reregister)") +
                             (local_network_id.empty() ? "" : (" network_id=" + local_network_id)));
                    if (!local_network_id.empty()) {
                        m_signaling_client->sendRegister(local_peer_id, local_network_id);
                    } else {
                        m_signaling_client->sendRegister(local_peer_id);
                    }
                }
            }
            return;
        }
    }

    if (force_reconnect) {
        const int64_t now_ms = steady_now_ms();
        const int64_t last_change_ms = m_last_network_change_ms.load(std::memory_order_acquire);
        const int64_t age_ms = (last_change_ms > 0) ? (now_ms - last_change_ms) : -1;
        LOG_WARN(std::string("SM: Signaling: forcing full reconnect") +
                 (age_ms >= 0 ? (" (network_change_age_ms=" + std::to_string(age_ms) + ")") : ""));
    }

    const auto now = std::chrono::steady_clock::now();
    // Throttle reconnect attempts to avoid hot loops, but be more aggressive right after
    // a network change. During WiFi<->cell handoffs it's common to see transient ENETUNREACH;
    // we want multiple retries inside the 8s recovery SLA window.
    auto min_gap = std::chrono::milliseconds(
        std::max(250, ConfigManager::getInstance().getSignalingReconnectIntervalMs())
    );
    const int64_t change_ms_for_retry = m_last_network_change_ms.load(std::memory_order_acquire);
    const int64_t age_ms_for_retry = (change_ms_for_retry > 0) ? (steady_now_ms() - change_ms_for_retry) : -1;
    const bool in_post_handoff_grace = (age_ms_for_retry >= 0 && age_ms_for_retry < 15000);
    if (in_post_handoff_grace) {
        // Fast-retry window after a network transition.
        min_gap = std::min(min_gap, std::chrono::milliseconds(1000));
    }
    if (!force && m_last_signaling_reconnect_attempt != std::chrono::steady_clock::time_point{} &&
        (now - m_last_signaling_reconnect_attempt) < min_gap) {
        return;
    }

    bool expected = false;
    if (!m_signaling_reconnect_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }
    m_last_signaling_reconnect_attempt = now;

    const uint64_t attempt_seq = m_signaling_reconnect_seq.fetch_add(1, std::memory_order_acq_rel) + 1;

    const std::string url = m_signaling_url;
    const std::string local_peer_id = m_localPeerId;
    if (url.empty() || local_peer_id.empty()) {
        m_signaling_reconnect_in_progress.store(false, std::memory_order_release);
        return;
    }

    // When reconnecting around a network transition, the first TCP connect often fails transiently
    // with ENETUNREACH while the new interface finishes coming up. Instead of waiting for a later
    // timer tick, retry inside the reconnect thread for a bounded window so REGISTER_ACK recovery
    // is deterministic under the strict 8s SLA.
    //
    // NOTE: The caller may not always pass `force=true` even when a network change has requested
    // a forced reconnect. Use the request flag as an additional signal to enable fast-retry.
    const bool want_fast_retry =
        force ||
        in_post_handoff_grace ||
        m_force_signaling_reconnect_requested.load(std::memory_order_acquire);
    const int64_t fast_retry_deadline_ms = want_fast_retry ? (steady_now_ms() + 8000) : 0;

    // If the previous thread is still joinable, we cannot overwrite it.
    if (m_signaling_reconnect_thread.joinable()) {
        m_signaling_reconnect_in_progress.store(false, std::memory_order_release);
        return;
    }

    m_signaling_reconnect_thread = std::thread([this, url, local_peer_id, attempt_seq, fast_retry_deadline_ms]() {
        struct Guard {
            std::atomic<bool>& flag;
            ~Guard() { flag.store(false, std::memory_order_release); }
        } guard{m_signaling_reconnect_in_progress};

        // Make sure we don't keep trying while tearing down.
        if (m_shutting_down.load(std::memory_order_acquire) || !m_running.load(std::memory_order_acquire)) {
            return;
        }

        try {
            std::unique_ptr<SignalingClient> new_client;
            int new_fd = -1;
            int retry = 0;
            auto backoff = std::chrono::milliseconds(250);

            while (true) {
                // Make sure we don't keep trying while tearing down.
                if (m_shutting_down.load(std::memory_order_acquire) || !m_running.load(std::memory_order_acquire)) {
                    return;
                }

                new_client = std::make_unique<SignalingClient>();
                setup_signaling_callbacks(*new_client);

                LOG_INFO("SM: Signaling reconnect attempt #" + std::to_string(attempt_seq) +
                         (retry > 0 ? (" retry=" + std::to_string(retry)) : std::string("")) +
                         " to: " + url);

                if (is_single_thread_mode()) {
                    new_fd = new_client->connectEventLoop(url);
                    if (new_fd >= 0) {
                        break;
                    }
                    LOG_WARN("SM: Signaling reconnect failed (event-loop mode)");
                } else {
                    if (new_client->connect(url)) {
                        break;
                    }
                    LOG_WARN("SM: Signaling reconnect failed");
                }
                {
                    // Field diagnostics: the signaling server is unreachable.
                    // Rate-limited (same detail folds repeats into suppressed_count).
                    AnomalyReporter::Event ev;
                    ev.type = "runtime_error";
                    ev.severity = "warning";
                    ev.reason = "The engine could not (re)connect to the signaling server; discovery/bootstrap degraded";
                    ev.detail = "Signaling reconnect failed: " + url;
                    ev.extras.emplace_back("subsystem", "signaling");
                    ev.extras.emplace_back("attempt", std::to_string(attempt_seq));
                    AnomalyReporter::getInstance().report(ev);
                }

                // If we're in fast-retry mode, keep trying for a bounded window.
                if (fast_retry_deadline_ms > 0 && steady_now_ms() < fast_retry_deadline_ms) {
                    std::this_thread::sleep_for(backoff);
                    backoff = std::min(backoff * 2, std::chrono::milliseconds(1000));
                    retry++;
                    continue;
                }

                // Give up for now; a later timer tick may try again.
                m_last_forced_signaling_reconnect_change_ms.store(0, std::memory_order_release);
                return;
            }

            // If a network change requested a forced signaling reconnect, treat a successful socket
            // connect as satisfying that request. Waiting for REGISTER_ACK to clear the flag can
            // cause a second forced reconnect (churn) if another forced tick fires while the
            // first REGISTER is still in flight.
            if (m_force_signaling_reconnect_requested.load(std::memory_order_acquire)) {
                const int64_t change_ms = m_last_network_change_ms.load(std::memory_order_acquire);
                if (change_ms > 0) {
                    m_last_forced_signaling_reconnect_change_ms.store(change_ms, std::memory_order_release);
                }
                m_force_signaling_reconnect_requested.store(false, std::memory_order_release);
            }

            // Re-check shutdown after a potentially slow connect.
            if (m_shutting_down.load(std::memory_order_acquire) || !m_running.load(std::memory_order_acquire)) {
                new_client->disconnect();
                return;
            }

            // Swap in the new signaling client (old one will be disconnected best-effort).
            std::unique_ptr<SignalingClient> old;
            int old_fd = -1;
            {
                std::lock_guard<std::mutex> lock(m_signaling_lifecycle_mutex);
                if (m_signaling_client) {
                    old_fd = m_signaling_client->getSocketFd();
                }
                old = std::move(m_signaling_client);
                m_signaling_client = std::move(new_client);
                m_signaling_registered.store(false, std::memory_order_release);
            }

            if (old) {
                // In single-thread mode, unregister before closing the socket.
                if (old_fd >= 0 && m_event_manager) {
                    UnifiedEventLoop* loop = m_event_manager->getUnifiedEventLoop();
                    if (loop) {
                        loop->unregisterFd(old_fd);
                    }
                }
                old->disconnect();
            }

            // In single-thread mode, register the new signaling socket with the event loop.
            if (is_single_thread_mode() && new_fd >= 0 && m_event_manager) {
                UnifiedEventLoop* loop = m_event_manager->getUnifiedEventLoop();
                if (loop) {
                    loop->registerFd(new_fd, UnifiedEventLoop::FdType::TCP_CLIENT, "signaling");
                    LOG_INFO("SM: Registered Signaling fd=" + std::to_string(new_fd) + " with UnifiedEventLoop (best-effort)");
                }
            }

            // Register (include network_id if we already have one).
            std::string local_network_id;
            {
                std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
                local_network_id = m_pending_signaling_network_id;
            }
            if (m_signaling_client) {
                LOG_INFO(std::string("SM: Signaling: sending REGISTER after reconnect #") + std::to_string(attempt_seq) +
                         (local_network_id.empty() ? "" : (" network_id=" + local_network_id)));
                if (!local_network_id.empty()) {
                    m_signaling_client->sendRegister(local_peer_id, local_network_id);
                } else {
                    m_signaling_client->sendRegister(local_peer_id);
                }
            }
        } catch (const std::exception& e) {
            LOG_WARN(std::string("SM: Signaling reconnect exception: ") + e.what());
            return;
        } catch (...) {
            LOG_WARN("SM: Signaling reconnect unknown exception");
            return;
        }
    });
}

void SessionManager::Impl::refresh_external_address_async(bool force) {
    if (m_comms_mode == "TCP") {
        return;
    }
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }
    if (!m_network_available.load(std::memory_order_acquire) && !force) {
        return;
    }

    // Join any completed NAT detection thread to free the thread handle.
    if (m_nat_detect_thread.joinable() && !m_nat_detect_in_progress.load(std::memory_order_acquire)) {
        m_nat_detect_thread.join();
    }

    bool expected = false;
    if (!m_nat_detect_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return; // already running
    }

    // If the previous thread is still joinable, we cannot overwrite it.
    if (m_nat_detect_thread.joinable()) {
        // Another NAT detection is still running; allow it to complete.
        m_nat_detect_in_progress.store(false, std::memory_order_release);
        return;
    }

    const int port = m_listen_port;
    m_nat_detect_thread = std::thread([this, port]() {
        struct Guard {
            std::atomic<bool>& flag;
            ~Guard() { flag.store(false, std::memory_order_release); }
        } guard{m_nat_detect_in_progress};

        if (m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        // Ensure NATTraversal still has a transport manager bound (stop() clears it).
        ensure_nat_connection_manager_registered_();

        NATTraversal& nat = NATTraversal::getInstance();
        nat.initialize(static_cast<uint16_t>(port));
        
        // Retry STUN up to 3 times with increasing delays.
        // During WiFi→mobile data transitions, the new network interface may not be ready
        // immediately, causing "Network is unreachable" or DNS resolution failures.
        NATInfo info;
        constexpr int max_stun_retries = 3;
        constexpr int initial_retry_delay_ms = 1000;  // 1s, 2s, 4s
        
        for (int attempt = 0; attempt < max_stun_retries; ++attempt) {
            if (m_shutting_down.load(std::memory_order_acquire)) {
                return;
            }
            
            if (attempt > 0) {
                // Wait before retry with exponential backoff
                const int delay_ms = initial_retry_delay_ms * (1 << (attempt - 1));
                LOG_INFO("SM: STUN retry attempt " + std::to_string(attempt + 1) + 
                         "/" + std::to_string(max_stun_retries) + " after " + 
                         std::to_string(delay_ms) + "ms delay");
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                
                if (m_shutting_down.load(std::memory_order_acquire)) {
                    return;
                }
            }
            
            info = nat.detectNATType();
            
            // Success - break out of retry loop
            if (!info.external_ip.empty() && info.external_port != 0) {
                break;
            }
            
            LOG_INFO("SM: STUN attempt " + std::to_string(attempt + 1) + 
                     " failed (nat_type=" + std::to_string(static_cast<int>(info.nat_type)) + ")");
        }

        if (m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        if (info.external_ip.empty() || info.external_port == 0) {
            // Don't silently fail: this is the root cause for many "local->4G" failures on
            // IPv6-only carrier networks (IPv4-only transport) or when STUN cannot resolve.
            LOG_INFO("SM: NAT refresh produced no IPv4 external endpoint (nat_type=" +
                     std::to_string(static_cast<int>(info.nat_type)) + ") - not updating signaling network_id");

            // Critical: avoid continuing to advertise a stale network_id after a network change.
            // Stale endpoints can collide with other peers (same public IP:port) and cause
            // reconnect failures or misdirected connect attempts.
            {
                std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
                m_pending_signaling_network_id.clear();
            }
            if (m_signaling_registered.load(std::memory_order_acquire) && m_signaling_client) {
                // Empty string is interpreted by SignalingClient as "clear" (network_id: null).
                m_signaling_client->sendUpdateNetworkId(std::string{});
                LOG_INFO("SM: Cleared signaling network_id (UPDATE null) due to NAT refresh failure");
            }
            return;
        }

        const std::string network_id = info.external_ip + ":" + std::to_string(info.external_port);
        {
            std::lock_guard<std::mutex> lock(m_signaling_update_mutex);
            m_pending_signaling_network_id = network_id;
        }

        if (m_signaling_registered.load(std::memory_order_acquire) && m_signaling_client) {
            m_signaling_client->sendUpdateNetworkId(network_id);
        }
    });
}

void SessionManager::Impl::ensure_nat_connection_manager_registered_() {
    if (m_comms_mode == "TCP") {
        return;
    }
    if (!m_udpConnectionManager) {
        return;
    }
    // Idempotent: NATTraversal swaps callbacks only when the pointer changes.
    NATTraversal::getInstance().setConnectionManager(m_udpConnectionManager.get());
}

void SessionManager::Impl::ensure_nat_punch_observer_registered_() {
    if (m_comms_mode == "TCP") {
        return;
    }
    if (m_nat_punch_observer_id >= 0) {
        return;
    }

    NATTraversal& nat = NATTraversal::getInstance();
    m_nat_punch_observer_id = nat.addPunchResultObserver(
        [this](const std::string& peer_id, bool success) {
            this->handle_nat_punch_result_(peer_id, success);
        }
    );
}

void SessionManager::Impl::unregister_nat_punch_observer_() {
    if (m_nat_punch_observer_id < 0) {
        return;
    }
    NATTraversal::getInstance().removePunchResultObserver(m_nat_punch_observer_id);
    m_nat_punch_observer_id = -1;
}

void SessionManager::Impl::handle_nat_punch_result_(const std::string& peer_id, bool success) {
    if (peer_id.empty()) {
        return;
    }
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }
    if (peer_id == m_localPeerId) {
        return;
    }

    if (success) {
        // NAT hole punch succeeded! The hole is now open.
        // If peer is still CONNECTING and not yet connected, resend CONTROL_CONNECT.
        // The original CONTROL_CONNECT was likely dropped before the hole was punched.
        
        bool should_resend = false;
        std::string network_id;
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            auto ctx_it = m_peer_contexts.find(peer_id);
            if (ctx_it == m_peer_contexts.end()) {
                return;
            }
            const PeerState st = ctx_it->second.state;
            
            auto p_it = m_peers.find(peer_id);
            const bool connected_flag = (p_it != m_peers.end()) ? p_it->second.connected : false;
            
            // Only resend if peer is CONNECTING and not yet marked connected
            if ((st == PeerState::CONNECTING || st == PeerState::DEGRADED) && !connected_flag) {
                should_resend = true;
                if (p_it != m_peers.end()) {
                    network_id = p_it->second.network_id;
                }
            }
        }
        
        if (should_resend && !network_id.empty()) {
            LOG_INFO("SM: NAT hole punch succeeded for " + peer_id + " - resending CONTROL_CONNECT");
            
            std::string payload = m_localPeerId;
#if HAVE_NOISE_PROTOCOL
            if (m_use_noise_protocol && m_noise_key_store) {
                auto pk = m_noise_key_store->get_local_static_public_key();
                std::string pk_hex;
                const char* hex_chars = "0123456789abcdef";
                for (uint8_t b : pk) {
                    pk_hex.push_back(hex_chars[b >> 4]);
                    pk_hex.push_back(hex_chars[b & 0x0F]);
                }
                payload += "|" + pk_hex + "|" + std::to_string(m_local_boot_id);
            }
#endif
            std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, payload);
            send_message_to_peer(network_id, connect_msg);
        }
        return;
    }

    // Handle failure case
    bool should_fail = false;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto ctx_it = m_peer_contexts.find(peer_id);
        if (ctx_it == m_peer_contexts.end()) {
            return;
        }
        const PeerState st = ctx_it->second.state;

        auto p_it = m_peers.find(peer_id);
        const bool connected_flag = (p_it != m_peers.end()) ? p_it->second.connected : false;

        // Only force a failure transition if the peer is still CONNECTING.
        // This avoids races where CONNECT_SUCCESS arrives after a punch failure.
        if (st == PeerState::CONNECTING && !connected_flag) {
            should_fail = true;
        }
    }

    if (should_fail) {
        LOG_WARN("SM: NAT hole punching exhausted retries for CONNECTING peer " + peer_id + "; generating CONNECT_FAILED");
        
        // Get current epoch for this peer
        uint64_t current_epoch = 0;
        {
            std::lock_guard<std::mutex> lock(m_peers_mutex);
            auto ctx_it = m_peer_contexts.find(peer_id);
            if (ctx_it != m_peer_contexts.end()) {
                current_epoch = ctx_it->second.connect_epoch;
            }
        }
        
        // Report failure with reason
        PeerReconnectPolicy& policy = PeerReconnectPolicy::getInstance();
        std::string policy_method = m_comms_mode;
        if (policy_method == "QUIC") policy_method = "UDP";
        policy.on_connection_failure(peer_id, policy_method, 
            ConnectionFailureReason::NAT_TRAVERSAL_FAIL, 0.0f);
        
        pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_FAILED, current_epoch});
    }
}

void SessionManager::Impl::handlePeerDiscovered(const std::string& network_id, const std::string& peer_id) {
    // Shutdown guard
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    pushEvent(PeerDiscoveredEvent{peer_id, network_id});
}

void SessionManager::Impl::onData(const std::string& network_id, const std::string& data) {
    // Shutdown guard
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    
    LOG_INFO("SM: onData called with network_id=" + network_id + ", data length=" + std::to_string(data.length()));
    
    NATIVELOGW("SM_NATIVE: Checking if CONNECT_ACK");
    // Handle connection acknowledgement from TCP connection manager
    if (data == "CONNECT_ACK") {
        NATIVELOGW("SM_NATIVE: It IS CONNECT_ACK");
        LOG_INFO("SM: Received CONNECT_ACK for network_id=" + network_id);
        
        std::string peer_id;
        bool create_ephemeral_mapping = false;
        std::string mapping_advertised_network_id;
        
        {
            // Lock order enforced: peers -> network index
            PeersThenNetworkIndexLock guard(*this);
            Peer* peer = find_peer_by_network_id_locked_(network_id);

            // If not found by full network_id, try to match by IP address only.
            // This handles incoming connections which use ephemeral ports.
            // BUT: Only do this if we have a clear match (exactly 1 peer with that IP).
            if (!peer) {
                // Extract IP from network_id (format: "IP:PORT")
                size_t colon_pos = network_id.find(':');
                if (colon_pos != std::string::npos) {
                    std::string incoming_ip = network_id.substr(0, colon_pos);
                    LOG_INFO("SM: CONNECT_ACK: Peer not found by full network_id, checking for IP match: " + incoming_ip);

                    Peer* ip_match = nullptr;
                    int match_count = 0;
                    for (auto& kv : m_peers) {
                        Peer& candidate = kv.second;
                        size_t peer_colon_pos = candidate.network_id.find(':');
                        if (peer_colon_pos != std::string::npos) {
                            std::string peer_ip = candidate.network_id.substr(0, peer_colon_pos);
                            if (peer_ip == incoming_ip) {
                                ip_match = &candidate;
                                match_count++;
                            }
                        }
                    }

                    if (match_count == 1 && ip_match) {
                        peer = ip_match;
                        LOG_INFO("SM: CONNECT_ACK: Matched peer by IP (unique): " + peer->id + " (incoming: " + network_id + ", stored: " + peer->network_id + ")");
                        create_ephemeral_mapping = true;
                        mapping_advertised_network_id = peer->network_id;
                    } else if (match_count > 1) {
                        LOG_WARN("SM: CONNECT_ACK: Ambiguous IP match (found " + std::to_string(match_count) + " peers with IP " + incoming_ip + "). Cannot identify peer. Waiting for CONTROL_CONNECT.");
                    }
                }
            }

            if (peer) {
                peer_id = peer->id;
                peer->last_seen = std::chrono::steady_clock::now();
                if (create_ephemeral_mapping && !mapping_advertised_network_id.empty()) {
                    upsert_ephemeral_mapping_locked_(network_id, mapping_advertised_network_id);
                    LOG_INFO("SM: CONNECT_ACK: Created ephemeral port mapping: " + network_id + " -> " + mapping_advertised_network_id);
                }
            } else {
                LOG_WARN("SM: Received CONNECT_ACK for unknown network_id: " + network_id + ". Searching all peers:");
                for (const auto& kv : m_peers) {
                    LOG_WARN("  - Peer: " + kv.second.id + ", stored_network_id: " + kv.second.network_id);
                }
            }
        } // locks released

        if (!peer_id.empty()) {
            LOG_INFO("SM: Received CONNECT_ACK from peer: " + peer_id);
            
            // First, send CONNECT_REQUESTED to transition from DISCOVERED to CONNECTING
            pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_REQUESTED});
            // Then send CONNECT_SUCCESS to transition from CONNECTING to CONNECTED
            pushEvent(FSMEvent{peer_id, PeerEvent::CONNECT_SUCCESS});
            
            LOG_INFO("SM: Queued FSM events for peer: " + peer_id + " (CONNECT_REQUESTED -> CONNECT_SUCCESS)");

#if HAVE_NOISE_PROTOCOL
            if (m_use_noise_protocol && m_noise_key_store) {
                LOG_INFO("SM: Getting local public key...");
                auto pk = m_noise_key_store->get_local_static_public_key();
                LOG_INFO("SM: Got local public key");
                std::string pk_hex;
                const char* hex_chars = "0123456789abcdef";
                for (uint8_t b : pk) {
                    pk_hex.push_back(hex_chars[b >> 4]);
                    pk_hex.push_back(hex_chars[b & 0x0F]);
                }
                
                std::string payload = m_localPeerId + "|" + pk_hex + "|" + std::to_string(m_local_boot_id);
                std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, payload);
                send_message_to_peer(network_id, connect_msg);
                LOG_INFO("SM: Sent CONTROL_CONNECT with public key to " + peer_id);
            } else {
                std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, m_localPeerId);
                send_message_to_peer(network_id, connect_msg);
                LOG_INFO("SM: Sent CONTROL_CONNECT to " + peer_id);
            }
#else
            std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, m_localPeerId);
            send_message_to_peer(network_id, connect_msg);
            LOG_INFO("SM: Sent CONTROL_CONNECT to " + peer_id);
#endif
        }
        return;  // Don't treat CONNECT_ACK as data
    }
    
    NATIVELOGW("SM_NATIVE: Not CONNECT_ACK, pushing event");
    // LOG_INFO("SM: Pushing DataReceivedEvent for network_id=" + network_id + ", data length=" + std::to_string(data.length()));
    
    // Update last_seen for general data
    // Note: If both the peer store and the network index are needed, follow the
    // documented lock order (m_peers_mutex -> m_network_index_mutex). Avoid
    // holding m_network_index_mutex while acquiring m_peers_mutex.
    std::string peer_id;
    {
        NATIVELOGW("SM_NATIVE: onData - acquiring network_index_mutex");
        std::lock_guard<std::mutex> lock(m_network_index_mutex);
        NATIVELOGW("SM_NATIVE: onData - network_index_mutex acquired");
        auto it = m_network_id_to_peer_id.find(network_id);
        if (it != m_network_id_to_peer_id.end()) {
            peer_id = it->second;
        } else {
            // Check ephemeral port mapping
            auto eph_it = m_ephemeral_to_advertised_port_map.find(network_id);
            if (eph_it != m_ephemeral_to_advertised_port_map.end()) {
                auto mapped_it = m_network_id_to_peer_id.find(eph_it->second);
                if (mapped_it != m_network_id_to_peer_id.end()) {
                    peer_id = mapped_it->second;
                }
            }
        }
        NATIVELOGW("SM_NATIVE: onData - releasing network_index_mutex");
    }
    
    if (!peer_id.empty()) {
        NATIVELOGW("SM_NATIVE: onData - acquiring peers_mutex for last_seen update");
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        NATIVELOGW("SM_NATIVE: onData - peers_mutex acquired");
        auto it = m_peers.find(peer_id);
        if (it != m_peers.end()) {
            it->second.last_seen = std::chrono::steady_clock::now();
        }
        NATIVELOGW("SM_NATIVE: onData - releasing peers_mutex");
    }
    
    pushEvent(DataReceivedEvent{network_id, data, std::chrono::steady_clock::now()});
}

void SessionManager::Impl::onDisconnect(const std::string& network_id) {
    // Shutdown guard
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }
    pushEvent(PeerDisconnectEvent{network_id});
}

void SessionManager::Impl::pushEvent(SessionEvent event) {
    // Don't add new events when stopping - LOG this to help diagnose event loss
    if (m_shutting_down.load(std::memory_order_acquire)) {
        // Extract event type for logging
        std::string eventType = "Unknown";
        std::visit([&eventType](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, FSMEvent>) {
                eventType = "FSMEvent";
            } else if constexpr (std::is_same_v<T, TimerTickEvent>) {
                eventType = "TimerTickEvent";
            } else {
                eventType = "OtherEvent";
            }
        }, event);
        LOG_WARN("SM: DROPPING event (" + eventType + ") - shutting down");
        return;
    }

    // v0.4 backpressure: track in-flight plain-send events so the C ABI can
    // return LITEP2P_ERR_QUEUE_FULL and expose litep2p_pending_send_count().
    // Counted here (covers every push path) and decremented when the event
    // handler dispatches the SendMessageEvent to the transport.
    const bool is_send_event = std::holds_alternative<SendMessageEvent>(event);
    if (is_send_event) {
        m_pending_sends.fetch_add(1, std::memory_order_relaxed);
    }

    if (m_event_manager) {
        m_event_manager->pushEvent(std::move(event));
    } else {
        // WARN: Using legacy queue - events may not be processed!
        LOG_WARN("SM: Using legacy queue (m_event_manager is null) - this may cause event loss!");
        std::lock_guard<std::mutex> lock(m_eventMutex);
        m_eventQueue.push(std::move(event));
        m_eventCv.notify_one();
    }
}

int SessionManager::Impl::pending_send_count() const {
    const int n = m_pending_sends.load(std::memory_order_relaxed);
    return n > 0 ? n : 0;
}

void SessionManager::Impl::note_outbound(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    m_last_outbound_ts[peer_id] = std::chrono::steady_clock::now();
}

bool SessionManager::Impl::recently_sent_to(const std::string& peer_id,
                                            std::chrono::milliseconds window) const {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    auto it = m_last_outbound_ts.find(peer_id);
    if (it == m_last_outbound_ts.end()) return false;
    return std::chrono::steady_clock::now() - it->second < window;
}

bool SessionManager::Impl::isPeerConnected(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    const Peer* peer = find_peer_by_id(peer_id);
    return peer && peer->connected;
}

std::string SessionManager::Impl::getPeerFsmState(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    auto it = m_peer_contexts.find(peer_id);
    if (it == m_peer_contexts.end()) {
        return "UNKNOWN";
    }
    return state_to_string(it->second.state);
}

std::string SessionManager::Impl::getPeerConnectionType(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    const Peer* peer = find_peer_by_id(peer_id);
    if (!peer || !peer->connected) {
        return "UNKNOWN";
    }
    
    // First, check if we have explicitly tracked the connection path
    if (peer->active_connection_path != ConnectionPath::UNKNOWN) {
        return connectionPathToString(peer->active_connection_path);
    }
    
    // Fallback: Infer connection type from the endpoint being used
    const std::string& current_network_id = peer->network_id;
    if (current_network_id.empty()) {
        return "UNKNOWN";
    }
    
    // Parse the current ip:port
    size_t colon_pos = current_network_id.rfind(':');
    if (colon_pos == std::string::npos) {
        return "UNKNOWN";
    }
    std::string current_ip = current_network_id.substr(0, colon_pos);
    
    // Find the matching endpoint candidate to determine the type
    for (const auto& candidate : peer->endpoint_candidates) {
        if (candidate.ip == current_ip) {
            switch (candidate.type) {
                case EndpointType::LAN:   return "LAN";
                case EndpointType::WAN:   return "WAN_DIRECT";  // Assume direct if WAN candidate matched
                case EndpointType::RELAY: return "TURN";
            }
        }
    }
    
    // Fallback: Detect LAN based on private IP pattern
    if (current_ip.rfind("10.", 0) == 0 ||
        current_ip.rfind("192.168.", 0) == 0 ||
        current_ip.rfind("127.", 0) == 0 ||
        current_ip.rfind("169.254.", 0) == 0) {
        return "LAN";
    }
    // Check 172.16.0.0 - 172.31.255.255 range
    if (current_ip.rfind("172.", 0) == 0 && current_ip.size() > 4) {
        size_t dot_pos = current_ip.find('.', 4);
        if (dot_pos != std::string::npos) {
            int second_octet = std::stoi(current_ip.substr(4, dot_pos - 4));
            if (second_octet >= 16 && second_octet <= 31) {
                return "LAN";
            }
        }
    }
    
    // Public IP - assume direct hole punch since we reached here without relay candidate
    return "WAN_DIRECT";
}

void SessionManager::Impl::send_message_to_peer(const std::string& network_id, const std::string& message) {
    // Check if we have an ephemeral port mapping for this network_id
    // If the message is to an advertised port but the connection is on ephemeral, we need to send to ephemeral
    std::string actual_network_id = network_id;
    
    {
        std::lock_guard<std::mutex> lock(m_network_index_mutex);
        // Debug: Log the ephemeral mapping table
        LOG_INFO("SM: send_message_to_peer: Looking for ephemeral mapping for network_id=" + network_id + ", map_size=" + std::to_string(m_ephemeral_to_advertised_port_map.size()));
        for (const auto& m : m_ephemeral_to_advertised_port_map) {
            LOG_INFO("SM: Ephemeral map entry: " + m.first + " -> " + m.second);
        }
        // Check if we have any ephemeral ports mapping TO this network_id
        // This means the peer connected to us on an ephemeral port, and we stored it mapping to our advertised port
        for (const auto& mapping : m_ephemeral_to_advertised_port_map) {
            if (mapping.second == network_id) {
                // Found: ephemeral port maps to this advertised port
                // Use the ephemeral port for sending
                actual_network_id = mapping.first;
                LOG_INFO("SM: *** TRANSLATING *** advertised " + network_id + " -> ephemeral " + actual_network_id);
                break;
            }
        }
        if (actual_network_id == network_id) {
            LOG_INFO("SM: No ephemeral translation found, sending directly to " + network_id);
        }
    }
    
    // Choose the outbound transport. Homogeneous mode always uses the single
    // configured protocol. Heterogeneous mode replies on the same transport the
    // peer used to reach us (Peer::transport), falling back to UDP for peers we
    // have not heard from (e.g., an outbound connect to a just-discovered peer).
    // The peers lookup acquires m_peers_mutex separately (not nested with
    // m_network_index_mutex above) to preserve lock ordering.
    std::string transport = (m_comms_mode == "TCP") ? "TCP" : "UDP";
    if (m_comms_heterogeneous) {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        Peer* peer = find_peer_by_network_id_locked_(network_id);
        if (peer && (peer->transport == "TCP" || peer->transport == "UDP")) {
            transport = peer->transport;
        }
    }

    if (transport == "TCP") {
        m_tcpConnectionManager->sendMessageToPeer(actual_network_id, message);
    } else {
        m_udpConnectionManager->sendMessageToPeer(actual_network_id, message);
    }
}

// Implements the mode helpers declared in session_manager_p.h.
void SessionManager::Impl::note_inbound_transport(const std::string& network_id, const std::string& transport) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    Peer* peer = find_peer_by_network_id_locked_(network_id);
    if (!peer) {
        // Fallback: incoming connections may arrive on an ephemeral port, so match
        // by IP when the full network_id is not yet indexed.
        size_t colon = network_id.find(':');
        if (colon != std::string::npos) {
            const std::string ip = network_id.substr(0, colon);
            for (auto& kv : m_peers) {
                const std::string id_net = kv.second.network_id;
                const std::string id_adv = kv.second.advertised_network_id;
                if (id_net.rfind(ip + ":", 0) == 0 || id_adv.rfind(ip + ":", 0) == 0) {
                    peer = &kv.second;
                    break;
                }
            }
        }
    }
    if (peer) {
        peer->transport = transport;
    }
}

std::string SessionManager::Impl::outbound_transport_for_peer(const std::string& peer_id) const {
    if (!m_comms_heterogeneous) {
        return (m_comms_mode == "TCP") ? "TCP" : "UDP";
    }
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    auto it = m_peers.find(peer_id);
    if (it != m_peers.end()) {
        const std::string& t = it->second.transport;
        if (t == "TCP" || t == "UDP" || t == "QUIC") {
            return t;
        }
    }
    return "UDP";
}

Peer* SessionManager::Impl::find_peer_by_id(const std::string& peer_id) {
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? &it->second : nullptr;
}

const Peer* SessionManager::Impl::find_peer_by_id(const std::string& peer_id) const {
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? &it->second : nullptr;
}

std::string SessionManager::Impl::peer_id_by_network_id_locked_(const std::string& network_id) const {
    auto it = m_network_id_to_peer_id.find(network_id);
    if (it != m_network_id_to_peer_id.end()) {
        return it->second;
    }

    // Check ephemeral port mapping if direct lookup failed
    auto eph_it = m_ephemeral_to_advertised_port_map.find(network_id);
    if (eph_it != m_ephemeral_to_advertised_port_map.end()) {
        auto mapped_it = m_network_id_to_peer_id.find(eph_it->second);
        if (mapped_it != m_network_id_to_peer_id.end()) {
            LOG_DEBUG("SM: Found peer via ephemeral port mapping: " + network_id + " -> " + eph_it->second);
            return mapped_it->second;
        }
    }

    return {};
}

Peer* SessionManager::Impl::find_peer_by_network_id_locked_(const std::string& network_id) {
    const std::string peer_id = peer_id_by_network_id_locked_(network_id);
    if (peer_id.empty()) {
        return nullptr;
    }
    return find_peer_by_id(peer_id);
}

const Peer* SessionManager::Impl::find_peer_by_network_id_locked_(const std::string& network_id) const {
    const std::string peer_id = peer_id_by_network_id_locked_(network_id);
    if (peer_id.empty()) {
        return nullptr;
    }
    return find_peer_by_id(peer_id);
}

void SessionManager::Impl::add_peer_to_network_index(const std::string& peer_id, const std::string& network_id) {
    if (network_id.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    add_peer_to_network_index_locked_(peer_id, network_id);
}

void SessionManager::Impl::remove_peer_from_network_index(const std::string& network_id) {
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    remove_peer_from_network_index_locked_(network_id);
}

void SessionManager::Impl::add_peer_to_network_index_locked_(const std::string& peer_id, const std::string& network_id) {
    if (network_id.empty()) {
        return;
    }

    auto it = m_network_id_to_peer_id.find(network_id);
    if (it != m_network_id_to_peer_id.end() && it->second != peer_id) {
        // Network endpoints are not guaranteed to be globally unique:
        // - A peer may advertise a stale/incorrect WAN port (e.g., local listen port)
        // - Routers with UPnP/NAT-PMP can briefly re-map a public port, causing temporary duplication
        // Overwriting here can break existing live sessions by misattributing inbound packets.
        LOG_WARN("SM: Network_id collision for " + network_id + " (existing_peer=" + it->second + ", new_peer=" + peer_id + ") - keeping existing mapping");
        return;
    }
    m_network_id_to_peer_id[network_id] = peer_id;
}

void SessionManager::Impl::remove_peer_from_network_index_locked_(const std::string& network_id) {
    m_network_id_to_peer_id.erase(network_id);
}

void SessionManager::Impl::prune_ephemeral_mappings_for_advertised_locked_(const std::string& advertised_network_id) {
    if (advertised_network_id.empty()) {
        return;
    }
    for (auto it = m_ephemeral_to_advertised_port_map.begin(); it != m_ephemeral_to_advertised_port_map.end();) {
        if (it->second == advertised_network_id) {
            it = m_ephemeral_to_advertised_port_map.erase(it);
        } else {
            ++it;
        }
    }
}

void SessionManager::Impl::upsert_ephemeral_mapping_locked_(const std::string& ephemeral_network_id,
                                                           const std::string& advertised_network_id) {
    if (ephemeral_network_id.empty() || advertised_network_id.empty()) {
        LOG_WARN("SM: upsert_ephemeral_mapping: empty input - ephemeral=" + ephemeral_network_id + ", advertised=" + advertised_network_id);
        return;
    }
    LOG_INFO("SM: *** CREATING EPHEMERAL MAPPING *** " + ephemeral_network_id + " -> " + advertised_network_id);
    // Keep only the newest ephemeral mapping for this advertised network_id.
    prune_ephemeral_mappings_for_advertised_locked_(advertised_network_id);
    m_ephemeral_to_advertised_port_map[ephemeral_network_id] = advertised_network_id;
    LOG_INFO("SM: Ephemeral map now has " + std::to_string(m_ephemeral_to_advertised_port_map.size()) + " entries");
}

void SessionManager::Impl::handlePeerLeftFromSignaling(const std::string& peer_id) {
    if (peer_id.empty()) {
        return;
    }

    LOG_INFO("SM: Signaling indicates peer left: " + peer_id);

    std::string old_network_id;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        Peer* peer = find_peer_by_id(peer_id);
        if (peer) {
            old_network_id = peer->network_id;
            peer->connected = false;
            peer->last_seen = std::chrono::steady_clock::now();
            // Drop the endpoint so we don't keep trying to connect to a stale WAN address.
            peer->network_id.clear();
            peer->advertised_network_id.clear();
            peer->ip.clear();
            peer->port = -1;
        }
    }

    if (!old_network_id.empty()) {
        remove_peer_from_network_index(old_network_id);

        // Clear ephemeral->advertised mappings that referenced this peer's old advertised endpoint.
        {
            std::lock_guard<std::mutex> index_lock(m_network_index_mutex);
            for (auto it = m_ephemeral_to_advertised_port_map.begin(); it != m_ephemeral_to_advertised_port_map.end();) {
                if (it->second == old_network_id) {
                    it = m_ephemeral_to_advertised_port_map.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    // Stop any ongoing NAT traversal work for this peer (common after abrupt app kills).
    NATTraversal::getInstance().unregisterPeer(peer_id);

    // Get current epoch for this peer
    uint64_t current_epoch = 0;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto ctx_it = m_peer_contexts.find(peer_id);
        if (ctx_it != m_peer_contexts.end()) {
            current_epoch = ctx_it->second.connect_epoch;
        }
    }

    // Drive FSM cleanup for Noise/session state. (If the peer/context doesn't exist, this is a no-op.)
    pushEvent(FSMEvent{peer_id, PeerEvent::DISCONNECT_DETECTED, current_epoch});

    notifyPeerUpdate();
}

void SessionManager::Impl::remove_peer_by_id(const std::string& peer_id) {
    std::string network_id_to_remove;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        const Peer* peer = find_peer_by_id(peer_id);
        if (!peer) {
            return;
        }
        network_id_to_remove = peer->network_id;
        m_peers.erase(peer_id);
        m_peer_contexts.erase(peer_id);
    }

    // Remove *all* network index entries that reference this peer_id.
    // This guards against stale mappings when a peer's network_id was cleared/changed
    // before removal (e.g., after PEER_LEFT or ephemeral port mapping updates).
    {
        std::lock_guard<std::mutex> index_lock(m_network_index_mutex);
        for (auto it = m_network_id_to_peer_id.begin(); it != m_network_id_to_peer_id.end();) {
            if (it->second == peer_id) {
                it = m_network_id_to_peer_id.erase(it);
            } else {
                ++it;
            }
        }
        if (!network_id_to_remove.empty()) {
            m_network_id_to_peer_id.erase(network_id_to_remove);
        }
    }
}

std::mutex& SessionManager::Impl::get_peer_mutex(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_peer_mutexes_mutex);
    if (m_peer_mutexes.find(peer_id) == m_peer_mutexes.end()) {
        m_peer_mutexes[peer_id] = std::make_unique<std::mutex>();
    }
    return *m_peer_mutexes[peer_id];
}

// ============================================================================
// Noise Protocol Implementation
// ============================================================================

void SessionManager::enable_noise_nk() {
    m_impl->enable_noise_nk();
}

bool SessionManager::is_noise_nk_enabled() const {
    return m_impl->is_noise_nk_enabled();
}

std::vector<uint8_t> SessionManager::get_local_static_public_key() const {
#if HAVE_NOISE_PROTOCOL
    if (auto store = m_impl->get_noise_key_store()) {
        return store->get_local_static_public_key();
    }
#endif
    return {};
}

void SessionManager::register_peer_nk_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk) {
#if HAVE_NOISE_PROTOCOL
    if (auto store = m_impl->get_noise_key_store()) {
        store->register_peer_key(peer_id, static_pk);
    }
    if (auto manager = m_impl->get_noise_nk_manager()) {
        manager->register_peer_key(peer_id, static_pk);
    }
#endif
}

bool SessionManager::has_peer_nk_key(const std::string& peer_id) const {
#if HAVE_NOISE_PROTOCOL
    if (auto store = m_impl->get_noise_key_store()) {
        return !store->get_peer_key(peer_id).empty();
    }
#endif
    return false;
}

int SessionManager::get_nk_peer_count() const {
#if HAVE_NOISE_PROTOCOL
    if (auto store = m_impl->get_noise_key_store()) {
        return store->get_peer_count();
    }
#endif
    return 0;
}

std::vector<std::string> SessionManager::get_nk_peer_ids() const {
#if HAVE_NOISE_PROTOCOL
    if (auto store = m_impl->get_noise_key_store()) {
        return store->get_all_peer_ids();
    }
#endif
    return {};
}

bool SessionManager::import_nk_peer_keys_hex(const std::map<std::string, std::string>& hex_keys) {
#if HAVE_NOISE_PROTOCOL
    if (auto store = m_impl->get_noise_key_store()) {
        return store->import_peer_keys_hex(hex_keys);
    }
#endif
    return false;
}

std::map<std::string, std::string> SessionManager::export_nk_peer_keys_hex() const {
#if HAVE_NOISE_PROTOCOL
    if (auto store = m_impl->get_noise_key_store()) {
        return store->export_peer_keys_hex();
    }
#endif
    return {};
}

// Impl methods

void SessionManager::Impl::enable_noise_nk() {
#if HAVE_NOISE_PROTOCOL
    m_noise_nk_enabled = true;
    m_use_noise_protocol = true;
#endif
}

bool SessionManager::Impl::is_noise_nk_enabled() const {
#if HAVE_NOISE_PROTOCOL
    return m_noise_nk_enabled;
#else
    return false;
#endif
}

#if HAVE_NOISE_PROTOCOL
NoiseNKManager* SessionManager::Impl::get_noise_nk_manager() {
    return m_noise_nk_manager.get();
}

NoiseKeyStore* SessionManager::Impl::get_noise_key_store() {
    return m_noise_key_store.get();
}
#endif

BatteryOptimizer* SessionManager::Impl::get_battery_optimizer() {
    return m_battery_optimizer.get();
}

SessionCache* SessionManager::Impl::get_session_cache() {
    return m_session_cache.get();
}

MessageBatcher* SessionManager::Impl::get_message_batcher() {
    return m_message_batcher.get();
}

PeerIndex* SessionManager::Impl::get_peer_index() {
    return m_peer_index.get();
}

FileTransferManager* SessionManager::Impl::get_file_transfer_manager() {
    return m_file_transfer_manager.get();
}

// ============================================================================
// File transfer (offer/accept model) — public wrappers + Impl adapters
// ============================================================================

std::string SessionManager::send_file(const std::string& peer_id, const std::string& file_path,
                                      int priority) {
    return m_impl->send_file(peer_id, file_path, priority);
}

bool SessionManager::accept_file_transfer(const std::string& transfer_id,
                                          const std::string& save_path) {
    return m_impl->accept_file_transfer(transfer_id, save_path);
}

bool SessionManager::decline_file_transfer(const std::string& transfer_id) {
    return m_impl->decline_file_transfer(transfer_id);
}

bool SessionManager::pause_transfer(const std::string& transfer_id) {
    return m_impl->pause_transfer(transfer_id);
}

bool SessionManager::resume_transfer(const std::string& transfer_id) {
    return m_impl->resume_transfer(transfer_id);
}

bool SessionManager::cancel_transfer(const std::string& transfer_id) {
    return m_impl->cancel_transfer(transfer_id);
}

float SessionManager::get_transfer_progress(const std::string& transfer_id) const {
    return m_impl->get_transfer_progress(transfer_id);
}

float SessionManager::get_transfer_speed(const std::string& transfer_id) const {
    return m_impl->get_transfer_speed(transfer_id);
}

std::vector<std::string> SessionManager::get_active_transfers() const {
    return m_impl->get_active_transfers();
}

void SessionManager::set_file_transfer_callbacks(FileTransferOfferCallback on_offer,
                                                 FileTransferProgressCallback on_progress,
                                                 FileTransferCompleteCallback on_complete) {
    m_impl->set_file_transfer_callbacks(std::move(on_offer), std::move(on_progress),
                                        std::move(on_complete));
}

// ---------------- Impl adapters ----------------

void SessionManager::Impl::set_file_transfer_callbacks(
    SessionManager::FileTransferOfferCallback on_offer,
    SessionManager::FileTransferProgressCallback on_progress,
    SessionManager::FileTransferCompleteCallback on_complete) {
    {
        std::lock_guard<std::mutex> lock(m_file_transfer_cb_mutex);
        m_ft_offer_cb = std::move(on_offer);
        m_ft_progress_cb = std::move(on_progress);
        m_ft_complete_cb = std::move(on_complete);
    }
    // Re-apply forwarding onto the (possibly re-created) FileTransferManager.
    wire_file_transfer_manager();
}

void SessionManager::Impl::wire_file_transfer_manager() {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return;

    // Outbound FILE_TRANSFER payloads -> session send path. Wrapping with the
    // wire codec here means chunks/offers/acks travel as MessageType::FILE_TRANSFER
    // frames (bypassing batching) and get Noise encryption when enabled.
    ft->set_outbound_message_callback([this](const std::string& peer_id, const std::string& payload) {
        const std::string frame = wire::encode_message(MessageType::FILE_TRANSFER, payload);
        this->sendMessageToPeer(peer_id, frame);
    });

    // Forward offer/progress/complete events to the registered callbacks.
    ft->on_transfer_offered([this](const IncomingFileOffer& offer) {
        SessionManager::FileTransferOfferCallback cb;
        {
            std::lock_guard<std::mutex> lock(m_file_transfer_cb_mutex);
            cb = m_ft_offer_cb;
        }
        if (cb) cb(offer.transfer_id, offer.peer_id, offer.file_name, offer.file_size);
    });

    ft->on_transfer_progress([this](const std::string& transfer_id, float progress, float speed_kbps) {
        SessionManager::FileTransferProgressCallback cb;
        {
            std::lock_guard<std::mutex> lock(m_file_transfer_cb_mutex);
            cb = m_ft_progress_cb;
        }
        // Convert Kbps -> bytes/sec for the public API.
        if (cb) cb(transfer_id, progress, speed_kbps * 125.0f);
    });

    ft->on_transfer_complete([this](const std::string& transfer_id, bool success, const std::string& error) {
        SessionManager::FileTransferCompleteCallback cb;
        {
            std::lock_guard<std::mutex> lock(m_file_transfer_cb_mutex);
            cb = m_ft_complete_cb;
        }
        if (cb) cb(transfer_id, success, error);
    });
}

std::string SessionManager::Impl::send_file(const std::string& peer_id,
                                            const std::string& file_path, int priority) {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) {
        LOG_WARN("SM: send_file - file transfer manager unavailable");
        return "";
    }
    if (!isPeerConnected(peer_id)) {
        LOG_WARN("SM: send_file - peer not connected: " + peer_id);
        return "";
    }
    TransferPriority tp = TransferPriority::NORMAL;
    if (priority <= 0) tp = TransferPriority::LOW;
    else if (priority >= 2) tp = TransferPriority::HIGH;
    return ft->offer_file(file_path, peer_id, tp);
}

bool SessionManager::Impl::accept_file_transfer(const std::string& transfer_id,
                                                const std::string& save_path) {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return false;
    return ft->accept_incoming_offer(transfer_id, save_path);
}

bool SessionManager::Impl::decline_file_transfer(const std::string& transfer_id) {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return false;
    return ft->decline_incoming_offer(transfer_id);
}

bool SessionManager::Impl::pause_transfer(const std::string& transfer_id) {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return false;
    return ft->pause_transfer(transfer_id);
}

bool SessionManager::Impl::resume_transfer(const std::string& transfer_id) {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return false;
    return ft->resume_transfer(transfer_id);
}

bool SessionManager::Impl::cancel_transfer(const std::string& transfer_id) {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return false;
    return ft->cancel_transfer(transfer_id);
}

float SessionManager::Impl::get_transfer_progress(const std::string& transfer_id) const {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return -1.0f;
    return ft->get_transfer_progress(transfer_id);
}

float SessionManager::Impl::get_transfer_speed(const std::string& transfer_id) const {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return 0.0f;
    // FileTransferManager reports Kbps; convert to bytes/sec.
    return ft->get_transfer_speed(transfer_id) * 125.0f;
}

std::vector<std::string> SessionManager::Impl::get_active_transfers() const {
    FileTransferManager* ft = m_file_transfer_manager.get();
    if (!ft) return {};
    return ft->get_active_transfers();
}

// PRODUCTION-READY: IP change detection and monitoring
void SessionManager::Impl::start_ip_monitor() {
    if (m_ip_monitor_running.load(std::memory_order_acquire)) {
        return;  // Already running
    }
    
    // Get initial IP (IPv6-preferred when the host has IPv6 connectivity).
    m_last_known_primary_ip = get_primary_ip_address();
    LOG_INFO("SM: IP monitor started, initial IP: " + (m_last_known_primary_ip.empty() ? "<none>" : m_last_known_primary_ip));
    
    m_ip_monitor_running.store(true, std::memory_order_release);
    m_ip_monitor_thread = std::thread(&SessionManager::Impl::ip_monitor_loop, this);
}

void SessionManager::Impl::stop_ip_monitor() {
    if (!m_ip_monitor_running.load(std::memory_order_acquire)) {
        return;  // Not running
    }
    
    m_ip_monitor_running.store(false, std::memory_order_release);
    m_ip_monitor_wait_cv.notify_all();
    if (m_ip_monitor_thread.joinable()) {
        m_ip_monitor_thread.join();
    }
    LOG_INFO("SM: IP monitor stopped");
}

void SessionManager::Impl::ip_monitor_loop() {
    // Monitor IP changes every 5 seconds
    constexpr int check_interval_sec = 5;
    
    while (m_ip_monitor_running.load(std::memory_order_acquire) && 
           !m_shutting_down.load(std::memory_order_acquire)) {
        {
            std::unique_lock<std::mutex> lock(m_ip_monitor_wait_mutex);
            if (m_ip_monitor_wait_cv.wait_for(lock, std::chrono::seconds(check_interval_sec), [this] {
                    return !m_ip_monitor_running.load(std::memory_order_acquire) ||
                           m_shutting_down.load(std::memory_order_acquire);
                })) {
                break;
            }
        }
        
        if (m_shutting_down.load(std::memory_order_acquire)) {
            break;
        }
        
        std::string current_ip = get_primary_ip_address();
        
        // Check if IP changed
        if (!current_ip.empty() && current_ip != m_last_known_primary_ip && !m_last_known_primary_ip.empty()) {
            LOG_INFO("SM: IP address changed detected: " + m_last_known_primary_ip + " -> " + current_ip);
            m_last_known_primary_ip = current_ip;
            
            // Trigger network change handling (treat as network type change to refresh everything)
            // This will trigger NAT refresh, signaling refresh, and immediate reconnect
            bool was_wifi = m_is_wifi.load(std::memory_order_acquire);
            bool was_available = m_network_available.load(std::memory_order_acquire);
            
            // IP change on same interface - treat as network change
            set_network_info(was_wifi, was_available);
            
            Telemetry::getInstance().inc_counter("ip_change_detected_total");
        } else if (current_ip.empty() && !m_last_known_primary_ip.empty()) {
            // IP disappeared (network down)
            LOG_WARN("SM: IP address disappeared (network may be down)");
            m_last_known_primary_ip.clear();
        } else if (!current_ip.empty() && m_last_known_primary_ip.empty()) {
            // IP appeared (network restored)
            LOG_INFO("SM: IP address appeared: " + current_ip);
            m_last_known_primary_ip = current_ip;
            
            // Trigger network restore
            bool was_wifi = m_is_wifi.load(std::memory_order_acquire);
            set_network_info(was_wifi, true);
        }
    }
}

// ============================================================================
// v0.4 IMPLEMENTATION (ask.md §1/§2/§3/§5)
// ============================================================================

namespace {
int64_t v04_now_epoch_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
} // namespace

void SessionManager::Impl::set_delivery_status_callback(SessionManager::DeliveryStatusCallback cb) {
    std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
    m_delivery_status_cb = std::move(cb);
}

void SessionManager::Impl::set_ping_result_callback(SessionManager::PingResultCallback cb) {
    std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
    m_ping_result_cb = std::move(cb);
}

void SessionManager::Impl::set_presence_callback(SessionManager::PresenceCallback cb) {
    std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
    m_presence_cb = std::move(cb);
}

void SessionManager::Impl::set_lookup_result_callback(SessionManager::LookupResultCallback cb) {
    std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
    m_lookup_result_cb = std::move(cb);
}

void SessionManager::Impl::set_invite_callback(SessionManager::InviteCallback cb) {
    std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
    m_invite_cb = std::move(cb);
}

bool SessionManager::Impl::send_reliable(const std::string& peer_id, const std::string& msg_id,
                                         const std::string& payload, int max_retries,
                                         uint32_t retry_timeout_ms) {
    if (!m_reliable_send_manager) return false;
    return m_reliable_send_manager->send_reliable(peer_id, msg_id, payload, max_retries,
                                                  retry_timeout_ms);
}

bool SessionManager::Impl::cancel_reliable(const std::string& msg_id) {
    if (!m_reliable_send_manager) return false;
    return m_reliable_send_manager->cancel(msg_id);
}

bool SessionManager::Impl::reliable_outbox_full() const {
    if (!m_reliable_send_manager) return false;
    return m_reliable_send_manager->is_full();
}

size_t SessionManager::Impl::reliable_pending_count() const {
    if (!m_reliable_send_manager) return 0;
    return m_reliable_send_manager->pending_count();
}

int64_t SessionManager::Impl::get_peer_last_seen_ms(const std::string& peer_id) const {
    {
        std::lock_guard<std::mutex> lock(m_last_seen_mutex);
        auto it = m_peer_last_seen_epoch_ms.find(peer_id);
        if (it != m_peer_last_seen_epoch_ms.end()) return it->second;
    }
    {
        std::lock_guard<std::mutex> lock(m_presence_mutex);
        auto it = m_presence_state.find(peer_id);
        if (it != m_presence_state.end()) return it->second.second;
    }
    return 0;
}


void SessionManager::Impl::note_peer_presence(const std::string& peer_id, bool online) {
    if (peer_id.empty()) return;
    const int64_t now = v04_now_epoch_ms();

    SessionManager::PresenceCallback cb;
    bool subscribed = false;
    bool changed = false;
    int64_t last_seen = now;
    {
        std::lock_guard<std::mutex> lock(m_presence_mutex);
        subscribed = m_presence_subscribed.count(peer_id) > 0;
        auto it = m_presence_state.find(peer_id);
        if (it == m_presence_state.end()) {
            m_presence_state[peer_id] = {online, online ? now : 0};
            changed = true;
        } else if (it->second.first != online) {
            it->second.first = online;
            if (online) it->second.second = now;
            changed = true;
        } else if (online) {
            it->second.second = now;
        }
        last_seen = m_presence_state[peer_id].second;
    }
    {
        std::lock_guard<std::mutex> lock(m_last_seen_mutex);
        if (online) m_peer_last_seen_epoch_ms[peer_id] = now;
    }
    {
        std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
        cb = m_presence_cb;
    }
    if (cb && subscribed && changed) {
        cb(peer_id, online, last_seen);
    }
}

bool SessionManager::Impl::subscribe_presence(const std::vector<std::string>& peer_ids) {
    if (peer_ids.empty()) return false;
    {
        std::lock_guard<std::mutex> lock(m_presence_mutex);
        for (const auto& pid : peer_ids) {
            if (!pid.empty()) m_presence_subscribed.insert(pid);
        }
    }
    // Ask the signaling server for current state (works without sessions).
    signaling_send_subscribe_presence(peer_ids);
    return true;
}

bool SessionManager::Impl::ping_peer(const std::string& peer_id, uint32_t timeout_ms) {
    if (peer_id.empty()) return false;

    // Resolve the peer's network endpoint; ping requires a known endpoint.
    std::string network_id;
    {
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        Peer* peer = find_peer_by_id(peer_id);
        if (peer) {
            network_id = peer->network_id;
        }
    }
    if (network_id.empty()) {
        // Unknown peer: report unreachable immediately.
        SessionManager::PingResultCallback cb;
        {
            std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
            cb = m_ping_result_cb;
        }
        if (cb) cb(peer_id, -1);
        return true;
    }

    const uint64_t token = m_ping_seq.fetch_add(1, std::memory_order_relaxed) + 1;
    const auto sent_time = std::chrono::steady_clock::now();
    const auto deadline = sent_time + std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 3000);
    {
        std::lock_guard<std::mutex> lk(m_ping_mutex);
        m_last_ping_by_peer[peer_id] = {token, sent_time};
    }
    {
        std::lock_guard<std::mutex> lk(m_app_ping_mutex);
        m_pending_pings[peer_id] = {token, deadline};
    }

    const std::string ping_payload = std::to_string(token);
    const std::string ping_message = wire::encode_message(MessageType::CONTROL_PING, ping_payload);
    send_message_to_peer(network_id, ping_message);
    return true;
}

bool SessionManager::Impl::register_alias(const std::string& alias_hash) {
    if (alias_hash.empty()) return false;
    signaling_send_register_alias(alias_hash);
    return true;
}

bool SessionManager::Impl::lookup_peer(const std::string& alias_hash) {
    if (alias_hash.empty()) return false;
    signaling_send_lookup(alias_hash);
    return true;
}

bool SessionManager::Impl::invite_peer(const std::string& peer_id) {
    if (peer_id.empty()) return false;
    signaling_send_invite(peer_id);
    return true;
}

void SessionManager::Impl::check_ping_timeouts_() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::string> expired;
    {
        std::lock_guard<std::mutex> lk(m_app_ping_mutex);
        for (auto it = m_pending_pings.begin(); it != m_pending_pings.end();) {
            if (now >= it->second.deadline) {
                expired.push_back(it->first);
                it = m_pending_pings.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (expired.empty()) return;
    SessionManager::PingResultCallback cb;
    {
        std::lock_guard<std::mutex> lk(m_v04_cb_mutex);
        cb = m_ping_result_cb;
    }
    if (!cb) return;
    for (const auto& pid : expired) {
        cb(pid, -1);  // UNREACHABLE
    }
}


// ---------------------------------------------------------------------------
// v0.4 signaling protocol helpers. All messages ride the existing signaling
// WebSocket (server.py v0.4 extensions): STORE/FETCH (offline mailbox),
// REGISTER_ALIAS/LOOKUP (identity directory), INVITE (connect nudge),
// SUBSCRIBE_PRESENCE/PRESENCE (server-assisted presence).
// ---------------------------------------------------------------------------

void SessionManager::Impl::signaling_send_store(const std::string& target_peer_id,
                                                const std::string& msg_id,
                                                const std::string& payload_b64) {
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) return;
    nlohmann::json j;
    j["type"] = "STORE";
    j["target_peer_id"] = target_peer_id;
    j["msg_id"] = msg_id;
    j["payload_b64"] = payload_b64;
    m_signaling_client->sendRawJson(j.dump());
}

void SessionManager::Impl::signaling_send_fetch() {
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) return;
    m_signaling_client->sendRawJson("{\"type\": \"FETCH\"}");
}

void SessionManager::Impl::signaling_send_register_alias(const std::string& alias_hash) {
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) {
        // Best-effort: connect on demand so alias registration works pre-bootstrap.
        ensure_signaling_connected_async(false);
        return;
    }
    nlohmann::json j;
    j["type"] = "REGISTER_ALIAS";
    j["alias"] = alias_hash;
    m_signaling_client->sendRawJson(j.dump());
}

void SessionManager::Impl::signaling_send_lookup(const std::string& alias_hash) {
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) {
        ensure_signaling_connected_async(false);
        return;
    }
    nlohmann::json j;
    j["type"] = "LOOKUP";
    j["alias"] = alias_hash;
    m_signaling_client->sendRawJson(j.dump());
}

void SessionManager::Impl::signaling_send_invite(const std::string& target_peer_id) {
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) {
        ensure_signaling_connected_async(false);
        return;
    }
    nlohmann::json j;
    j["type"] = "INVITE";
    j["target_peer_id"] = target_peer_id;
    m_signaling_client->sendRawJson(j.dump());
}

void SessionManager::Impl::signaling_send_subscribe_presence(const std::vector<std::string>& peer_ids) {
    if (!m_signaling_client || !m_signaling_registered.load(std::memory_order_acquire)) {
        ensure_signaling_connected_async(false);
        return;
    }
    nlohmann::json j;
    j["type"] = "SUBSCRIBE_PRESENCE";
    j["peer_ids"] = peer_ids;
    m_signaling_client->sendRawJson(j.dump());
}

// Handle v0.4 signaling server messages. Called from setup_signaling_callbacks
// for types the base protocol does not recognize.
void SessionManager::Impl::handle_signaling_v04_message(const json& data) {
    const std::string type = data.value("type", "");

    if (type == "STORED_MESSAGES") {
        // Offline mailbox delivery: [{"msg_id","from_peer_id","payload_b64"}]
        if (!data.contains("messages") || !data["messages"].is_array()) return;
        for (const auto& m : data["messages"]) {
            const std::string msg_id = m.value("msg_id", "");
            const std::string from = m.value("from_peer_id", "");
            const std::string b64 = m.value("payload_b64", "");
            if (msg_id.empty() || from.empty()) continue;

            // Receiver-side dedup: fire onMessageReceived at most once per msg_id.
            if (m_reliable_send_manager && m_reliable_send_manager->is_duplicate(msg_id)) {
                LOG_INFO("SM: dropping duplicate offline message " + msg_id);
                continue;
            }

            const std::string payload = reliable_base64_decode(b64);
            if (m_message_received_cb) {
                m_message_received_cb(from, payload);
            }
        }
        return;
    }

    if (type == "LOOKUP_RESULT") {
        const std::string alias = data.value("alias", "");
        const std::string peer_id = data.value("peer_id", "");
        const bool online = data.value("online", false);
        const int64_t last_seen = data.value("last_seen_ms", static_cast<int64_t>(0));
        SessionManager::LookupResultCallback cb;
        {
            std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
            cb = m_lookup_result_cb;
        }
        if (cb) cb(alias, peer_id, online, last_seen);
        return;
    }

    if (type == "INVITE") {
        const std::string from = data.value("source_peer_id", "");
        if (from.empty()) return;
        LOG_INFO("SM: invite received from " + from);
        SessionManager::InviteCallback cb;
        {
            std::lock_guard<std::mutex> lock(m_v04_cb_mutex);
            cb = m_invite_cb;
        }
        if (cb) cb(from);
        return;
    }

    if (type == "PRESENCE") {
        const std::string peer_id = data.value("peer_id", "");
        const bool online = data.value("online", false);
        if (peer_id.empty()) return;
        // Record last-seen even for non-subscribed peers (feeds lastSeenMs).
        {
            std::lock_guard<std::mutex> lock(m_last_seen_mutex);
            if (online) m_peer_last_seen_epoch_ms[peer_id] = v04_now_epoch_ms();
        }
        note_peer_presence(peer_id, online);
        return;
    }
}
