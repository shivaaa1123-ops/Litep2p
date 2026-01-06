#include "session_manager_p.h"
#include "../../../corep2p/transport/include/quic_connection_manager.h"
#include "../../../corep2p/transport/include/udp_connection_manager.h"
#include "../../../corep2p/core/include/config_manager.h"
#include "../../../corep2p/core/include/telemetry.h"
#include "../../routing/include/upnp_controller.h"
#include "../../discovery/include/signaling_client.h"
#include "unified_event_loop.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <sys/select.h>
#include <unistd.h>
#include <limits.h>

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

void SessionManager::connectToPeer(const std::string& peer_id) {
    m_impl->connectToPeer(peer_id);
}

void SessionManager::addPeer(const std::string& peer_id, const std::string& network_id) {
    m_impl->handlePeerDiscovered(network_id, peer_id);
}

void SessionManager::sendMessageToPeer(const std::string& peer_id, const std::string& message) {
    m_impl->sendMessageToPeer(peer_id, message);
}

bool SessionManager::isPeerConnected(const std::string& peer_id) const {
    return m_impl->isPeerConnected(peer_id);
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
// IMPLEMENTATION
// ============================================================================

SessionManager::Impl::Impl(std::shared_ptr<ISessionDependenciesFactory> factory)
    : m_factory(factory ? factory : std::make_shared<DefaultSessionDependenciesFactory>()),
      m_running(false), m_use_noise_protocol(false), m_noise_nk_enabled(false),
      m_peer_tier_manager(nullptr),
      m_broadcast_discovery(nullptr),
      m_stopped(false),
      m_shutting_down(false) {
    
    // Initialize dependent members after m_factory is initialized
    m_peer_index = m_factory->createPeerIndex();
    m_battery_optimizer = m_factory->createBatteryOptimizer();
    m_session_cache = m_factory->createSessionCache();
    m_message_batcher = m_factory->createMessageBatcher(100, 10);  // Using default values
    m_failsafe = m_factory->createTierSystemFailsafe();
    m_file_transfer_manager = m_factory->createFileTransferManager();
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
    // Default: act as both gateway and client.
    // NOTE: enable_test_echo must remain false for non-test deployments.
    m_proxy_endpoint->configure(proxy::ProxySettings{true, true});
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
    if (!m_file_transfer_manager) m_file_transfer_manager = m_factory->createFileTransferManager();

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
                m_message_handler->handleSendMessage(*e);
            } else if (auto* e = std::get_if<TimerTickEvent>(&event)) {
                LOG_DEBUG("SM: Event type = TimerTickEvent");
                m_maintenance_manager->handleTimerTick(*e);
            } else if (auto* e = std::get_if<DiscoveryInitiatedEvent>(&event)) {
                LOG_DEBUG("SM: Event type = DiscoveryInitiatedEvent");
                // Handle discovery initiation (queued from handleSendMessageEvent)
                if (m_broadcast_discovery && m_broadcast_discovery->is_running()) {
                    m_broadcast_discovery->discover_peer(e->peerId,
                        [this](const DiscoveryResponse& response) {
                            handleDiscoveryResponse(response.responder_peer_id);
                        });
                }
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
        
        // Start Discovery in event-loop mode
        single_thread_discovery_fd = discovery->startEventLoop(port, peer_id);
        if (single_thread_discovery_fd < 0) {
            LOG_WARN("SM: Failed to start discovery in event-loop mode");
        } else {
            LOG_INFO("SM: Discovery started in event-loop mode, fd=" + std::to_string(single_thread_discovery_fd));
        }
        
        // Start UDP in event-loop mode (no listener thread)
        if (comms_mode != "TCP") {
            // Cast to concrete type to access event-loop methods
            single_thread_udp_mgr = dynamic_cast<UdpConnectionManager*>(m_udpConnectionManager.get());
            if (single_thread_udp_mgr) {
                single_thread_udp_mgr->startServerEventLoop(port,
                    [this](const std::string& id, const std::string& data) { onData(id, data); },
                    [this](const std::string& id) { onDisconnect(id); });
                single_thread_udp_fd = single_thread_udp_mgr->getSocketFd();
                LOG_INFO("SM: UDP started in event-loop mode, fd=" + std::to_string(single_thread_udp_fd));
            }
        } else {
            // TCP not supported in single-thread mode yet
            m_tcpConnectionManager->startServer(port, 
                [this](const std::string& id, const std::string& data) { onData(id, data); },
                [this](const std::string& id) { onDisconnect(id); });
        }
        
        // Do NAT detection synchronously at startup (no thread)
        if (comms_mode != "TCP") {
            NATTraversal& nat = NATTraversal::getInstance();
            nat.initialize(static_cast<uint16_t>(port));

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
        
        discovery->start(port, peer_id);
        
        if (comms_mode == "TCP") {
            m_tcpConnectionManager->startServer(port, 
                [this](const std::string& id, const std::string& data) { onData(id, data); },
                [this](const std::string& id) { onDisconnect(id); });
        } else if (comms_mode == "QUIC") {
            LOG_INFO("SM: Switching to QUIC protocol");
            NATTraversal::getInstance().setConnectionManager(nullptr);
            auto ptr = std::make_unique<QuicConnectionManager>();
            m_udpConnectionManager = std::move(ptr);
            NATTraversal::getInstance().setConnectionManager(m_udpConnectionManager.get());
            m_udpConnectionManager->startServer(port,
                [this](const std::string& id, const std::string& data) { onData(id, data); },
                [this](const std::string& id) { onDisconnect(id); });
        } else {
            m_udpConnectionManager->startServer(port,
                [this](const std::string& id, const std::string& data) { onData(id, data); },
                [this](const std::string& id) { onDisconnect(id); });
        }

        // NAT detection in separate thread (multi-threaded mode)
        if (comms_mode != "TCP") {
            if (m_nat_detect_thread.joinable()) {
                m_nat_detect_thread.join();
            }
            m_nat_detect_in_progress.store(true, std::memory_order_release);
            m_nat_detect_thread = std::thread([this, port]() {
                struct Guard {
                    std::atomic<bool>& flag;
                    ~Guard() { flag.store(false, std::memory_order_release); }
                } guard{m_nat_detect_in_progress};

                if (m_shutting_down.load(std::memory_order_acquire)) {
                    return;
                }

                NATTraversal& nat = NATTraversal::getInstance();
                nat.initialize(static_cast<uint16_t>(port));
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
                    add_peer_to_network_index(rec.peer_id, p.network_id);
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
    if (m_comms_mode == "TCP") {
        LOG_INFO("SM: Stopping TCP connection manager...");
        m_tcpConnectionManager->stop();
        LOG_INFO("SM: TCP connection manager stopped.");

        // Even in TCP mode we construct a UDP manager (used for NAT/STUN and UDP sessions).
        // Ensure NATTraversal never holds a dangling raw pointer across SessionManager lifetimes.
        NATTraversal::getInstance().setConnectionManager(nullptr);
    } else {
        LOG_INFO("SM: Stopping UDP connection manager...");
        NATTraversal::getInstance().setConnectionManager(nullptr);
        m_udpConnectionManager->stop();
        NATTraversal::getInstance().shutdown();
        LOG_INFO("SM: UDP connection manager stopped.");
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
        // Clear network index
        {
            std::lock_guard<std::mutex> index_lock(m_network_index_mutex);
            m_network_id_to_peer_id.clear();
        }
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
    if (peer_id.empty()) {
        return;
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

    LOG_INFO("SM: connectToPeer requested for peer: " + peer_id);
    pushEvent(ConnectToPeerEvent{peer_id});
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
        if (!session) {
            LOG_WARN("SM: Failed to create secure session for initiator " + peer_id);
            pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED});
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
                pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED});
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

    std::string response;
    bool handshake_ready = false;
    {
        // IMPORTANT: SecureSession/Noise state is not thread-safe. Hold the mutex while
        // checking readiness and processing the handshake message.
        std::lock_guard<std::mutex> lock(m_secure_session_mutex);
        auto session = m_secure_session_manager->get_session(peer_id);

        // IMPORTANT: If a session is already READY, do not reset it just because a handshake
        // message arrived. During connect/handshake races, the peer may resend handshake frames,
        // and resetting here can create an endless loop where neither side can finish.
        // Restart/re-key scenarios are handled via CONTROL_CONNECT (and related) restart detection.
        if (session && session->is_ready()) {
            LOG_INFO("SM: Received handshake message for READY session with " + peer_id + " - ignoring");
            return "";
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
    }

    LOG_INFO("SM: Returned from session->process_handshake for " + peer_id + ", response size=" + std::to_string(response.size()));

    if (!response.empty()) {
        LOG_INFO("SM: Sending Noise handshake response to " + peer_id + ", payload_len=" + std::to_string(response.size()));
        sendNoiseHandshakeMessage(peer_id, response);
    }

    if (handshake_ready) {
        LOG_INFO("SM: Noise handshake completed with peer " + peer_id);
        pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_SUCCESS});
        flushQueuedMessages(peer_id);
    } else if (response.empty()) {
        LOG_WARN("SM: Noise handshake with peer " + peer_id + " did not progress - marking as failed");
        pushEvent(FSMEvent{peer_id, PeerEvent::HANDSHAKE_FAILED});
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
    
    m_failsafe->set_health_callback([this](bool is_healthy) {
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
        m_peer_update_cb(peer_list);
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
    
    PeerContext* ctx = nullptr;

    {
        NATIVELOGW("SM_NATIVE: handleFSMEvent - acquiring peers_mutex");
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        auto it = m_peer_contexts.find(event.peerId);
        if (it != m_peer_contexts.end()) {
            ctx = &it->second;
        }
        NATIVELOGW("SM_NATIVE: handleFSMEvent - releasing peers_mutex");
    }

    if (!ctx) {
        NATIVELOGW("SM_NATIVE: handleFSMEvent - ctx not found");
        return;
    }

    const PeerState prev_state = ctx->state;
    const auto prev_enter = ctx->last_state_change;
    NATIVELOGW(("SM_NATIVE: handleFSMEvent - calling fsm.handle_event. Current State: " + std::to_string(static_cast<int>(ctx->state)) + ", Event: " + std::to_string(static_cast<int>(event.fsmEvent))).c_str());
    FSMResult result = m_peer_fsm.handle_event(*ctx, event.fsmEvent);
    const PeerState new_state = ctx->state;

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

            const bool is_ready_for_messages = m_use_noise_protocol ? (ctx->state == PeerState::READY)
                                                                    : (ctx->state == PeerState::CONNECTED || ctx->state == PeerState::READY);
            const bool is_hard_disconnected = (ctx->state == PeerState::DISCONNECTED || ctx->state == PeerState::FAILED || ctx->state == PeerState::DEGRADED);

            if (is_ready_for_messages) {
                if (!peer.connected) {
                    peer.connected = true;
                    LOG_INFO("SM: Peer " + event.peerId + " is now CONNECTED (FSM state=" + std::to_string(static_cast<int>(ctx->state)) + ")");
                    peer_status_changed = true;
                    should_persist_connected_state = true;
                    new_connected_state = true;
                }
            } else if (is_hard_disconnected) {
                if (peer.connected) {
                    peer.connected = false;
                    LOG_INFO("SM: Peer " + event.peerId + " is now DISCONNECTED (FSM state=" + std::to_string(static_cast<int>(ctx->state)) + ")");
                    peer_status_changed = true;
                    should_persist_connected_state = true;
                    new_connected_state = false;
                }
            } else {
                // Intermediate states (CONNECTING/HANDSHAKING/etc). For Noise-enabled sessions these should not
                // be treated as connected; keep current peer.connected value unless we need to drop it.
                if (m_use_noise_protocol && peer.connected) {
                    peer.connected = false;
                    LOG_INFO("SM: Peer " + event.peerId + " leaving READY; now not connected for messaging (FSM state=" + std::to_string(static_cast<int>(ctx->state)) + ")");
                    peer_status_changed = true;
                    should_persist_connected_state = true;
                    new_connected_state = false;
                }
            }
        }
    }
    
    if (peer_status_changed) {
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

        // Failures / disconnects: schedule backoff.
        if (event.fsmEvent == PeerEvent::CONNECT_FAILED) {
            policy.on_connection_failure(event.peerId, policy_method);
        } else if (event.fsmEvent == PeerEvent::HANDSHAKE_FAILED) {
            policy.on_connection_failure(event.peerId, "HANDSHAKE");
        } else if (event.fsmEvent == PeerEvent::DISCONNECT_DETECTED) {
            policy.on_connection_failure(event.peerId, "DISCONNECT");
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
    LOG_DEBUG("SM: Network - WiFi: " + (is_wifi ? std::string("true") : std::string("false")));

    const bool was_available = m_network_available.exchange(is_available, std::memory_order_acq_rel);
    const bool was_wifi = m_is_wifi.exchange(is_wifi, std::memory_order_acq_rel);

    // Treat a WiFi<->cellular transition as a network change even if "available" stays true.
    // This is critical on Android: LTE -> WiFi often does NOT produce an "unavailable" gap,
    // but it *does* invalidate our NAT mapping + signaling-advertised network_id.
    const bool network_restored = (!was_available && is_available);
    const bool network_type_changed = (was_available && is_available && was_wifi != is_wifi);
    if (network_restored || network_type_changed) {
        Telemetry::getInstance().inc_counter("network_change_total");
        if (network_restored) Telemetry::getInstance().inc_counter("network_change_restored_total");
        if (network_type_changed) Telemetry::getInstance().inc_counter("network_change_type_total");
        LOG_INFO(std::string("SM: Network change detected (") +
                 (network_restored ? "restored" : "type_changed") +
                 ", wifi=" + (is_wifi ? "true" : "false") + "). Refreshing NAT/signaling.");

        // Refresh external address and publish updated network_id to signaling (if registered).
        refresh_external_address_async(true);

        if (m_signaling_enabled) {
            // Treat a network change as a recovery opportunity: ask signaling for a fresh peer list
            // and keep a best-effort persistent connection so future flaps can self-heal.
            m_signaling_bootstrap_requested.store(true, std::memory_order_release);
            m_signaling_persistent_after_db_exhausted.store(true, std::memory_order_release);

            constexpr auto kPeerListCooldown = std::chrono::seconds(5);
            const auto now_local = std::chrono::steady_clock::now();
            const bool allow_list = (m_last_signaling_peer_list_request == std::chrono::steady_clock::time_point{} ||
                                     (now_local - m_last_signaling_peer_list_request) >= kPeerListCooldown);
            if (allow_list) {
                m_last_signaling_peer_list_request = now_local;
                if (m_signaling_client && m_signaling_client->isConnected() &&
                    m_signaling_registered.load(std::memory_order_acquire)) {
                    m_signaling_client->sendListPeers();
                } else {
                    ensure_signaling_connected_async(true);
                }
            } else {
                // Even if we throttle LIST_PEERS, still ensure we reconnect signaling.
                ensure_signaling_connected_async(true);
            }
        }
    }
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
                if (m_signaling_bootstrap_requested.load(std::memory_order_acquire) || no_known_peers) {
                    constexpr auto kPeerListCooldown = std::chrono::seconds(30);
                    const auto now_local = std::chrono::steady_clock::now();
                    if (m_last_signaling_peer_list_request == std::chrono::steady_clock::time_point{} ||
                        (now_local - m_last_signaling_peer_list_request) >= kPeerListCooldown) {
                        m_last_signaling_peer_list_request = now_local;
                        LOG_INFO(std::string("SM: Requesting signaling PEER_LIST after REGISTER_ACK (") +
                                 (m_signaling_bootstrap_requested.load(std::memory_order_acquire) ? "bootstrap" : "no_known_peers") +
                                 ")");
                        m_signaling_client->sendListPeers();
                    }
                }
            }
            return;
        }

        if (type == "PEER_LIST") {
            if (!data.contains("peers") || !data["peers"].is_array()) {
                return;
            }

            std::string first_connectable_peer;
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

                if (first_connectable_peer.empty()) {
                    // Only attempt direct connects when we have a real ip:port endpoint.
                    if (pid != m_localPeerId &&
                        network_id.find(':') != std::string::npos && network_id.rfind("signaling-", 0) != 0) {
                        first_connectable_peer = pid;
                    }
                }
            }

            // If we are bootstrapping (DB empty/exhausted), connect to the first connectable peer.
            if (!first_connectable_peer.empty() &&
                m_signaling_bootstrap_requested.load(std::memory_order_acquire)) {
                connectToPeer(first_connectable_peer);
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
            handlePeerDiscovered(network_id, pid);

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
                // Not bootstrapping: reconnect only for peers we already knew about.
                // This ensures WAN endpoint updates are acted on after interface changes.
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

        if (type == "PEER_LEFT") {
            const std::string pid = data.value("peer_id", "");
            if (pid.empty()) {
                return;
            }
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
            //   CONNECT_REQUEST|<network_id>|<comms_mode>
            // Example:
            //   CONNECT_REQUEST|110.235.237.26:30001|UDP
            if (payload.rfind("CONNECT_REQUEST|", 0) == 0) {
                std::string rest = payload.substr(std::strlen("CONNECT_REQUEST|"));
                std::string their_network_id;
                std::string their_mode;
                const size_t sep = rest.find('|');
                if (sep != std::string::npos) {
                    their_network_id = rest.substr(0, sep);
                    their_mode = rest.substr(sep + 1);
                } else {
                    their_network_id = rest;
                }

                if (!their_network_id.empty()) {
                    LOG_INFO("SM: Received CONNECT_REQUEST from " + source_peer_id + " endpoint=" + their_network_id +
                             (their_mode.empty() ? std::string("") : (" mode=" + their_mode)));

                    // Ensure we have a peer entry with the provided endpoint.
                    handlePeerDiscovered(their_network_id, source_peer_id);

                    // Best-effort: initiate reciprocal connect to help NAT traversal.
                    connectToPeer(source_peer_id);
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

    {
        std::lock_guard<std::mutex> lock(m_signaling_lifecycle_mutex);
        if (m_signaling_client && m_signaling_client->isConnected()) {
            // We can be TCP-connected but not registered (e.g., server restart, late start, or a
            // previous reconnect swap). In that state we will never receive PEER_LIST/updates.
            const bool registered = m_signaling_registered.load(std::memory_order_acquire);
            const bool want_register = (!registered) &&
                (force ||
                 m_signaling_bootstrap_requested.load(std::memory_order_acquire) ||
                 m_signaling_persistent_after_db_exhausted.load(std::memory_order_acquire));

            if (want_register) {
                const std::string local_peer_id = m_localPeerId;
                if (!local_peer_id.empty()) {
                    std::string local_network_id;
                    {
                        std::lock_guard<std::mutex> lock2(m_signaling_update_mutex);
                        local_network_id = m_pending_signaling_network_id;
                    }
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

    const auto now = std::chrono::steady_clock::now();
    if (!force && m_last_signaling_reconnect_attempt != std::chrono::steady_clock::time_point{} &&
        (now - m_last_signaling_reconnect_attempt) < std::chrono::seconds(5)) {
        return;
    }

    bool expected = false;
    if (!m_signaling_reconnect_in_progress.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }
    m_last_signaling_reconnect_attempt = now;

    const std::string url = m_signaling_url;
    const std::string local_peer_id = m_localPeerId;
    if (url.empty() || local_peer_id.empty()) {
        m_signaling_reconnect_in_progress.store(false, std::memory_order_release);
        return;
    }

    // If the previous thread is still joinable, we cannot overwrite it.
    if (m_signaling_reconnect_thread.joinable()) {
        m_signaling_reconnect_in_progress.store(false, std::memory_order_release);
        return;
    }

    m_signaling_reconnect_thread = std::thread([this, url, local_peer_id]() {
        struct Guard {
            std::atomic<bool>& flag;
            ~Guard() { flag.store(false, std::memory_order_release); }
        } guard{m_signaling_reconnect_in_progress};

        // Make sure we don't keep trying while tearing down.
        if (m_shutting_down.load(std::memory_order_acquire) || !m_running.load(std::memory_order_acquire)) {
            return;
        }

        try {
            auto new_client = std::make_unique<SignalingClient>();
            setup_signaling_callbacks(*new_client);

            LOG_INFO("SM: Signaling reconnect attempt to: " + url);
            int new_fd = -1;
            if (is_single_thread_mode()) {
                new_fd = new_client->connectEventLoop(url);
                if (new_fd < 0) {
                    LOG_WARN("SM: Signaling reconnect failed (event-loop mode)");
                    return;
                }
            } else {
                if (!new_client->connect(url)) {
                    LOG_WARN("SM: Signaling reconnect failed");
                    return;
                }
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

        NATTraversal& nat = NATTraversal::getInstance();
        nat.initialize(static_cast<uint16_t>(port));
        NATInfo info = nat.detectNATType();

        if (m_shutting_down.load(std::memory_order_acquire)) {
            return;
        }

        if (info.external_ip.empty() || info.external_port == 0) {
            // Don't silently fail: this is the root cause for many "local->4G" failures on
            // IPv6-only carrier networks (IPv4-only transport) or when STUN cannot resolve.
            LOG_INFO("SM: NAT refresh produced no IPv4 external endpoint (nat_type=" +
                     std::to_string(static_cast<int>(info.nat_type)) + ") - not updating signaling network_id");
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
        
        // Find the peer by network_id and generate FSM events
        std::lock_guard<std::mutex> lock(m_peers_mutex);
        Peer* peer = find_peer_by_network_id(network_id);
        
        // If not found by full network_id, try to match by IP address only
        // This handles incoming connections which use ephemeral ports
        // BUT: Only do this if we have a clear match (exactly 1 peer with that IP)
        if (!peer) {
            // Extract IP from network_id (format: "IP:PORT")
            size_t colon_pos = network_id.find(':');
            if (colon_pos != std::string::npos) {
                std::string incoming_ip = network_id.substr(0, colon_pos);
                LOG_INFO("SM: CONNECT_ACK: Peer not found by full network_id, checking for IP match: " + incoming_ip);
                
                // Search for peers with matching IP - but only use if exactly ONE match
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
                
                // Only use IP match if exactly 1 peer found (avoid ambiguity on localhost)
                if (match_count == 1 && ip_match) {
                    peer = ip_match;
                    LOG_INFO("SM: CONNECT_ACK: Matched peer by IP (unique): " + peer->id + " (incoming: " + network_id + ", stored: " + peer->network_id + ")");
                    
                    // Store the mapping from ephemeral port to advertised port for future lookups
                    {
                        std::lock_guard<std::mutex> index_lock(m_network_index_mutex);
                        m_ephemeral_to_advertised_port_map[network_id] = peer->network_id;
                    }
                    LOG_INFO("SM: CONNECT_ACK: Created ephemeral port mapping: " + network_id + " -> " + peer->network_id);
                } else if (match_count > 1) {
                    LOG_WARN("SM: CONNECT_ACK: Ambiguous IP match (found " + std::to_string(match_count) + " peers with IP " + incoming_ip + "). Cannot identify peer. Waiting for CONTROL_CONNECT.");
                }
            }
        }
        
        if (peer) {
            // Update last_seen
            peer->last_seen = std::chrono::steady_clock::now();

            LOG_INFO("SM: Received CONNECT_ACK from peer: " + peer->id);
            
            // First, send CONNECT_REQUESTED to transition from DISCOVERED to CONNECTING
            // This ensures the peer is in the correct state before we send CONNECT_SUCCESS
            pushEvent(FSMEvent{peer->id, PeerEvent::CONNECT_REQUESTED});
            
            // Then send CONNECT_SUCCESS to transition from CONNECTING to CONNECTED
            pushEvent(FSMEvent{peer->id, PeerEvent::CONNECT_SUCCESS});
            
            LOG_INFO("SM: Queued FSM events for peer: " + peer->id + " (CONNECT_REQUESTED -> CONNECT_SUCCESS)");

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
                
                std::string payload = m_localPeerId + "|" + pk_hex;
                std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, payload);
                send_message_to_peer(network_id, connect_msg);
                LOG_INFO("SM: Sent CONTROL_CONNECT with public key to " + peer->id);
            } else {
                std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, m_localPeerId);
                send_message_to_peer(network_id, connect_msg);
                LOG_INFO("SM: Sent CONTROL_CONNECT to " + peer->id);
            }
#else
            std::string connect_msg = wire::encode_message(MessageType::CONTROL_CONNECT, m_localPeerId);
            send_message_to_peer(network_id, connect_msg);
            LOG_INFO("SM: Sent CONTROL_CONNECT to " + peer->id);
#endif
        } else {
            LOG_WARN("SM: Received CONNECT_ACK for unknown network_id: " + network_id + ". Searching all peers:");
            for (const auto& kv : m_peers) {
                LOG_WARN("  - Peer: " + kv.second.id + ", stored_network_id: " + kv.second.network_id);
            }
        }
        return;  // Don't treat CONNECT_ACK as data
    }
    
    NATIVELOGW("SM_NATIVE: Not CONNECT_ACK, pushing event");
    // LOG_INFO("SM: Pushing DataReceivedEvent for network_id=" + network_id + ", data length=" + std::to_string(data.length()));
    
    // Update last_seen for general data
    // Note: We must NOT hold m_peers_mutex when calling find_peer_by_network_id
    // as it acquires m_network_index_mutex internally
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
    // Don't add new events when stopping
    if (m_shutting_down.load(std::memory_order_acquire)) {
        return;
    }

    if (m_event_manager) {
        m_event_manager->pushEvent(std::move(event));
    } else {
        std::lock_guard<std::mutex> lock(m_eventMutex);
        m_eventQueue.push(std::move(event));
        m_eventCv.notify_one();
    }
}

bool SessionManager::Impl::isPeerConnected(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    const Peer* peer = find_peer_by_id(peer_id);
    return peer && peer->connected;
}

void SessionManager::Impl::send_message_to_peer(const std::string& network_id, const std::string& message) {
    // Check if we have an ephemeral port mapping for this network_id
    // If the message is to an advertised port but the connection is on ephemeral, we need to send to ephemeral
    std::string actual_network_id = network_id;
    
    {
        std::lock_guard<std::mutex> lock(m_network_index_mutex);
        // Check if we have any ephemeral ports mapping TO this network_id
        // This means the peer connected to us on an ephemeral port, and we stored it mapping to our advertised port
        for (const auto& mapping : m_ephemeral_to_advertised_port_map) {
            if (mapping.second == network_id) {
                // Found: ephemeral port maps to this advertised port
                // Use the ephemeral port for sending
                actual_network_id = mapping.first;
                LOG_DEBUG("SM: Translating advertised port " + network_id + " to ephemeral port " + actual_network_id + " for sending");
                break;
            }
        }
    }
    
    if (m_comms_mode == "TCP") {
        m_tcpConnectionManager->sendMessageToPeer(actual_network_id, message);
    } else {
        m_udpConnectionManager->sendMessageToPeer(actual_network_id, message);
    }
}

Peer* SessionManager::Impl::find_peer_by_id(const std::string& peer_id) {
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? &it->second : nullptr;
}

const Peer* SessionManager::Impl::find_peer_by_id(const std::string& peer_id) const {
    auto it = m_peers.find(peer_id);
    return (it != m_peers.end()) ? &it->second : nullptr;
}

Peer* SessionManager::Impl::find_peer_by_network_id(const std::string& network_id) {
    NATIVELOGW("SM_NATIVE: find_peer_by_network_id - about to acquire m_network_index_mutex");
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    NATIVELOGW("SM_NATIVE: find_peer_by_network_id - m_network_index_mutex acquired");
    auto it = m_network_id_to_peer_id.find(network_id);
    if (it != m_network_id_to_peer_id.end()) {
        NATIVELOGW("SM_NATIVE: find_peer_by_network_id - found in index, calling find_peer_by_id");
        return find_peer_by_id(it->second);
    }
    
    // Check ephemeral port mapping if direct lookup failed
    auto eph_it = m_ephemeral_to_advertised_port_map.find(network_id);
    if (eph_it != m_ephemeral_to_advertised_port_map.end()) {
        auto mapped_it = m_network_id_to_peer_id.find(eph_it->second);
        if (mapped_it != m_network_id_to_peer_id.end()) {
            LOG_DEBUG("SM: Found peer via ephemeral port mapping: " + network_id + " -> " + eph_it->second);
            NATIVELOGW("SM_NATIVE: find_peer_by_network_id - found via ephemeral mapping");
            return find_peer_by_id(mapped_it->second);
        }
    }
    
    NATIVELOGW("SM_NATIVE: find_peer_by_network_id - not found");
    return nullptr;
}

const Peer* SessionManager::Impl::find_peer_by_network_id(const std::string& network_id) const {
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    auto it = m_network_id_to_peer_id.find(network_id);
    if (it != m_network_id_to_peer_id.end()) {
        return find_peer_by_id(it->second);
    }
    
    // Check ephemeral port mapping if direct lookup failed
    auto eph_it = m_ephemeral_to_advertised_port_map.find(network_id);
    if (eph_it != m_ephemeral_to_advertised_port_map.end()) {
        auto mapped_it = m_network_id_to_peer_id.find(eph_it->second);
        if (mapped_it != m_network_id_to_peer_id.end()) {
            LOG_DEBUG("SM: Found peer via ephemeral port mapping: " + network_id + " -> " + eph_it->second);
            return find_peer_by_id(mapped_it->second);
        }
    }
    
    return nullptr;
}

void SessionManager::Impl::add_peer_to_network_index(const std::string& peer_id, const std::string& network_id) {
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    m_network_id_to_peer_id[network_id] = peer_id;
}

void SessionManager::Impl::remove_peer_from_network_index(const std::string& network_id) {
    std::lock_guard<std::mutex> lock(m_network_index_mutex);
    m_network_id_to_peer_id.erase(network_id);
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

    // Drive FSM cleanup for Noise/session state. (If the peer/context doesn't exist, this is a no-op.)
    pushEvent(FSMEvent{peer_id, PeerEvent::DISCONNECT_DETECTED});

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
