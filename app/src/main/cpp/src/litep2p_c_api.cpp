/*
 * litep2p_c_api.cpp — Phase 1 implementation of the public C ABI (litep2p.h)
 * on top of the existing SessionManager engine.
 *
 * Phase 1 constraints (docs/api-spec.md §8):
 *   - No behavior change to the running engine or the JNI bridge.
 *   - The JNI bridge (src/jni_bridge.cpp) keeps its own SessionManager and is
 *     untouched. This file adds an *additive* C ABI that is not yet called by
 *     anything; it is compiled and linked to prove the contract builds.
 *   - The SessionManager is created lazily in litep2p_start() (not init) so
 *     that merely loading/initializing the C ABI never constructs a second
 *     engine or touches process-wide singletons.
 *
 * Known Phase 1 gaps (return LITEP2P_ERR_UNSUPPORTED, wired in later phases):
 *   - File transfer send/receive/accept/decline/pause/resume/cancel: the
 *     SessionManager file-transfer wrappers are declared but not defined, and
 *     the spec's offer/accept model needs a new wire protocol.
 *   - litep2p_disconnect: the engine has no per-peer disconnect API yet.
 *   - on_log level: the engine log callback carries no level; INFO is reported.
 *   - on_telemetry push: telemetry is pull-based via litep2p_telemetry_snapshot.
 */
#include "litep2p.h"

#include "session_manager.h"
#include "peer.h"
#include "logger.h"
#include "telemetry.h"
#include "config_manager.h"
#include "device_utils.h"
#include "constants.h"

#if ENABLE_PROXY_MODULE
#include "proxy_endpoint.h"
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Process-wide singleton state (no handles by design — api-spec.md §3.5/§9).
// ---------------------------------------------------------------------------
struct StoredConfig {
    std::string peer_id;
    std::string comms_mode = "AUTO";
    int listen_port = 0;
    std::string files_dir;
    std::string config_path;
    int enable_encryption = 1;
    int enable_discovery = 1;
    int enable_file_transfer = 1;
    int telemetry_enabled = 1;
    int telemetry_interval_ms = 30000;
    int single_thread_mode = 0;
};

std::mutex g_api_mutex;                       // guards lifecycle + engine pointer
std::atomic<int> g_state{(int)LITEP2P_STATE_STOPPED};
bool g_initialized = false;
StoredConfig g_config;
std::string g_resolved_peer_id;
std::unique_ptr<SessionManager> g_engine;     // created in litep2p_start()

std::mutex g_cb_mutex;
litep2p_callbacks_t g_callbacks{};
bool g_callbacks_set = false;

std::thread g_stop_completion_thread;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
std::string to_hex(const std::vector<uint8_t>& bytes) {
    static const char* hexd = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(hexd[b >> 4]);
        out.push_back(hexd[b & 0xF]);
    }
    return out;
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nib(hex[i]);
        int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

void copy_to_buf(char* buf, uint32_t buf_len, const std::string& s) {
    if (!buf || buf_len == 0) return;
    const size_t n = std::min<size_t>(static_cast<size_t>(buf_len) - 1, s.size());
    std::memcpy(buf, s.data(), n);
    buf[n] = '\0';
}

bool file_readable(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

// Map the engine's connection-path strings to the canonical ABI names.
const char* normalize_connection_path(const std::string& engine_path) {
    if (engine_path == "LAN") return "LAN_DIRECT";
    if (engine_path == "WAN_DIRECT") return "WAN_HOLE_PUNCH";
    if (engine_path == "TURN") return "TURN_RELAY";
    if (engine_path == "SIGNALING") return "SIGNALING_RELAY";
    return "UNKNOWN";
}

// Replicate the JNI bridge's files-dir configuration without JNI (api-spec §3.4).
void apply_files_dir_config(const StoredConfig& cfg) {
    ConfigManager& cm = ConfigManager::getInstance();

    // Load an explicit config.json (or auto-discover under files_dir).
    if (!cfg.config_path.empty()) {
        if (file_readable(cfg.config_path) && cm.loadConfig(cfg.config_path)) {
            nativeLog("CABI: Loaded config from " + cfg.config_path);
        }
    } else if (!cfg.files_dir.empty() && cm.getConfigPath().empty()) {
        const std::string p = cfg.files_dir + "/config.json";
        if (file_readable(p) && cm.loadConfig(p)) {
            nativeLog("CABI: Loaded config from " + p);
        }
    }

    // Ensure the Noise keystore path is writable (default "keystore" is relative).
    if (cm.isNoiseNKEnabled()) {
        const std::string cur = cm.getKeyStorePath();
        if ((cur.empty() || cur == "keystore") && !cfg.files_dir.empty()) {
            const std::string ks = cfg.files_dir + "/keystore";
            cm.setValueAtPath({"security", "noise_nk_protocol", "key_store_path"}, ks);
            nativeLog("CABI: Noise keystore path set to " + ks);
        }
    }

    // Inject a safe peer-DB default when enabled but unconfigured.
    if (cm.isPeerDbEnabled() && cm.getPeerDbPath().empty() && !cfg.files_dir.empty()) {
        const std::string db = cfg.files_dir + "/litep2p_peers.sqlite";
        cm.setValueAtPath({"storage", "peer_db", "path"}, db);
        nativeLog("CABI: Peer DB path set to " + db);
    }
}

} // namespace

extern "C" {

/* ------------------------------------------------------------------------ */
/* Versioning                                                                */
/* ------------------------------------------------------------------------ */
uint32_t litep2p_version(void) {
    return (LITEP2P_VERSION_MAJOR << 16) | (LITEP2P_VERSION_MINOR << 8) | LITEP2P_VERSION_PATCH;
}

const char* litep2p_version_string(void) {
    return "0.3.0";
}

const char* litep2p_result_string(litep2p_result_t result) {
    switch (result) {
        case LITEP2P_OK:                return "OK";
        case LITEP2P_ERR_INVALID_ARG:   return "INVALID_ARG";
        case LITEP2P_ERR_INVALID_STATE: return "INVALID_STATE";
        case LITEP2P_ERR_BUSY:          return "BUSY";
        case LITEP2P_ERR_NOT_FOUND:     return "NOT_FOUND";
        case LITEP2P_ERR_IO:            return "IO";
        case LITEP2P_ERR_TIMEOUT:       return "TIMEOUT";
        case LITEP2P_ERR_UNSUPPORTED:   return "UNSUPPORTED";
        case LITEP2P_ERR_INTERNAL:      return "INTERNAL";
        default:                        return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------------ */
/* Configuration                                                             */
/* ------------------------------------------------------------------------ */
void litep2p_config_init(litep2p_config_t* config) {
    if (!config) return;
    std::memset(config, 0, sizeof(*config));
    config->struct_size = sizeof(litep2p_config_t);
    config->peer_id = nullptr;
    config->comms_mode = "AUTO";
    config->listen_port = 0;
    config->files_dir = nullptr;
    config->config_path = nullptr;
    config->enable_encryption = 1;
    config->enable_discovery = 1;
    config->enable_file_transfer = 1;
    config->telemetry_enabled = 1;
    config->telemetry_interval_ms = 30000;
    config->single_thread_mode = 0;
}

/* ------------------------------------------------------------------------ */
/* Callbacks                                                                 */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_set_callbacks(const litep2p_callbacks_t* callbacks) {
    if (!callbacks || callbacks->struct_size < sizeof(litep2p_callbacks_t)) {
        return LITEP2P_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_cb_mutex);
    // Copy only the fields this ABI knows about (forward compatibility: a
    // newer caller may pass a larger struct).
    std::memcpy(&g_callbacks, callbacks, sizeof(litep2p_callbacks_t));
    g_callbacks.struct_size = sizeof(litep2p_callbacks_t);
    g_callbacks_set = true;
    return LITEP2P_OK;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_init(const litep2p_config_t* config) {
    if (!config || config->struct_size < sizeof(litep2p_config_t)) {
        return LITEP2P_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (g_initialized) {
        return LITEP2P_ERR_INVALID_STATE;  // already initialized; shutdown first
    }

    g_config = StoredConfig{};
    if (config->peer_id) g_config.peer_id = config->peer_id;
    if (config->comms_mode) g_config.comms_mode = config->comms_mode;
    g_config.listen_port = config->listen_port;
    if (config->files_dir) g_config.files_dir = config->files_dir;
    if (config->config_path) g_config.config_path = config->config_path;
    g_config.enable_encryption = config->enable_encryption;
    g_config.enable_discovery = config->enable_discovery;
    g_config.enable_file_transfer = config->enable_file_transfer;
    g_config.telemetry_enabled = config->telemetry_enabled;
    g_config.telemetry_interval_ms = config->telemetry_interval_ms;
    g_config.single_thread_mode = config->single_thread_mode;

    g_initialized = true;
    nativeLog("CABI: litep2p_init complete (comms_mode=" + g_config.comms_mode + ")");
    return LITEP2P_OK;
}


litep2p_result_t litep2p_start(void) {
    SessionManager* engine = nullptr;
    std::string comms_mode;
    std::string peer_id;
    int port = DEFAULT_SERVER_PORT;

    {
        std::lock_guard<std::mutex> lock(g_api_mutex);

        if (!g_initialized) {
            return LITEP2P_ERR_INVALID_STATE;  // init() first
        }
        const int cur = g_state.load(std::memory_order_acquire);
        if (cur != (int)LITEP2P_STATE_STOPPED) {
            return (cur == (int)LITEP2P_STATE_STARTING || cur == (int)LITEP2P_STATE_STOPPING)
                       ? LITEP2P_ERR_BUSY
                       : LITEP2P_ERR_INVALID_STATE;
        }
        g_state.store((int)LITEP2P_STATE_STARTING, std::memory_order_release);

        // A prior stop-completion thread may still be finishing; join before restart.
        if (g_stop_completion_thread.joinable()) {
            g_stop_completion_thread.join();
        }

        // Resolve the local peer id (generate a stable one when not supplied).
        if (g_config.peer_id.empty()) {
            g_resolved_peer_id = get_persistent_device_id();
        } else {
            g_resolved_peer_id = g_config.peer_id;
        }

        // Apply files-dir based configuration (config.json, keystore, peer DB).
        apply_files_dir_config(g_config);

        // Lazily construct the engine so init() alone never builds a SessionManager.
        if (!g_engine) {
            g_engine = std::make_unique<SessionManager>();
        }

        comms_mode = g_config.comms_mode;
        peer_id = g_resolved_peer_id;
        port = g_config.listen_port > 0 ? g_config.listen_port : DEFAULT_SERVER_PORT;
        engine = g_engine.get();
    }

    // Wire the peer-snapshot callback -> on_peers_changed.
    auto peers_cb = [](const std::vector<Peer>& peers) {
        std::vector<litep2p_peer_info_t> infos;
        infos.reserve(peers.size());
        for (const Peer& p : peers) {
            litep2p_peer_info_t info{};
            copy_to_buf(info.peer_id, sizeof(info.peer_id), p.id);
            copy_to_buf(info.ip, sizeof(info.ip), p.ip);
            info.port = p.port;
            info.connected = p.connected ? 1 : 0;
            copy_to_buf(info.network_id, sizeof(info.network_id), p.network_id);
            copy_to_buf(info.connection_path, sizeof(info.connection_path),
                        normalize_connection_path(connectionPathToString(p.active_connection_path)));
            infos.push_back(info);
        }
        void* user_data = nullptr;
        void (*cb)(void*, const litep2p_peer_info_t*, uint32_t) = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_cb_mutex);
            if (g_callbacks_set) {
                user_data = g_callbacks.user_data;
                cb = g_callbacks.on_peers_changed;
            }
        }
        if (cb) {
            cb(user_data, infos.empty() ? nullptr : infos.data(),
               static_cast<uint32_t>(infos.size()));
        }
    };

    // Wire the message callback -> on_message_received.
    engine->setMessageReceivedCallback(
        [](const std::string& peer_id, const std::string& message) {
            void* user_data = nullptr;
            void (*cb)(void*, const char*, const uint8_t*, uint32_t) = nullptr;
            {
                std::lock_guard<std::mutex> lk(g_cb_mutex);
                if (g_callbacks_set) {
                    user_data = g_callbacks.user_data;
                    cb = g_callbacks.on_message_received;
                }
            }
            if (cb) {
                cb(user_data, peer_id.c_str(),
                   reinterpret_cast<const uint8_t*>(message.data()),
                   static_cast<uint32_t>(message.size()));
            }
        });

    // Blocking engine start — no API lock held, so consumers may re-enter the
    // C ABI from callbacks without deadlocking.
    engine->start(port, peers_cb, comms_mode, peer_id);

    g_state.store((int)LITEP2P_STATE_RUNNING, std::memory_order_release);

    // Notify start completion (no lock held).
    void* user_data = nullptr;
    void (*started_cb)(void*) = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_cb_mutex);
        if (g_callbacks_set) {
            user_data = g_callbacks.user_data;
            started_cb = g_callbacks.on_engine_started;
        }
    }
    if (started_cb) started_cb(user_data);

    nativeLog("CABI: engine started (peer_id=" + peer_id + ")");
    return LITEP2P_OK;
}

litep2p_result_t litep2p_stop(void) {
    std::future<void> stop_future;
    {
        std::lock_guard<std::mutex> lock(g_api_mutex);
        const int cur = g_state.load(std::memory_order_acquire);
        if (cur == (int)LITEP2P_STATE_STOPPED || cur == (int)LITEP2P_STATE_STOPPING) {
            return LITEP2P_OK;  // idempotent no-op
        }
        if (cur == (int)LITEP2P_STATE_STARTING) {
            return LITEP2P_ERR_BUSY;
        }
        g_state.store((int)LITEP2P_STATE_STOPPING, std::memory_order_release);
        if (!g_engine) {
            g_state.store((int)LITEP2P_STATE_STOPPED, std::memory_order_release);
            return LITEP2P_OK;
        }
        stop_future = g_engine->stopAsync();
    }

    // Wait for stop completion on a helper thread, then notify (JNI pattern).
    if (g_stop_completion_thread.joinable()) {
        g_stop_completion_thread.join();
    }
    g_stop_completion_thread = std::thread([fut = std::move(stop_future)]() mutable {
        fut.wait();
        {
            std::lock_guard<std::mutex> lock(g_api_mutex);
            g_state.store((int)LITEP2P_STATE_STOPPED, std::memory_order_release);
        }
        void* user_data = nullptr;
        void (*stopped_cb)(void*) = nullptr;
        {
            std::lock_guard<std::mutex> lk(g_cb_mutex);
            if (g_callbacks_set) {
                user_data = g_callbacks.user_data;
                stopped_cb = g_callbacks.on_engine_stopped;
            }
        }
        if (stopped_cb) stopped_cb(user_data);
        nativeLog("CABI: engine stopped");
    });

    return LITEP2P_OK;
}

litep2p_result_t litep2p_shutdown(void) {
    // Stop first if running (best-effort, synchronous wait).
    {
        std::lock_guard<std::mutex> lock(g_api_mutex);
        const int cur = g_state.load(std::memory_order_acquire);
        if (cur == (int)LITEP2P_STATE_RUNNING && g_engine) {
            g_state.store((int)LITEP2P_STATE_STOPPING, std::memory_order_release);
            auto fut = g_engine->stopAsync();
            fut.wait();
            g_state.store((int)LITEP2P_STATE_STOPPED, std::memory_order_release);
        }
    }
    if (g_stop_completion_thread.joinable()) {
        g_stop_completion_thread.join();
    }

    std::lock_guard<std::mutex> lock(g_api_mutex);
    g_engine.reset();
    g_resolved_peer_id.clear();
    g_initialized = false;
    g_state.store((int)LITEP2P_STATE_STOPPED, std::memory_order_release);
    nativeLog("CABI: shutdown complete");
    return LITEP2P_OK;
}

litep2p_state_t litep2p_get_state(void) {
    return static_cast<litep2p_state_t>(g_state.load(std::memory_order_acquire));
}

litep2p_result_t litep2p_get_peer_id(char* buf, uint32_t buf_len) {
    if (!buf || buf_len == 0) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (g_resolved_peer_id.empty()) {
        buf[0] = '\0';
        return LITEP2P_ERR_INVALID_STATE;  // not started yet
    }
    copy_to_buf(buf, buf_len, g_resolved_peer_id);
    return static_cast<litep2p_result_t>(
        std::min<uint32_t>(buf_len - 1, static_cast<uint32_t>(g_resolved_peer_id.size())));
}

/* ------------------------------------------------------------------------ */
/* Peer operations                                                           */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_connect(const char* peer_id) {
    if (!peer_id || !peer_id[0]) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    g_engine->connectToPeer(peer_id);
    return LITEP2P_OK;
}

litep2p_result_t litep2p_add_peer(const char* peer_id, const char* network_id) {
    if (!peer_id || !peer_id[0]) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    g_engine->addPeer(peer_id, network_id ? network_id : "");
    return LITEP2P_OK;
}

litep2p_result_t litep2p_disconnect(const char* peer_id) {
    if (!peer_id || !peer_id[0]) return LITEP2P_ERR_INVALID_ARG;
    // Phase 1 gap: the engine has no per-peer disconnect API yet.
    // Tracked for a later phase (needs SessionManager::disconnectFromPeer).
    return LITEP2P_ERR_UNSUPPORTED;
}

litep2p_result_t litep2p_peer_is_connected(const char* peer_id, int* out_connected) {
    if (!peer_id || !peer_id[0] || !out_connected) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    *out_connected = g_engine->isPeerConnected(peer_id) ? 1 : 0;
    return LITEP2P_OK;
}

litep2p_result_t litep2p_peer_get_connection_path(const char* peer_id,
                                                  char* buf, uint32_t buf_len) {
    if (!peer_id || !peer_id[0] || !buf || buf_len == 0) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    const std::string path = g_engine->getPeerConnectionType(peer_id);
    copy_to_buf(buf, buf_len, normalize_connection_path(path));
    return LITEP2P_OK;
}

/* ------------------------------------------------------------------------ */
/* Messaging — fire-and-forget (api-spec.md §3.8/§9)                         */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_send(const char* peer_id, const uint8_t* data, uint32_t len) {
    if (!peer_id || !peer_id[0]) return LITEP2P_ERR_INVALID_ARG;
    if (len > 0 && !data) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    // LITEP2P_OK means "accepted into the send path", not "delivered".
    g_engine->sendMessageToPeer(peer_id,
                                std::string(reinterpret_cast<const char*>(data), len));
    return LITEP2P_OK;
}

/* ------------------------------------------------------------------------ */
/* Security — Noise NK                                                       */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_get_local_public_key(char* buf, uint32_t buf_len) {
    if (!buf || buf_len < 65) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    const std::vector<uint8_t> key = g_engine->get_local_static_public_key();
    if (key.empty()) return LITEP2P_ERR_UNSUPPORTED;
    copy_to_buf(buf, buf_len, to_hex(key));
    return LITEP2P_OK;
}

litep2p_result_t litep2p_register_peer_key(const char* peer_id,
                                           const char* public_key_hex) {
    if (!peer_id || !peer_id[0] || !public_key_hex) return LITEP2P_ERR_INVALID_ARG;
    const std::vector<uint8_t> key = from_hex(public_key_hex);
    if (key.empty()) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    g_engine->register_peer_nk_key(peer_id, key);
    return LITEP2P_OK;
}

litep2p_result_t litep2p_has_peer_key(const char* peer_id, int* out_has_key) {
    if (!peer_id || !peer_id[0] || !out_has_key) return LITEP2P_ERR_INVALID_ARG;
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    *out_has_key = g_engine->has_peer_nk_key(peer_id) ? 1 : 0;
    return LITEP2P_OK;
}

/* ------------------------------------------------------------------------ */
/* File transfer — Phase 1: contract present, not yet wired                  */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_set_transfer_callbacks(const litep2p_transfer_callbacks_t* callbacks) {
    if (!callbacks || callbacks->struct_size < sizeof(litep2p_transfer_callbacks_t)) {
        return LITEP2P_ERR_INVALID_ARG;
    }
    // Accepted and validated, but the transfer pipeline is not wired in Phase 1.
    return LITEP2P_ERR_UNSUPPORTED;
}

litep2p_result_t litep2p_send_file(const char* peer_id, const char* file_path,
                                   int priority, char* out_transfer_id, uint32_t buf_len) {
    (void)peer_id; (void)file_path; (void)priority; (void)out_transfer_id; (void)buf_len;
    return LITEP2P_ERR_UNSUPPORTED;
}

litep2p_result_t litep2p_accept_file_transfer(const char* transfer_id,
                                              const char* save_path) {
    (void)transfer_id; (void)save_path;
    return LITEP2P_ERR_UNSUPPORTED;
}

litep2p_result_t litep2p_decline_file_transfer(const char* transfer_id) {
    (void)transfer_id;
    return LITEP2P_ERR_UNSUPPORTED;
}

litep2p_result_t litep2p_pause_transfer(const char* transfer_id) {
    (void)transfer_id;
    return LITEP2P_ERR_UNSUPPORTED;
}

litep2p_result_t litep2p_resume_transfer(const char* transfer_id) {
    (void)transfer_id;
    return LITEP2P_ERR_UNSUPPORTED;
}

litep2p_result_t litep2p_cancel_transfer(const char* transfer_id) {
    (void)transfer_id;
    return LITEP2P_ERR_UNSUPPORTED;
}

/* ------------------------------------------------------------------------ */
/* Proxy / relay                                                             */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_set_proxy_role(const char* role) {
    if (!role) return LITEP2P_ERR_INVALID_ARG;
#if ENABLE_PROXY_MODULE
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;

    proxy::ProxyEndpoint* ep = g_engine->get_proxy_endpoint();
    if (!ep) return LITEP2P_ERR_UNSUPPORTED;

    proxy::ProxySettings s = ep->settings();
    std::string r(role);
    for (auto& c : r) c = static_cast<char>(::tolower(c));

    if (r == "off" || r == "0" || r == "false") {
        s.enable_gateway = false;
        s.enable_client = false;
        s.enable_test_echo = false;
    } else if (r == "gateway" || r == "exit") {
        s.enable_gateway = true;
        s.enable_client = false;
        s.enable_test_echo = false;
    } else if (r == "client") {
        s.enable_gateway = false;
        s.enable_client = true;
    } else if (r == "both") {
        s.enable_gateway = true;
        s.enable_client = true;
        s.enable_test_echo = false;
    } else {
        return LITEP2P_ERR_INVALID_ARG;
    }

    g_engine->configure_proxy(s);
    return LITEP2P_OK;
#else
    return LITEP2P_ERR_UNSUPPORTED;
#endif
}

/* ------------------------------------------------------------------------ */
/* Environment hints                                                         */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_set_network_info(int is_wifi, int network_available) {
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    g_engine->set_network_info(is_wifi != 0, network_available != 0);
    return LITEP2P_OK;
}

litep2p_result_t litep2p_set_battery_level(int percent, int is_charging) {
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    g_engine->set_battery_level(percent, is_charging != 0);
    return LITEP2P_OK;
}

litep2p_result_t litep2p_set_reconnect_mode(const char* mode) {
    if (!mode) return LITEP2P_ERR_INVALID_ARG;
    const std::string m(mode);
    if (m != "auto" && m != "aggressive" && m != "balanced" && m != "power_saver") {
        return LITEP2P_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_api_mutex);
    if (!g_engine) return LITEP2P_ERR_INVALID_STATE;
    g_engine->set_reconnect_mode(m);
    return LITEP2P_OK;
}

/* ------------------------------------------------------------------------ */
/* Telemetry and diagnostics                                                 */
/* ------------------------------------------------------------------------ */
litep2p_result_t litep2p_telemetry_snapshot(char** out_json) {
    if (!out_json) return LITEP2P_ERR_INVALID_ARG;
    *out_json = nullptr;

    const std::string json = Telemetry::getInstance().snapshot_json("c_api");
    char* buf = static_cast<char*>(std::malloc(json.size() + 1));
    if (!buf) return LITEP2P_ERR_INTERNAL;
    std::memcpy(buf, json.data(), json.size());
    buf[json.size()] = '\0';
    *out_json = buf;

    // Also deliver via the on_telemetry callback when registered.
    void* user_data = nullptr;
    void (*cb)(void*, const char*) = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_cb_mutex);
        if (g_callbacks_set) {
            user_data = g_callbacks.user_data;
            cb = g_callbacks.on_telemetry;
        }
    }
    if (cb) cb(user_data, buf);

    return LITEP2P_OK;
}

void litep2p_free(void* ptr) {
    std::free(ptr);
}

litep2p_result_t litep2p_set_log_level(int level) {
    switch (level) {
        case 0: set_log_level(LogLevel::DEBUG); break;
        case 1: set_log_level(LogLevel::INFO); break;
        case 2: set_log_level(LogLevel::WARNING); break;
        case 3: set_log_level(LogLevel::ERROR); break;
        default: return LITEP2P_ERR_INVALID_ARG;
    }
    return LITEP2P_OK;
}

} // extern "C"

