#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include "peer.h"
#include "session_dependencies.h"
#include "peer_state_machine.h"
#include "message_types.h"
#include "../../../corep2p/transport/include/connection_manager.h"
#include "../../../corep2p/transport/include/udp_connection_manager.h"
#include "battery_optimizer.h"
#include "session_cache.h"
#include "message_batcher.h"
#include "../../../corep2p/crypto/include/noise_nk.h"
#include "noise_key_store.h"
#include "file_transfer_manager.h"
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <future>

#if ENABLE_PROXY_MODULE
namespace proxy {
class ProxyEndpoint;
struct ProxySettings;
} // namespace proxy
#endif

class SessionManager {
public:
    SessionManager(std::shared_ptr<ISessionDependenciesFactory> factory = nullptr);
    ~SessionManager();

    void start(int port, std::function<void(const std::vector<Peer>&)> cb, const std::string& comms_mode, const std::string& peer_id);
    void stop();
    std::future<void> stopAsync();
    void connectToPeer(const std::string& peer_id);
    void addPeer(const std::string& peer_id, const std::string& network_id);
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);
    bool isPeerConnected(const std::string& peer_id) const;
    
    // Set callback for received messages from peers (peer_id, message)
    void setMessageReceivedCallback(std::function<void(const std::string&, const std::string&)> cb);

#if ENABLE_PROXY_MODULE
    // Optional Proxy Module accessors (only present when compiled with -DENABLE_PROXY_MODULE=ON).
    // Include "proxy_endpoint.h" to use proxy::ProxyEndpoint / proxy::ProxySettings types.
    proxy::ProxyEndpoint* get_proxy_endpoint();
    void configure_proxy(const proxy::ProxySettings& settings);
#endif

    void set_optimization_level(BatteryOptimizer::OptimizationLevel level);
    void set_network_type(BatteryOptimizer::NetworkType type);
    int get_cached_session_count() const;
    int get_session_cache_hit_rate() const;
    BatteryOptimizer::OptimizationConfig get_optimization_config() const;

    void enable_noise_nk();
    bool is_noise_nk_enabled() const;
    std::vector<uint8_t> get_local_static_public_key() const;
    void register_peer_nk_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk);
    bool has_peer_nk_key(const std::string& peer_id) const;
    int get_nk_peer_count() const;
    std::vector<std::string> get_nk_peer_ids() const;
    bool import_nk_peer_keys_hex(const std::map<std::string, std::string>& hex_keys);
    std::map<std::string, std::string> export_nk_peer_keys_hex() const;

    std::string request_file_transfer(const std::string& peer_id, const std::string& file_path,
                                      TransferPriority priority = TransferPriority::NORMAL,
                                      PathSelectionStrategy strategy = PathSelectionStrategy::BALANCED);
    std::string find_optimal_path(const std::string& peer_id, PathSelectionStrategy strategy);
    void report_congestion(const std::string& path_id, const CongestionMetrics& metrics);

    void set_battery_level(int batteryPercent, bool isCharging);
    void set_network_info(bool isWiFi, bool isNetworkAvailable);
    // Override reconnect policy behavior. Accepted values: "auto", "aggressive", "balanced", "power_saver".
    void set_reconnect_mode(const std::string& mode);
    std::string get_reconnect_status_json() const;

    // File transfer methods
    std::string send_file(const std::string& peer_id, const std::string& file_path,
                         const std::string& transfer_id, int priority,
                         TransferPriority transfer_priority, PathSelectionStrategy strategy);
    bool receive_file(const std::string& peer_id, const std::string& file_name,
                     const std::string& save_path, const std::string& checkpoint_path,
                     int priority, uint64_t max_transfer_time_ms);
    bool pause_transfer(const std::string& transfer_id);
    bool resume_transfer(const std::string& transfer_id);
    bool cancel_transfer(const std::string& transfer_id);

    // Network path registration
    std::string register_network_path(const std::string& path_id, const std::string& host,
                                     const std::string& ip, int port, int bandwidth_mbps,
                                     int latency_ms);

    // Transfer monitoring
    float get_transfer_progress(const std::string& transfer_id) const;
    float get_transfer_speed(const std::string& transfer_id) const;
    std::vector<std::string> get_active_transfers() const;
    uint32_t get_adaptive_rate_limit() const;
    bool can_resume_transfer(const std::string& checkpoint_path) const;

// private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

#endif // SESSION_MANAGER_H
