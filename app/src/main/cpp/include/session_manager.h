#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include "peer.h"
#include "connection_manager.h"
#include "udp_connection_manager.h"
#include "battery_optimizer.h"
#include "session_cache.h"
#include "message_batcher.h"
#include "noise_nk.h"
#include "noise_key_store.h"
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <memory>

class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    void start(int port, std::function<void(const std::vector<Peer>&)> peer_update_cb, const std::string& comms_mode, const std::string& peer_id);
    void stop();

    void connectToPeer(const std::string& peer_id);
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);

    // Battery optimization APIs
    void set_optimization_level(BatteryOptimizer::OptimizationLevel level);
    void set_network_type(BatteryOptimizer::NetworkType type);
    int get_cached_session_count() const;
    int get_session_cache_hit_rate() const;
    BatteryOptimizer::OptimizationConfig get_optimization_config() const;

    // Noise NK MITM Protection APIs
    // =============================
    
    /**
     * Enable Noise NK pattern for MITM protection
     * Call this before starting if you want NK-protected channels
     * Requires peer static keys to be registered first
     */
    void enable_noise_nk();

    /**
     * Check if Noise NK is enabled
     */
    bool is_noise_nk_enabled() const;

    /**
     * Get local static public key (to share with peers)
     * Share this via QR code, NFC, or initial setup
     */
    std::vector<uint8_t> get_local_static_public_key() const;

    /**
     * Register peer's static public key
     * Must be done before initiating NK handshake with peer
     * In production: load from QR code scan, NFC, or provisioning server
     */
    void register_peer_nk_key(const std::string& peer_id, const std::vector<uint8_t>& static_pk);

    /**
     * Check if peer's NK key is registered
     */
    bool has_peer_nk_key(const std::string& peer_id) const;

    /**
     * Get number of registered peer NK keys
     */
    int get_nk_peer_count() const;

    /**
     * Get all known peer IDs (with NK keys)
     */
    std::vector<std::string> get_nk_peer_ids() const;

    /**
     * Import peer keys from hex-encoded map (for restoring from backup)
     */
    bool import_nk_peer_keys_hex(const std::map<std::string, std::string>& hex_keys);

    /**
     * Export peer keys as hex-encoded strings (for backup/sharing)
     */
    std::map<std::string, std::string> export_nk_peer_keys_hex() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

#endif // SESSION_MANAGER_H
