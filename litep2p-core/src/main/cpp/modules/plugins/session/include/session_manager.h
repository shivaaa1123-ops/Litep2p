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
    // Bypass reconnect-policy gating for this connect attempt (use sparingly).
    // Intended for remote-initiated recovery signals (e.g., CONNECT_REQUEST) where suppression
    // can prevent progress after interface/NAT mapping changes.
    void connectToPeer(const std::string& peer_id, bool bypass_reconnect_policy);
    // Gracefully disconnect a specific peer and suppress automatic reconnects
    // to it until the next explicit connectToPeer() or an inbound connection
    // from that peer. Closes the transport connection where applicable (TCP)
    // and transitions the peer FSM to DISCONNECTED. Returns true when the peer
    // was known.
    bool disconnectFromPeer(const std::string& peer_id);
    void addPeer(const std::string& peer_id, const std::string& network_id);
    void sendMessageToPeer(const std::string& peer_id, const std::string& message);
    bool isPeerConnected(const std::string& peer_id) const;

    // v0.4 backpressure: number of plain-send events currently queued in the
    // engine event loop (accepted but not yet handed to the transport). Used
    // by the C ABI to return LITEP2P_ERR_QUEUE_FULL and to expose the
    // litep2p_pending_send_count() metric.
    int pendingSendCount() const;

    // Expose the Peer FSM state as a stable string for UI/debugging.
    // This is intentionally best-effort and returns "UNKNOWN" if the peer context is missing.
    std::string getPeerFsmState(const std::string& peer_id) const;
    
    // Get the connection type for a peer: "LAN", "WAN", "RELAY", or "UNKNOWN".
    // Returns the type of the current endpoint being used for communication.
    std::string getPeerConnectionType(const std::string& peer_id) const;
    
    // Set callback for received messages from peers (peer_id, message)
    void setMessageReceivedCallback(std::function<void(const std::string&, const std::string&)> cb);

#if ENABLE_PROXY_MODULE
    // Optional Proxy Module accessors (only present when compiled with -DENABLE_PROXY_MODULE=ON).
    // Include "proxy_endpoint.h" to use proxy::ProxyEndpoint / proxy::ProxySettings types.
    proxy::ProxyEndpoint* get_proxy_endpoint();
    void configure_proxy(const proxy::ProxySettings& settings);
#endif

#if ENABLE_OVERLAY_MODULE
    // ==================== Multi-hop overlay (LPX2) ====================
    // Opt in / out of forwarding frames and holding mailboxes for other
    // peers. Origin/destination roles are always available.
    void set_overlay_relay_enabled(bool enabled);

    // Send an application payload through N sealed relay hops to `peer_id`
    // (requires the peer's static key to be registered). want_ack enables
    // bounded reliable delivery (retries rotate the relay path). via_mailbox
    // asks the terminal relay to hold the sealed blob until the destination
    // picks it up (offline delivery). Returns the frame id ("" on failure).
    std::string send_overlay(const std::string& peer_id, const std::string& payload,
                             bool want_ack, bool via_mailbox);

    // Like send_overlay, but returns the overlay SendResult code as an int
    // (0 = OK; the C ABI maps this onto litep2p_result_t). `out_frame_id` is
    // filled with the frame id on success.
    int send_overlay_ex(const std::string& peer_id, const std::string& payload,
                        bool want_ack, bool via_mailbox, std::string& out_frame_id);

    // Collect any mailboxes `relay_peer_id` is holding for us (call after
    // coming online, or periodically).
    void overlay_pickup_mailbox(const std::string& relay_peer_id);

    // Report overlay reliable-send completion (frame_id, delivered=true/false).
    // Called on engine threads; the callback must not block.
    void set_overlay_delivery_cb(std::function<void(const std::string& frame_id, bool delivered)> cb);

    // Manually add a relay candidate (e.g. from a config file, a QR code, or
    // a bootstrap server). persistent=true keeps it in the table regardless of
    // advertisement freshness. capacity/max_hops tune path scoring.
    void overlay_register_relay(const std::string& peer_id, int capacity = 32,
                                int max_hops = 4, bool persistent = true);

    // Phase B: register a peer's Ed25519 signing public key (32 bytes) as the
    // trust anchor for origin authentication. Once registered, overlay payloads
    // claiming to come from `peer_id` must be signed by this exact key or they
    // are dropped. Exchange keys out-of-band (QR code, pinned config, etc.).
    void overlay_register_peer_signing_key(const std::string& peer_id,
                                           const std::vector<uint8_t>& public_key);

    // Overlay counters as single-line JSON (telemetry/diagnostics).
    std::string overlay_stats_json() const;
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

    // ==================== File transfer (offer/accept model) ====================
    // Offer a file to a peer. Returns the transfer ID ("" on failure). The
    // transfer stays PENDING until the peer accepts; no file data is sent
    // before acceptance.
    std::string send_file(const std::string& peer_id, const std::string& file_path, int priority);

    // Accept or decline an incoming offer (delivered via the offer callback).
    // Accepting starts the receive session writing to save_path.
    bool accept_file_transfer(const std::string& transfer_id, const std::string& save_path);
    bool decline_file_transfer(const std::string& transfer_id);

    // Transfer control (propagated to the remote peer).
    bool pause_transfer(const std::string& transfer_id);
    bool resume_transfer(const std::string& transfer_id);
    bool cancel_transfer(const std::string& transfer_id);

    // Transfer status queries.
    float get_transfer_progress(const std::string& transfer_id) const;  // 0-100, -1 unknown
    float get_transfer_speed(const std::string& transfer_id) const;     // bytes/sec
    std::vector<std::string> get_active_transfers() const;

    // File transfer event callbacks (offer/progress/completion). May be
    // (re-)registered at any time; invoked on engine threads.
    using FileTransferOfferCallback =
        std::function<void(const std::string& transfer_id, const std::string& peer_id,
                           const std::string& file_name, uint64_t size_bytes)>;
    using FileTransferProgressCallback =
        std::function<void(const std::string& transfer_id, float progress_percent,
                           float bytes_per_sec)>;
    using FileTransferCompleteCallback =
        std::function<void(const std::string& transfer_id, bool success,
                           const std::string& error)>;
    void set_file_transfer_callbacks(FileTransferOfferCallback on_offer,
                                     FileTransferProgressCallback on_progress,
                                     FileTransferCompleteCallback on_complete);

    // ==================== Voice calls (realtime audio) ====================
    // Offer a call to a connected peer. `codec` is opaque to the engine
    // (e.g. "PCM_S16LE"); sample_rate/channels/frame_ms describe the profile
    // and are advertised to the callee. Returns the call id ("" on failure).
    std::string start_voice_call(const std::string& peer_id, const std::string& codec,
                                 uint16_t sample_rate, uint8_t channels, uint8_t frame_ms);

    // Callee accepts/declines an incoming offer (delivered via the offer callback).
    bool accept_voice_call(const std::string& call_id);
    bool decline_voice_call(const std::string& call_id);

    // Either side hangs up.
    bool end_voice_call(const std::string& call_id);

    // Send one audio frame (fire-and-forget; only valid while IN_CALL).
    bool send_voice_frame(const std::string& call_id, const uint8_t* data, size_t len);

    // Voice call event callbacks (offered/state/frame). May be (re-)registered
    // at any time; invoked on engine threads. `state` is a VoiceCallState value.
    using VoiceCallOfferedCallback =
        std::function<void(const std::string& call_id, const std::string& peer_id,
                           const std::string& codec, uint16_t sample_rate,
                           uint8_t channels, uint8_t frame_ms)>;
    using VoiceCallStateCallback =
        std::function<void(const std::string& call_id, const std::string& peer_id,
                           int state, const std::string& detail)>;
    using VoiceFrameCallback =
        std::function<void(const std::string& call_id, const std::string& peer_id,
                           const uint8_t* data, size_t len)>;
    void set_voice_call_callbacks(VoiceCallOfferedCallback on_offered,
                                  VoiceCallStateCallback on_state,
                                  VoiceFrameCallback on_frame);

    void set_battery_level(int batteryPercent, bool isCharging);
    void set_network_info(bool isWiFi, bool isNetworkAvailable);
    // Override reconnect policy behavior. Accepted values: "auto", "aggressive", "balanced", "power_saver".
    void set_reconnect_mode(const std::string& mode);
    std::string get_reconnect_status_json() const;

    // ==================== Reliable messaging (v0.4, ask.md §1/§2) ====================
    // Send with delivery guarantees: persistent outbox, retry, receiver dedup,
    // and offline store-and-forward via the signaling server. Returns true when
    // accepted into the outbox. Status is reported via the delivery-status
    // callback (QUEUED/SENT/DELIVERED/FAILED + machine-readable reason).
    bool send_reliable(const std::string& peer_id, const std::string& msg_id,
                       const std::string& payload, int max_retries, uint32_t retry_timeout_ms);
    bool cancel_reliable(const std::string& msg_id);

    // v0.4 backpressure metrics: outbox occupancy of the reliable-send queue.
    // reliable_outbox_full() is true when send_reliable would reject with
    // QUEUE_FULL; reliable_pending_count() counts QUEUED/SENT messages.
    bool reliable_outbox_full() const;
    size_t reliable_pending_count() const;

    using DeliveryStatusCallback =
        std::function<void(const std::string& msg_id, int status, const std::string& reason)>;
    void set_delivery_status_callback(DeliveryStatusCallback cb);

    // ==================== Presence & reachability (v0.4, ask.md §5) ====================
    // Cheap liveness probe; result via the ping callback (rtt_ms >= 0, or -1
    // on timeout). Works for connected peers without extra app plumbing.
    using PingResultCallback = std::function<void(const std::string& peer_id, int64_t rtt_ms)>;
    void set_ping_result_callback(PingResultCallback cb);
    bool ping_peer(const std::string& peer_id, uint32_t timeout_ms);

    // Server-assisted presence. Subscribed peers get transition updates via
    // the presence callback; works without holding an open session.
    using PresenceCallback =
        std::function<void(const std::string& peer_id, bool online, int64_t last_seen_ms)>;
    void set_presence_callback(PresenceCallback cb);
    bool subscribe_presence(const std::vector<std::string>& peer_ids);

    // Epoch ms when the peer was last observed online (0 = never).
    int64_t get_peer_last_seen_ms(const std::string& peer_id) const;

    // ==================== Identity directory & invites (v0.4, ask.md §3) ====================
    using LookupResultCallback = std::function<void(const std::string& alias,
                                                    const std::string& peer_id,
                                                    bool online, int64_t last_seen_ms)>;
    using InviteCallback = std::function<void(const std::string& from_peer_id)>;
    void set_lookup_result_callback(LookupResultCallback cb);
    void set_invite_callback(InviteCallback cb);

    bool register_alias(const std::string& alias_hash);
    bool lookup_peer(const std::string& alias_hash);
    bool invite_peer(const std::string& peer_id);

    // ==================== Capability negotiation hooks (Network OS Phase 2) ====================
    // Registers the capability provider/consumer used during session setup
    // (CONTROL_CONNECT exchange). Backward compatible: no hooks = old wire format.
    using CapabilityProvider = std::function<std::string()>;
    using CapabilityConsumer =
        std::function<void(const std::string& peer_id, const std::string& cap_b64)>;
    void set_capability_hooks(CapabilityProvider provider, CapabilityConsumer consumer);

// private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

#endif // SESSION_MANAGER_H
