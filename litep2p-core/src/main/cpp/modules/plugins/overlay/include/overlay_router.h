#ifndef OVERLAY_ROUTER_H
#define OVERLAY_ROUTER_H

/*
 * overlay_router.h — multi-hop onion-routed overlay messaging (roadmap B2).
 *
 * Role of this class inside the engine:
 *   ORIGIN side
 *     - send(): builds an LPX2 envelope through N selected relays and hands
 *       the first hop to the session send path.
 *     - Tracks pending frames; retries with a ROTATED path on timeout, then
 *       reports final status via on_delivery_status (bounded reliability).
 *   RELAY side (opt-in, off by default)
 *     - on_frame() peels one sealed layer and forwards (connect-on-demand,
 *       bounded forwarding queue while the connection establishes).
 *     - Holds a mailbox of sealed blobs for offline peers.
 *   DESTINATION side
 *     - Unseals the final payload, delivers it to the application callback
 *       with the ORIGIN's peer id, and (when requested) sends an overlay ACK
 *       back along a fresh reverse path.
 *
 * Ruggedness properties (why this survives hostile networks):
 *   - Relays are stateless: a relay disappearing mid-flight only kills one
 *     attempt; the origin immediately retries on a different path.
 *   - No central anything: relay table is built from peer advertisements.
 *   - The destination's mailbox survives destination downtime.
 *
 * Privacy properties (see overlay_frame.h):
 *   - Each relay sees only prev/next hop. Payload is sealed end-to-end.
 */

#include "overlay_frame.h"
#include "overlay_mailbox.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace overlay {

class OverlayRouter {
public:
    struct Config {
        bool relay_enabled{false};        // forward frames + hold mailbox (opt-in)
        bool advertise_relay{true};       // broadcast relay role to connected peers
        uint8_t default_hops{2};          // relays per path (not counting destination)
        uint8_t max_hops{4};              // hard bound for TTL
        size_t max_pending_sends{512};    // origin-side retry table bound
        size_t max_forward_queue{256};    // relay-side connect-wait queue bound
        int ack_timeout_ms{4000};         // origin retry timeout
        int max_send_attempts{3};         // attempts before reporting failure
        size_t dedup_cache_size{4096};    // seen frame_ids
        size_t relay_table_max{256};
        uint64_t relay_ad_ttl_ms{90000};  // advertisement freshness
        int tick_interval_ms{2500};       // housekeeping period
        size_t mailbox_pickup_batch{16};  // blobs per pickup response
        uint64_t replay_window_ms{15ull * 60 * 1000};  // reject sealed payloads older than this

        // ---- Phase B: censorship resistance --------------------------------
        // SECURE BY DEFAULT (0.3.0): every knob below ships enabled. Each can
        // still be relaxed via the `overlay` object in config.json, but the
        // stock configuration must resist DPI and traffic analysis out of the
        // box — opt-out, never opt-in.
        //
        // Cover traffic: pad every LPX2 frame to the next multiple of
        // `padding_bucket` bytes (0 = off). All frames from a node then fall
        // into a small set of sizes, hiding real message lengths from DPI.
        // 128 keeps the worst case (1100 B frame + 78 B OBF1 overhead = 1178
        // -> 1216 B) under the IPv6 minimum MTU of 1280, so overlay frames
        // never force IP fragmentation. Do not raise above ~192 without
        // re-checking that bound.
        size_t padding_bucket{128};
        // Obfuscated transport: wrap every outgoing hop frame in the OBF1
        // envelope so the "LPX2" magic is never visible on the wire. The
        // receive path auto-detects OBF1 by magic, so legacy plain LPX2
        // frames are still accepted (mixed-config interop).
        bool obfuscate_transport{true};
        // Emit cover (dummy) frames when no real traffic has been sent for
        // this many ms (0 = off). Obscures silence / presence patterns.
        // Only nodes with the relay role enabled ever emit cover traffic, so
        // this costs nothing on default (non-relay) mobile clients.
        uint64_t cover_interval_ms{30000};
        // Relay-list exchange period (ms). 0 = off. Peers also answer a PEX
        // whenever they receive a relay advertisement (B5). Periodic PEX
        // spreads relay knowledge without any central directory.
        uint64_t pex_interval_ms{60000};
        // Reject unsigned FinalPayloads entirely (origin authentication). All
        // 0.3.0 nodes auto-generate an Ed25519 signing keypair and sign every
        // payload, so enforcing signatures breaks no legitimate traffic. Set
        // false only to interoperate with pre-Phase-B senders. NOTE: identity
        // BINDING (dropping payloads signed by the wrong key for a claimed
        // origin) additionally requires registering the origin's signing key
        // (litep2p_overlay_register_peer_signing_key).
        bool require_origin_auth{true};
    };

    enum class SendResult {
        Ok = 0,
        NoKey,          // destination (or relay) static key unknown
        NoRelays,       // no relay candidates available
        TooLarge,       // payload does not fit after sealing
        Busy,           // pending-send table full
        NotStarted,
        Internal,
    };

    enum class DeliveryStatus { Delivered, Failed };

    // --- Wiring (all set before start(); never invoked with locks held) ---
    using SendFn        = std::function<bool(const std::string& peer_id, const std::string& wire_message)>;
    using ConnectFn     = std::function<void(const std::string& peer_id)>;
    using IsConnectedFn = std::function<bool(const std::string& peer_id)>;
    using DeliverFn     = std::function<void(const std::string& origin_peer_id, const std::string& payload)>;
    using DeliveryCb    = std::function<void(const std::string& frame_id_hex, DeliveryStatus status)>;

    explicit OverlayRouter(const Config& cfg);
    OverlayRouter();
    ~OverlayRouter();

    void set_send_fn(SendFn fn);
    void set_connect_fn(ConnectFn fn);
    void set_is_connected_fn(IsConnectedFn fn);
    void set_deliver_fn(DeliverFn fn);
    void set_delivery_cb(DeliveryCb cb);

    // Local identity (from the Noise key store). Required for sealing.
    void set_local_identity(const std::string& peer_id,
                            const std::vector<uint8_t>& public_key,
                            const std::vector<uint8_t>& secret_key);

    // Resolve a peer's static public key (from the Noise key store / DHT).
    void set_peer_key_fn(std::function<std::vector<uint8_t>(const std::string&)> fn);

    // ---- Origin authentication (Phase B / roadmap §8 item 7) ---------------
    // Local Ed25519 signing keypair (32B pk, 64B sk). When set, every sealed
    // FinalPayload is signed; the destination verifies it.
    void set_local_signing_keys(const std::vector<uint8_t>& public_key,
                                const std::vector<uint8_t>& secret_key);
    // Resolve a peer's Ed25519 signing public key for identity binding. When
    // the returned key does not match the payload's embedded signer, the
    // message is dropped (forgery / key-mismatch).
    void set_peer_signing_key_fn(std::function<std::vector<uint8_t>(const std::string&)> fn);

    // ---- Lifecycle -------------------------------------------------------
    void start();
    void stop();
    bool is_running() const { return m_running.load(); }

    // ---- Origin API ------------------------------------------------------
    // Send `payload` to `dest_peer_id` through `cfg.default_hops` relays.
    // want_ack: bounded reliable delivery with path-rotating retries.
    // via_mailbox: last hop is a mailbox hold instead of direct delivery
    //              (use when the destination may be offline).
    // On success returns SendResult::Ok and fills out_frame_id_hex.
    SendResult send(const std::string& dest_peer_id, const std::string& payload,
                    bool want_ack, bool via_mailbox, std::string& out_frame_id_hex);

    // ---- Destination API -------------------------------------------------
    // Ask `relay_peer_id` to hand over any mailboxes held for us (blobs are
    // sealed to our key; the relay cannot read them). Call periodically after
    // coming online to collect messages received while we were unreachable.
    void pickup_mailbox(const std::string& relay_peer_id);

    // ---- Relay / destination input (called by the session on OVERLAY_FRAME)
    void on_frame(const std::string& from_peer_id, const std::string& frame_bytes);

    // ---- Management ------------------------------------------------------
    void set_relay_enabled(bool enabled);
    bool relay_enabled() const { return m_relay_enabled.load(std::memory_order_relaxed); }

    // Pin a relay candidate manually (bootstrap / config-provided list).
    void register_relay_candidate(const std::string& peer_id, uint16_t capacity,
                                  uint8_t max_hops, bool persistent);

    // Known relay ids (best effort, for telemetry / tests).
    std::vector<std::string> relay_candidates() const;

    struct Stats {
        uint64_t sent_total{0};
        uint64_t sent_ok_total{0};
        uint64_t retries_total{0};
        uint64_t failed_total{0};
        uint64_t acked_total{0};
        uint64_t relayed_total{0};
        uint64_t delivered_total{0};
        uint64_t dedup_drops_total{0};
        uint64_t ttl_drops_total{0};
        uint64_t unseal_fail_total{0};
        uint64_t mailbox_stored_total{0};
        uint64_t mailbox_picked_total{0};
        uint64_t adverts_tx_total{0};
        uint64_t adverts_rx_total{0};
        uint64_t pex_tx_total{0};       // Phase B: relay-list exchanges sent
        uint64_t pex_rx_total{0};       // Phase B: relay-list exchanges received
        uint64_t cover_tx_total{0};     // Phase B: cover frames emitted
        uint64_t cover_rx_total{0};     // Phase B: cover frames consumed
        uint64_t auth_ok_total{0};      // Phase B: verified origin signatures
        uint64_t auth_fail_total{0};    // Phase B: signature missing/mismatch/bad
        uint64_t obf_ok_total{0};       // Phase B: obfuscated envelopes unwrapped
        uint64_t obf_fail_total{0};     // Phase B: obfuscation failures (drop)
    };
    Stats stats() const;
    std::string stats_json() const;

private:
    struct RelayInfo {
        std::string peer_id;
        uint16_t capacity{32};
        uint8_t max_hops{4};
        uint64_t last_seen_ms{0};
        bool persistent{false};
        uint32_t forward_load{0};       // in-flight forwards (decay)
        uint32_t success_score{100};    // EWMA of forward success
    };

    struct PendingSend {
        std::string dest_peer_id;
        std::string payload;
        bool via_mailbox{false};
        uint8_t attempts{0};
        uint64_t next_retry_ms{0};
        uint64_t deadline_ms{0};
        std::string frame_id_hex;
    };

    struct ForwardWait {
        std::string wire_frame;
        uint64_t expires_ms{0};
    };

    // Internal helpers (all assume no router mutex is held when invoking
    // callbacks; state access is guarded by m_mu).
    void tick_loop_();
    void do_tick_(uint64_t now_ms);
    std::vector<std::string> pick_path_(size_t hop_count, const std::string& exclude1,
                                        const std::string& exclude2) const;
    SendResult dispatch_frame_(const std::string& dest_peer_id, const std::string& payload,
                               bool want_ack, bool via_mailbox, uint8_t attempts_hint,
                               std::string& out_frame_id_hex,
                               const uint8_t frame_id[kFrameIdSize]);
    void handle_relay_advert_(const std::string& from_peer, std::string_view body);
    void handle_forward_(const std::string& from_peer, const HopInstruction& hop,
                         uint8_t flags, uint8_t ttl, const uint8_t frame_id[kFrameIdSize]);
    void handle_deliver_(const HopInstruction& hop, uint8_t flags,
                         const uint8_t frame_id[kFrameIdSize]);
    void handle_mailbox_store_(const std::string& from_peer, const HopInstruction& hop);
    void handle_mailbox_pickup_(const std::string& from_peer);
    void send_ack_(const FinalPayload& delivered, std::string acked_id_hex);
    void send_or_queue_(const std::string& peer_id, const std::string& wire_frame,
                        uint64_t now_ms);
    void send_frame_(const std::string& peer_id, const std::string& wire_frame,
                     uint64_t now_ms);
    void advertise_if_due_();
    // Phase B: exchange known relay lists with a connected peer (B5).
    void send_relay_pex_(const std::string& to_peer, uint64_t now_ms);
    void handle_relay_pex_(std::string_view body);
    // Phase B: emit a sealed cover frame if the link has been idle too long.
    void maybe_send_cover_(uint64_t now_ms);
    bool seen_frame_(const uint8_t frame_id[kFrameIdSize]);
    bool check_replay_(uint64_t created_ts_ms, uint64_t now_ms) const;

    Config m_cfg;
    // Atomic mirror of m_cfg.relay_enabled: set_relay_enabled() may be called
    // at runtime from any thread while relay paths read the flag on engine
    // threads. Concurrent non-atomic bool read/write would be UB.
    std::atomic<bool> m_relay_enabled{false};
    mutable std::mutex m_mu;
    std::condition_variable m_tick_cv;
    std::atomic<bool> m_running{false};
    std::thread m_tick_thread;

    // Identity
    std::string m_local_id;
    std::vector<uint8_t> m_local_pk;
    std::vector<uint8_t> m_local_sk;

    // Wiring
    SendFn m_send;
    ConnectFn m_connect;
    IsConnectedFn m_is_connected;
    DeliverFn m_deliver;
    DeliveryCb m_delivery_cb;
    std::function<std::vector<uint8_t>(const std::string&)> m_peer_key_fn;
    std::function<std::vector<uint8_t>(const std::string&)> m_peer_sign_fn;

    // Origin authentication (Phase B): local Ed25519 signing keypair.
    std::vector<uint8_t> m_local_sign_pk;
    std::vector<uint8_t> m_local_sign_sk;

    // Cover-traffic tracking (Phase B). Atomic: tick thread + send paths touch them.
    std::atomic<uint64_t> m_last_tx_ms{0};     // last real frame handed to the transport
    std::atomic<uint64_t> m_last_cover_ms{0};  // last cover frame emitted
    std::atomic<uint64_t> m_last_pex_ms{0};    // last PEX sent

    // State
    std::unordered_map<std::string, RelayInfo> m_relays;
    std::unordered_map<std::string, PendingSend> m_pending;      // frame_id_hex -> pending
    std::unordered_map<std::string, std::vector<ForwardWait>> m_forward_wait;  // peer -> queued frames
    OverlayMailbox m_mailbox;

    // Dedup LRU (frame_id hex -> recency list iterator)
    std::list<std::string> m_dedup_lru;
    std::unordered_map<std::string, std::list<std::string>::iterator> m_dedup_it;

    Stats m_stats;

    static uint64_t steady_ms_();
};

} // namespace overlay

#endif // OVERLAY_ROUTER_H
