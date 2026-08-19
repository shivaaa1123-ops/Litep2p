#ifndef VOICE_CALL_MANAGER_H
#define VOICE_CALL_MANAGER_H

#include "voice_call_types.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

/**
 * Manages realtime voice calls for the local peer.
 *
 * - Call control follows the file-transfer idiom: the caller offers, the
 *   callee accepts/declines, either side ends. Control frames are small and
 *   ride the same session send path as every other engine message.
 * - Audio frames are fire-and-forget UDP datagrams (no ACK/retransmit) —
 *   each frame is tiny (<1.5 KB with the default profile), so frames stay
 *   well under the network MTU and never need IP fragmentation.
 * - Thread-safety: all public methods are safe to call from any thread.
 *   Event callbacks (offered/state/frame) may fire on engine threads (from
 *   [handle_incoming_message]) or on the internal watchdog thread; consumers
 *   must not block in them.
 */
class VoiceCallManager {
public:
    struct CallConfig {
        // An unanswered offer is auto-declined after this long.
        uint32_t ring_timeout_ms;
        // A connected call with no frames or control traffic in either
        // direction for this long is ended locally ("no media activity") so a
        // peer that vanishes (engine restart, radio off) cannot orphan the
        // call forever. Capture normally produces frames continuously, so this
        // only fires when the remote side is truly gone.
        uint32_t media_timeout_ms;

        CallConfig() : ring_timeout_ms(kVoiceRingTimeoutMs), media_timeout_ms(300000) {}
    };

    using OutboundCallback = std::function<void(const std::string& peer_id,
                                                const std::string& payload)>;
    // Incoming call offer (callee side). The caller chooses accept/decline.
    using CallOfferedCallback = std::function<void(
        const std::string& call_id, const std::string& peer_id,
        const std::string& codec, uint16_t sample_rate, uint8_t channels, uint8_t frame_ms)>;
    // Call state change (both sides). detail: "declined by peer", "ended",
    // "ring timeout", "declined", "connected", ...
    using CallStateCallback = std::function<void(
        const std::string& call_id, const std::string& peer_id,
        VoiceCallState state, const std::string& detail)>;
    // Incoming audio frame (call must be IN_CALL). data is valid only for the
    // duration of the callback.
    using FrameReceivedCallback = std::function<void(
        const std::string& call_id, const std::string& peer_id,
        const uint8_t* data, size_t len)>;

    explicit VoiceCallManager(const CallConfig& cfg = CallConfig());
    ~VoiceCallManager();
    VoiceCallManager(const VoiceCallManager&) = delete;
    VoiceCallManager& operator=(const VoiceCallManager&) = delete;

    void stop();

    // Provide a callback used by the engine to emit VOICE_STREAM payloads back
    // to the session/network layer.
    void set_outbound_message_callback(OutboundCallback cb);

    // ----- Caller API -----
    // Offer a call to a connected peer. Returns the call id, or "" on failure
    // (peer not connected / already in a call with this peer / busy).
    std::string start_call(const std::string& peer_id, const std::string& codec,
                           uint16_t sample_rate, uint8_t channels, uint8_t frame_ms);

    // ----- Callee API -----
    bool accept_call(const std::string& call_id);
    bool decline_call(const std::string& call_id);

    // Either side: hang up a call that is OUTGOING / RINGING / IN_CALL.
    bool end_call(const std::string& call_id);

    // Send one audio frame (fire-and-forget). Only allowed while IN_CALL.
    bool send_frame(const std::string& call_id, const uint8_t* data, size_t len);

    // Entry point for the session layer to deliver raw VOICE_STREAM payloads.
    void handle_incoming_message(const std::string& peer_id, std::string_view payload);

    // ----- Event callbacks (set once at wiring time) -----
    void on_call_offered(CallOfferedCallback cb);
    void on_call_state(CallStateCallback cb);
    void on_frame_received(FrameReceivedCallback cb);

    VoiceCallState get_call_state(const std::string& call_id) const;

private:
    struct Call {
        std::string call_id;
        std::string peer_id;
        std::string codec;
        uint16_t sample_rate = kVoiceDefaultSampleRate;
        uint8_t channels = kVoiceDefaultChannels;
        uint8_t frame_ms = kVoiceDefaultFrameMs;
        VoiceCallState state = VoiceCallState::IDLE;
        std::chrono::steady_clock::time_point created_at;
        std::chrono::steady_clock::time_point last_activity;
        uint32_t seq = 0;
    };

    static std::string generate_call_id();
    static std::string encode_control(VoiceControlType type, const std::string& call_id);
    static std::string encode_offer(const std::string& call_id, const std::string& codec,
                                    uint16_t sample_rate, uint8_t channels, uint8_t frame_ms);
    static std::string encode_frame(const std::string& call_id, uint32_t seq,
                                    const uint8_t* data, size_t len);
    // Returns the call_id on a well-formed id field (single-byte length).
    static bool parse_id_field(std::string_view payload, size_t& offset, std::string& out);

    void send_payload(const std::string& peer_id, const std::string& payload);
    void dispatch_state(const std::string& call_id, const std::string& peer_id,
                        VoiceCallState state, const std::string& detail);
    void watchdog_loop();
    // Removes the call (if present) and fires ENDED with `detail`.
    void terminate_call_locked(const std::string& call_id, const std::string& detail);

    mutable std::mutex m_mutex;
    std::map<std::string, Call> m_calls;  // keyed by call_id

    OutboundCallback m_outbound_cb;
    CallOfferedCallback m_offered_cb;
    CallStateCallback m_state_cb;
    FrameReceivedCallback m_frame_cb;
    std::mutex m_cb_mutex;

    uint32_t m_ring_timeout_ms;
    uint32_t m_media_timeout_ms;
    std::atomic<bool> m_running{true};
    std::thread m_watchdog_thread;
};

#endif // VOICE_CALL_MANAGER_H
