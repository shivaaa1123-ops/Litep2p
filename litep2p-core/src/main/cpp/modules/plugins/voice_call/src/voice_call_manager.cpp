#include "voice_call_manager.h"

#include "logger.h"

#include <algorithm>
#include <cstring>
#include <random>

namespace {

constexpr size_t kMaxCallIdLen = 64;
constexpr size_t kMaxCodecLen = 32;

uint16_t read_u16_le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

void write_u16_le(std::string& out, uint16_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}

void write_u32_le(std::string& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
    }
}

std::string generate_uuid() {
    static thread_local std::mt19937 gen{std::random_device{}()};
    static constexpr char hex_chars[] = "0123456789abcdef";
    auto rnd_hex = [&](int n) {
        std::string s;
        s.reserve(n);
        for (int i = 0; i < n; ++i) s += hex_chars[gen() % 16];
        return s;
    };
    return rnd_hex(8) + "-" + rnd_hex(4) + "-" + rnd_hex(4) + "-" +
           rnd_hex(4) + "-" + rnd_hex(12);
}

} // namespace

// ============================================================================
// VoiceCallManager — construction / teardown
// ============================================================================

VoiceCallManager::VoiceCallManager(const CallConfig& cfg)
    : m_ring_timeout_ms(cfg.ring_timeout_ms), m_media_timeout_ms(cfg.media_timeout_ms) {
    m_watchdog_thread = std::thread(&VoiceCallManager::watchdog_loop, this);
    LOG_INFO("VC: VoiceCallManager initialized (ring_timeout_ms=" +
             std::to_string(m_ring_timeout_ms) + ", media_timeout_ms=" +
             std::to_string(m_media_timeout_ms) + ")");
}

VoiceCallManager::~VoiceCallManager() {
    stop();
}


// ============================================================================
// Callback registration
// ============================================================================

void VoiceCallManager::set_outbound_message_callback(OutboundCallback cb) {
    std::lock_guard<std::mutex> lk(m_cb_mutex);
    m_outbound_cb = std::move(cb);
}

void VoiceCallManager::on_call_offered(CallOfferedCallback cb) {
    std::lock_guard<std::mutex> lk(m_cb_mutex);
    m_offered_cb = std::move(cb);
}

void VoiceCallManager::on_call_state(CallStateCallback cb) {
    std::lock_guard<std::mutex> lk(m_cb_mutex);
    m_state_cb = std::move(cb);
}

void VoiceCallManager::on_frame_received(FrameReceivedCallback cb) {
    std::lock_guard<std::mutex> lk(m_cb_mutex);
    m_frame_cb = std::move(cb);
}

// ============================================================================
// Wire encoding
// ============================================================================

std::string VoiceCallManager::encode_control(VoiceControlType type,
                                             const std::string& call_id) {
    std::string out;
    out.push_back(static_cast<char>(type));
    out.push_back(static_cast<char>(static_cast<uint8_t>(call_id.size())));
    out.append(call_id);
    return out;
}

std::string VoiceCallManager::encode_offer(const std::string& call_id,
                                           const std::string& codec,
                                           uint16_t sample_rate, uint8_t channels,
                                           uint8_t frame_ms) {
    std::string out;
    out.push_back(static_cast<char>(VoiceControlType::OFFER));
    out.push_back(static_cast<char>(static_cast<uint8_t>(call_id.size())));
    out.append(call_id);
    out.push_back(static_cast<char>(static_cast<uint8_t>(codec.size())));
    out.append(codec);
    write_u16_le(out, sample_rate);
    out.push_back(static_cast<char>(channels));
    out.push_back(static_cast<char>(frame_ms));
    return out;
}

std::string VoiceCallManager::encode_frame(const std::string& call_id, uint32_t seq,
                                           const uint8_t* data, size_t len) {
    std::string out;
    out.push_back(static_cast<char>(VoiceControlType::FRAME));
    out.push_back(static_cast<char>(static_cast<uint8_t>(call_id.size())));
    out.append(call_id);
    write_u32_le(out, seq);
    out.append(reinterpret_cast<const char*>(data), len);
    return out;
}

bool VoiceCallManager::parse_id_field(std::string_view payload, size_t& offset,
                                      std::string& out) {
    if (offset >= payload.size()) return false;
    const uint8_t id_len = static_cast<uint8_t>(payload[offset++]);
    if (id_len == 0 || id_len > kMaxCallIdLen) return false;
    if (offset + id_len > payload.size()) return false;
    out.assign(payload.data() + offset, id_len);
    offset += id_len;
    return true;
}

void VoiceCallManager::stop() {
    m_running.store(false, std::memory_order_release);
    if (m_watchdog_thread.joinable()) {
        m_watchdog_thread.join();
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_calls.clear();
    LOG_INFO("VC: VoiceCallManager shutdown complete");
}


// ============================================================================
// Outbound
// ============================================================================

void VoiceCallManager::send_payload(const std::string& peer_id,
                                    const std::string& payload) {
    OutboundCallback outbound;
    {
        std::lock_guard<std::mutex> lk(m_cb_mutex);
        outbound = m_outbound_cb;
    }
    if (!outbound) {
        LOG_WARN("VC: Dropping outbound frame (no outbound callback wired)");
        return;
    }
    outbound(peer_id, payload);
}

std::string VoiceCallManager::start_call(const std::string& peer_id,
                                         const std::string& codec,
                                         uint16_t sample_rate, uint8_t channels,
                                         uint8_t frame_ms) {
    if (peer_id.empty()) {
        LOG_WARN("VC: start_call rejected (empty peer id)");
        return "";
    }
    if (codec.empty() || codec.size() > kMaxCodecLen || sample_rate == 0 ||
        channels == 0 || channels > 2 || frame_ms == 0) {
        LOG_WARN("VC: start_call rejected (invalid codec/profile)");
        return "";
    }
    const std::string call_id = generate_uuid();
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // One active call per peer keeps the media path unambiguous.
        for (const auto& kv : m_calls) {
            const Call& c = kv.second;
            if (c.peer_id == peer_id && c.state != VoiceCallState::ENDED) {
                LOG_WARN("VC: start_call rejected (call already active with " + peer_id + ")");
                return "";
            }
        }
        Call call;
        call.call_id = call_id;
        call.peer_id = peer_id;
        call.codec = codec;
        call.sample_rate = sample_rate;
        call.channels = channels;
        call.frame_ms = frame_ms;
        call.state = VoiceCallState::OUTGOING;
        call.created_at = std::chrono::steady_clock::now();
        call.last_activity = call.created_at;
        m_calls.emplace(call_id, std::move(call));
    }
    // Notify locally BEFORE transmitting so a fast (loopback) peer response can
    // never clobber the OUTGOING snapshot with a newer state.
    dispatch_state(call_id, peer_id, VoiceCallState::OUTGOING, "offered");
    send_payload(peer_id, encode_offer(call_id, codec, sample_rate, channels, frame_ms));
    LOG_INFO("VC: Call offered: " + call_id + " to " + peer_id + " codec=" + codec +
             " rate=" + std::to_string(sample_rate) + " ch=" + std::to_string(channels) +
             " frame_ms=" + std::to_string(frame_ms));
    return call_id;
}

bool VoiceCallManager::accept_call(const std::string& call_id) {
    if (call_id.empty()) return false;
    std::string peer_id;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_calls.find(call_id);
        if (it == m_calls.end()) {
            LOG_WARN("VC: accept_call - call not found: " + call_id);
            return false;
        }
        Call& c = it->second;
        if (c.state != VoiceCallState::OUTGOING && c.state != VoiceCallState::RINGING) {
            LOG_WARN("VC: accept_call - call " + call_id + " not awaiting decision");
            return false;
        }
        c.state = VoiceCallState::IN_CALL;
        c.last_activity = std::chrono::steady_clock::now();
        peer_id = c.peer_id;
    }
    send_payload(peer_id, encode_control(VoiceControlType::ACCEPT, call_id));
    dispatch_state(call_id, peer_id, VoiceCallState::IN_CALL, "connected");
    LOG_INFO("VC: Call accepted: " + call_id + " with " + peer_id);
    return true;
}

bool VoiceCallManager::decline_call(const std::string& call_id) {
    if (call_id.empty()) return false;
    std::string peer_id;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_calls.find(call_id);
        if (it == m_calls.end()) return false;
        peer_id = it->second.peer_id;
    }
    send_payload(peer_id, encode_control(VoiceControlType::DECLINE, call_id));
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_calls.find(call_id);
        if (it != m_calls.end()) m_calls.erase(it);
    }
    dispatch_state(call_id, peer_id, VoiceCallState::ENDED, "declined");
    LOG_INFO("VC: Call declined: " + call_id);
    return true;
}

bool VoiceCallManager::end_call(const std::string& call_id) {
    if (call_id.empty()) return false;
    std::string peer_id;
    bool active = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_calls.find(call_id);
        if (it == m_calls.end()) return false;
        peer_id = it->second.peer_id;
        active = it->second.state == VoiceCallState::IN_CALL ||
                 it->second.state == VoiceCallState::RINGING ||
                 it->second.state == VoiceCallState::OUTGOING;
    }
    if (active) {
        send_payload(peer_id, encode_control(VoiceControlType::END, call_id));
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_calls.find(call_id);
        if (it != m_calls.end()) m_calls.erase(it);
    }
    dispatch_state(call_id, peer_id, VoiceCallState::ENDED, "ended");
    LOG_INFO("VC: Call ended: " + call_id);
    return true;
}

bool VoiceCallManager::send_frame(const std::string& call_id, const uint8_t* data,
                                  size_t len) {
    if (call_id.empty() || (!data && len > 0)) return false;
    if (len > kVoiceMaxFrameBytes) {
        LOG_WARN("VC: Dropping oversize voice frame (" + std::to_string(len) + " B)");
        return false;
    }
    std::string peer_id;
    std::string payload;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_calls.find(call_id);
        if (it == m_calls.end()) return false;
        Call& c = it->second;
        if (c.state != VoiceCallState::IN_CALL) return false;
        peer_id = c.peer_id;
        payload = encode_frame(call_id, c.seq++, data, len);
        c.last_activity = std::chrono::steady_clock::now();
    }
    send_payload(peer_id, payload);
    return true;
}

VoiceCallState VoiceCallManager::get_call_state(const std::string& call_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_calls.find(call_id);
    return it == m_calls.end() ? VoiceCallState::IDLE : it->second.state;
}


// ============================================================================
// Inbound
// ============================================================================

void VoiceCallManager::handle_incoming_message(const std::string& peer_id,
                                               std::string_view payload) {
    if (payload.empty()) return;

    const uint8_t subtype = static_cast<uint8_t>(payload[0]);
    size_t offset = 1;

    // All subtypes share the leading id field.
    std::string call_id;
    if (!parse_id_field(payload, offset, call_id)) {
        LOG_WARN("VC: Malformed voice payload (bad call id) from " + peer_id);
        return;
    }

    switch (static_cast<VoiceControlType>(subtype)) {
        case VoiceControlType::OFFER: {
            // [codec_len][codec][sample_rate u16][channels u8][frame_ms u8]
            if (offset >= payload.size()) return;
            const uint8_t codec_len = static_cast<uint8_t>(payload[offset++]);
            if (codec_len == 0 || codec_len > kMaxCodecLen ||
                offset + codec_len + 4 > payload.size()) {
                LOG_WARN("VC: Malformed OFFER from " + peer_id);
                return;
            }
            std::string codec(payload.data() + offset, codec_len);
            offset += codec_len;
            const uint16_t sample_rate = read_u16_le(
                reinterpret_cast<const uint8_t*>(payload.data()) + offset);
            offset += 2;
            const uint8_t channels = static_cast<uint8_t>(payload[offset++]);
            const uint8_t frame_ms = static_cast<uint8_t>(payload[offset++]);
            if (sample_rate == 0 || channels == 0 || channels > 2 || frame_ms == 0) {
                LOG_WARN("VC: Invalid OFFER profile from " + peer_id);
                return;
            }

            bool busy = false;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                for (const auto& kv : m_calls) {
                    const Call& c = kv.second;
                    if (c.peer_id == peer_id && c.state != VoiceCallState::ENDED) {
                        busy = true;
                        break;
                    }
                }
                if (!busy) {
                    Call call;
                    call.call_id = call_id;
                    call.peer_id = peer_id;
                    call.codec = codec;
                    call.sample_rate = sample_rate;
                    call.channels = channels;
                    call.frame_ms = frame_ms;
                    call.state = VoiceCallState::RINGING;
                    call.created_at = std::chrono::steady_clock::now();
                    call.last_activity = call.created_at;
                    m_calls.emplace(call_id, std::move(call));
                }
            }
            if (busy) {
                LOG_WARN("VC: Auto-declining " + call_id + " (call already active with " + peer_id + ")");
                send_payload(peer_id, encode_control(VoiceControlType::DECLINE, call_id));
                return;
            }
            LOG_INFO("VC: Incoming call offer: " + call_id + " from " + peer_id +
                     " codec=" + codec + " rate=" + std::to_string(sample_rate) +
                     " ch=" + std::to_string(channels) + " frame_ms=" + std::to_string(frame_ms));
            CallOfferedCallback cb;
            {
                std::lock_guard<std::mutex> lk(m_cb_mutex);
                cb = m_offered_cb;
            }
            if (cb) cb(call_id, peer_id, codec, sample_rate, channels, frame_ms);
            break;
        }


        case VoiceControlType::ACCEPT: {
            bool accepted = false;
            std::string call_peer;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto it = m_calls.find(call_id);
                if (it != m_calls.end() && it->second.state == VoiceCallState::OUTGOING) {
                    it->second.state = VoiceCallState::IN_CALL;
                    it->second.last_activity = std::chrono::steady_clock::now();
                    call_peer = it->second.peer_id;
                    accepted = true;
                }
            }
            if (accepted) {
                dispatch_state(call_id, call_peer, VoiceCallState::IN_CALL, "connected");
                LOG_INFO("VC: Call accepted by peer: " + call_id);
            }
            break;
        }
        case VoiceControlType::DECLINE: {
            std::string call_peer;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto it = m_calls.find(call_id);
                if (it != m_calls.end()) {
                    call_peer = it->second.peer_id;
                    m_calls.erase(it);
                }
            }
            if (!call_peer.empty()) {
                dispatch_state(call_id, call_peer, VoiceCallState::ENDED, "declined by peer");
                LOG_INFO("VC: Call declined by peer: " + call_id);
            }
            break;
        }
        case VoiceControlType::END: {
            std::string call_peer;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto it = m_calls.find(call_id);
                if (it != m_calls.end()) {
                    call_peer = it->second.peer_id;
                    m_calls.erase(it);
                }
            }
            if (!call_peer.empty()) {
                dispatch_state(call_id, call_peer, VoiceCallState::ENDED, "ended by peer");
                LOG_INFO("VC: Call ended by peer: " + call_id);
            }
            break;
        }
        case VoiceControlType::FRAME: {
            // [id_len][call_id][seq u32][audio...]
            if (offset + 4 > payload.size()) return;
            offset += 4;  // skip the sequence number — it is not audio data
            const uint8_t* data = reinterpret_cast<const uint8_t*>(payload.data()) + offset;
            const size_t len = payload.size() - offset;
            FrameReceivedCallback cb;
            {
                std::lock_guard<std::mutex> lk(m_cb_mutex);
                cb = m_frame_cb;
            }
            if (!cb) return;
            bool active = false;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto it = m_calls.find(call_id);
                if (it != m_calls.end() && it->second.state == VoiceCallState::IN_CALL) {
                    it->second.last_activity = std::chrono::steady_clock::now();
                    active = true;
                }
            }
            if (active) cb(call_id, peer_id, data, len);
            break;
        }
        default:
            LOG_WARN("VC: Unknown voice subtype " + std::to_string(subtype) + " from " + peer_id);
            break;
    }
}


// ============================================================================
// Internal helpers
// ============================================================================

void VoiceCallManager::dispatch_state(const std::string& call_id,
                                      const std::string& peer_id,
                                      VoiceCallState state, const std::string& detail) {
    CallStateCallback cb;
    {
        std::lock_guard<std::mutex> lk(m_cb_mutex);
        cb = m_state_cb;
    }
    if (cb) cb(call_id, peer_id, state, detail);
}

void VoiceCallManager::watchdog_loop() {
    using clock = std::chrono::steady_clock;
    while (m_running.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        const auto now = clock::now();
        std::vector<std::pair<std::string, std::string>> ring_timeouts;  // (call_id, peer_id)
        std::vector<std::pair<std::string, std::string>> dead_calls;     // IN_CALL no media
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto it = m_calls.begin(); it != m_calls.end();) {
                Call& c = it->second;
                const bool unanswered = (c.state == VoiceCallState::RINGING) ||
                                        (c.state == VoiceCallState::OUTGOING);
                if (unanswered &&
                    now - c.created_at > std::chrono::milliseconds(m_ring_timeout_ms)) {
                    ring_timeouts.emplace_back(c.call_id, c.peer_id);
                    it = m_calls.erase(it);
                } else if (c.state == VoiceCallState::IN_CALL &&
                           m_media_timeout_ms > 0 &&
                           now - c.last_activity > std::chrono::milliseconds(m_media_timeout_ms)) {
                    dead_calls.emplace_back(c.call_id, c.peer_id);
                    it = m_calls.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (const auto& [call_id, peer_id] : ring_timeouts) {
            // The callee politely declines; the caller just drops silently.
            send_payload(peer_id, encode_control(VoiceControlType::DECLINE, call_id));
            dispatch_state(call_id, peer_id, VoiceCallState::ENDED, "ring timeout");
            LOG_WARN("VC: Call " + call_id + " timed out waiting for answer");
        }
        for (const auto& [call_id, peer_id] : dead_calls) {
            send_payload(peer_id, encode_control(VoiceControlType::END, call_id));
            dispatch_state(call_id, peer_id, VoiceCallState::ENDED, "no media activity");
            LOG_WARN("VC: Call " + call_id + " ended: no media activity for " +
                     std::to_string(m_media_timeout_ms) + " ms");
        }
    }
}
