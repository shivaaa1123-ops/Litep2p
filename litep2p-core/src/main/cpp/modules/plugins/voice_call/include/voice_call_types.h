#pragma once

#include <cstdint>

/**
 * VOICE CALL MODULE — realtime audio calls between peers.
 *
 * Control plane (reliable small frames): OFFER / ACCEPT / DECLINE / END.
 * Data plane (fire-and-forget, loss-tolerant): FRAME. No ACK/retransmit —
 * that is exactly what realtime audio wants (a late retransmit is useless).
 *
 * The engine is codec-agnostic: a FRAME payload is opaque bytes owned by the
 * application (Android: PCM S16LE; a future Opus codec slots in without any
 * wire-protocol change).
 *
 * Wire subtypes carried inside MessageType::VOICE_STREAM payloads. All
 * integers on the wire are little-endian; strings are length-prefixed with a
 * single byte.
 */

enum class VoiceControlType : uint8_t {
    OFFER   = 1,  // [id_len][call_id][codec_len][codec][sample_rate u16][channels u8][frame_ms u8]
    ACCEPT  = 2,  // [id_len][call_id]
    DECLINE = 3,  // [id_len][call_id]
    END     = 4,  // [id_len][call_id]
    FRAME   = 5,  // [id_len][call_id][seq u32][audio bytes...]
};

enum class VoiceCallState : uint8_t {
    IDLE     = 0,  // no call
    OUTGOING = 1,  // caller: offer sent, awaiting accept/decline
    RINGING  = 2,  // callee: offer received, awaiting user decision
    IN_CALL  = 3,  // connected; audio flows both ways
    ENDED    = 4,  // terminal: ended/declined/ring timeout (call removed)
};

// Default audio profile offered by the app when the peer does not negotiate.
inline constexpr uint16_t kVoiceDefaultSampleRate = 16000;  // Hz
inline constexpr uint8_t  kVoiceDefaultChannels   = 1;      // mono
inline constexpr uint8_t  kVoiceDefaultFrameMs    = 20;     // audio packet period
inline constexpr uint32_t kVoiceRingTimeoutMs     = 60000;  // unanswered offer lifetime
inline constexpr uint32_t kVoiceMaxFrameBytes     = 8192;   // sanity cap for FRAME payloads
