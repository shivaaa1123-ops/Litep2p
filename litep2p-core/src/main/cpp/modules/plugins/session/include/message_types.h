#pragma once

#include <cstdint>

enum class MessageType : uint8_t {
    CONTROL_PING         = 0x01,
    CONTROL_PONG         = 0x02,
    CONTROL_CONNECT      = 0x03,
    CONTROL_CONNECT_ACK  = 0x04,
    HANDSHAKE_NOISE      = 0x10,
    ENCRYPTED_DATA       = 0x11,
    APPLICATION_DATA     = 0x12,
    APPLICATION_ACK      = 0x13,

    // Proxy module frames (optional module, but enum values are always reserved).
    PROXY_CONTROL        = 0x30,
    PROXY_STREAM_DATA    = 0x31,

    // Overlay module frames (optional module; multi-hop LPX2 envelopes,
    // relay advertisements, mailbox traffic).
    OVERLAY_FRAME        = 0x32,

    // High-volume frames (not batched) for file transfer.
    FILE_TRANSFER        = 0x20,

    // Realtime voice-call frames (control + audio, not batched). Frames are
    // fire-and-forget: the app tolerates loss instead of retransmitting.
    VOICE_STREAM         = 0x21
};
