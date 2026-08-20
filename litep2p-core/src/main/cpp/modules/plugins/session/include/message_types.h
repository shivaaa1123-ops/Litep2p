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

    // Network OS Phase 3: generic network-object envelope framing (carries a
    // serialized obj::NetworkObject inside the existing session framing).
    NETWORK_OBJECT       = 0x33,

    // Network OS Phase 4: confirmed remote storage (two-phase durable
    // handoff, master doc §82 typed frames). Point-to-point session frames
    // between the sender and a carrier (the relay/mailbox roles from P2);
    // they ride the encrypted session channel and are never batched.
    OBJECT_OFFER         = 0x34,   // offer: object_id, size, payload_hash, lease ask
    OBJECT_ACCEPT        = 0x35,   // accept: offered lease terms (carrier->sender)
    OBJECT_REJECT        = 0x36,   // reject: structured reason + retry_after
    OBJECT_DATA          = 0x37,   // payload: serialized NetworkObject envelope
    STORED_ACK           = 0x38,   // signed storage lease (carrier->sender)

    // High-volume frames (not batched) for file transfer.
    FILE_TRANSFER        = 0x20,

    // Realtime voice-call frames (control + audio, not batched). Frames are
    // fire-and-forget: the app tolerates loss instead of retransmitting.
    VOICE_STREAM         = 0x21
};
