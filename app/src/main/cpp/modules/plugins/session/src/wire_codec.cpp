#include "wire_codec.h"

#include <stdexcept>
#include <iostream>

namespace {
    inline void wire_debug_log(const std::string& msg) {
#ifdef LITEP2P_WIRE_CODEC_DEBUG
        std::cout << msg << std::endl;
#else
        (void)msg;
#endif
    }

    inline bool is_valid_message_type(uint8_t raw) {
        switch (static_cast<MessageType>(raw)) {
            case MessageType::CONTROL_PING:
            case MessageType::CONTROL_PONG:
            case MessageType::CONTROL_CONNECT:
            case MessageType::CONTROL_CONNECT_ACK:
            case MessageType::HANDSHAKE_NOISE:
            case MessageType::ENCRYPTED_DATA:
            case MessageType::APPLICATION_DATA:
            case MessageType::FILE_TRANSFER:
            case MessageType::PROXY_CONTROL:
            case MessageType::PROXY_STREAM_DATA:
                return true;
        }
        return false;
    }
}

namespace wire {

std::string encode_message(MessageType type, std::string_view payload) {
    const uint32_t length = static_cast<uint32_t>(payload.size());

    std::string encoded;
    encoded.reserve(1 + sizeof(uint32_t) + length);

    encoded.push_back(static_cast<char>(type));

    // length big-endian
    encoded.push_back(static_cast<char>((length >> 24) & 0xFF));
    encoded.push_back(static_cast<char>((length >> 16) & 0xFF));
    encoded.push_back(static_cast<char>((length >> 8) & 0xFF));
    encoded.push_back(static_cast<char>(length & 0xFF));

    encoded.append(payload.data(), payload.size());
    return encoded;
}

bool decode_message(std::string_view data, MessageType& type, std::string_view& payload) {
    if (data.size() < 5) {
        return false;
    }

    const uint8_t raw_type = static_cast<uint8_t>(data[0]);
    if (!is_valid_message_type(raw_type)) {
        // Common/expected case: callers probe arbitrary strings to see if they are already
        // wire-framed. Do not emit debug noise for non-wire payloads.
        return false;
    }

    type = static_cast<MessageType>(raw_type);

    const uint32_t length = (static_cast<uint32_t>(static_cast<uint8_t>(data[1])) << 24) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(data[2])) << 16) |
                            (static_cast<uint32_t>(static_cast<uint8_t>(data[3])) << 8) |
                            static_cast<uint32_t>(static_cast<uint8_t>(data[4]));

    if (length > kMaxMessageSize) {
        wire_debug_log("WIRE_DEBUG: Length too large: " + std::to_string(length));
        return false;
    }

    if (data.size() < 5ull + length) {
        wire_debug_log("WIRE_DEBUG: Data incomplete. Expected " + std::to_string(5ull + length) + ", got " +
                       std::to_string(data.size()));
        return false;
    }

    payload = data.substr(5, length);
    return true;
}

bool decode_message(const std::string& data, MessageType& type, std::string& payload) {
    std::string_view view_payload;
    if (!decode_message(std::string_view{data}, type, view_payload)) {
        return false;
    }
    payload.assign(view_payload.data(), view_payload.size());
    return true;
}

} // namespace wire
