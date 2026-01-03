#pragma once

#include "message_types.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace wire {

// Maximum allowed message size to prevent DoS attacks (10 MB)
inline constexpr uint32_t kMaxMessageSize = 10u * 1024u * 1024u;

// Simple binary format: [type: 1 byte][length: 4 bytes big-endian][payload: length bytes]
std::string encode_message(MessageType type, std::string_view payload);

// Decodes a wire message into type and payload. Returns false if malformed or too large.
bool decode_message(std::string_view data, MessageType& type, std::string_view& payload);

// Convenience overload that copies payload into a std::string (matches older call sites).
bool decode_message(const std::string& data, MessageType& type, std::string& payload);

} // namespace wire
