#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>
#include <vector>

// Protocol message types
enum class MessageType {
    HELLO = 1,
    PING,
    PONG,
    DATA,
    GOODBYE
};

// Protocol helper functions
inline std::string getMessageTypeString(MessageType type) {
    switch (type) {
        case MessageType::HELLO: return "HELLO";
        case MessageType::PING: return "PING";
        case MessageType::PONG: return "PONG";
        case MessageType::DATA: return "DATA";
        case MessageType::GOODBYE: return "GOODBYE";
        default: return "UNKNOWN";
    }
}

inline std::vector<uint8_t> createMessage(MessageType type, const std::string& payload) {
    std::vector<uint8_t> msg;
    msg.push_back(static_cast<uint8_t>(type));
    msg.push_back(static_cast<uint8_t>(payload.size() >> 24));
    msg.push_back(static_cast<uint8_t>(payload.size() >> 16));
    msg.push_back(static_cast<uint8_t>(payload.size() >> 8));
    msg.push_back(static_cast<uint8_t>(payload.size()));
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

#endif
