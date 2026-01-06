#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <sys/types.h>

class UdpMessage {
public:
    // Sends a payload to a specific IP and port
    // Returns true on success, false on error
    static bool send(int socket, const std::string& ip, int port, const std::string& payload);
    
    // Sends raw data (vector<uint8_t>) to a specific IP and port
    // Returns true on success, false on error
    static bool sendRaw(int socket, const std::string& ip, int port, const std::vector<uint8_t>& data);

    // Checks if the received buffer contains a STUN packet
    // (RFC 5389: first 2 bits are 00, magic cookie at offset 4)
    static bool isStunPacket(const char* buffer, size_t length);
};
