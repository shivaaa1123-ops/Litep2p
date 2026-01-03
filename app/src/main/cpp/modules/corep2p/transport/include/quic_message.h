#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

// Simple QUIC-like packet structure for LiteP2P
// Header: [Flags (1)] [ConnectionID (8)] [PacketNumber (4)]
class QuicMessage {
public:
    struct Header {
        uint8_t flags;
        uint64_t connection_id;
        uint32_t packet_number;
    };

    // Encapsulates a payload into a QUIC-like packet
    static std::string framePacket(uint64_t connection_id, uint32_t packet_number, const std::string& payload);

    // Parses a raw buffer into a header and payload
    // Returns true if successful, false if packet is too short or invalid
    static bool parsePacket(const std::vector<uint8_t>& buffer, Header& out_header, std::string& out_payload);

    // Sends a QUIC packet over a UDP socket
    static bool send(int socket, const std::string& ip, int port, uint64_t connection_id, uint32_t packet_number, const std::string& payload);
};
