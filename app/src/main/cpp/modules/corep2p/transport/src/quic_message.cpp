#include "quic_message.h"
#include "logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>

// Helper to write integers in network byte order (Big Endian)
static void write_uint64(std::string& buf, uint64_t val) {
    // Simple implementation, assuming little-endian host for now or using standard conversion if available
    // For simplicity in this mock, we'll just append bytes. 
    // In production, use htobe64.
    for (int i = 7; i >= 0; --i) {
        buf.push_back((val >> (i * 8)) & 0xFF);
    }
}

static void write_uint32(std::string& buf, uint32_t val) {
    uint32_t net_val = htonl(val);
    const char* p = reinterpret_cast<const char*>(&net_val);
    buf.append(p, 4);
}

static uint64_t read_uint64(const uint8_t* ptr) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | ptr[i];
    }
    return val;
}

static uint32_t read_uint32(const uint8_t* ptr) {
    uint32_t net_val;
    std::memcpy(&net_val, ptr, 4);
    return ntohl(net_val);
}

std::string QuicMessage::framePacket(uint64_t connection_id, uint32_t packet_number, const std::string& payload) {
    std::string packet;
    packet.reserve(1 + 8 + 4 + payload.size());
    
    // Flags (0x40 = Fixed bit for QUIC Short Header, just a mock)
    packet.push_back(0x40); 
    
    write_uint64(packet, connection_id);
    write_uint32(packet, packet_number);
    packet.append(payload);
    
    return packet;
}

bool QuicMessage::parsePacket(const std::vector<uint8_t>& buffer, Header& out_header, std::string& out_payload) {
    if (buffer.size() < 13) { // 1 + 8 + 4
        return false;
    }
    
    const uint8_t* ptr = buffer.data();
    out_header.flags = ptr[0];
    out_header.connection_id = read_uint64(ptr + 1);
    out_header.packet_number = read_uint32(ptr + 9);
    
    out_payload.assign(reinterpret_cast<const char*>(ptr + 13), buffer.size() - 13);
    return true;
}

bool QuicMessage::send(int socket, const std::string& ip, int port, uint64_t connection_id, uint32_t packet_number, const std::string& payload) {
    std::string packet = framePacket(connection_id, packet_number, payload);
    
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr) <= 0) {
        nativeLog("QUIC Error: Invalid IP address: " + ip);
        return false;
    }

    ssize_t bytes_sent = sendto(socket, packet.c_str(), packet.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (bytes_sent < 0) {
        nativeLog("QUIC Error: sendto failed: " + std::string(strerror(errno)));
        return false;
    }
    return true;
}
