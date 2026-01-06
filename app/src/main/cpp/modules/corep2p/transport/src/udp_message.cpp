#include "udp_message.h"
#include "logger.h"
#include "config_manager.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <random>

bool UdpMessage::send(int socket, const std::string& ip, int port, const std::string& payload) {
    // Simulate packet loss if configured (for testing purposes)
    // This is a simple random drop simulation
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    // Check if we should simulate loss (e.g., 10% loss)
    // In a real scenario, this would be controlled by a config flag
    // For now, we'll assume reliable localhost unless specifically testing loss
    // if (dist(rng) < 0.1) { 
    //     return true; // Pretend we sent it
    // }

    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr) <= 0) {
        nativeLog("UDP Error: Invalid IP address: " + ip);
        return false;
    }

    ssize_t bytes_sent = sendto(socket, payload.c_str(), payload.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (bytes_sent < 0) {
        nativeLog("UDP_SEND_ERROR_INTERNAL: Failed to send message to " + ip + ":" + std::to_string(port) + " (" + strerror(errno) + ")");
        return false;
    } else {
        nativeLog("UDP_SEND_SUCCESS_INTERNAL: Sent message to " + ip + ":" + std::to_string(port));
        return true;
    }
}

bool UdpMessage::sendRaw(int socket, const std::string& ip, int port, const std::vector<uint8_t>& data) {
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr) <= 0) {
        nativeLog("UDP Error: Invalid IP address: " + ip);
        return false;
    }

    ssize_t bytes_sent = sendto(socket, data.data(), data.size(), 0, (sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (bytes_sent < 0) {
        nativeLog("UDP Error: Failed to send raw packet to " + ip + ":" + std::to_string(port) + " (" + strerror(errno) + ")");
        return false;
    }
    return true;
}

bool UdpMessage::isStunPacket(const char* buffer, size_t length) {
    // Check for STUN packet (RFC 5389: first 2 bits are 00, magic cookie at offset 4)
    // STUN Message Type is 0x0001 (Binding Request) or 0x0101 (Binding Response) etc.
    // First byte is 0x00 or 0x01.
    // Magic cookie is 0x2112A442.
    
    if (length < 20) {
        return false;
    }

    uint8_t b0 = static_cast<uint8_t>(buffer[0]);
    if ((b0 & 0xC0) != 0) { // First 2 bits must be 0
        return false;
    }

    uint32_t magic_cookie;
    std::memcpy(&magic_cookie, buffer + 4, 4);
    if (ntohl(magic_cookie) != 0x2112A442) {
        return false;
    }

    return true;
}
