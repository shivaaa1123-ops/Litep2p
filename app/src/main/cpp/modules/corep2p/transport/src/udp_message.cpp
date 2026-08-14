#include "udp_message.h"
#include "logger.h"
#include "device_utils.h"
#include "config_manager.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <random>


// Determine the socket's address family (dual-stack sockets report AF_INET6).
static int udp_sock_family(int socket_fd) {
    struct sockaddr_storage ss {};
    socklen_t len = sizeof(ss);
    if (getsockname(socket_fd, reinterpret_cast<sockaddr*>(&ss), &len) == 0) {
        return ss.ss_family;
    }
    return AF_INET;
}

// Build a destination sockaddr matching BOTH the destination address family
// and the socket family. Sending to an IPv4 address through an AF_INET6
// dual-stack socket requires a v4-mapped IPv6 address (::ffff:a.b.c.d).
static bool udp_build_dest(int socket_fd, const std::string& ip, int port,
                           sockaddr_storage& dest, socklen_t& dest_len) {
    const int family = udp_sock_family(socket_fd);
    const bool ip_is_v6 = is_ipv6_literal(ip);

    if (family == AF_INET6 && !ip_is_v6) {
        // v4-mapped address on the dual-stack socket.
        auto* d6 = reinterpret_cast<sockaddr_in6*>(&dest);
        memset(d6, 0, sizeof(*d6));
        d6->sin6_family = AF_INET6;
        d6->sin6_port = htons(static_cast<uint16_t>(port));
        d6->sin6_addr.s6_addr[10] = 0xFF;
        d6->sin6_addr.s6_addr[11] = 0xFF;
        if (inet_pton(AF_INET, ip.c_str(), &d6->sin6_addr.s6_addr[12]) <= 0) {
            nativeLog("UDP Error: Invalid IPv4 address: " + ip);
            return false;
        }
        dest_len = sizeof(sockaddr_in6);
        return true;
    }
    if (family == AF_INET6) {
        auto* d6 = reinterpret_cast<sockaddr_in6*>(&dest);
        memset(d6, 0, sizeof(*d6));
        d6->sin6_family = AF_INET6;
        d6->sin6_port = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET6, ip.c_str(), &d6->sin6_addr) <= 0) {
            nativeLog("UDP Error: Invalid IPv6 address: " + ip);
            return false;
        }
        dest_len = sizeof(sockaddr_in6);
        return true;
    }

    // AF_INET socket: IPv4 destinations only.
    if (ip_is_v6) {
        nativeLog("UDP Error: IPv6 destination on an IPv4-only socket: " + ip);
        return false;
    }
    auto* d4 = reinterpret_cast<sockaddr_in*>(&dest);
    memset(d4, 0, sizeof(*d4));
    d4->sin_family = AF_INET;
    d4->sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &d4->sin_addr) <= 0) {
        nativeLog("UDP Error: Invalid IPv4 address: " + ip);
        return false;
    }
    dest_len = sizeof(sockaddr_in);
    return true;
}

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

    sockaddr_storage dest{};
    socklen_t dest_len = 0;
    if (!udp_build_dest(socket, ip, port, dest, dest_len)) {
        return false;
    }

    ssize_t bytes_sent = sendto(socket, payload.c_str(), payload.size(), 0, reinterpret_cast<sockaddr*>(&dest), dest_len);
    
    if (bytes_sent < 0) {
        LOG_WARN("UDP_SEND_ERROR_INTERNAL: Failed to send message to " + ip + ":" + std::to_string(port) + " (" + strerror(errno) + ")");
        return false;
    } else {
        LOG_DEBUG("UDP_SEND_SUCCESS_INTERNAL: Sent message to " + ip + ":" + std::to_string(port));
        return true;
    }
}

bool UdpMessage::sendRaw(int socket, const std::string& ip, int port, const std::vector<uint8_t>& data) {
    sockaddr_storage dest{};
    socklen_t dest_len = 0;
    if (!udp_build_dest(socket, ip, port, dest, dest_len)) {
        return false;
    }

    ssize_t bytes_sent = sendto(socket, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&dest), dest_len);
    
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
