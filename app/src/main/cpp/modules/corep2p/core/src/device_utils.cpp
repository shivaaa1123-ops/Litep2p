#include "device_utils.h"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstring>
#include <algorithm>

#if defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__)
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#if defined(__APPLE__)
#include <net/if_dl.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <netpacket/packet.h>
#endif

namespace {

// Helper to generate random ID if MAC fails
std::string generate_random_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    const char* hex = "0123456789abcdef";
    std::string id = "litep2p-random-";
    
    for (int i = 0; i < 12; i++) {
        id += hex[dis(gen)];
    }
    return id;
}

} // namespace

std::string get_persistent_device_id() {
    std::string mac_addr;
    
#if defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__)
    struct ifaddrs *ifaddr = nullptr, *ifa = nullptr;
    
    if (getifaddrs(&ifaddr) == -1) {
        return generate_random_id();
    }

    // Iterate through interfaces
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        // Skip loopback
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
        
        // Look for active interfaces (UP and RUNNING)
        if ((ifa->ifa_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) continue;

#if defined(__APPLE__)
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
            if (sdl->sdl_alen == 6) { // MAC address length
                unsigned char* mac = (unsigned char*)LLADDR(sdl);
                std::stringstream ss;
                ss << std::hex << std::setfill('0');
                for (int i = 0; i < 6; i++) {
                    ss << std::setw(2) << (int)mac[i];
                }
                mac_addr = ss.str();
                // Prefer en0 (WiFi) or en1
                std::string name(ifa->ifa_name);
                if (name == "en0" || name == "wlan0" || name == "eth0") {
                    break; // Found a good candidate
                }
            }
        }
#elif defined(__linux__) || defined(__ANDROID__)
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* sll = (struct sockaddr_ll*)ifa->ifa_addr;
            if (sll->sll_halen == 6) {
                std::stringstream ss;
                ss << std::hex << std::setfill('0');
                for (int i = 0; i < 6; i++) {
                    ss << std::setw(2) << (int)sll->sll_addr[i];
                }
                mac_addr = ss.str();
                // Prefer wlan0 or eth0
                std::string name(ifa->ifa_name);
                if (name == "wlan0" || name == "eth0") {
                    break;
                }
            }
        }
#endif
    }

    freeifaddrs(ifaddr);
#endif

    if (!mac_addr.empty()) {
        return "litep2p-device-" + mac_addr;
    }

    return generate_random_id();
}

std::vector<std::string> get_active_ipv4_addresses() {
    std::vector<std::string> addresses;
    
#if defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__)
    struct ifaddrs *ifaddr = nullptr, *ifa = nullptr;
    
    if (getifaddrs(&ifaddr) == -1) {
        return addresses;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        // Skip loopback
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
        
        // Only active interfaces
        if ((ifa->ifa_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) continue;
        
        // Only IPv4
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        
        struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
        char ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sin->sin_addr, ip_str, INET_ADDRSTRLEN) != nullptr) {
            addresses.push_back(std::string(ip_str));
        }
    }

    freeifaddrs(ifaddr);
#endif

    return addresses;
}

std::string get_primary_ipv4_address() {
    std::vector<std::string> addresses = get_active_ipv4_addresses();
    if (addresses.empty()) {
        return "";
    }
    
    // Prefer non-169.254.x.x (link-local) addresses
    for (const auto& addr : addresses) {
        if (addr.rfind("169.254.", 0) != 0) {
            return addr;
        }
    }
    
    // Fallback to first address
    return addresses[0];
}

// ============================================================================
// IPv6 support (preferred when available)
// ============================================================================

namespace {

bool is_ipv6_link_local(const struct in6_addr& addr) {
    // fe80::/10
    return (addr.s6_addr[0] == 0xFE) && ((addr.s6_addr[1] & 0xC0) == 0x80);
}

bool is_ipv6_multicast(const struct in6_addr& addr) {
    return addr.s6_addr[0] == 0xFF;
}

bool is_ipv6_v4_mapped(const struct in6_addr& addr) {
    // ::ffff:a.b.c.d
    for (int i = 0; i < 10; ++i) {
        if (addr.s6_addr[i] != 0) return false;
    }
    return addr.s6_addr[10] == 0xFF && addr.s6_addr[11] == 0xFF;
}

bool is_ipv6_global(const struct in6_addr& addr) {
    // 2000::/3
    return (addr.s6_addr[0] & 0xE0) == 0x20;
}

} // namespace

std::vector<std::string> get_active_ipv6_addresses() {
    std::vector<std::string> addresses;

#if defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__)
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        return addresses;
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
        if ((ifa->ifa_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) continue;
        if (ifa->ifa_addr->sa_family != AF_INET6) continue;

        const struct sockaddr_in6* sin6 =
            reinterpret_cast<const struct sockaddr_in6*>(ifa->ifa_addr);
        const struct in6_addr& a = sin6->sin6_addr;

        if (is_ipv6_link_local(a) || is_ipv6_multicast(a) ||
            is_ipv6_v4_mapped(a) || IN6_IS_ADDR_LOOPBACK(&a)) {
            continue;
        }

        char ip_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &a, ip_str, INET6_ADDRSTRLEN) != nullptr) {
            addresses.push_back(ip_str);
        }
    }

    freeifaddrs(ifaddr);
#endif

    return addresses;
}

std::string get_primary_ip_address() {
    // IPv6-preferred policy (mirrors RFC 6724 default policy):
    // 1. global IPv6 (2000::/3)
    // 2. unique-local IPv6 (fc00::/7)
    // 3. IPv4 (non-link-local preferred)
    std::string ula_fallback;

    const auto v6 = get_active_ipv6_addresses();
    for (const auto& addr : v6) {
        // Parse to classify.
        struct in6_addr parsed;
        if (inet_pton(AF_INET6, addr.c_str(), &parsed) != 1) continue;
        if (is_ipv6_global(parsed)) {
            return addr;
        }
        if (ula_fallback.empty()) {
            ula_fallback = addr;
        }
    }
    if (!ula_fallback.empty()) {
        return ula_fallback;
    }

    return get_primary_ipv4_address();
}

bool has_ipv6_connectivity() {
    return !get_active_ipv6_addresses().empty();
}

// ============================================================================
// Endpoint helpers (IPv6-aware)
// ============================================================================

bool is_ipv6_literal(const std::string& host) {
    return host.find(':') != std::string::npos;
}

std::string format_network_id(const std::string& host, uint16_t port) {
    if (is_ipv6_literal(host)) {
        return "[" + host + "]:" + std::to_string(port);
    }
    return host + ":" + std::to_string(port);
}

bool parse_network_id(const std::string& network_id, std::string& host, uint16_t& port) {
    host.clear();
    port = 0;
    if (network_id.empty()) return false;

    if (network_id[0] == '[') {
        // Bracketed IPv6: "[v6]" or "[v6]:port"
        const size_t close = network_id.find(']');
        if (close == std::string::npos || close < 2) return false;
        host = network_id.substr(1, close - 1);
        if (host.find(':') == std::string::npos) return false; // not an IPv6 literal

        if (close + 1 < network_id.size()) {
            if (network_id[close + 1] != ':') return false;
            const std::string port_str = network_id.substr(close + 2);
            if (port_str.empty()) return false;
            try {
                const int p = std::stoi(port_str);
                if (p < 0 || p > 65535) return false;
                port = static_cast<uint16_t>(p);
            } catch (...) {
                return false;
            }
        }
        return true;
    }

    // Unbracketed: "host" or "host:port". For IPv6 literals without brackets,
    // only allow the bare form (no port - ambiguous otherwise).
    const size_t colon = network_id.find(':');
    if (colon == std::string::npos) {
        host = network_id;
        return !host.empty();
    }
    if (network_id.find(':', colon + 1) != std::string::npos) {
        // Multiple colons: bare IPv6 literal without port.
        host = network_id;
        return !host.empty();
    }

    host = network_id.substr(0, colon);
    const std::string port_str = network_id.substr(colon + 1);
    if (host.empty() || port_str.empty()) return false;
    try {
        const int p = std::stoi(port_str);
        if (p < 0 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } catch (...) {
        return false;
    }
    return true;
}

std::string sockaddr_to_network_id(const struct sockaddr* sa) {
    if (sa == nullptr) return {};

    char host[INET6_ADDRSTRLEN];
    uint16_t port = 0;

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(sa);
        if (inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host)) == nullptr) return {};
        port = ntohs(sin->sin_port);
        return format_network_id(host, port);
    }

    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* sin6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        port = ntohs(sin6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            struct in_addr v4;
            std::memcpy(&v4, reinterpret_cast<const uint8_t*>(&sin6->sin6_addr) + 12, 4);
            if (inet_ntop(AF_INET, &v4, host, sizeof(host)) == nullptr) return {};
            return format_network_id(host, port);
        }
        if (inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host)) == nullptr) return {};
        return format_network_id(host, port);
    }

    return {};
}
