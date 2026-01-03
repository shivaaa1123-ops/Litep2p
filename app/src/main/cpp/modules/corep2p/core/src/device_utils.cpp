#include "device_utils.h"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstring>

#if defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__)
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
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
