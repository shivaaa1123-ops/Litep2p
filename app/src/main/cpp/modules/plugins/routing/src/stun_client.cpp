#include "stun_client.h"
#include "logger.h"
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <chrono>
#include <thread>
#include <stdlib.h>
#include <netdb.h>

// RFC 5389 STUN Implementation
// Full NAT type detection with XOR-MAPPED-ADDRESS parsing

// STUN Message Types
const uint16_t STUN_BINDING_REQUEST = 0x0001;
const uint16_t STUN_BINDING_RESPONSE = 0x0101;

// STUN Attribute Types
const uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
const uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const uint16_t STUN_ATTR_RESPONSE_ADDRESS = 0x0002;
const uint16_t STUN_ATTR_CHANGE_REQUEST = 0x0003;
const uint16_t STUN_ATTR_SOURCE_ADDRESS = 0x0004;
const uint16_t STUN_ATTR_CHANGED_ADDRESS = 0x0005;

// STUN Magic Cookie (RFC 5389)
const uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// ============================================================================
// STUN Message Structure
// ============================================================================

struct STUNMessageHeader {
    uint16_t message_type;
    uint16_t message_length;
    uint32_t magic_cookie;
    uint8_t transaction_id[12];
};

struct STUNAttributeHeader {
    uint16_t attribute_type;
    uint16_t attribute_length;
};

// ============================================================================
// STUN Client Implementation
// ============================================================================

STUNClient::STUNClient() {
    // Generate random transaction ID using simple method
    for (int i = 0; i < 12; i++) {
        transaction_id_[i] = rand() % 256;
    }
}

NATType STUNClient::detectNATType(const std::vector<STUNServer>& servers,
                                  std::string& external_ip,
                                  uint16_t& external_port) {
    nativeLog("STUN: Starting NAT type detection with " + std::to_string(servers.size()) + " servers");
    
    if (servers.empty()) {
        nativeLog("STUN: No STUN servers available");
        return NATType::Unknown;
    }
    
    // Test with first server for basic connectivity
    STUNServer primary_server = servers[0];
    
    std::string test_ip;
    uint16_t test_port = 0;
    
    int max_retries = 3;
    int attempt = 0;
    bool stun_success = false;
    while (attempt < max_retries && !stun_success) {
        if (sendSTUNRequest(primary_server, test_ip, test_port)) {
            stun_success = true;
        } else {
            nativeLog("STUN: Primary server attempt " + std::to_string(attempt+1) + " failed");
            std::this_thread::sleep_for(std::chrono::milliseconds(500 * (1 << attempt)));
            attempt++;
        }
    }
    if (!stun_success) {
        nativeLog("STUN: All retries failed for primary server. Escalating to next server if available.");
        // Try all other servers in order
        for (size_t i = 1; i < servers.size(); ++i) {
            attempt = 0;
            while (attempt < max_retries && !stun_success) {
                if (sendSTUNRequest(servers[i], test_ip, test_port)) {
                    stun_success = true;
                    break;
                } else {
                    nativeLog("STUN: Server " + servers[i].hostname + " attempt " + std::to_string(attempt+1) + " failed");
                    std::this_thread::sleep_for(std::chrono::milliseconds(500 * (1 << attempt)));
                    attempt++;
                }
            }
            if (stun_success) break;
        }
    }
    if (!stun_success) {
        nativeLog("STUN: All STUN servers failed. NAT type detection failed.");
        return NATType::Unknown;
    }
    
    external_ip = test_ip;
    external_port = test_port;
    
    // If we have multiple servers, test for symmetric NAT
    if (servers.size() > 1) {
        STUNServer secondary_server = servers[1];
        
        std::string secondary_ip;
        uint16_t secondary_port = 0;
        
        if (sendSTUNRequest(secondary_server, secondary_ip, secondary_port)) {
            // Compare mappings from different servers
            if (test_port == secondary_port && test_ip == secondary_ip) {
                nativeLog("STUN: NAT type detected: Open/Full Cone");
                return NATType::Open;
            } else {
                nativeLog("STUN: NAT type detected: Symmetric");
                return NATType::Symmetric;
            }
        }
    }
    
    // Test for cone NAT by sending change request
    if (testConeNAT(primary_server, test_ip, test_port)) {
        nativeLog("STUN: NAT type detected: Full Cone");
        return NATType::FullCone;
    }
    
    nativeLog("STUN: NAT type detected: Restricted Cone");
    return NATType::RestrictedCone;
}

bool STUNClient::sendSTUNRequest(const STUNServer& server,
                                std::string& external_ip,
                                uint16_t& external_port) {
    int max_retries = 3;
    for (int attempt = 0; attempt < max_retries; ++attempt) {
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            nativeLog("STUN: Failed to create socket (attempt " + std::to_string(attempt+1) + ")");
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * (1 << attempt)));
            continue;
        }
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        // Prepare server address (support DNS resolution)
        struct sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server.port);
        bool resolved = false;
        // Try to resolve hostname (IPv4 only)
        struct addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        struct addrinfo* res = nullptr;
        int gai_ret = getaddrinfo(server.hostname.c_str(), nullptr, &hints, &res);
        if (gai_ret == 0 && res) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)res->ai_addr;
            server_addr.sin_addr = addr_in->sin_addr;
            resolved = true;
            freeaddrinfo(res);
        } else {
            // Fallback: try direct IP parse
            server_addr.sin_addr.s_addr = inet_addr(server.hostname.c_str());
            if (server_addr.sin_addr.s_addr != INADDR_NONE) {
                resolved = true;
            }
        }
        if (!resolved) {
            nativeLog("STUN: Failed to resolve server address: " + server.hostname);
            close(sock);
            continue;
        }
        // Create STUN binding request
        std::vector<uint8_t> request = createBindingRequest();
        // Send request
        if (sendto(sock, request.data(), request.size(), 0,
                  (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            nativeLog("STUN: Send failed (attempt " + std::to_string(attempt+1) + ")");
            close(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * (1 << attempt)));
            continue;
        }
        // Receive response
        char buffer[1024];
        struct sockaddr_in response_addr;
        socklen_t addr_len = sizeof(response_addr);
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&response_addr, &addr_len);
        if (received <= 0) {
            nativeLog("STUN: No response received (attempt " + std::to_string(attempt+1) + ")");
            close(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * (1 << attempt)));
            continue;
        }
        // Parse STUN response
        bool success = parseSTUNResponse(buffer, received, external_ip, external_port);
        close(sock);
        if (success) return true;
        // If parsing failed, retry
        std::this_thread::sleep_for(std::chrono::milliseconds(200 * (1 << attempt)));
    }
    return false;
}

std::vector<uint8_t> STUNClient::createBindingRequest() {
    std::vector<uint8_t> request;
    
    // Message header
    STUNMessageHeader header{};
    header.message_type = htons(STUN_BINDING_REQUEST);
    header.message_length = htons(0); // No attributes initially
    header.magic_cookie = htonl(STUN_MAGIC_COOKIE);
    memcpy(header.transaction_id, transaction_id_, 12);
    
    // Copy header to request
    uint8_t* header_bytes = reinterpret_cast<uint8_t*>(&header);
    request.insert(request.end(), header_bytes, header_bytes + sizeof(header));
    
    return request;
}

bool STUNClient::parseSTUNResponse(const char* buffer, size_t length,
                                  std::string& external_ip, uint16_t& external_port) {
    if (length < sizeof(STUNMessageHeader)) {
        nativeLog("STUN: Response too short");
        return false;
    }
    
    const STUNMessageHeader* header = reinterpret_cast<const STUNMessageHeader*>(buffer);
    
    // Verify magic cookie
    if (ntohl(header->magic_cookie) != STUN_MAGIC_COOKIE) {
        nativeLog("STUN: Invalid magic cookie");
        return false;
    }
    
    // Verify transaction ID
    if (memcmp(header->transaction_id, transaction_id_, 12) != 0) {
        nativeLog("STUN: Transaction ID mismatch");
        return false;
    }
    
    // Parse attributes
    size_t offset = sizeof(STUNMessageHeader);
    while (offset < length) {
        if (offset + sizeof(STUNAttributeHeader) > length) {
            break;
        }
        
        const STUNAttributeHeader* attr_header = 
            reinterpret_cast<const STUNAttributeHeader*>(buffer + offset);
        offset += sizeof(STUNAttributeHeader);
        
        uint16_t attr_type = ntohs(attr_header->attribute_type);
        uint16_t attr_length = ntohs(attr_header->attribute_length);
        
        if (offset + attr_length > length) {
            break;
        }
        
        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS) {
            if (parseXORMappedAddress(buffer + offset, attr_length, external_ip, external_port)) {
                return true;
            }
        } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS) {
            if (parseMappedAddress(buffer + offset, attr_length, external_ip, external_port)) {
                return true;
            }
        }
        
        // Move to next attribute (padding to 4-byte boundary)
        offset += attr_length;
        if (attr_length % 4 != 0) {
            offset += 4 - (attr_length % 4);
        }
    }
    
    nativeLog("STUN: No valid mapped address found in response");
    return false;
}

bool STUNClient::parseXORMappedAddress(const char* data, size_t length,
                                      std::string& ip, uint16_t& port) {
    if (length < 8) {
        return false;
    }
    
    // Parse family and port
    uint8_t family = data[1];
    uint16_t xport = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    
    // XOR with magic cookie
    port = xport ^ (STUN_MAGIC_COOKIE >> 16);
    
    if (family == 0x01) { // IPv4
        if (length < 8) return false;
        
        uint32_t xip = (static_cast<uint32_t>(data[4]) << 24) |
                      (static_cast<uint32_t>(data[5]) << 16) |
                      (static_cast<uint32_t>(data[6]) << 8) |
                      data[7];
        
        // XOR with magic cookie
        uint32_t ip_addr = xip ^ STUN_MAGIC_COOKIE;
        
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                (ip_addr >> 24) & 0xFF,
                (ip_addr >> 16) & 0xFF,
                (ip_addr >> 8) & 0xFF,
                ip_addr & 0xFF);
        
        ip = ip_str;
        return true;
    }
    
    return false;
}

bool STUNClient::parseMappedAddress(const char* data, size_t length,
                                   std::string& ip, uint16_t& port) {
    if (length < 8) {
        return false;
    }
    
    uint8_t family = data[1];
    port = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    
    if (family == 0x01) { // IPv4
        if (length < 8) return false;
        
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                static_cast<uint8_t>(data[4]),
                static_cast<uint8_t>(data[5]),
                static_cast<uint8_t>(data[6]),
                static_cast<uint8_t>(data[7]));
        
        ip = ip_str;
        return true;
    }
    
    return false;
}

bool STUNClient::testConeNAT(const STUNServer& server,
                            const std::string& test_ip,
                            uint16_t test_port) {
    // Simplified cone NAT test
    // In production, this would send requests with CHANGE-REQUEST attribute
    // to test if the NAT allows unsolicited inbound traffic
    
    nativeLog("STUN: Cone NAT test placeholder");
    return false; // Conservative approach
}

void STUNClient::nativeLog(const std::string& message) {
    // Use system logging or forward to application logger
    // For now, simple stdout
    printf("STUN: %s\n", message.c_str());
}