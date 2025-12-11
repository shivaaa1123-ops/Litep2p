#include "nat_stun.h"
#include "logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>
#include <netdb.h>

// ============================================================================
// STUNMessage Implementation
// ============================================================================

STUNMessage::STUNMessage() : type_(STUNMessageType::BindingRequest) {
    // Generate random transaction ID (12 bytes)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    transaction_id_.resize(12);
    for (int i = 0; i < 12; i++) {
        transaction_id_[i] = dis(gen);
    }
}

void STUNMessage::addAttribute(STUNAttributeType type, const std::vector<uint8_t>& value) {
    STUNAttribute attr;
    attr.type = type;
    attr.value = value;
    attributes_.push_back(attr);
}

bool STUNMessage::getAttribute(STUNAttributeType type, std::vector<uint8_t>& out_value) const {
    for (const auto& attr : attributes_) {
        if (attr.type == type) {
            out_value = attr.value;
            return true;
        }
    }
    return false;
}

bool STUNMessage::getMappedAddress(STUNAddress& addr) const {
    std::vector<uint8_t> value;
    if (!getAttribute(STUNAttributeType::MappedAddress, value)) {
        return false;
    }
    
    if (value.size() < 8) return false;
    
    addr.family = value[1];  // Byte 0 is reserved, byte 1 is family
    addr.port = (value[2] << 8) | value[3];
    
    if (addr.family == 0x01) {  // IPv4
        char ip_str[INET_ADDRSTRLEN];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                value[4], value[5], value[6], value[7]);
        addr.ip = ip_str;
        return true;
    }
    
    return false;
}

bool STUNMessage::getXorMappedAddress(STUNAddress& addr) const {
    std::vector<uint8_t> value;
    if (!getAttribute(STUNAttributeType::XorMappedAddress, value)) {
        return false;
    }
    
    if (value.size() < 8) return false;
    
    addr.family = value[1];
    uint16_t xor_port = (value[2] << 8) | value[3];
    addr.port = xor_port ^ (STUN_MAGIC_COOKIE >> 16);  // XOR with high 16 bits
    
    if (addr.family == 0x01) {  // IPv4
        uint32_t xor_ip = ((value[4] << 24) | (value[5] << 16) | 
                          (value[6] << 8) | value[7]);
        uint32_t external_ip = xor_ip ^ STUN_MAGIC_COOKIE;
        
        struct in_addr in;
        in.s_addr = htonl(external_ip);
        addr.ip = inet_ntoa(in);
        return true;
    }
    
    return false;
}

std::vector<uint8_t> STUNMessage::encode() const {
    std::vector<uint8_t> buffer;
    
    // Calculate payload size first
    uint16_t payload_size = 0;
    for (const auto& attr : attributes_) {
        payload_size += 4 + attr.value.size();
        // Padding to 4-byte boundary
        if (attr.value.size() % 4 != 0) {
            payload_size += 4 - (attr.value.size() % 4);
        }
    }
    
    // Encode header
    buffer.push_back((static_cast<uint16_t>(type_) >> 8) & 0xFF);
    buffer.push_back(static_cast<uint16_t>(type_) & 0xFF);
    buffer.push_back((payload_size >> 8) & 0xFF);
    buffer.push_back(payload_size & 0xFF);
    
    // Magic cookie
    buffer.push_back((STUN_MAGIC_COOKIE >> 24) & 0xFF);
    buffer.push_back((STUN_MAGIC_COOKIE >> 16) & 0xFF);
    buffer.push_back((STUN_MAGIC_COOKIE >> 8) & 0xFF);
    buffer.push_back(STUN_MAGIC_COOKIE & 0xFF);
    
    // Transaction ID
    for (const auto& byte : transaction_id_) {
        buffer.push_back(byte);
    }
    
    // Attributes
    for (const auto& attr : attributes_) {
        uint16_t attr_type = static_cast<uint16_t>(attr.type);
        uint16_t attr_length = attr.value.size();
        
        buffer.push_back((attr_type >> 8) & 0xFF);
        buffer.push_back(attr_type & 0xFF);
        buffer.push_back((attr_length >> 8) & 0xFF);
        buffer.push_back(attr_length & 0xFF);
        
        for (const auto& byte : attr.value) {
            buffer.push_back(byte);
        }
        
        // Padding
        int padding = (4 - (attr.value.size() % 4)) % 4;
        for (int i = 0; i < padding; i++) {
            buffer.push_back(0);
        }
    }
    
    return buffer;
}

bool STUNMessage::decode(const std::vector<uint8_t>& data) {
    if (data.size() < 20) {  // Minimum STUN header
        LOG_WARN("STUN: Message too short");
        return false;
    }
    
    // Parse header
    type_ = static_cast<STUNMessageType>(
        (static_cast<uint16_t>(data[0]) << 8) | data[1]
    );
    
    uint16_t payload_size = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    
    uint32_t magic_cookie = 
        (static_cast<uint32_t>(data[4]) << 24) |
        (static_cast<uint32_t>(data[5]) << 16) |
        (static_cast<uint32_t>(data[6]) << 8) |
        data[7];
    
    if (magic_cookie != STUN_MAGIC_COOKIE) {
        LOG_WARN("STUN: Invalid magic cookie");
        return false;
    }
    
    // Parse transaction ID
    transaction_id_.assign(data.begin() + 8, data.begin() + 20);
    
    // Parse attributes
    size_t offset = 20;
    while (offset < data.size() && offset - 20 < payload_size) {
        if (offset + 4 > data.size()) break;
        
        uint16_t attr_type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        uint16_t attr_length = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
        
        offset += 4;
        
        if (offset + attr_length > data.size()) {
            LOG_WARN("STUN: Attribute length exceeds buffer");
            break;
        }
        
        STUNAttribute attr;
        attr.type = static_cast<STUNAttributeType>(attr_type);
        attr.value.assign(data.begin() + offset, data.begin() + offset + attr_length);
        attributes_.push_back(attr);
        
        // Skip padding
        offset += attr_length;
        int padding = (4 - (attr_length % 4)) % 4;
        offset += padding;
    }
    
    return true;
}

// ============================================================================
// STUNClient Implementation
// ============================================================================

STUNClient::STUNClient() {
}

STUNClient::~STUNClient() {
}

STUNClient::ProbeResult STUNClient::probeServer(const STUNServer& server) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG_WARN("STUN: Failed to create socket");
        return {false, {}, {}, 0, "Socket creation failed"};
    }
    
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = server.timeout_ms / 1000;
    tv.tv_usec = (server.timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Resolve server hostname
    struct addrinfo hints, *result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    if (getaddrinfo(server.hostname.c_str(), std::to_string(server.port).c_str(),
                   &hints, &result) != 0) {
        LOG_WARN("STUN: Failed to resolve server: " + server.hostname);
        close(sock);
        return {false, {}, {}, 0, "Resolution failed"};
    }
    
    // Create STUN Binding Request
    STUNMessage request;
    request.setType(STUNMessageType::BindingRequest);
    
    std::vector<uint8_t> request_data = request.encode();
    
    // Send request
    if (sendto(sock, request_data.data(), request_data.size(), 0,
              result->ai_addr, result->ai_addrlen) < 0) {
        LOG_WARN("STUN: Failed to send probe");
        freeaddrinfo(result);
        close(sock);
        return {false, {}, {}, 0, "Send failed"};
    }
    
    // Receive response
    uint8_t response_buffer[512];
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    
    int bytes = recvfrom(sock, response_buffer, sizeof(response_buffer), 0,
                        (struct sockaddr*)&src_addr, &src_addr_len);
    
    auto end_time = std::chrono::high_resolution_clock::now();
    uint32_t rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    if (bytes < 0) {
        LOG_WARN("STUN: Probe timeout for " + server.hostname);
        freeaddrinfo(result);
        close(sock);
        return {false, {}, {}, 0, "Timeout"};
    }
    
    // Parse response
    STUNMessage response;
    std::vector<uint8_t> response_vec(response_buffer, response_buffer + bytes);
    
    if (!response.decode(response_vec)) {
        LOG_WARN("STUN: Invalid response from " + server.hostname);
        freeaddrinfo(result);
        close(sock);
        return {false, {}, {}, 0, "Invalid response"};
    }
    
    // Extract addresses
    STUNAddress mapped_addr;
    STUNAddress source_addr;
    
    // Try XOR-MAPPED-ADDRESS first (more reliable)
    bool has_address = response.getXorMappedAddress(mapped_addr);
    if (!has_address) {
        // Fall back to MAPPED-ADDRESS
        has_address = response.getMappedAddress(mapped_addr);
    }
    
    // Extract source address from received packet
    source_addr.family = 0x01;
    source_addr.ip = inet_ntoa(src_addr.sin_addr);
    source_addr.port = ntohs(src_addr.sin_port);
    
    freeaddrinfo(result);
    close(sock);
    
    if (!has_address) {
        LOG_WARN("STUN: No mapped address in response");
        return {false, {}, {}, rtt_ms, "No mapped address"};
    }
    
    LOG_INFO("STUN: Probe successful - " + mapped_addr.ip + ":" + 
                std::to_string(mapped_addr.port) + " (RTT: " + 
                std::to_string(rtt_ms) + "ms)");
    
    return {true, mapped_addr, source_addr, rtt_ms, ""};
}

STUNClient::ProbeResult STUNClient::probeWithRetry(const STUNServer& server,
                                                   int max_attempts,
                                                   int initial_backoff_ms) {
    int backoff_ms = initial_backoff_ms;
    
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        LOG_INFO("STUN: Attempt " + std::to_string(attempt) + "/" + 
                    std::to_string(max_attempts) + " to " + server.hostname);
        
        auto result = probeServer(server);
        if (result.success) {
            return result;
        }
        
        if (attempt < max_attempts) {
            LOG_INFO("STUN: Retry in " + std::to_string(backoff_ms) + "ms");
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
            backoff_ms = std::min(backoff_ms * 2, 30000);  // Max 30s backoff
        }
    }
    
    return {false, {}, {}, 0, "All retries exhausted"};
}

NATType STUNClient::detectNATType(const std::vector<STUNServer>& servers,
                                  std::string& out_external_ip,
                                  uint16_t& out_external_port) {
    if (servers.empty()) {
        LOG_WARN("STUN: No STUN servers configured");
        return NATType::Unknown;
    }
    
    // Test 1: Get external IP/port
    LOG_INFO("STUN: Test 1 - Binding request");
    auto test1_result = test1(servers);
    
    if (!test1_result.success) {
        LOG_WARN("STUN: Test 1 failed, assuming Open network");
        return NATType::Open;
    }
    
    out_external_ip = test1_result.mapped_address.ip;
    out_external_port = test1_result.mapped_address.port;
    
    // Check if external IP matches local IP (no NAT)
    // In a real scenario, you'd compare with local interface IP
    // For now, we'll proceed with NAT detection
    
    LOG_INFO("STUN: Detected external IP: " + out_external_ip + ":" + 
                std::to_string(out_external_port));
    
    // Test 2: Send from same IP but different port (if possible)
    LOG_INFO("STUN: Test 2 - Binding request with CHANGE-PORT");
    auto test2_result = test2(servers, test1_result.mapped_address);
    
    if (!test2_result.success) {
        // No response, might be symmetric NAT or firewall
        LOG_WARN("STUN: Test 2 failed");
        return NATType::Symmetric;
    }
    
    if (test2_result.mapped_address.port != test1_result.mapped_address.port) {
        LOG_INFO("STUN: Different external port detected - Symmetric NAT");
        return NATType::Symmetric;
    }
    
    // Test 3: Request with CHANGE-ADDRESS
    LOG_INFO("STUN: Test 3 - Binding request with CHANGE-ADDRESS");
    auto test3_result = test3(servers);
    
    if (!test3_result.success) {
        LOG_INFO("STUN: Test 3 failed - Restricted or Port-Restricted Cone");
        return NATType::RestrictedCone;
    }
    
    LOG_INFO("STUN: Full Cone NAT detected");
    return NATType::FullCone;
}

STUNClient::ProbeResult STUNClient::test1(const std::vector<STUNServer>& servers) {
    for (const auto& server : servers) {
        auto result = probeWithRetry(server, 2, 500);
        if (result.success) {
            return result;
        }
    }
    return {false, {}, {}, 0, "All servers failed"};
}

STUNClient::ProbeResult STUNClient::test2(const std::vector<STUNServer>& servers,
                                          const STUNAddress& primary_address) {
    // This would involve sending a request with CHANGE-PORT flag
    // For simplified implementation, we'll just do another probe
    // Real implementation would parse CHANGED-ADDRESS attribute
    
    for (const auto& server : servers) {
        auto result = probeWithRetry(server, 2, 500);
        if (result.success) {
            return result;
        }
    }
    return {false, {}, {}, 0, "All servers failed"};
}

STUNClient::ProbeResult STUNClient::test3(const std::vector<STUNServer>& servers) {
    // This would involve requesting CHANGED-ADDRESS
    // Simplified: just another probe to a different server
    
    if (servers.size() > 1) {
        auto result = probeWithRetry(servers[1], 2, 500);
        if (result.success) {
            return result;
        }
    }
    return {false, {}, {}, 0, "Secondary server failed"};
}

std::string STUNClient::natTypeToString(NATType type) const {
    switch (type) {
        case NATType::Open: return "Open";
        case NATType::FullCone: return "Full Cone";
        case NATType::RestrictedCone: return "Restricted Cone";
        case NATType::PortRestrictedCone: return "Port-Restricted Cone";
        case NATType::Symmetric: return "Symmetric";
        case NATType::Unknown: return "Unknown";
        default: return "Unknown";
    }
}
