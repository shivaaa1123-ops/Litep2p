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

void STUNMessage::addChangeRequest(bool change_ip, bool change_port) {
    // CHANGE-REQUEST attribute is 4 bytes (RFC 5780)
    std::vector<uint8_t> value(4, 0);
    uint32_t flags = 0;
    if (change_ip) flags |= STUN_CHANGE_IP;
    if (change_port) flags |= STUN_CHANGE_PORT;
    
    value[0] = static_cast<uint8_t>((flags >> 24) & 0xFF);
    value[1] = static_cast<uint8_t>((flags >> 16) & 0xFF);
    value[2] = static_cast<uint8_t>((flags >> 8) & 0xFF);
    value[3] = static_cast<uint8_t>(flags & 0xFF);
    
    addAttribute(STUNAttributeType::ChangeRequest, value);
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
    } else if (addr.family == 0x02) {  // IPv6
        if (value.size() < 20) return false;  // 4 header + 16 address bytes
        struct in6_addr in6;
        std::memcpy(&in6, &value[4], 16);
        char ip6_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &in6, ip6_str, sizeof(ip6_str)) != nullptr) {
            addr.ip = ip6_str;
            return true;
        }
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
        char ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str)) != nullptr) {
            addr.ip = ip_str;
            return true;
        }
        return false;
    } else if (addr.family == 0x02) {  // IPv6
        if (value.size() < 20) return false;  // 4 header + 16 address bytes
        
        // XOR with magic cookie (first 4 bytes) + transaction ID (remaining 12)
        struct in6_addr in6;
        std::memcpy(&in6, &value[4], 16);
        
        // XOR first 4 bytes with magic cookie (avoid unaligned access)
        uint32_t first32 = 0;
        std::memcpy(&first32, &in6, sizeof(first32));
        first32 ^= htonl(STUN_MAGIC_COOKIE);
        std::memcpy(&in6, &first32, sizeof(first32));
        
        // XOR remaining 12 bytes with transaction ID
        if (transaction_id_.size() < 12) return false;
        uint8_t* addr_bytes = reinterpret_cast<uint8_t*>(&in6);
        for (size_t i = 0; i < 12; ++i) {
            addr_bytes[4 + i] ^= transaction_id_[i];
        }
        
        char ip6_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &in6, ip6_str, sizeof(ip6_str)) != nullptr) {
            addr.ip = ip6_str;
            return true;
        }
    }
    
    return false;
}

bool STUNMessage::getOtherAddress(STUNAddress& addr) const {
    // Try OTHER-ADDRESS (RFC 5780) first, then fall back to CHANGED-ADDRESS (RFC 3489)
    std::vector<uint8_t> value;
    if (!getAttribute(STUNAttributeType::OtherAddress, value)) {
        if (!getAttribute(STUNAttributeType::ChangedAddress, value)) {
            return false;
        }
    }
    
    if (value.size() < 8) return false;
    
    addr.family = value[1];
    addr.port = (value[2] << 8) | value[3];
    
    if (addr.family == 0x01) {  // IPv4
        char ip_str[INET_ADDRSTRLEN];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                value[4], value[5], value[6], value[7]);
        addr.ip = ip_str;
        return true;
    } else if (addr.family == 0x02) {  // IPv6
        if (value.size() < 20) return false;
        struct in6_addr in6;
        std::memcpy(&in6, &value[4], 16);
        char ip6_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &in6, ip6_str, sizeof(ip6_str)) != nullptr) {
            addr.ip = ip6_str;
            return true;
        }
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
    // Allow reuse of the same STUNMessage instance safely.
    attributes_.clear();
    transaction_id_.clear();

    if (data.size() < 20) {  // Minimum STUN header
        LOG_WARN("STUN: Message too short");
        return false;
    }
    
    // Parse header
    type_ = static_cast<STUNMessageType>(
        (static_cast<uint16_t>(data[0]) << 8) | data[1]
    );
    
    uint16_t payload_size = (static_cast<uint16_t>(data[2]) << 8) | data[3];

    // Validate payload size against buffer.
    if (static_cast<size_t>(payload_size) + 20 > data.size()) {
        LOG_WARN("STUN: Payload length exceeds buffer");
        return false;
    }
    
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
    const size_t payload_end = 20 + payload_size;
    while (offset < payload_end) {
        if (offset + 4 > payload_end) {
            LOG_WARN("STUN: Truncated attribute header");
            return false;
        }
        
        uint16_t attr_type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        uint16_t attr_length = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
        
        offset += 4;
        
        if (offset + attr_length > payload_end) {
            LOG_WARN("STUN: Attribute length exceeds payload");
            return false;
        }
        
        STUNAttribute attr;
        attr.type = static_cast<STUNAttributeType>(attr_type);
        attr.value.assign(data.begin() + offset, data.begin() + offset + attr_length);
        attributes_.push_back(attr);
        
        // Skip padding
        offset += attr_length;
        int padding = (4 - (attr_length % 4)) % 4;
        if (offset + static_cast<size_t>(padding) > payload_end) {
            LOG_WARN("STUN: Attribute padding exceeds payload");
            return false;
        }
        offset += static_cast<size_t>(padding);
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

void STUNClient::requestCancel() {
    cancel_requested_.store(true, std::memory_order_release);
}

void STUNClient::clearCancel() {
    cancel_requested_.store(false, std::memory_order_release);
}

bool STUNClient::isCancelRequested() const {
    return cancel_requested_.load(std::memory_order_acquire);
}

STUNClient::ProbeResult STUNClient::probeServer(const STUNServer& server) {
    auto start_time = std::chrono::high_resolution_clock::now();

    if (isCancelRequested()) {
        return ProbeResult::failure(STUNErrorCode::Cancelled, "Cancelled");
    }
    
    // Validate input
    if (server.hostname.empty()) {
        return ProbeResult::failure(STUNErrorCode::DnsResolutionFailed, "Empty hostname");
    }
    
    // Resolve server hostname first to determine address family
    struct addrinfo hints, *result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Allow both IPv4 and IPv6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    
    int gai_err = getaddrinfo(server.hostname.c_str(), std::to_string(server.port).c_str(),
                              &hints, &result);
    if (gai_err != 0) {
        LOG_WARN("STUN: Failed to resolve server: " + server.hostname + " (" + gai_strerror(gai_err) + ")");
        return ProbeResult::failure(STUNErrorCode::DnsResolutionFailed, 
                                    server.hostname + ": " + gai_strerror(gai_err));
    }
    
    // Prefer IPv4 on dual-stack networks. The rest of Litep2p currently treats
    // IPv6 endpoints as non-connectable for the UDP transport.
    struct addrinfo* selected = result;
    for (struct addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            selected = ai;
            break;
        }
    }

    // Create UDP socket matching the selected address family
    int sock = socket(selected->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        int err = errno;
        LOG_WARN("STUN: Failed to create socket: " + std::string(strerror(err)));
        freeaddrinfo(result);
        return ProbeResult::failure(STUNErrorCode::SocketCreationFailed, strerror(err));
    }
    
    // Set a small socket timeout so we can respond quickly to cancellation.
    const int total_timeout_ms = std::max(0, server.timeout_ms);
    const int slice_timeout_ms = std::max(50, std::min(200, total_timeout_ms > 0 ? total_timeout_ms : 200));
    struct timeval tv;
    tv.tv_sec = slice_timeout_ms / 1000;
    tv.tv_usec = (slice_timeout_ms % 1000) * 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        LOG_WARN("STUN: Failed to set socket timeout: " + std::string(strerror(errno)));
        // Continue anyway, timeout just won't work properly
    }
    
    // Create STUN Binding Request
    STUNMessage request;
    request.setType(STUNMessageType::BindingRequest);
    
    std::vector<uint8_t> request_data = request.encode();
    
    // Send request
    if (sendto(sock, request_data.data(), request_data.size(), 0,
              selected->ai_addr, selected->ai_addrlen) < 0) {
        int err = errno;
        LOG_WARN("STUN: Failed to send probe: " + std::string(strerror(err)));
        freeaddrinfo(result);
        close(sock);
        return ProbeResult::failure(STUNErrorCode::SendFailed, strerror(err));
    }
    
    // Receive response - use sockaddr_storage for IPv4/IPv6 compatibility
    uint8_t response_buffer[1024];  // Increased buffer for IPv6
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    int bytes = -1;
    int remaining_ms = total_timeout_ms;
    if (remaining_ms <= 0) {
        remaining_ms = server.timeout_ms;
    }
    // If total_timeout_ms was 0, treat as one slice attempt.
    if (remaining_ms <= 0) {
        remaining_ms = slice_timeout_ms;
    }

    while (remaining_ms > 0) {
        if (isCancelRequested()) {
            freeaddrinfo(result);
            close(sock);
            return ProbeResult::failure(STUNErrorCode::Cancelled, "Cancelled");
        }

        errno = 0;
        src_addr_len = sizeof(src_addr);
        bytes = recvfrom(sock, response_buffer, sizeof(response_buffer), 0,
                        (struct sockaddr*)&src_addr, &src_addr_len);
        if (bytes >= 0) {
            break;
        }

        const int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK) {
            remaining_ms -= slice_timeout_ms;
            continue;
        }

        // Non-timeout error.
        break;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    uint32_t rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    if (bytes < 0) {
        int err = errno;
        freeaddrinfo(result);
        close(sock);
        if (isCancelRequested()) {
            return ProbeResult::failure(STUNErrorCode::Cancelled, "Cancelled");
        }
        if (err == EAGAIN || err == EWOULDBLOCK) {
            LOG_WARN("STUN: Probe timeout for " + server.hostname + " (RTT >" + 
                     std::to_string(server.timeout_ms) + "ms)");
            return ProbeResult::failure(STUNErrorCode::ReceiveTimeout, server.hostname);
        }
        LOG_WARN("STUN: Receive error for " + server.hostname + ": " + strerror(err));
        return ProbeResult::failure(STUNErrorCode::ReceiveFailed, strerror(err));
    }
    
    if (bytes < 20) {  // Minimum STUN header size
        LOG_WARN("STUN: Response too short from " + server.hostname + " (" + 
                 std::to_string(bytes) + " bytes)");
        freeaddrinfo(result);
        close(sock);
        return ProbeResult::failure(STUNErrorCode::MessageTooShort);
    }
    
    // Parse response
    STUNMessage response;
    std::vector<uint8_t> response_vec(response_buffer, response_buffer + bytes);
    
    if (!response.decode(response_vec)) {
        LOG_WARN("STUN: Invalid response from " + server.hostname);
        freeaddrinfo(result);
        close(sock);
        return ProbeResult::failure(STUNErrorCode::InvalidMessageFormat);
    }
    
    // Verify transaction ID matches
    if (response.getTransactionId() != request.getTransactionId()) {
        LOG_WARN("STUN: Transaction ID mismatch from " + server.hostname);
        freeaddrinfo(result);
        close(sock);
        return ProbeResult::failure(STUNErrorCode::TransactionIdMismatch);
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
    
    // Extract source address from received packet (thread-safe, IPv4/IPv6 compatible)
    if (src_addr.ss_family == AF_INET) {
        source_addr.family = 0x01;
        const struct sockaddr_in* addr4 = reinterpret_cast<const struct sockaddr_in*>(&src_addr);
        char src_ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr4->sin_addr, src_ip_str, sizeof(src_ip_str)) != nullptr) {
            source_addr.ip = src_ip_str;
        } else {
            source_addr.ip = "0.0.0.0";
        }
        source_addr.port = ntohs(addr4->sin_port);
    } else if (src_addr.ss_family == AF_INET6) {
        source_addr.family = 0x02;
        const struct sockaddr_in6* addr6 = reinterpret_cast<const struct sockaddr_in6*>(&src_addr);
        char src_ip_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, src_ip_str, sizeof(src_ip_str)) != nullptr) {
            source_addr.ip = src_ip_str;
        } else {
            source_addr.ip = "::";
        }
        source_addr.port = ntohs(addr6->sin6_port);
    } else {
        source_addr.family = 0x01;
        source_addr.ip = "0.0.0.0";
        source_addr.port = 0;
    }
    
    freeaddrinfo(result);
    close(sock);
    
    if (!has_address) {
        LOG_WARN("STUN: No mapped address in response from " + server.hostname);
        ProbeResult r;
        r.success = false;
        r.rtt_ms = rtt_ms;
        r.error_code = STUNErrorCode::NoMappedAddress;
        r.error_message = "No mapped address in STUN response";
        return r;
    }
    
    LOG_INFO("STUN: Probe successful - " + mapped_addr.ip + ":" + 
             std::to_string(mapped_addr.port) + " (RTT: " + 
             std::to_string(rtt_ms) + "ms, server: " + server.hostname + ")");
    
    ProbeResult r;
    r.success = true;
    r.mapped_address = mapped_addr;
    r.source_address = source_addr;
    r.rtt_ms = rtt_ms;
    r.error_code = STUNErrorCode::Success;
    return r;
}

STUNClient::ProbeResult STUNClient::probeWithRetry(const STUNServer& server,
                                                   int max_attempts,
                                                   int initial_backoff_ms) {
    // RFC 5389 compliant retransmission
    // RTO starts at initial value, doubles each retry up to max
    // Default: 500ms -> 1000ms -> 2000ms -> 3000ms (capped)
    
    int rto_ms = (initial_backoff_ms > 0) ? initial_backoff_ms : STUN_RTO_INITIAL_MS;
    const int max_rto_ms = STUN_RTO_MAX_MS;
    ProbeResult last_result;
    
    auto transaction_start = std::chrono::steady_clock::now();
    const auto transaction_timeout = std::chrono::milliseconds(STUN_Ti_MS);
    
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        if (isCancelRequested()) {
            return ProbeResult::failure(STUNErrorCode::Cancelled, "Cancelled");
        }
        // Check if transaction has timed out
        auto elapsed = std::chrono::steady_clock::now() - transaction_start;
        if (elapsed > transaction_timeout) {
            LOG_WARN("STUN: Transaction timeout (Ti=" + std::to_string(STUN_Ti_MS) + "ms)");
            break;
        }
        
        LOG_INFO("STUN: Attempt " + std::to_string(attempt) + "/" + 
                 std::to_string(max_attempts) + " to " + server.hostname + 
                 " (RTO=" + std::to_string(rto_ms) + "ms)");
        
        // Create a server copy with the current RTO as timeout
        STUNServer server_with_rto = server;
        server_with_rto.timeout_ms = rto_ms;
        
        last_result = probeServer(server_with_rto);
        if (last_result.success) {
            LOG_INFO("STUN: Success on attempt " + std::to_string(attempt) + 
                     " (total RTT: " + std::to_string(last_result.rtt_ms) + "ms)");
            return last_result;
        }
        
        // Don't retry on certain errors (they won't resolve themselves)
        if (last_result.error_code == STUNErrorCode::DnsResolutionFailed ||
            last_result.error_code == STUNErrorCode::SocketCreationFailed ||
            last_result.error_code == STUNErrorCode::InvalidMessageFormat ||
            last_result.error_code == STUNErrorCode::TransactionIdMismatch ||
            last_result.error_code == STUNErrorCode::Cancelled) {
            LOG_WARN("STUN: Non-retriable error (" + stunErrorToString(last_result.error_code) + 
                     "), aborting retries");
            break;
        }
        
        if (attempt < max_attempts) {
            // RFC 5389: Double RTO for each retransmission, cap at max
            rto_ms = std::min(rto_ms * 2, max_rto_ms);
        }
    }
    
    // Calculate total time spent
    auto total_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - transaction_start).count();
    
    // Return last error with updated message
    last_result.error_message = "All " + std::to_string(max_attempts) + 
                                " retries exhausted after " + std::to_string(total_elapsed) + 
                                "ms: " + last_result.error_message;
    last_result.error_code = STUNErrorCode::AllServersFailed;
    return last_result;
}

STUNClient::ProbeResult STUNClient::probeServerWithFlags(const STUNServer& server,
                                                          bool change_ip,
                                                          bool change_port) {
    auto start_time = std::chrono::high_resolution_clock::now();

    if (isCancelRequested()) {
        return ProbeResult::failure(STUNErrorCode::Cancelled, "Cancelled");
    }
    
    // Validate input
    if (server.hostname.empty()) {
        return ProbeResult::failure(STUNErrorCode::DnsResolutionFailed, "Empty hostname");
    }
    
    // Resolve server hostname first
    struct addrinfo hints, *result = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    
    int gai_err = getaddrinfo(server.hostname.c_str(), std::to_string(server.port).c_str(),
                              &hints, &result);
    if (gai_err != 0) {
        return ProbeResult::failure(STUNErrorCode::DnsResolutionFailed, gai_strerror(gai_err));
    }
    
    int sock = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        freeaddrinfo(result);
        return ProbeResult::failure(STUNErrorCode::SocketCreationFailed, "Socket creation failed");
    }
    
    // Small timeout slices allow cancellation responsiveness.
    const int total_timeout_ms = std::max(0, server.timeout_ms);
    const int slice_timeout_ms = std::max(50, std::min(200, total_timeout_ms > 0 ? total_timeout_ms : 200));
    struct timeval tv;
    tv.tv_sec = slice_timeout_ms / 1000;
    tv.tv_usec = (slice_timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Create STUN Binding Request with CHANGE-REQUEST attribute
    STUNMessage request;
    request.setType(STUNMessageType::BindingRequest);
    if (change_ip || change_port) {
        request.addChangeRequest(change_ip, change_port);
    }
    
    std::vector<uint8_t> request_data = request.encode();
    
    if (sendto(sock, request_data.data(), request_data.size(), 0,
              result->ai_addr, result->ai_addrlen) < 0) {
        int err = errno;
        freeaddrinfo(result);
        close(sock);
        return ProbeResult::failure(STUNErrorCode::SendFailed, strerror(err));
    }
    
    uint8_t response_buffer[1024];
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    
    int bytes = -1;
    int remaining_ms = total_timeout_ms;
    if (remaining_ms <= 0) {
        remaining_ms = slice_timeout_ms;
    }
    while (remaining_ms > 0) {
        if (isCancelRequested()) {
            freeaddrinfo(result);
            close(sock);
            return ProbeResult::failure(STUNErrorCode::Cancelled, "Cancelled");
        }
        errno = 0;
        src_addr_len = sizeof(src_addr);
        bytes = recvfrom(sock, response_buffer, sizeof(response_buffer), 0,
                        (struct sockaddr*)&src_addr, &src_addr_len);
        if (bytes >= 0) {
            break;
        }
        const int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK) {
            remaining_ms -= slice_timeout_ms;
            continue;
        }
        break;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    uint32_t rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();
    
    freeaddrinfo(result);
    
    if (bytes < 0) {
        close(sock);
        int err = errno;
        if (isCancelRequested()) {
            return ProbeResult::failure(STUNErrorCode::Cancelled, "Cancelled");
        }
        if (err == EAGAIN || err == EWOULDBLOCK) {
            return ProbeResult::failure(STUNErrorCode::ReceiveTimeout, 
                                        "Timeout with CHANGE flags");
        }
        return ProbeResult::failure(STUNErrorCode::ReceiveFailed, strerror(err));
    }
    
    STUNMessage response;
    std::vector<uint8_t> response_vec(response_buffer, response_buffer + bytes);
    
    if (!response.decode(response_vec)) {
        close(sock);
        return ProbeResult::failure(STUNErrorCode::InvalidMessageFormat);
    }
    
    STUNAddress mapped_addr;
    STUNAddress source_addr;
    
    bool has_address = response.getXorMappedAddress(mapped_addr);
    if (!has_address) {
        has_address = response.getMappedAddress(mapped_addr);
    }
    
    // Extract source address
    if (src_addr.ss_family == AF_INET) {
        source_addr.family = 0x01;
        const struct sockaddr_in* addr4 = reinterpret_cast<const struct sockaddr_in*>(&src_addr);
        char src_ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr4->sin_addr, src_ip_str, sizeof(src_ip_str)) != nullptr) {
            source_addr.ip = src_ip_str;
        }
        source_addr.port = ntohs(addr4->sin_port);
    } else if (src_addr.ss_family == AF_INET6) {
        source_addr.family = 0x02;
        const struct sockaddr_in6* addr6 = reinterpret_cast<const struct sockaddr_in6*>(&src_addr);
        char src_ip_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, src_ip_str, sizeof(src_ip_str)) != nullptr) {
            source_addr.ip = src_ip_str;
        }
        source_addr.port = ntohs(addr6->sin6_port);
    }
    
    close(sock);
    
    if (!has_address) {
        ProbeResult r;
        r.success = false;
        r.rtt_ms = rtt_ms;
        r.error_code = STUNErrorCode::NoMappedAddress;
        r.error_message = "No mapped address with CHANGE flags";
        return r;
    }
    
    ProbeResult r;
    r.success = true;
    r.mapped_address = mapped_addr;
    r.source_address = source_addr;
    r.rtt_ms = rtt_ms;
    r.error_code = STUNErrorCode::Success;
    return r;
}

std::string STUNClient::getLocalIP() const {
    // Get local IP by connecting to a public address (doesn't actually send data)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "";
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(53);  // DNS port
    inet_pton(AF_INET, "8.8.8.8", &serv_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return "";
    }
    
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) < 0) {
        close(sock);
        return "";
    }
    
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &local_addr.sin_addr, ip_str, sizeof(ip_str)) == nullptr) {
        close(sock);
        return "";
    }
    
    close(sock);
    return std::string(ip_str);
}

NATType STUNClient::detectNATType(const std::vector<STUNServer>& servers,
                                  std::string& out_external_ip,
                                  uint16_t& out_external_port) {
    if (servers.empty()) {
        LOG_WARN("STUN: No STUN servers configured");
        return NATType::Unknown;
    }
    
    // RFC 3489/5780 NAT Detection Algorithm
    // =====================================
    // Test I: Basic binding request - get external IP:port
    // Test II: Request with CHANGE-IP and CHANGE-PORT flags (full cone test)
    // Test III: Request with just CHANGE-PORT (restricted cone test)  
    // Test IV: Probe different server to detect symmetric NAT
    
    LOG_INFO("STUN: === Starting NAT Detection (RFC 3489/5780) ===");
    
    // Test I: Basic binding request to get external address
    LOG_INFO("STUN: Test I - Basic binding request");
    auto test1_result = test1(servers);
    
    if (!test1_result.success) {
        LOG_WARN("STUN: Test I failed - UDP may be blocked");
        return NATType::Unknown;
    }
    
    out_external_ip = test1_result.mapped_address.ip;
    out_external_port = test1_result.mapped_address.port;
    
    // Check if external IP matches local IP (Open/No NAT)
    std::string local_ip = getLocalIP();
    if (!local_ip.empty() && local_ip == out_external_ip) {
        LOG_INFO("STUN: External IP matches local IP - Open (No NAT)");
        return NATType::Open;
    }
    
    LOG_INFO("STUN: External address: " + out_external_ip + ":" + 
             std::to_string(out_external_port) + " (local: " + local_ip + ")");
    
    // Test II: Request with CHANGE-IP + CHANGE-PORT (Full Cone Test)
    // If response received from different IP:port, we have Full Cone NAT
    LOG_INFO("STUN: Test II - Binding request with CHANGE-IP + CHANGE-PORT");
    auto test2_result = test2(servers, test1_result.mapped_address);
    
    if (test2_result.success) {
        // Received response from different IP:port - Full Cone NAT
        LOG_INFO("STUN: Test II succeeded - Full Cone NAT");
        return NATType::FullCone;
    }
    
    // Test II failed - need more tests to determine NAT type
    LOG_INFO("STUN: Test II failed - not Full Cone, continuing detection");
    
    // Test III: Probe a different STUN server to detect Symmetric NAT
    LOG_INFO("STUN: Test III - Probe different server to detect Symmetric NAT");
    auto test3_result = test3(servers);
    
    if (test3_result.success) {
        // Compare mapped addresses - if different, Symmetric NAT
        if (test3_result.mapped_address.ip != test1_result.mapped_address.ip ||
            test3_result.mapped_address.port != test1_result.mapped_address.port) {
            LOG_INFO("STUN: Different external address from second server - Symmetric NAT");
            LOG_INFO("STUN: Server1: " + test1_result.mapped_address.ip + ":" + 
                     std::to_string(test1_result.mapped_address.port));
            LOG_INFO("STUN: Server2: " + test3_result.mapped_address.ip + ":" + 
                     std::to_string(test3_result.mapped_address.port));
            return NATType::Symmetric;
        }
    }
    
    // Test IV: Request with CHANGE-PORT only to distinguish Restricted vs Port-Restricted
    LOG_INFO("STUN: Test IV - Binding request with CHANGE-PORT only");
    auto test4_result = test4(servers);
    
    if (test4_result.success) {
        // Response from same IP, different port - Restricted Cone NAT
        LOG_INFO("STUN: Test IV succeeded - Restricted Cone NAT");
        return NATType::RestrictedCone;
    }
    
    // No response with CHANGE-PORT - Port-Restricted Cone NAT
    LOG_INFO("STUN: Test IV failed - Port-Restricted Cone NAT");
    return NATType::PortRestrictedCone;
}

STUNClient::ProbeResult STUNClient::test1(const std::vector<STUNServer>& servers) {
    // Test I: Basic binding request
    for (const auto& server : servers) {
        auto result = probeWithRetry(server, 3, 300);
        if (result.success) {
            return result;
        }
    }
    return ProbeResult::failure(STUNErrorCode::AllServersFailed, "All servers failed");
}

STUNClient::ProbeResult STUNClient::test2(const std::vector<STUNServer>& servers,
                                          const STUNAddress& primary_address) {
    // Test II: Binding request with CHANGE-IP + CHANGE-PORT
    // This tests if the NAT allows incoming packets from any source
    (void)primary_address;  // Used for logging/comparison if needed
    
    for (const auto& server : servers) {
        // Use shorter timeout for change requests (less likely to succeed)
        STUNServer server_copy = server;
        server_copy.timeout_ms = std::min(server.timeout_ms, 1500);
        
        auto result = probeServerWithFlags(server_copy, true, true);
        if (result.success) {
            LOG_INFO("STUN: Test II - Received response from " + 
                     result.source_address.ip + ":" + 
                     std::to_string(result.source_address.port));
            return result;
        }
    }
    return ProbeResult::failure(STUNErrorCode::ReceiveTimeout, "No response with CHANGE-IP+PORT");
}

STUNClient::ProbeResult STUNClient::test3(const std::vector<STUNServer>& servers) {
    // Test III: Probe a different STUN server to detect Symmetric NAT
    // We need at least 2 different STUN servers to detect symmetric NAT
    
    if (servers.size() >= 2) {
        // Try second server first (more likely to have different IP)
        auto result = probeWithRetry(servers[1], 2, 300);
        if (result.success) {
            return result;
        }
        
        // Try other servers
        for (size_t i = 2; i < servers.size(); ++i) {
            result = probeWithRetry(servers[i], 2, 300);
            if (result.success) {
                return result;
            }
        }
    }
    
    return ProbeResult::failure(STUNErrorCode::NoServersConfigured, "No secondary server available");
}

STUNClient::ProbeResult STUNClient::test4(const std::vector<STUNServer>& servers) {
    // Test IV: Binding request with CHANGE-PORT only
    // This tests if NAT is Port-Restricted
    
    for (const auto& server : servers) {
        STUNServer server_copy = server;
        server_copy.timeout_ms = std::min(server.timeout_ms, 1500);
        
        auto result = probeServerWithFlags(server_copy, false, true);
        if (result.success) {
            return result;
        }
    }
    return ProbeResult::failure(STUNErrorCode::ReceiveTimeout, "No response with CHANGE-PORT");
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
