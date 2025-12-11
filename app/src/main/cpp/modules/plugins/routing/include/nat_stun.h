#ifndef NAT_STUN_H
#define NAT_STUN_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <chrono>

/**
 * STUN Protocol Implementation (RFC 5389)
 * 
 * Handles STUN message creation, parsing, and NAT type detection
 * using MAPPED-ADDRESS and XOR-MAPPED-ADDRESS attributes.
 */

// STUN Magic Cookie (RFC 5389)
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN Message Types
enum class STUNMessageType : uint16_t {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingError = 0x0111,
};

// STUN Attribute Types
enum class STUNAttributeType : uint16_t {
    MappedAddress = 0x0001,
    ResponseAddress = 0x0002,
    ChangeRequest = 0x0003,
    SourceAddress = 0x0004,
    ChangedAddress = 0x0005,
    Username = 0x0006,
    Password = 0x0007,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020,
    Fingerprint = 0x8028,
};

// NAT Type Classification
enum class NATType {
    Open,                    // No NAT (same IP as external)
    FullCone,               // Same EP for all destinations
    RestrictedCone,         // Same EP, but destination IP restricted
    PortRestrictedCone,     // Same EP, but destination IP:port restricted
    Symmetric,              // Different EP for different destinations
    Unknown,                // Could not determine
};

struct STUNAddress {
    uint8_t family;         // 0x01 = IPv4, 0x02 = IPv6
    std::string ip;
    uint16_t port;
};

struct STUNAttribute {
    STUNAttributeType type;
    std::vector<uint8_t> value;
};

/**
 * STUN Message for RFC 5389 compliance
 */
class STUNMessage {
public:
    STUNMessage();
    
    // Getters
    STUNMessageType getType() const { return type_; }
    const std::vector<uint8_t>& getTransactionId() const { return transaction_id_; }
    const std::vector<STUNAttribute>& getAttributes() const { return attributes_; }
    
    // Setters
    void setType(STUNMessageType type) { type_ = type; }
    void setTransactionId(const std::vector<uint8_t>& id) { transaction_id_ = id; }
    
    // Attribute operations
    void addAttribute(STUNAttributeType type, const std::vector<uint8_t>& value);
    bool getAttribute(STUNAttributeType type, std::vector<uint8_t>& out_value) const;
    bool getMappedAddress(STUNAddress& addr) const;
    bool getXorMappedAddress(STUNAddress& addr) const;
    
    // Serialization
    std::vector<uint8_t> encode() const;
    bool decode(const std::vector<uint8_t>& data);
    
private:
    STUNMessageType type_;
    std::vector<uint8_t> transaction_id_;
    std::vector<STUNAttribute> attributes_;
    
    // Encoding helpers
    void encodeAddress(STUNAttributeType type, const STUNAddress& addr, 
                      std::vector<uint8_t>& out, bool xor_ip = false) const;
};

/**
 * STUN Client for NAT traversal
 */
class STUNClient {
public:
    struct STUNServer {
        std::string hostname;
        uint16_t port;
        int timeout_ms;
    };
    
    struct ProbeResult {
        bool success;
        STUNAddress mapped_address;
        STUNAddress source_address;
        uint32_t rtt_ms;
        std::string error_message;
    };
    
    STUNClient();
    ~STUNClient();
    
    /**
     * Probe STUN server to get external IP:port
     */
    ProbeResult probeServer(const STUNServer& server);
    
    /**
     * Detect NAT type using 4-test algorithm (RFC 3489)
     * Returns: Open, FullCone, RestrictedCone, PortRestrictedCone, Symmetric, or Unknown
     */
    NATType detectNATType(const std::vector<STUNServer>& servers,
                         std::string& out_external_ip,
                         uint16_t& out_external_port);
    
    /**
     * Retry probe with exponential backoff
     */
    ProbeResult probeWithRetry(const STUNServer& server, 
                             int max_attempts = 3,
                             int initial_backoff_ms = 500);
    
private:
    // STUN protocol helpers
    bool sendSTUNRequest(int sock, const STUNServer& server, 
                        const STUNMessage& request);
    
    bool receiveSTUNResponse(int sock, STUNMessage& response, 
                           uint32_t& out_rtt_ms);
    
    // NAT detection algorithm
    ProbeResult test1(const std::vector<STUNServer>& servers);
    ProbeResult test2(const std::vector<STUNServer>& servers,
                     const STUNAddress& primary_address);
    ProbeResult test3(const std::vector<STUNServer>& servers);
    
    // Helper
    std::string natTypeToString(NATType type) const;
};

#endif // NAT_STUN_H
