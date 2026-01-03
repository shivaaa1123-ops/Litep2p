#ifndef NAT_STUN_H
#define NAT_STUN_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/**
 * @file nat_stun.h
 * @brief STUN Protocol Implementation (RFC 5389/3489)
 * 
 * This module provides a complete STUN (Session Traversal Utilities for NAT)
 * implementation supporting:
 * - STUN Binding Request/Response with RFC 5389 message format
 * - XOR-MAPPED-ADDRESS and MAPPED-ADDRESS attribute parsing (IPv4 + IPv6)
 * - CHANGE-REQUEST attribute for NAT type detection (RFC 3489 compatibility)
 * - RFC 5389 compliant retransmission timing (RTO = 500ms base, Rm = 7)
 * - Comprehensive NAT type detection (Open, Full Cone, Restricted, 
 *   Port-Restricted, Symmetric)
 * 
 * Thread Safety:
 * - All public methods are thread-safe (uses POSIX sockets internally)
 * - inet_ntop used instead of inet_ntoa for thread safety
 * 
 * Usage Example:
 * @code
 *   STUNClient client;
 *   STUNServer server{"stun.l.google.com", 19302};
 *   auto result = client.probeServer(server);
 *   if (result.success) {
 *       std::cout << "External IP: " << result.mapped_address.ip << std::endl;
 *   }
 * @endcode
 */

/**
 * @enum STUNErrorCode
 * @brief Detailed error codes for STUN operations
 * 
 * Error codes are grouped by category:
 * - 1xx: Socket/network errors
 * - 2xx: Protocol/parsing errors
 * - 3xx: Configuration/server errors
 */
enum class STUNErrorCode {
    Success = 0,
    SocketCreationFailed = 100,
    SocketOptionFailed = 101,
    DnsResolutionFailed = 102,
    SendFailed = 103,
    ReceiveTimeout = 104,
    ReceiveFailed = 105,
    InvalidMagicCookie = 200,
    InvalidMessageFormat = 201,
    MessageTooShort = 202,
    AttributeParseError = 203,
    NoMappedAddress = 204,
    TransactionIdMismatch = 205,
    NoServersConfigured = 300,
    AllServersFailed = 301,
    UdpBlocked = 302,
    Cancelled = 303,
};

inline std::string stunErrorToString(STUNErrorCode code) {
    switch (code) {
        case STUNErrorCode::Success: return "Success";
        case STUNErrorCode::SocketCreationFailed: return "Socket creation failed";
        case STUNErrorCode::SocketOptionFailed: return "Socket option failed";
        case STUNErrorCode::DnsResolutionFailed: return "DNS resolution failed";
        case STUNErrorCode::SendFailed: return "Send failed";
        case STUNErrorCode::ReceiveTimeout: return "Receive timeout";
        case STUNErrorCode::ReceiveFailed: return "Receive failed";
        case STUNErrorCode::InvalidMagicCookie: return "Invalid STUN magic cookie";
        case STUNErrorCode::InvalidMessageFormat: return "Invalid message format";
        case STUNErrorCode::MessageTooShort: return "Message too short";
        case STUNErrorCode::AttributeParseError: return "Attribute parse error";
        case STUNErrorCode::NoMappedAddress: return "No mapped address in response";
        case STUNErrorCode::TransactionIdMismatch: return "Transaction ID mismatch";
        case STUNErrorCode::NoServersConfigured: return "No STUN servers configured";
        case STUNErrorCode::AllServersFailed: return "All STUN servers failed";
        case STUNErrorCode::UdpBlocked: return "UDP appears to be blocked";
        case STUNErrorCode::Cancelled: return "Cancelled";
        default: return "Unknown error";
    }
}

// STUN Magic Cookie (RFC 5389)
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN Message Types
enum class STUNMessageType : uint16_t {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingError = 0x0111,
    BindingIndication = 0x0011,
    // TURN Messages
    AllocateRequest = 0x0003,
    AllocateResponse = 0x0103,
    AllocateError = 0x0113,
    CreatePermissionRequest = 0x0004,
    CreatePermissionResponse = 0x0104,
    CreatePermissionError = 0x0114,
    SendIndication = 0x0016,
    DataIndication = 0x0017,
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
    OtherAddress = 0x802C,      // RFC 5780 - alternate server address
    Fingerprint = 0x8028,
    // TURN Attributes
    ChannelNumber = 0x000C,
    Lifetime = 0x000D,
    XorPeerAddress = 0x0012,
    Data = 0x0013,
    XorRelayedAddress = 0x0016,
    EvenPort = 0x0018,
    RequestedTransport = 0x0019,
    DontFragment = 0x001A,
    ReservationToken = 0x0022,
};

// CHANGE-REQUEST flags (RFC 5780)
constexpr uint32_t STUN_CHANGE_IP = 0x04;
constexpr uint32_t STUN_CHANGE_PORT = 0x02;

// NAT Type Classification
enum class NATType {
    Open,                    // No NAT (same IP as external)
    FullCone,               // Same EP for all destinations
    RestrictedCone,         // Same EP, but destination IP restricted
    PortRestrictedCone,     // Same EP, but destination IP:port restricted
    Symmetric,              // Different EP for different destinations
    Unknown,                // Could not determine
};

// RFC 5389 Retransmission constants
constexpr int STUN_RTO_INITIAL_MS = 500;      // Initial RTO (500ms for UDP)
constexpr int STUN_RTO_MAX_MS = 3000;         // Maximum RTO
constexpr int STUN_RC_DEFAULT = 7;            // Default retransmit count (Rc)
constexpr int STUN_RM_DEFAULT = 16;           // Rm = 16 (retransmit multiplier)
constexpr int STUN_Ti_MS = 39500;             // Transaction timeout (39.5s)

struct STUNAddress {
    uint8_t family{0x01};   // 0x01 = IPv4, 0x02 = IPv6
    std::string ip;
    uint16_t port{0};
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
    void addChangeRequest(bool change_ip, bool change_port);
    bool getAttribute(STUNAttributeType type, std::vector<uint8_t>& out_value) const;
    bool getMappedAddress(STUNAddress& addr) const;
    bool getXorMappedAddress(STUNAddress& addr) const;
    bool getOtherAddress(STUNAddress& addr) const;
    
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
        uint16_t port{3478};
        int timeout_ms{2000};
        
        STUNServer() = default;
        STUNServer(const std::string& h, uint16_t p, int t = 2000)
            : hostname(h), port(p), timeout_ms(t) {}
    };
    
    struct ProbeResult {
        bool success{false};
        STUNAddress mapped_address;
        STUNAddress source_address;
        uint32_t rtt_ms{0};
        STUNErrorCode error_code{STUNErrorCode::Success};
        std::string error_message;
        
        // Convenience constructor for failure
        static ProbeResult failure(STUNErrorCode code, const std::string& msg = "") {
            ProbeResult r;
            r.success = false;
            r.error_code = code;
            r.error_message = msg.empty() ? stunErrorToString(code) : msg;
            return r;
        }
    };
    
    STUNClient();
    ~STUNClient();

    // Best-effort cancellation to accelerate engine shutdown.
    // When set, ongoing probe/detection calls should abort early.
    void requestCancel();
    void clearCancel();
    bool isCancelRequested() const;
    
    /**
     * Probe STUN server to get external IP:port
     */
    ProbeResult probeServer(const STUNServer& server);
    
    /**
     * Probe STUN server with CHANGE-REQUEST flags
     * @param server The STUN server to probe
     * @param change_ip Request response from different IP
     * @param change_port Request response from different port
     */
    ProbeResult probeServerWithFlags(const STUNServer& server, 
                                     bool change_ip, 
                                     bool change_port);
    
    /**
     * Detect NAT type using 4-test algorithm (RFC 3489/5780)
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

    std::atomic_bool cancel_requested_{false};
    
    // NAT detection algorithm (RFC 3489/5780)
    ProbeResult test1(const std::vector<STUNServer>& servers);
    ProbeResult test2(const std::vector<STUNServer>& servers,
                     const STUNAddress& primary_address);
    ProbeResult test3(const std::vector<STUNServer>& servers);
    ProbeResult test4(const std::vector<STUNServer>& servers);
    
    // Get local interface IP for Open NAT detection
    std::string getLocalIP() const;
    
    // Helper
    std::string natTypeToString(NATType type) const;
};

#endif // NAT_STUN_H
