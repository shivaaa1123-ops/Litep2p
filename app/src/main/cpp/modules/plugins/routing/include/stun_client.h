#ifndef STUN_CLIENT_H
#define STUN_CLIENT_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * RFC 5389 STUN Client Implementation
 * Full NAT type detection with XOR-MAPPED-ADDRESS parsing
 */

enum class NATType {
    Unknown,
    Open,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric
};

struct STUNServer {
    std::string hostname;
    uint16_t port;
    int timeout_ms;
};

class STUNClient {
public:
    STUNClient();
    
    /**
     * Detect NAT type using multiple STUN servers
     */
    NATType detectNATType(const std::vector<STUNServer>& servers,
                         std::string& external_ip,
                         uint16_t& external_port);
    
    /**
     * Send STUN binding request to specific server
     */
    bool sendSTUNRequest(const STUNServer& server,
                        std::string& external_ip,
                        uint16_t& external_port);

private:
    uint8_t transaction_id_[12];
    
    // STUN message creation
    std::vector<uint8_t> createBindingRequest();
    
    // STUN response parsing
    bool parseSTUNResponse(const char* buffer, size_t length,
                          std::string& external_ip, uint16_t& external_port);
    bool parseXORMappedAddress(const char* data, size_t length,
                              std::string& ip, uint16_t& port);
    bool parseMappedAddress(const char* data, size_t length,
                           std::string& ip, uint16_t& port);
    
    // NAT type testing
    bool testConeNAT(const STUNServer& server,
                    const std::string& test_ip,
                    uint16_t test_port);
    
    void nativeLog(const std::string& message);
};

#endif // STUN_CLIENT_H