#pragma once

#include "nat_stun.h"
#include <string>
#include <vector>
#include <functional>

struct TurnConfig {
    std::string server_ip;
    uint16_t server_port{3478};
    std::string username;
    std::string password;
    std::string realm;
};

struct TurnAllocation {
    std::string relayed_ip;
    uint16_t relayed_port{0};
    uint32_t lifetime{0};
    std::string token;
    bool active{false};
};

class TurnClient {
public:
    TurnClient(const TurnConfig& config);
    ~TurnClient();

    // Synchronous blocking call for simplicity in this iteration
    bool allocate(TurnAllocation& out_allocation);
    bool createPermission(const std::string& peer_ip);
    
    // Send data via relay
    bool sendData(const std::string& peer_ip, uint16_t peer_port, const std::vector<uint8_t>& data);

private:
    TurnConfig m_config;
    int m_socket{-1};
    
    bool sendRequest(const STUNMessage& req, STUNMessage& res);
    void addAuthAttributes(STUNMessage& msg, const std::string& realm, const std::string& nonce);
};
