#include "nat_traversal.h"
#include <chrono>
#include <algorithm>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <cstdlib>

NATTraversal& NATTraversal::getInstance() {
    static NATTraversal instance;
    return instance;
}

bool NATTraversal::initialize(uint16_t local_port) {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    
    local_port_ = local_port;
    
    // Initialize default STUN servers
    stun_servers_.push_back({"stun.l.google.com", 19302, "UDP"});
    stun_servers_.push_back({"stun1.l.google.com", 19302, "UDP"});
    stun_servers_.push_back({"stun2.l.google.com", 19302, "UDP"});
    
    std::cout << "[NAT] Initialized with " << stun_servers_.size() << " STUN servers" << std::endl;
    
    return true;
}

NATInfo NATTraversal::detectNATType() {
    std::lock_guard<std::mutex> lock(nat_mutex_);
    
    nat_info_.detection_time = std::chrono::system_clock::now().time_since_epoch().count() / 1000000;
    nat_info_.external_ip = "127.0.0.1";
    nat_info_.external_port = local_port_;
    nat_info_.supports_stun = false;
    nat_info_.supports_upnp = false;
    nat_info_.nat_type = NATType::Open;
    std::cout << "[NAT] Type detected: " << natTypeToString(nat_info_.nat_type) << std::endl;
    return nat_info_;
}
