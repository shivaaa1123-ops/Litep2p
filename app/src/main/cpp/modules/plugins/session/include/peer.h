#ifndef PEER_H
#define PEER_H

#include <string>
#include <chrono>
#include <vector>
#include <cstdint>
#include "peer_tier.h"

// Endpoint candidate types for multi-path connectivity
enum class EndpointType {
    LAN,    // Private IPv4 (RFC1918) - direct local network
    WAN,    // Public IPv4 - via NAT traversal
    RELAY   // Via relay/proxy server
};

// Detailed connection path - tracks HOW the connection was established
// This is used for analytics and optimization decisions
enum class ConnectionPath {
    UNKNOWN,           // Connection path not yet determined
    LAN_DIRECT,        // Direct connection over local network (private IPs)
    WAN_HOLE_PUNCH,    // Direct P2P via UDP/TCP hole punching (NAT traversal succeeded)
    WAN_TURN_RELAY,    // Traffic routed through TURN relay server
    SIGNALING_RELAY    // Handshake/data relayed via signaling server (AP isolation workaround)
};

inline const char* connectionPathToString(ConnectionPath path) {
    switch (path) {
        case ConnectionPath::LAN_DIRECT:       return "LAN";
        case ConnectionPath::WAN_HOLE_PUNCH:   return "WAN_DIRECT";
        case ConnectionPath::WAN_TURN_RELAY:   return "TURN";
        case ConnectionPath::SIGNALING_RELAY:  return "SIGNALING";
        case ConnectionPath::UNKNOWN:
        default:                               return "UNKNOWN";
    }
}

// Endpoint candidate for a peer (multiple paths may be available)
struct EndpointCandidate {
    std::string ip;
    int port = -1;
    EndpointType type = EndpointType::LAN;
    
    // Quality metrics
    uint64_t last_seen_ms = 0;        // When we last observed this endpoint
    uint64_t last_success_ms = 0;     // When we last successfully connected via this endpoint
    uint64_t last_failure_ms = 0;     // When we last failed to connect via this endpoint
    int consecutive_failures = 0;     // Number of consecutive failures on this endpoint
    int total_failures = 0;           // Total failures on this endpoint
    uint32_t last_rtt_ms = 0;         // Last measured RTT
    uint32_t avg_rtt_ms = 0;          // Average RTT (exponential moving average)
    
    // Compute a score for this candidate (higher = better)
    float compute_score(uint64_t now_ms) const {
        float score = 0.0f;
        
        // Base score by type (prefer LAN over WAN over Relay)
        if (type == EndpointType::LAN) score += 100.0f;
        else if (type == EndpointType::WAN) score += 50.0f;
        else score += 10.0f;
        
        // Freshness bonus (more recent = better, up to 30 seconds)
        if (last_seen_ms > 0 && now_ms >= last_seen_ms) {
            uint64_t age_ms = now_ms - last_seen_ms;
            float freshness_sec = std::min(30.0f, static_cast<float>(age_ms) / 1000.0f);
            score += (30.0f - freshness_sec);  // 0-30 point bonus
        }
        
        // Success bonus (recent success = much better)
        if (last_success_ms > 0 && now_ms >= last_success_ms) {
            uint64_t age_ms = now_ms - last_success_ms;
            if (age_ms < 60000) {  // Success within last minute
                score += 50.0f;
            }
        }
        
        // Penalty for failures
        score -= (20.0f * consecutive_failures);
        
        // RTT penalty (higher RTT = lower score)
        if (avg_rtt_ms > 0) {
            score -= std::min(30.0f, static_cast<float>(avg_rtt_ms) / 10.0f);
        }
        
        return score;
    }
    
    std::string to_network_id() const {
        return ip + ":" + std::to_string(port);
    }
};

struct Peer {
    std::string id;
    std::string ip;
    int port = -1;
    std::chrono::steady_clock::time_point last_seen;
    // Timestamp of last *discovery* announcement observed for this peer.
    // IMPORTANT: For connected peers, discovery traffic must not be treated as liveness for the
    // encrypted session. Otherwise a restarted peer (new Noise keys) can keep an old READY session
    // "alive" forever via discovery while PING/PONG cannot decrypt, preventing reconnection.
    std::chrono::steady_clock::time_point last_discovery_seen;
    int latency = -1;
    // Active endpoint used for the current session and for sending traffic.
    // For UDP this is the ip:port we last connected to (or discovered on LAN).
    std::string network_id;

    // Latest endpoint advertised via discovery/signaling. This may differ from `network_id`
    // while we are actively connected (e.g., peer switches LAN->WAN or restarts and updates
    // its public mapping). We keep it separate so we can switch cleanly on reconnect
    // without breaking an otherwise healthy LAN session.
    std::string advertised_network_id;
    
    // Endpoint candidate set: Multiple paths (LAN, WAN, Relay) that may work for this peer.
    // This enables happy-eyeballs parallel connects and intelligent fallback.
    std::vector<EndpointCandidate> endpoint_candidates;
    
    bool connected = false;
    PeerTier tier = PeerTier::TIER_1;
    
    // Active connection path - tracks HOW the current connection was established
    // Updated when connection becomes READY; reset to UNKNOWN on disconnect
    ConnectionPath active_connection_path = ConnectionPath::UNKNOWN;
    
    // Get the best candidate endpoint based on score
    EndpointCandidate* get_best_candidate(uint64_t now_ms) {
        if (endpoint_candidates.empty()) return nullptr;
        
        float best_score = -1.0f;
        EndpointCandidate* best = nullptr;
        for (auto& candidate : endpoint_candidates) {
            float score = candidate.compute_score(now_ms);
            if (score > best_score) {
                best_score = score;
                best = &candidate;
            }
        }
        return best;
    }
    
    // Update or add an endpoint candidate
    void update_endpoint_candidate(const std::string& ip, int port, EndpointType type, uint64_t now_ms) {
        // Check if candidate already exists
        for (auto& candidate : endpoint_candidates) {
            if (candidate.ip == ip && candidate.port == port) {
                candidate.type = type;
                candidate.last_seen_ms = now_ms;
                return;
            }
        }
        
        // Add new candidate
        EndpointCandidate new_candidate;
        new_candidate.ip = ip;
        new_candidate.port = port;
        new_candidate.type = type;
        new_candidate.last_seen_ms = now_ms;
        endpoint_candidates.push_back(new_candidate);
    }
};

#endif // PEER_H
