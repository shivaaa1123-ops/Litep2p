#ifndef SESSION_EVENTS_H
#define SESSION_EVENTS_H

#include <string>
#include <chrono>
#include <variant>
#include "peer_state_machine.h"

// --- Event for when a new peer is discovered ---
struct PeerDiscoveredEvent {
    std::string peerId;
    std::string networkId;
};

// --- Event for when data is received from a peer ---
struct DataReceivedEvent {
    std::string network_id;
    std::string data;
    std::chrono::steady_clock::time_point arrival_time;
};

// --- Event for when a peer's connection is lost ---
struct PeerDisconnectEvent {
    std::string network_id;
};

// --- Event to explicitly connect to a peer ---
struct ConnectToPeerEvent {
    // Target peer ID to connect to.
    std::string peerId;

    // When true, bypass reconnect-policy gating for this connect attempt.
    // Used for remote-initiated recovery signals (e.g., CONNECT_REQUEST) where
    // suppression can prevent forward progress under network flaps.
    bool bypass_reconnect_policy = false;

    // Optional debug source tag (e.g., "ui", "signaling_connect_request", "discovery").
    std::string source;

    ConnectToPeerEvent() = default;
    explicit ConnectToPeerEvent(std::string peer) : peerId(std::move(peer)) {}
    ConnectToPeerEvent(std::string peer, bool bypass, std::string src = {})
        : peerId(std::move(peer)), bypass_reconnect_policy(bypass), source(std::move(src)) {}
};

// --- Event to send a message to a peer ---
struct SendMessageEvent {
    std::string peerId;
    std::string message;
};

// --- An internal event to trigger the ping/reap cycle ---
struct TimerTickEvent {};

// --- Event to initiate peer discovery (non-blocking) ---
struct DiscoveryInitiatedEvent {
    std::string peerId;
};

// --- Event for NAT traversal completion ---
struct NATTraversalCompleteEvent {
    std::string peerId;
    bool success;
    std::string external_ip;
    uint16_t external_port;
    std::string error_message;
};

// --- Event for connection attempt completion ---
struct ConnectionAttemptCompleteEvent {
    std::string peerId;
    std::string network_id;
    bool success;
    std::string error_message;
};

// --- Event for enhanced data received with peer info ---
struct EnhancedDataReceivedEvent {
    std::string peerId;
    std::string network_id;
    std::string data;
    std::chrono::steady_clock::time_point arrival_time;
};

// --- Event for enhanced peer disconnect with peer info ---
struct EnhancedPeerDisconnectEvent {
    std::string peerId;
    std::string network_id;
};

// --- Event for message send completion with success/failure status ---
struct MessageSendCompleteEvent {
    std::string peerId;
    std::string message_id;
    bool success;
    std::string error_message;
};

// --- Event for LAN discovery result (local endpoint discovered) ---
struct LanDiscoveryResultEvent {
    std::string peerId;          // Target peer ID that responded
    std::string lanIp;           // Discovered LAN IP address (RFC1918)
    int lanPort = -1;            // Discovered LAN port
    int hopCount = 0;            // Number of hops in discovery
    int latencyMs = 0;           // Discovery round-trip latency
};

// --- Event for FSM state transitions ---
struct FSMEvent {
    std::string peerId;
    PeerEvent fsmEvent;
    uint64_t connect_epoch = 0;  // Connection epoch for gating stale events
};

// --- A variant to hold any of the possible event types ---
using SessionEvent = std::variant<
    PeerDiscoveredEvent,
    DataReceivedEvent,
    PeerDisconnectEvent,
    ConnectToPeerEvent,
    SendMessageEvent,
    TimerTickEvent,
    DiscoveryInitiatedEvent,
    NATTraversalCompleteEvent,
    ConnectionAttemptCompleteEvent,
    EnhancedDataReceivedEvent,
    EnhancedPeerDisconnectEvent,
    MessageSendCompleteEvent,
    FSMEvent,
    LanDiscoveryResultEvent
>;

#endif // SESSION_EVENTS_H
