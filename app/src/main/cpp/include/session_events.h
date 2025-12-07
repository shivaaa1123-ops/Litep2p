#ifndef SESSION_EVENTS_H
#define SESSION_EVENTS_H

#include <string>
#include <chrono>
#include <variant>

// --- Event for when a new peer is discovered ---
struct PeerDiscoveredEvent {
    std::string ip;
    int port;
    std::string peerId;
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
    std::string peerId;
};

// --- Event to send a message to a peer ---
struct SendMessageEvent {
    std::string peerId;
    std::string message;
};

// --- An internal event to trigger the ping/reap cycle ---
struct TimerTickEvent {};

// --- A variant to hold any of the possible event types ---
using SessionEvent = std::variant<
    PeerDiscoveredEvent,
    DataReceivedEvent,
    PeerDisconnectEvent,
    ConnectToPeerEvent,
    SendMessageEvent,
    TimerTickEvent
>;

#endif // SESSION_EVENTS_H
