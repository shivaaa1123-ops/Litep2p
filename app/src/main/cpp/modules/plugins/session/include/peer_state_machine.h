#ifndef PEER_STATE_MACHINE_H
#define PEER_STATE_MACHINE_H

#include <string>
#include <chrono>
#include <deque>
#include <vector>
#include "peer.h"
#include "../../routing/include/peer_tier_manager.h"

// Maximum number of handshake retries before giving up
static constexpr int MAX_HANDSHAKE_RETRIES = 3;

// =======================================================
// Authoritative Peer State (FSM owns this exclusively)
// =======================================================
enum class PeerState {
    UNKNOWN,        // Not yet known to FSM
    DISCOVERED,     // Seen via discovery
    CONNECTING,     // Outgoing or incoming connection attempt
    CONNECTED,      // Transport connected, security not ready
    HANDSHAKING,    // Security / protocol handshake in progress
    READY,          // Fully usable peer
    DEGRADED,       // Temporarily unstable but usable
    DISCONNECTED,   // Graceful or detected disconnect
    FAILED          // Terminal failure (retry exhausted)
};

// =======================================================
// FSM Input Events (external stimuli only)
// =======================================================
enum class PeerEvent {
    DISCOVERED,
    CONNECT_REQUESTED,
    CONNECT_SUCCESS,
    CONNECT_FAILED,
    HANDSHAKE_REQUIRED,
    HANDSHAKE_SUCCESS,
    HANDSHAKE_FAILED,
    HANDSHAKE_MESSAGE_RECEIVED,
    MESSAGE_RECEIVED,
    DISCONNECT_DETECTED,
    TIMEOUT,
    LATENCY_UPDATE,
    RETRY_EXHAUSTED,
    SHUTDOWN
};

// =======================================================
// FSM Output Actions (INTENTS ONLY — no side effects here)
// =======================================================
enum class PeerAction {
    NONE,
    INITIATE_HANDSHAKE,
    PROCESS_HANDSHAKE_MESSAGE,
    RETRY_HANDSHAKE,
    FLUSH_QUEUED_MESSAGES,
    CLEANUP_RESOURCES,
    RECORD_METRICS
};

// =======================================================
// FSM Result (pure description of what to do next)
// =======================================================
struct FSMResult {
    PeerState new_state;
    std::vector<PeerAction> actions;

    explicit FSMResult(PeerState state)
        : new_state(state) {}

    FSMResult(PeerState state, std::initializer_list<PeerAction> action_list)
        : new_state(state), actions(action_list) {}
};

// =======================================================
// Peer Context (FSM-owned mutable state only)
// =======================================================
// NOTE: This struct contains mutable state that is exclusively owned and managed by the FSM.
// While this creates controlled impurity (the FSM modifies its own state), this approach is 
// necessary for performance reasons to avoid expensive state copying on every transition.
// The FSM remains the single source of truth for all peer state and lifecycle management.
struct PeerContext {
    // Identity
    std::string peer_id;
    std::string network_id;

    // FSM state
    PeerState state = PeerState::UNKNOWN;

    // Tiering (advisory, not decisive)
    PeerTier tier = PeerTier::TIER_1;

    // Retry counters (FSM authoritative)
    // NOTE: These are mutated by the FSM itself for performance reasons
    // rather than returning new context objects on every transition
    int connect_retry_count = 0;
    int handshake_retry_count = 0;

    // Handshake nonce
    uint64_t next_nonce = 0;

    // Observational metrics (read-only to FSM)
    int latency_ms = 0;

    // Timestamps (FSM maintained)
    // NOTE: These are mutated by the FSM to track state changes
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point last_state_change;
    std::chrono::steady_clock::time_point last_handshake_attempt;

    // Connection attempt tracking (used for debouncing/out-of-date endpoint recovery)
    std::chrono::steady_clock::time_point last_connect_attempt;
    std::string last_connect_target_network_id;

    // Message queue (FSM owns lifecycle)
    std::deque<std::string> pending_messages;
    
    // Temporary storage for handshake message
    std::string pending_handshake_message;

    explicit PeerContext(const std::string& id = "",
                         const std::string& network = "")
        : peer_id(id), network_id(network) {
        auto now = std::chrono::steady_clock::now();
        last_seen = now;
        last_state_change = now;
        last_handshake_attempt = now;
        last_connect_attempt = now;
    }
};

// =======================================================
// Peer State Machine (PURE LOGIC ONLY)
// =======================================================
class PeerStateMachine {
public:
    // Pure FSM step:
    // (Context + Event) -> (New State + Actions)
    FSMResult handle_event(PeerContext& peer, PeerEvent event);

private:
    // Transition table logic (NO side effects)
    FSMResult compute_transition(PeerState current,
                                 PeerEvent event,
                                 PeerContext& peer) const;

    // Debug helpers (FSM-local only)
    static const char* state_to_string(PeerState state);
    static const char* event_to_string(PeerEvent event);
};

#endif // PEER_STATE_MACHINE_H