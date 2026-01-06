#include "peer_state_machine.h"
#include "logger.h"

#if HAVE_JNI
#include <android/log.h>
#define NATIVELOGW(msg) __android_log_write(ANDROID_LOG_WARN, "Litep2p", msg)
#else
#include <iostream>
#include <chrono>
#include <iomanip>
#define NATIVELOGW(msg)
#endif

// ==========================================================
// FSM Implementation Notes:
// 
// This FSM implementation uses controlled impurity for performance reasons:
// - The FSM mutates its own context (PeerContext) rather than returning 
//   entirely new context objects on every transition
// - Retry counters and timestamps are modified in-place
// - This avoids expensive copying of state on every event, which is critical
//   for high-throughput peer management
//
// Despite this controlled impurity, the FSM remains the single source of truth
// for all peer state transitions and lifecycle decisions.
// ==========================================================

// ==========================================================
// FSM ENTRY POINT (PURE except timestamp update)
// ==========================================================
FSMResult PeerStateMachine::handle_event(PeerContext& peer, PeerEvent event) {

    const PeerState old_state = peer.state;
    
    // NATIVELOGW(("PeerStateMachine::handle_event: old_state=" + std::to_string((int)old_state) + ", event=" + std::to_string((int)event)).c_str());

    FSMResult result = compute_transition(old_state, event, peer);
    
    // NATIVELOGW(("PeerStateMachine::handle_event: new_state=" + std::to_string((int)result.new_state)).c_str());

    if (result.new_state != old_state) {
        peer.state = result.new_state;
        peer.last_state_change = std::chrono::steady_clock::now();

        // NATIVELOGW(("PeerStateMachine::handle_event: State changed! " + std::to_string((int)old_state) + " -> " + std::to_string((int)result.new_state)).c_str());

        LOG_INFO(
            std::string("[PeerFSM] ") +
            state_to_string(old_state) +
            " --(" + event_to_string(event) + ")--> " +
            state_to_string(result.new_state) +
            " peer=" + peer.peer_id
        );
    } else {
        // NATIVELOGW("PeerStateMachine::handle_event: State did NOT change.");
    }

    return result;
}

// ==========================================================
// PURE FSM TRANSITION TABLE (AUTHORITATIVE)
// ==========================================================
FSMResult PeerStateMachine::compute_transition(
    PeerState current,
    PeerEvent event,
    PeerContext& peer
) const {

    switch (current) {

    // ------------------------------------------------------
    case PeerState::UNKNOWN:
        if (event == PeerEvent::DISCOVERED)
            return FSMResult(PeerState::DISCOVERED);
        break;

    // ------------------------------------------------------
    case PeerState::DISCOVERED:
        if (event == PeerEvent::CONNECT_REQUESTED)
            return FSMResult(PeerState::CONNECTING);

        if (event == PeerEvent::CONNECT_SUCCESS) {
            peer.connect_retry_count = 0;
            return FSMResult(PeerState::CONNECTED);
        }

        if (event == PeerEvent::DISCONNECT_DETECTED)
            return FSMResult(PeerState::DISCONNECTED);

        if (event == PeerEvent::SHUTDOWN)
            return FSMResult(PeerState::FAILED);
        break;

    // ------------------------------------------------------
    case PeerState::CONNECTING:
        // Idempotency: repeated connect triggers while already CONNECTING are common during
        // signaling/discovery races and network flaps. Treat as a no-op instead of logging
        // it as an "ignored transition" (which can look like an error condition).
        if (event == PeerEvent::CONNECT_REQUESTED)
            return FSMResult(PeerState::CONNECTING);

        if (event == PeerEvent::CONNECT_SUCCESS) {
            peer.connect_retry_count = 0;
            return FSMResult(PeerState::CONNECTED);
        }

        if (event == PeerEvent::CONNECT_FAILED) {
            if (++peer.connect_retry_count >= MAX_HANDSHAKE_RETRIES) {
                return FSMResult(
                    PeerState::FAILED,
                    { PeerAction::CLEANUP_RESOURCES }
                );
            }
            return FSMResult(PeerState::DEGRADED);
        }

        if (event == PeerEvent::DISCONNECT_DETECTED)
            return FSMResult(PeerState::DISCONNECTED);

        if (event == PeerEvent::SHUTDOWN)
            return FSMResult(PeerState::FAILED);
        break;

    // ------------------------------------------------------
    case PeerState::CONNECTED:
        // Idempotency: connect races can deliver duplicate CONNECT_SUCCESS or repeated
        // connect triggers even after transport is up.
        if (event == PeerEvent::CONNECT_REQUESTED)
            return FSMResult(PeerState::CONNECTED);

        if (event == PeerEvent::CONNECT_SUCCESS)
            return FSMResult(PeerState::CONNECTED);

        if (event == PeerEvent::HANDSHAKE_REQUIRED) {
            // Guard: do not re-enter handshake endlessly
            if (peer.handshake_retry_count >= MAX_HANDSHAKE_RETRIES)
                return FSMResult(
                    PeerState::FAILED,
                    { PeerAction::CLEANUP_RESOURCES }
                );

            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::INITIATE_HANDSHAKE }
            );
        }

        if (event == PeerEvent::HANDSHAKE_MESSAGE_RECEIVED)
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::PROCESS_HANDSHAKE_MESSAGE }
            );

        if (event == PeerEvent::DISCONNECT_DETECTED)
            return FSMResult(
                PeerState::DISCONNECTED,
                { PeerAction::CLEANUP_RESOURCES }
            );

        if (event == PeerEvent::SHUTDOWN)
            return FSMResult(
                PeerState::FAILED,
                { PeerAction::CLEANUP_RESOURCES }
            );
        break;

    // ------------------------------------------------------
    case PeerState::HANDSHAKING:
        // Idempotency: while HANDSHAKING, upper layers may (re)trigger connects/handshake-required
        // due to discovery/signaling races. Treat these as benign no-ops to avoid log spam.
        if (event == PeerEvent::CONNECT_REQUESTED)
            return FSMResult(PeerState::HANDSHAKING);

        if (event == PeerEvent::CONNECT_SUCCESS)
            return FSMResult(PeerState::HANDSHAKING);

        if (event == PeerEvent::CONNECT_FAILED)
            return FSMResult(PeerState::HANDSHAKING);

        if (event == PeerEvent::HANDSHAKE_REQUIRED)
            return FSMResult(PeerState::HANDSHAKING);

        if (event == PeerEvent::HANDSHAKE_MESSAGE_RECEIVED)
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::PROCESS_HANDSHAKE_MESSAGE }
            );

        if (event == PeerEvent::HANDSHAKE_SUCCESS) {
            peer.handshake_retry_count = 0;
            return FSMResult(
                PeerState::READY,
                { PeerAction::FLUSH_QUEUED_MESSAGES }
            );
        }

        if (event == PeerEvent::HANDSHAKE_FAILED) {
            if (++peer.handshake_retry_count >= MAX_HANDSHAKE_RETRIES) {
                return FSMResult(
                    PeerState::FAILED,
                    { PeerAction::CLEANUP_RESOURCES }
                );
            }
            return FSMResult(
                PeerState::CONNECTED,
                { PeerAction::RETRY_HANDSHAKE }
            );
        }

        if (event == PeerEvent::DISCONNECT_DETECTED)
            return FSMResult(
                PeerState::DISCONNECTED,
                { PeerAction::CLEANUP_RESOURCES }
            );
        break;

    // ------------------------------------------------------
    case PeerState::READY:
        if (event == PeerEvent::MESSAGE_RECEIVED)
            return FSMResult(PeerState::READY);

        // Idempotency: ignore redundant connect triggers once READY.
        if (event == PeerEvent::CONNECT_REQUESTED)
            return FSMResult(PeerState::READY);

        if (event == PeerEvent::CONNECT_SUCCESS)
            return FSMResult(PeerState::READY);

        // Allow re-key / restart recovery: a peer may re-initiate Noise handshake even if we
        // still consider the session READY (e.g., remote restart or transport reconnect races).
        if (event == PeerEvent::HANDSHAKE_REQUIRED)
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::INITIATE_HANDSHAKE }
            );

        // When already READY, receiving a handshake message is likely a duplicate or late-arriving
        // message from the remote peer. We still process it (to send back a response if needed for
        // their state machine), but do NOT transition back to HANDSHAKING. The actual processing
        // in SessionManager will check is_ready() and handle appropriately.
        if (event == PeerEvent::HANDSHAKE_MESSAGE_RECEIVED)
            return FSMResult(
                PeerState::READY,
                { PeerAction::PROCESS_HANDSHAKE_MESSAGE }
            );

        if (event == PeerEvent::LATENCY_UPDATE)
            return FSMResult(
                PeerState::READY,
                { PeerAction::RECORD_METRICS }
            );

        if (event == PeerEvent::TIMEOUT)
            return FSMResult(PeerState::DEGRADED);

        if (event == PeerEvent::DISCONNECT_DETECTED)
            return FSMResult(
                PeerState::DISCONNECTED,
                { PeerAction::CLEANUP_RESOURCES }
            );
        break;

    // ------------------------------------------------------
    case PeerState::DEGRADED:
        if (event == PeerEvent::HANDSHAKE_REQUIRED) {
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::INITIATE_HANDSHAKE }
            );
        }

        if (event == PeerEvent::CONNECT_REQUESTED)
            return FSMResult(PeerState::CONNECTING);

        if (event == PeerEvent::TIMEOUT)
            return FSMResult(PeerState::CONNECTING);

        if (event == PeerEvent::RETRY_EXHAUSTED)
            return FSMResult(
                PeerState::FAILED,
                { PeerAction::CLEANUP_RESOURCES }
            );

        if (event == PeerEvent::DISCONNECT_DETECTED)
            return FSMResult(
                PeerState::DISCONNECTED,
                { PeerAction::CLEANUP_RESOURCES }
            );
        break;

    // ------------------------------------------------------
    case PeerState::DISCONNECTED:
        if (event == PeerEvent::DISCOVERED)
            return FSMResult(PeerState::DISCOVERED);

        // Recovery: a peer may reconnect inbound (e.g., TCP accept) without a fresh discovery
        // transition. Allow the FSM to re-enter connected/handshaking flows.
        if (event == PeerEvent::CONNECT_REQUESTED)
            return FSMResult(PeerState::CONNECTING);

        if (event == PeerEvent::CONNECT_SUCCESS)
            return FSMResult(PeerState::CONNECTED);

        if (event == PeerEvent::HANDSHAKE_REQUIRED)
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::INITIATE_HANDSHAKE }
            );

        if (event == PeerEvent::HANDSHAKE_MESSAGE_RECEIVED)
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::PROCESS_HANDSHAKE_MESSAGE }
            );

        if (event == PeerEvent::SHUTDOWN)
            return FSMResult(PeerState::FAILED);
        break;

    // ------------------------------------------------------
    case PeerState::FAILED:
        // FAILED is not truly terminal in real networks (mobile/WAN restarts are normal).
        // Allow recovery paths so a previously failed peer can reconnect when it reappears.
        if (event == PeerEvent::DISCOVERED) {
            peer.connect_retry_count = 0;
            peer.handshake_retry_count = 0;
            return FSMResult(PeerState::DISCOVERED);
        }

        if (event == PeerEvent::CONNECT_REQUESTED) {
            peer.connect_retry_count = 0;
            return FSMResult(PeerState::CONNECTING);
        }

        if (event == PeerEvent::CONNECT_SUCCESS) {
            peer.connect_retry_count = 0;
            return FSMResult(PeerState::CONNECTED);
        }

        if (event == PeerEvent::HANDSHAKE_REQUIRED) {
            peer.handshake_retry_count = 0;
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::INITIATE_HANDSHAKE }
            );
        }

        if (event == PeerEvent::HANDSHAKE_MESSAGE_RECEIVED)
            return FSMResult(
                PeerState::HANDSHAKING,
                { PeerAction::PROCESS_HANDSHAKE_MESSAGE }
            );

        if (event == PeerEvent::DISCONNECT_DETECTED)
            return FSMResult(
                PeerState::DISCONNECTED,
                { PeerAction::CLEANUP_RESOURCES }
            );
        break;
    }

    LOG_WARN(
        std::string("[PeerFSM] Ignored transition ") +
        state_to_string(current) +
        " + " + event_to_string(event)
    );

    return FSMResult(current);
}

// ==========================================================
// DEBUG HELPERS
// ==========================================================
const char* PeerStateMachine::state_to_string(PeerState state) {
    switch (state) {
        case PeerState::UNKNOWN: return "UNKNOWN";
        case PeerState::DISCOVERED: return "DISCOVERED";
        case PeerState::CONNECTING: return "CONNECTING";
        case PeerState::CONNECTED: return "CONNECTED";
        case PeerState::HANDSHAKING: return "HANDSHAKING";
        case PeerState::READY: return "READY";
        case PeerState::DEGRADED: return "DEGRADED";
        case PeerState::DISCONNECTED: return "DISCONNECTED";
        case PeerState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

const char* PeerStateMachine::event_to_string(PeerEvent event) {
    switch (event) {
        case PeerEvent::DISCOVERED: return "DISCOVERED";
        case PeerEvent::CONNECT_REQUESTED: return "CONNECT_REQUESTED";
        case PeerEvent::CONNECT_SUCCESS: return "CONNECT_SUCCESS";
        case PeerEvent::CONNECT_FAILED: return "CONNECT_FAILED";
        case PeerEvent::HANDSHAKE_REQUIRED: return "HANDSHAKE_REQUIRED";
        case PeerEvent::HANDSHAKE_SUCCESS: return "HANDSHAKE_SUCCESS";
        case PeerEvent::HANDSHAKE_FAILED: return "HANDSHAKE_FAILED";
        case PeerEvent::HANDSHAKE_MESSAGE_RECEIVED: return "HANDSHAKE_MESSAGE_RECEIVED";
        case PeerEvent::MESSAGE_RECEIVED: return "MESSAGE_RECEIVED";
        case PeerEvent::DISCONNECT_DETECTED: return "DISCONNECT_DETECTED";
        case PeerEvent::TIMEOUT: return "TIMEOUT";
        case PeerEvent::LATENCY_UPDATE: return "LATENCY_UPDATE";
        case PeerEvent::RETRY_EXHAUSTED: return "RETRY_EXHAUSTED";
        case PeerEvent::SHUTDOWN: return "SHUTDOWN";
        default: return "UNKNOWN";
    }
}