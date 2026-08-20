#pragma once

// Network OS — SessionFacade (master doc §17 connection budgets, §18
// multiplexing, §39 capability negotiation; Phase 2).
//
// Thin facade over the existing SessionManager. It enforces SESSION BOUNDS
// (pending-handshake cap, active-session cap, handshake timeout), stores each
// peer's capability document + negotiated result, and keeps session telemetry
// (handshake latency, connect success/failure, reconnect counts, gauges).
// No transport logic moves here — the existing peer FSM stays authoritative.

#include "networkos/Runtime.h"
#include "networkos/capability.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

class SessionManager;

namespace networkos {

class SessionFacade {
public:
    struct Bounds {
        size_t max_pending_handshakes{16};   // peers in CONNECTING/HANDSHAKING
        size_t max_active_sessions{64};      // peers in READY
        uint32_t handshake_timeout_ms{15000};
    };

    struct SessionTelemetry {
        uint64_t connect_success_total{0};
        uint64_t connect_failed_total{0};
        uint64_t handshake_success_total{0};
        uint64_t handshake_failed_total{0};
        uint64_t reconnect_total{0};
        size_t pending_handshakes{0};
        size_t active_sessions{0};
    };

    explicit SessionFacade(std::shared_ptr<SessionManager> session, const Bounds& bounds);

    // Bounds (read-only snapshot).
    const Bounds& bounds() const { return m_bounds; }

    // The capability document this node advertises.
    const CapabilityDocument& localCapability() const { return m_local_cap; }

    // Register a peer capability received on session setup. Decodes the
    // base64 doc; computes the negotiated result. Returns false on malformed.
    bool setPeerCapability(const std::string& peer_id, const std::string& cap_b64);

    // Negotiated result for a peer (nullptr when not yet negotiated).
    const CapabilityDocument::Negotiated* negotiation(const std::string& peer_id) const;
    const CapabilityDocument* peerCapability(const std::string& peer_id) const;

    // Bounded connect: refuses when the pending-handshake cap is hit.
    Result connect(const std::string& peer_id, const std::string& endpoint);
    Result disconnect(const std::string& peer_id);
    bool isConnected(const std::string& peer_id) const;
    std::string peerState(const std::string& peer_id) const;

    // Session accounting — called from the NetworkRuntime peers callback.
    void onPeerState(const std::string& peer_id, const std::string& state);
    void onHandshakeStarted(const std::string& peer_id);
    void onHandshakeSucceeded(const std::string& peer_id);
    void onHandshakeFailed(const std::string& peer_id);

    // Reconnect mode passthrough (backoff+jitter+event model lives in
    // PeerReconnectPolicy). Bounded by the retry budget inside that policy.
    Result setReconnectMode(const std::string& mode);

    const SessionTelemetry& telemetry() const { return m_telemetry; }
    std::string telemetryJson() const;

    // The base64 provider registered on the underlying SessionManager.
    std::string capabilityB64() const;

private:
    // Called by SessionManager via the consumer hook.
    void onPeerCapability(const std::string& peer_id, const std::string& cap_b64);

    void recount_();

    std::shared_ptr<SessionManager> m_session;
    Bounds m_bounds;
    CapabilityDocument m_local_cap;

    struct PeerSessionInfo {
        CapabilityDocument cap;
        CapabilityDocument::Negotiated negotiated;
        bool has_capability{false};
        int64_t handshake_started_ms{0};
        std::string state;
    };
    mutable std::mutex m_mu;
    std::unordered_map<std::string, PeerSessionInfo> m_peers;
    SessionTelemetry m_telemetry;
};

std::unique_ptr<SessionFacade> createSessionFacade(std::shared_ptr<SessionManager> session);

} // namespace networkos
