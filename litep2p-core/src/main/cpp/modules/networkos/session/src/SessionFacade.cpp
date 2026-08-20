// SessionFacade.cpp — Network OS Phase 2 session facade with bounds,
// capability negotiation bookkeeping, and telemetry.

#include "networkos/session/SessionFacade.h"

#include "session_manager.h"

#include <sstream>

namespace networkos {

namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

SessionFacade::SessionFacade(std::shared_ptr<SessionManager> session, const Bounds& bounds)
    : m_session(std::move(session)), m_bounds(bounds) {
    // Default local capability: current protocol version, UDP+TCP, Noise NK,
    // carrier + receipts, standard class.
    m_local_cap.protocol_min = kWireProtocolMin;
    m_local_cap.protocol_max = kWireProtocolMax;
    m_local_cap.transports = kWireUdp | kWireTcp;
    m_local_cap.features = kFeatCarrier | kFeatReceipts;
    m_local_cap.carrier_class = CarrierCapacityClass::kStandard;
    m_local_cap.security_suites = kSecNoiseNK | kSecXChaCha20;

    if (m_session) {
        m_session->set_capability_hooks(
            [this]() { return capabilityB64(); },
            [this](const std::string& peer_id, const std::string& cap_b64) {
                onPeerCapability(peer_id, cap_b64);
            });
    }
}

std::string SessionFacade::capabilityB64() const {
    return cap::encodeB64(m_local_cap);
}

bool SessionFacade::setPeerCapability(const std::string& peer_id, const std::string& cap_b64) {
    CapabilityDocument remote;
    if (!cap::decodeB64(cap_b64, remote)) {
        return false;  // malformed — do not store; old peers are tolerated
    }
    std::lock_guard<std::mutex> lock(m_mu);
    auto& info = m_peers[peer_id];
    info.cap = remote;
    info.negotiated = m_local_cap.negotiated_with(remote);
    info.has_capability = true;
    return true;
}

void SessionFacade::onPeerCapability(const std::string& peer_id, const std::string& cap_b64) {
    (void)setPeerCapability(peer_id, cap_b64);
}

const CapabilityDocument::Negotiated* SessionFacade::negotiation(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_peers.find(peer_id);
    if (it == m_peers.end() || !it->second.has_capability) return nullptr;
    return &it->second.negotiated;
}

const CapabilityDocument* SessionFacade::peerCapability(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_peers.find(peer_id);
    if (it == m_peers.end() || !it->second.has_capability) return nullptr;
    return &it->second.cap;
}


Result SessionFacade::connect(const std::string& peer_id, const std::string& endpoint) {
    if (peer_id.empty() || endpoint.empty()) return Result::kInvalidArg;

    // Bounded pending handshakes (§17) — enforced at admission regardless of
    // the underlying session state.
    {
        std::lock_guard<std::mutex> lock(m_mu);
        const size_t pending = m_telemetry.pending_handshakes;
        if (pending >= m_bounds.max_pending_handshakes) {
            return Result::kBusy;
        }
        auto& info = m_peers[peer_id];
        info.handshake_started_ms = now_ms();
        info.state = "CONNECTING";
    }
    if (!m_session) return Result::kInvalidState;
    m_session->addPeer(peer_id, endpoint);
    m_session->connectToPeer(peer_id);
    return Result::kOk;
}

Result SessionFacade::disconnect(const std::string& peer_id) {
    if (!m_session) return Result::kInvalidState;
    const bool known = m_session->disconnectFromPeer(peer_id);
    return known ? Result::kOk : Result::kNotFound;
}

bool SessionFacade::isConnected(const std::string& peer_id) const {
    return m_session && m_session->isPeerConnected(peer_id);
}

std::string SessionFacade::peerState(const std::string& peer_id) const {
    return m_session ? m_session->getPeerFsmState(peer_id) : "UNKNOWN";
}

void SessionFacade::onPeerState(const std::string& peer_id, const std::string& state) {
    std::lock_guard<std::mutex> lock(m_mu);
    auto& info = m_peers[peer_id];
    info.state = state;
    if (state == "READY" || state == "CONNECTED") {
        ++m_telemetry.connect_success_total;
    } else if (state == "DISCONNECTED" || state == "FAILED") {
        ++m_telemetry.connect_failed_total;
    }
    recount_();
}

void SessionFacade::onHandshakeStarted(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mu);
    m_peers[peer_id].handshake_started_ms = now_ms();
    recount_();
}

void SessionFacade::onHandshakeSucceeded(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mu);
    ++m_telemetry.handshake_success_total;
    m_peers[peer_id].handshake_started_ms = 0;
    recount_();
}

void SessionFacade::onHandshakeFailed(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(m_mu);
    ++m_telemetry.handshake_failed_total;
    ++m_telemetry.reconnect_total;  // retry is a reconnect event
    m_peers[peer_id].handshake_started_ms = 0;
    recount_();
}

Result SessionFacade::setReconnectMode(const std::string& mode) {
    if (!m_session) return Result::kInvalidState;
    m_session->set_reconnect_mode(mode);
    return Result::kOk;
}

void SessionFacade::recount_() {
    size_t pending = 0, active = 0;
    for (const auto& kv : m_peers) {
        const auto& s = kv.second.state;
        if (s == "CONNECTING" || s == "HANDSHAKING") ++pending;
        if (s == "READY") ++active;
    }
    m_telemetry.pending_handshakes = pending;
    m_telemetry.active_sessions = active;
}

std::string SessionFacade::telemetryJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream os;
    os << "{"
       << "\"connect_success_total\":" << m_telemetry.connect_success_total << ","
       << "\"connect_failed_total\":" << m_telemetry.connect_failed_total << ","
       << "\"handshake_success_total\":" << m_telemetry.handshake_success_total << ","
       << "\"handshake_failed_total\":" << m_telemetry.handshake_failed_total << ","
       << "\"reconnect_total\":" << m_telemetry.reconnect_total << ","
       << "\"pending_handshakes\":" << m_telemetry.pending_handshakes << ","
       << "\"active_sessions\":" << m_telemetry.active_sessions
       << "}";
    return os.str();
}

std::unique_ptr<SessionFacade> createSessionFacade(std::shared_ptr<SessionManager> session) {
    return std::make_unique<SessionFacade>(std::move(session), SessionFacade::Bounds{});
}

} // namespace networkos
