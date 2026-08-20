// HandoffManager.cpp — Network OS Phase 4 two-phase durable handoff.

#include "networkos/handoff/HandoffManager.h"

#include "networkos/object/envelope.h"
#include "networkos/object/object_id.h"

#include <sodium.h>

#include <chrono>
#include <cstring>
#include <sstream>

namespace networkos {
namespace handoff {

namespace {

// libsodium must be initialized once before any crypto primitive is used.
// The engine initializes it at startup, but the handoff module is also used
// directly by desktop tests — make init idempotent and self-contained here.
struct SodiumInitGuard {
    SodiumInitGuard() { (void)sodium_init(); }
};
const SodiumInitGuard k_sodium_init;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

std::string to_hex(const std::string& raw) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0F]);
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// ResourceManager stub
// ---------------------------------------------------------------------------
ResourceManager::ResourceManager() = default;

void ResourceManager::onSignal(PlatformSignal sig, const std::string& value) {
    switch (sig) {
        case PlatformSignal::kCharging:
            m_charging = (value == "1");
            break;
        case PlatformSignal::kStoragePressure:
            m_storage_pressure = (value == "low");
            break;
        case PlatformSignal::kMetered:
            m_metered = (value == "1");
            break;
        case PlatformSignal::kBattery: {
            try { m_battery = std::stoi(value); } catch (...) { m_battery = 100; }
            break;
        }
        default:
            break;
    }
}

ResourceManager::Snapshot ResourceManager::snapshot() const {
    Snapshot s;
    // Storage pressure -> SHORTER leases (low-storage devices must not make
    // long promises, §11). Charging -> LONGER leases (always-on/charging
    // peers can hold copies longer).
    if (m_storage_pressure) {
        s.storage_lease_duration_hint_ms = 1LL * 3600 * 1000;   // 1h
    } else if (m_charging) {
        s.storage_lease_duration_hint_ms = 24LL * 3600 * 1000;  // 24h
    } else {
        s.storage_lease_duration_hint_ms = 6LL * 3600 * 1000;   // 6h default
    }
    // Battery/metering constrain how many parallel handoffs we service.
    s.max_concurrent_handoffs =
        (!m_charging && m_battery < 20) ? 2 : 8;
    s.accept_new_handoffs = true;
    return s;
}
// ---------------------------------------------------------------------------
// HandoffManager
// ---------------------------------------------------------------------------
HandoffManager::HandoffManager(ObjectStore* store, const Config& cfg)
    : m_store(store), m_cfg(cfg) {}

HandoffManager::~HandoffManager() = default;

void HandoffManager::setSendFn(SendFn fn) { m_send = std::move(fn); }
void HandoffManager::setConnectedPeersFn(ConnectedPeersFn fn) { m_connected = std::move(fn); }
void HandoffManager::setSigningKeysFns(LocalSignKeysFn local, PeerSignKeyFn peer) {
    m_local_keys = std::move(local);
    m_peer_key = std::move(peer);
}
void HandoffManager::setEventFn(EventFn fn) { m_event = std::move(fn); }

void HandoffManager::emit_(const std::string& kind, const std::string& payload) {
    if (m_event) {
        try { m_event(kind, payload); } catch (...) {}
    }
}

bool HandoffManager::send_(const std::string& peer_id, MessageType type,
                           const std::string& payload) {
    if (!m_send) return false;
    return m_send(peer_id, type, payload);
}

bool HandoffManager::originAuthorized_(const std::string& origin) const {
    if (m_cfg.trusted_origins.empty()) return true;   // allow all
    for (const auto& t : m_cfg.trusted_origins) {
        if (t == origin) return true;
    }
    return false;
}

int64_t HandoffManager::chooseLeaseUntilMs_(int64_t now_ms_value,
                                            int64_t object_expires_at_ms,
                                            const OfferFrame& f) const {
    const ResourceManager::Snapshot rs = m_resources.snapshot();
    int64_t duration = m_cfg.default_lease_duration_ms;
    if (f.requested_lease_ms > 0 &&
        f.requested_lease_ms <= m_cfg.max_lease_duration_ms) {
        duration = f.requested_lease_ms;
    }
    // Resource hints override: pressure shortens, charging lengthens.
    if (m_cfg.pressure_lease_duration_ms > 0 &&
        rs.storage_lease_duration_hint_ms < m_cfg.default_lease_duration_ms) {
        duration = m_cfg.pressure_lease_duration_ms;
    } else if (rs.storage_lease_duration_hint_ms > m_cfg.default_lease_duration_ms) {
        duration = std::min<int64_t>(rs.storage_lease_duration_hint_ms,
                                     m_cfg.max_lease_duration_ms);
    }
    int64_t until = now_ms_value + duration;
    // A lease must never outlive the object TTL (invariant; test-asserted).
    if (object_expires_at_ms > 0 && until > object_expires_at_ms) {
        until = object_expires_at_ms;
    }
    if (until > now_ms_value + m_cfg.max_lease_duration_ms) {
        until = now_ms_value + m_cfg.max_lease_duration_ms;
    }
    return until;
}

bool HandoffManager::verifyLeaseSignature_(const StoredAckFrame& f) const {
    if (f.signature.size() != 64) return false;
    const std::vector<uint8_t> pk = m_peer_key ? m_peer_key(f.carrier_id) : std::vector<uint8_t>{};
    if (pk.size() != 32) return false;   // no registered trust anchor
    const std::string msg = canonical_lease_bytes(f.object_id_hex, f.carrier_id,
                                                  f.accepted_until_ms,
                                                  f.storage_class);
    return crypto_sign_verify_detached(
               reinterpret_cast<const unsigned char*>(f.signature.data()),
               reinterpret_cast<const unsigned char*>(msg.data()),
               msg.size(), pk.data()) == 0;
}

HandoffManager::Counters HandoffManager::counters() const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_ctr;
}

std::string HandoffManager::telemetryJson() const {
    std::lock_guard<std::mutex> lock(m_mu);
    std::ostringstream os;
    os << "{\"offers_sent\":" << m_ctr.offers_sent
       << ",\"accepts_received\":" << m_ctr.accepts_received
       << ",\"rejects_received\":" << m_ctr.rejects_received
       << ",\"stored_acks_received\":" << m_ctr.stored_acks_received
       << ",\"stored_acks_validated\":" << m_ctr.stored_acks_validated
       << ",\"handoffs_succeeded\":" << m_ctr.handoffs_succeeded
       << ",\"no_carrier\":" << m_ctr.no_carrier
       << ",\"data_sent\":" << m_ctr.data_sent
       << ",\"carrier_offers_received\":" << m_ctr.carrier_offers_received
       << ",\"carrier_accepts_sent\":" << m_ctr.carrier_accepts_sent
       << ",\"carrier_rejects_sent\":" << m_ctr.carrier_rejects_sent
       << ",\"carrier_commits\":" << m_ctr.carrier_commits
       << ",\"leases_issued\":" << m_ctr.leases_issued
       << ",\"lease_expiry_events\":" << m_ctr.lease_expiry_events
       << "}";
    return os.str();
}

bool HandoffManager::isPending(const std::string& object_id_hex) const {
    std::lock_guard<std::mutex> lock(m_mu);
    return m_pending.find(object_id_hex) != m_pending.end();
}

// ---------------------------------------------------------------------------
// Sender side
// ---------------------------------------------------------------------------
Result HandoffManager::storeAndOffer(const ObjectMeta& meta,
                                     const std::string& envelope_blob,
                                     int64_t requested_lease_ms) {
    if (!m_store) return Result::kInvalidState;
    if (meta.id.empty() || envelope_blob.empty()) return Result::kInvalidArg;

    // Extract the payload from the signed envelope (it is the DATA payload).
    obj::NetworkObject obj;
    if (!obj::deserialize(envelope_blob, obj)) return Result::kInvalidArg;
    if (obj.origin.object_id_hex != meta.id.toHex() ||
        obj.origin.origin != meta.origin) {
        return Result::kInvalidArg;   // envelope does not match the meta
    }
    if (obj.payload.size() > m_store->options().max_object_bytes) {
        return Result::kInvalidArg;
    }

    // 1. Durable local persist (QUEUED_LOCAL). This is the sender's R1.
    ObjectStore::Outcome oc;
    ObjectMeta m = meta;
    m.status = ObjectStatus::kQueuedLocal;
    m.envelope_blob = envelope_blob;
    if (m.payload_hash.empty()) m.payload_hash = obj.origin.payload_hash;
    const Result rc = m_store->putWithOutcome(m, obj.payload, oc);
    if (rc != Result::kOk) {
        emit_("REMOTE_STORAGE_LOCAL_QUEUE_FAILED", meta.id.toHex());
        return rc;
    }

    // 2. Offer to eligible connected peers (peer selection minimal in this
    // phase: any READY peer up to the concurrent bound).
    OfferFrame offer;
    offer.object_id_hex = meta.id.toHex();
    offer.namespace_id = meta.namespace_id;
    offer.origin = meta.origin;
    offer.destination = meta.destination.value_or("");
    offer.size_bytes = obj.payload.size();
    offer.payload_hash_hex = to_hex(obj.origin.payload_hash);
    offer.expires_at_ms =
        meta.ttl_ms > 0 ? meta.created_at_ms + meta.ttl_ms : 0;
    offer.requested_storage_class = kStorageStandard;
    offer.requested_lease_ms = requested_lease_ms;

    std::vector<std::string> peers;
    if (m_connected) peers = m_connected();
    // Build the sends while holding the lock; deliver OUTSIDE it — the
    // transport may be synchronous (the remote ACCEPT arrives on the same
    // stack) and would otherwise self-deadlock on m_mu.
    std::vector<std::pair<std::string, std::string>> offer_sends;
    size_t offered = 0;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        const size_t bound = std::min<size_t>(peers.size(),
                                              m_cfg.max_concurrent_handoffs);
        for (size_t i = 0; i < bound; ++i) {
            const std::string& p = peers[i];
            if (p.empty() || p == m_cfg.local_peer_id) continue;
            offer_sends.emplace_back(p, encode_offer(offer));
        }
        offered = offer_sends.size();
        m_ctr.offers_sent += offered;
        if (offered > 0) {
            PendingOffer po;
            po.object_id_hex = offer.object_id_hex;
            po.namespace_id = meta.namespace_id;
            po.origin = meta.origin;
            po.envelope_blob = envelope_blob;
            po.payload_hash_hex = offer.payload_hash_hex;
            po.size_bytes = offer.size_bytes;
            po.expires_at_ms = offer.expires_at_ms;
            po.requested_lease_ms = requested_lease_ms;
            po.sent_at_ms = now_ms();
            po.carriers_in_flight = offered;
            m_pending[offer.object_id_hex] = std::move(po);
        }
    }
    for (const auto& s : offer_sends) {
        if (m_send) m_send(s.first, MessageType::OBJECT_OFFER, s.second);
    }
    emit_("REMOTE_STORAGE_REQUEST", offer.object_id_hex);
    if (offered == 0) {
        // NO_CARRIER is TRANSIENT (§61): keep the object queued so a later
        // retryPending() (peer_ready/connectivity) can offer it again.
        m_ctr.no_carrier++;
        emit_("REMOTE_STORAGE_NO_CARRIER", offer.object_id_hex);
    }
    return Result::kOk;
}

void HandoffManager::handleAccept_(const std::string& peer_id, const AcceptFrame& f) {
    std::string envelope;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_pending.find(f.object_id_hex);
        if (it == m_pending.end()) return;   // stale accept (no pending offer)
        envelope = it->second.envelope_blob;
        m_ctr.accepts_received++;
        m_ctr.data_sent++;
    }
    // OBJECT_ACCEPT -> transition REMOTE_ACCEPTED, then send OBJECT_DATA.
    ObjectId id;
    if (ObjectId::fromHex(f.object_id_hex, id)) {
        m_store->updateObjectState(id, ObjectStatus::kRemoteAccepted);
    }
    DataFrame df;
    df.object_id_hex = f.object_id_hex;
    df.envelope = envelope;
    send_(peer_id, MessageType::OBJECT_DATA, encode_data(df));
    emit_("REMOTE_STORAGE_ACCEPTED", f.object_id_hex);
}

void HandoffManager::handleReject_(const std::string& peer_id, const RejectFrame& f) {
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_pending.find(f.object_id_hex);
    if (it == m_pending.end()) return;
    m_ctr.rejects_received++;
    if (f.reason >= 1 && f.reason <= 5) m_ctr.rejects_by_reason[f.reason]++;
    if (it->second.carriers_in_flight > 0) --it->second.carriers_in_flight;
    emit_("REMOTE_STORAGE_REJECTED",
          f.object_id_hex + ":" + std::string(reject_reason_name(f.reason)));
    if (it->second.carriers_in_flight == 0 && !it->second.reached_durability) {
        // TRANSIENT failure (NO_CARRIER). Keep the entry queued (carriers_
        // in_flight == 0) so retryPending() can offer to new peers.
        m_ctr.no_carrier++;
        emit_("REMOTE_STORAGE_NO_CARRIER", f.object_id_hex);
    }
}

void HandoffManager::handleStoredAck_(const std::string& peer_id, const StoredAckFrame& f) {
    // 1. Signature validation (sender side): the lease must be signed by the
    // carrier's registered Ed25519 key.
    if (!verifyLeaseSignature_(f)) {
        emit_("STORED_ACK_INVALID", f.object_id_hex);
        return;
    }
    ObjectId id;
    if (!ObjectId::fromHex(f.object_id_hex, id)) return;

    // 2. Lease-term validation: accepted_until must not outlive the object TTL.
    ObjectMeta meta;
    if (m_store->getMeta(id, meta) != Result::kOk) return;
    const int64_t object_expires = meta.ttl_ms > 0
                                       ? meta.created_at_ms + meta.ttl_ms
                                       : 0;
    if (object_expires > 0 && f.accepted_until_ms > object_expires) {
        emit_("STORED_ACK_INVALID_TERMS", f.object_id_hex);
        return;
    }

    // 3. Persist the lease + mark DURABILITY_REACHED (replay-convergent).
    ObjectStore::LeaseInfo lease;
    lease.object_id_hex = f.object_id_hex;
    lease.carrier_id = f.carrier_id;
    lease.accepted_until_ms = f.accepted_until_ms;
    lease.storage_class = f.storage_class;
    lease.signature = f.signature;
    lease.carrier_id_hex = f.carrier_pk_hex;
    if (m_store->recordLease(id, lease) != Result::kOk) return;
    m_store->updateObjectState(id, ObjectStatus::kDurabilityReached);

    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_ctr.stored_acks_received++;
        m_ctr.stored_acks_validated++;
        m_ctr.handoffs_succeeded++;
        auto it = m_pending.find(f.object_id_hex);
        if (it != m_pending.end()) {
            it->second.reached_durability = true;
            if (it->second.carriers_in_flight > 0) --it->second.carriers_in_flight;
            if (it->second.carriers_in_flight == 0) m_pending.erase(it);
        }
    }
    emit_("STORED_ACK_RECEIVED", f.object_id_hex);
}

// ---------------------------------------------------------------------------
// Carrier side
// ---------------------------------------------------------------------------
void HandoffManager::handleOffer_(const std::string& peer_id, const OfferFrame& f) {
    if (!m_store) return;
    ObjectId id;
    if (!ObjectId::fromHex(f.object_id_hex, id)) return;   // malformed id
    if (!is_hex64(f.payload_hash_hex)) return;
    if (f.size_bytes > m_store->options().max_object_bytes) return;

    // Admission policy (Step 4.2).
    uint8_t reject_reason = 0;
    int64_t retry_after_ms = 0;
    if (!m_cfg.carrier_enabled) {
        reject_reason = kRejectedPolicy;
    } else if (!originAuthorized_(f.origin)) {
        reject_reason = kRejectedAuth;
    } else if (!m_local_keys) {
        reject_reason = kRejectedPolicy;   // cannot sign leases
    } else {
        const ResourceManager::Snapshot rs = m_resources.snapshot();
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.carrier_offers_received++;
            if (!rs.accept_new_handoffs) {
                reject_reason = kRejectedPolicy;
            } else if (m_active_carrier_handoffs >=
                       std::min(rs.max_concurrent_handoffs,
                                m_cfg.max_concurrent_handoffs)) {
                reject_reason = kBusy;
                retry_after_ms = 60 * 1000;
            }
        }
        if (reject_reason == 0) {
            // Quota headroom (honest REJECTED_QUOTA before any bytes move).
            // Global usable capacity (Options) minus what is already stored.
            const uint64_t usable_global =
                m_store->options().global_quota_bytes >
                        m_store->options().system_reserve_bytes
                    ? m_store->options().global_quota_bytes -
                          m_store->options().system_reserve_bytes
                    : 0;
            if (usable_global > 0 &&
                m_store->totalBytes() + f.size_bytes > usable_global) {
                reject_reason = kRejectedQuota;
            } else {
                QuotaInfo q;
                if (m_store->quota(f.namespace_id, f.origin, q) == Result::kOk &&
                    q.within_limits) {
                    const uint64_t used = q.used_bytes;
                    if (q.max_bytes > 0 && used + f.size_bytes > q.max_bytes) {
                        reject_reason = kRejectedQuota;
                    }
                }
            }
        }
    }

    if (reject_reason != 0) {
        RejectFrame rj;
        rj.object_id_hex = f.object_id_hex;
        rj.reason = reject_reason;
        rj.retry_after_ms = retry_after_ms;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.carrier_rejects_sent++;
            if (reject_reason >= 1 && reject_reason <= 5) {
                m_ctr.rejects_by_reason[reject_reason]++;
            }
        }
        send_(peer_id, MessageType::OBJECT_REJECT, encode_reject(rj));
        emit_("REMOTE_STORAGE_REJECTED",
              f.object_id_hex + ":" + reject_reason_name(reject_reason));
        return;
    }

    // Chosen lease terms (signed on DATA commit; remembered for the commit).
    const int64_t now = now_ms();
    const int64_t until = chooseLeaseUntilMs_(now, f.expires_at_ms, f);
    const int64_t storage_class =
        (f.requested_storage_class >= kStorageStandard &&
         f.requested_storage_class <= kStorageEphemeral)
            ? f.requested_storage_class
            : static_cast<int64_t>(kStorageStandard);

    {
        std::lock_guard<std::mutex> lock(m_mu);
        m_active_carrier_handoffs++;
        m_carrier_terms[f.object_id_hex] = CarrierTerms{until, storage_class};
        m_ctr.carrier_accepts_sent++;
    }

    AcceptFrame af;
    af.object_id_hex = f.object_id_hex;
    af.accepted_until_ms = until;
    af.storage_class = storage_class;
    af.carrier_id = m_cfg.local_peer_id;
    send_(peer_id, MessageType::OBJECT_ACCEPT, encode_accept(af));
}

void HandoffManager::handleData_(const std::string& peer_id, const DataFrame& f) {
    if (!m_store) return;
    ObjectId id;
    if (!ObjectId::fromHex(f.object_id_hex, id)) return;
    if (f.envelope.empty()) return;

    // Reconstruct + validate the signed envelope (§29: verify BEFORE work).
    obj::NetworkObject obj;
    if (!obj::deserialize(f.envelope, obj)) {
        emit_("OBJECT_DATA_INVALID", f.object_id_hex);
        return;
    }
    if (obj.origin.object_id_hex != f.object_id_hex) return;
    if (obj.payload.size() > m_store->options().max_object_bytes) return;

    // Origin signature verification (when configured). REJECTED_AUTH on
    // failure or when no trust anchor is registered — honest rejection.
    if (m_cfg.require_origin_signature) {
        const std::vector<uint8_t> origin_pk =
            m_peer_key ? m_peer_key(obj.origin.origin) : std::vector<uint8_t>{};
        if (origin_pk.size() != 32 ||
            !obj::verify_object(obj, origin_pk.data())) {
            RejectFrame rj;
            rj.object_id_hex = f.object_id_hex;
            rj.reason = kRejectedAuth;
            {
                std::lock_guard<std::mutex> lock(m_mu);
                m_ctr.carrier_rejects_sent++;
                m_ctr.rejects_by_reason[kRejectedAuth]++;
            }
            send_(peer_id, MessageType::OBJECT_REJECT, encode_reject(rj));
            emit_("REMOTE_STORAGE_REJECTED", f.object_id_hex + ":REJECTED_AUTH");
            return;
        }
    }

    // Lease terms: whatever we promised at ACCEPT (else fresh terms — covers
    // crash recovery where the offer record is gone).
    int64_t accepted_until = 0;
    int64_t storage_class = kStorageStandard;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_carrier_terms.find(f.object_id_hex);
        if (it != m_carrier_terms.end()) {
            accepted_until = it->second.accepted_until_ms;
            storage_class = it->second.storage_class;
        }
    }
    if (accepted_until == 0) {
        const int64_t expires = obj.origin.ttl_ms > 0
                                    ? obj.origin.created_at_ms + obj.origin.ttl_ms
                                    : 0;
        OfferFrame dummy;
        dummy.expires_at_ms = expires;
        accepted_until = chooseLeaseUntilMs_(now_ms(), expires, dummy);
        storage_class = kStorageStandard;
    }

    // Build ObjectMeta from the validated envelope.
    ObjectMeta meta;
    meta.id = id;
    meta.namespace_id = obj.origin.namespace_id;
    meta.origin = obj.origin.origin;
    if (!obj.origin.destination.empty()) meta.destination = obj.origin.destination;
    meta.object_type = obj.origin.object_type;
    meta.created_at_ms = obj.origin.created_at_ms;
    meta.ttl_ms = obj.origin.ttl_ms;
    meta.priority = obj.origin.priority;
    meta.payload_size = obj.payload.size();
    meta.payload_hash = obj.origin.payload_hash;
    meta.origin_header_blob = origin_canonical_bytes(obj.origin);
    meta.origin_signature = obj.origin_signature;
    meta.forwarding_header_blob = "";
    meta.envelope_blob = f.envelope;
    meta.status = ObjectStatus::kStored;

    // Carrier signs the lease (its origin-signing key = its identity anchor).
    const auto keys = m_local_keys ? m_local_keys()
                                   : std::pair<std::vector<uint8_t>,
                                               std::vector<uint8_t>>{};
    if (keys.second.size() != 64) {
        RejectFrame rj;
        rj.object_id_hex = f.object_id_hex;
        rj.reason = kRejectedPolicy;
        send_(peer_id, MessageType::OBJECT_REJECT, encode_reject(rj));
        return;
    }
    const std::string lease_msg = canonical_lease_bytes(
        f.object_id_hex, m_cfg.local_peer_id, accepted_until, storage_class);
    std::string sig(64, '\0');
    crypto_sign_detached(reinterpret_cast<unsigned char*>(&sig[0]), nullptr,
                         reinterpret_cast<const unsigned char*>(lease_msg.data()),
                         lease_msg.size(), keys.second.data());

    ObjectStore::LeaseInfo lease;
    lease.object_id_hex = f.object_id_hex;
    lease.carrier_id = m_cfg.local_peer_id;
    lease.accepted_until_ms = accepted_until;
    lease.storage_class = storage_class;
    lease.signature = sig;
    lease.carrier_id_hex = to_hex(std::string(keys.first.begin(), keys.first.end()));

    // Durable commit (object + dedup + usage + lease in ONE transaction).
    ObjectStore::Outcome oc;
    const Result rc = m_store->putWithLease(meta, obj.payload, lease, oc);
    if (rc != Result::kOk) {
        RejectFrame rj;
        rj.object_id_hex = f.object_id_hex;
        rj.reason = (oc == ObjectStore::Outcome::RejectedQuota)
                        ? kRejectedQuota
                        : (oc == ObjectStore::Outcome::Busy ? kBusy
                                                            : kRetryAfter);
        rj.retry_after_ms = (oc == ObjectStore::Outcome::Busy) ? 60 * 1000 : 0;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.carrier_rejects_sent++;
            if (rj.reason >= 1 && rj.reason <= 5) {
                m_ctr.rejects_by_reason[rj.reason]++;
            }
        }
        send_(peer_id, MessageType::OBJECT_REJECT, encode_reject(rj));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (m_active_carrier_handoffs > 0) --m_active_carrier_handoffs;
        m_carrier_terms.erase(f.object_id_hex);
        m_ctr.carrier_commits++;
        m_ctr.leases_issued++;
    }

    // STORED_ACK is sent ONLY after the durable commit (invariant 2).
    StoredAckFrame sa;
    sa.object_id_hex = f.object_id_hex;
    sa.carrier_id = m_cfg.local_peer_id;
    sa.accepted_until_ms = accepted_until;
    sa.storage_class = storage_class;
    sa.signature = sig;
    sa.carrier_pk_hex = lease.carrier_id_hex;
    send_(peer_id, MessageType::STORED_ACK, encode_stored_ack(sa));
    emit_("STORED_ACK_SENT", f.object_id_hex);
}

// ---------------------------------------------------------------------------
// Dispatch + lease sweep
// ---------------------------------------------------------------------------
void HandoffManager::onFrame(const std::string& peer_id, MessageType type,
                             const std::string& payload) {
    switch (type) {
        case MessageType::OBJECT_OFFER: {
            OfferFrame f;
            if (decode_offer(payload, f)) handleOffer_(peer_id, f);
            break;
        }
        case MessageType::OBJECT_ACCEPT: {
            AcceptFrame f;
            if (decode_accept(payload, f)) handleAccept_(peer_id, f);
            break;
        }
        case MessageType::OBJECT_REJECT: {
            RejectFrame f;
            if (decode_reject(payload, f)) handleReject_(peer_id, f);
            break;
        }
        case MessageType::OBJECT_DATA: {
            DataFrame f;
            if (decode_data(payload, f)) handleData_(peer_id, f);
            break;
        }
        case MessageType::STORED_ACK: {
            StoredAckFrame f;
            if (decode_stored_ack(payload, f)) handleStoredAck_(peer_id, f);
            break;
        }
        default:
            break;
    }
}

size_t HandoffManager::retryPending(int64_t now_ms_value) {
    if (!m_store) return 0;
    std::vector<std::string> peers;
    if (m_connected) peers = m_connected();
    if (peers.empty()) return 0;

    // Snapshot queued (no in-flight carrier, not yet durable) offers.
    std::vector<PendingOffer> retry;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        for (const auto& kv : m_pending) {
            if (kv.second.carriers_in_flight == 0 &&
                !kv.second.reached_durability) {
                retry.push_back(kv.second);
            }
        }
    }
    size_t sent = 0;
    for (auto& po : retry) {
        OfferFrame offer;
        offer.object_id_hex = po.object_id_hex;
        offer.namespace_id = po.namespace_id;
        offer.origin = po.origin;
        offer.destination = "";
        offer.size_bytes = po.size_bytes;
        offer.payload_hash_hex = po.payload_hash_hex;
        offer.expires_at_ms = po.expires_at_ms;
        offer.requested_storage_class = kStorageStandard;
        offer.requested_lease_ms = po.requested_lease_ms;

        std::vector<std::pair<std::string, std::string>> offer_sends;
        for (const auto& p : peers) {
            if (p.empty() || p == m_cfg.local_peer_id) continue;
            offer_sends.emplace_back(p, encode_offer(offer));
        }
        if (offer_sends.empty()) continue;
        {
            std::lock_guard<std::mutex> lock(m_mu);
            auto it = m_pending.find(po.object_id_hex);
            if (it == m_pending.end() || it->second.carriers_in_flight != 0 ||
                it->second.reached_durability) {
                continue;   // raced: already offered/completed
            }
            it->second.carriers_in_flight = offer_sends.size();
            it->second.sent_at_ms = now_ms_value;
            m_ctr.offers_sent += offer_sends.size();
        }
        for (const auto& s : offer_sends) {
            if (m_send && m_send(s.first, MessageType::OBJECT_OFFER, s.second)) {
                ++sent;
            }
        }
        emit_("REMOTE_STORAGE_RETRY", po.object_id_hex);
    }
    return sent;
}

void HandoffManager::sweepLeases(int64_t now_ms_value) {
    if (!m_store) return;
    m_store->forEachExpiringLease(now_ms_value, [this](const ObjectStore::LeaseInfo& l) {
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_ctr.lease_expiry_events++;
        }
        emit_("LEASE_EXPIRING", l.object_id_hex + ":" + l.carrier_id);
        return Result::kOk;
    });
}

std::unique_ptr<HandoffManager> createHandoffManager(ObjectStore* store,
                                                     const HandoffManager::Config& cfg) {
    return std::make_unique<HandoffManager>(store, cfg);
}

} // namespace handoff
} // namespace networkos
