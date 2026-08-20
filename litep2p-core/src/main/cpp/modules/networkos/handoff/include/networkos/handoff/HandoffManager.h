#pragma once

// Network OS Phase 4 — HandoffManager (master doc §63 two-phase durable
// handoff, §11 replica leases, §89 Phase 4).
//
// Implements the R1/R2 primitive on top of the Phase 3 object store and the
// existing session channel:
//
//   Sender:  QUEUED_LOCAL -> offer -> OBJECT_ACCEPT (REMOTE_ACCEPTED)
//            -> OBJECT_DATA -> STORED_ACK validated+persisted
//            -> DURABILITY_REACHED (>=1 signed lease)
//   Carrier: OBJECT_OFFER -> admission -> ACCEPT/REJECT;
//            OBJECT_DATA -> verify -> durable commit (object+dedup+usage+lease
//            in ONE transaction) -> STORED_ACK (NEVER before commit).
//
// Properties enforced here:
//   - never ACK before durable commit (invariant 2)
//   - idempotent replay: post-commit re-send -> STORED_ACK again, one copy
//   - honest rejection with structured reasons (§93 invariant 7)
//   - leases: signed, accepted_until <= object TTL, pressure-shortened
//   - bounded concurrent handoffs; explicit carrier opt-in
//   - telemetry events + counters

#include "networkos/Runtime.h"
#include "networkos/IPlatformAdapter.h"
#include "networkos/handoff/handoff_frames.h"
#include "networkos/objectstore/ObjectStore.h"

#include "message_types.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace networkos {
namespace handoff {

// ---------------------------------------------------------------------------
// Minimal ResourceManager stub (pulled forward from Phase 8 per Phase 4
// Step 4.7). Consumes PlatformAdapter signals and outputs admission + lease
// hints consumed by the handoff admission policy.
// ---------------------------------------------------------------------------
class ResourceManager {
public:
    struct Snapshot {
        bool accept_new_handoffs{true};
        size_t max_concurrent_handoffs{8};
        int64_t storage_lease_duration_hint_ms{6LL * 3600 * 1000};  // 6h
    };

    ResourceManager();
    void onSignal(PlatformSignal sig, const std::string& value);
    Snapshot snapshot() const;

private:
    bool m_charging{false};
    bool m_storage_pressure{false};
    bool m_metered{false};
    int m_battery{100};
};
// ---------------------------------------------------------------------------
// Two-phase handoff state machine (sender + carrier roles).
// ---------------------------------------------------------------------------
class HandoffManager {
public:
    struct Config {
        bool carrier_enabled{true};    // accept incoming offers (opt-in)
        int64_t default_lease_duration_ms{6LL * 3600 * 1000};
        int64_t max_lease_duration_ms{24LL * 3600 * 1000};
        int64_t pressure_lease_duration_ms{1LL * 3600 * 1000};  // storage pressure
        bool require_origin_signature{true};
        size_t max_concurrent_handoffs{8};
        std::vector<std::string> trusted_origins;  // empty = allow all
        std::string local_peer_id;
    };

    // Wiring callbacks (set by the runtime/tests).
    using SendFn = std::function<bool(const std::string& peer_id, MessageType type,
                                      const std::string& payload)>;
    using ConnectedPeersFn = std::function<std::vector<std::string>()>;
    using LocalSignKeysFn =
        std::function<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>()>;
    using PeerSignKeyFn = std::function<std::vector<uint8_t>(const std::string& peer_id)>;
    using EventFn = std::function<void(const std::string& kind, const std::string& payload)>;

    struct Counters {
        uint64_t offers_sent{0};
        uint64_t accepts_received{0};
        uint64_t rejects_received{0};
        uint64_t stored_acks_received{0};
        uint64_t stored_acks_validated{0};
        uint64_t handoffs_succeeded{0};      // reached DURABILITY_REACHED
        uint64_t no_carrier{0};              // transient NO_CARRIER failure
        uint64_t data_sent{0};
        uint64_t carrier_offers_received{0};
        uint64_t carrier_accepts_sent{0};
        uint64_t carrier_rejects_sent{0};
        uint64_t carrier_commits{0};         // durable commits (incl. idempotent)
        uint64_t leases_issued{0};
        uint64_t lease_expiry_events{0};
        uint64_t rejects_by_reason[6]{0};    // indexed by RejectReason
    };

    HandoffManager(ObjectStore* store, const Config& cfg);
    ~HandoffManager();
    HandoffManager(const HandoffManager&) = delete;
    HandoffManager& operator=(const HandoffManager&) = delete;

    void setSendFn(SendFn fn);
    void setConnectedPeersFn(ConnectedPeersFn fn);
    void setSigningKeysFns(LocalSignKeysFn local, PeerSignKeyFn peer);
    void setEventFn(EventFn fn);

    // ---- Sender side -------------------------------------------------------
    // Durably persist the object locally (QUEUED_LOCAL) then offer it to
    // eligible connected peers. `envelope_blob` is the serialized, origin-
    // signed obj::NetworkObject (the OBJECT_DATA payload). Returns kOk when
    // durably queued and offered; the outcome streams via events + counters.
    Result storeAndOffer(const ObjectMeta& meta, const std::string& envelope_blob,
                         int64_t requested_lease_ms = 0);

    // ---- Both roles --------------------------------------------------------
    // Receive path (invoked by the session handoff frame hook). Must not block.
    void onFrame(const std::string& peer_id, MessageType type,
                 const std::string& payload);

    // Event-triggered lease sweep: emits LEASE_EXPIRING for leases whose
    // accepted_until is at or before now_ms (Phase 7 planner hooks this).
    void sweepLeases(int64_t now_ms);

    // Re-offer objects that were queued (QUEUED_LOCAL) but have no in-flight
    // carrier yet (NO_CARRIER or new peers became available). Idempotent;
    // call on peer_ready/connectivity events. Returns number of offers sent.
    size_t retryPending(int64_t now_ms_value);

    ResourceManager& resourceManager() { return m_resources; }
    Counters counters() const;
    std::string telemetryJson() const;
    bool isPending(const std::string& object_id_hex) const;

private:
    struct PendingOffer {
        std::string object_id_hex;
        std::string namespace_id;
        std::string origin;
        std::string envelope_blob;
        std::string payload_hash_hex;    // offer metadata (persistable re-offer)
        uint64_t size_bytes{0};
        int64_t expires_at_ms{0};
        int64_t requested_lease_ms{0};
        int64_t sent_at_ms{0};
        size_t carriers_in_flight{0};
        bool reached_durability{false};
    };

    // Carrier-side: the lease terms promised at ACCEPT (used at DATA commit).
    struct CarrierTerms {
        int64_t accepted_until_ms{0};
        int64_t storage_class{kStorageStandard};
    };

    // Sender-side handlers.
    void handleAccept_(const std::string& peer_id, const AcceptFrame& f);
    void handleReject_(const std::string& peer_id, const RejectFrame& f);
    void handleStoredAck_(const std::string& peer_id, const StoredAckFrame& f);

    // Carrier-side handlers.
    void handleOffer_(const std::string& peer_id, const OfferFrame& f);
    void handleData_(const std::string& peer_id, const DataFrame& f);

    // Helpers.
    int64_t chooseLeaseUntilMs_(int64_t now_ms, int64_t object_expires_at_ms,
                                const OfferFrame& f) const;
    bool originAuthorized_(const std::string& origin) const;
    bool verifyLeaseSignature_(const StoredAckFrame& f) const;
    void emit_(const std::string& kind, const std::string& payload);
    bool send_(const std::string& peer_id, MessageType type, const std::string& payload);

    ObjectStore* m_store{nullptr};
    Config m_cfg;
    ResourceManager m_resources;

    SendFn m_send;
    ConnectedPeersFn m_connected;
    LocalSignKeysFn m_local_keys;
    PeerSignKeyFn m_peer_key;
    EventFn m_event;

    mutable std::mutex m_mu;
    std::unordered_map<std::string, PendingOffer> m_pending;  // object_id_hex
    std::unordered_map<std::string, CarrierTerms> m_carrier_terms;
    size_t m_active_carrier_handoffs{0};  // carrier-side concurrent cap
    Counters m_ctr;
    int64_t m_now_epoch_ms{0};            // carrier decision clock (test seed)
};

std::unique_ptr<HandoffManager> createHandoffManager(ObjectStore* store,
                                                     const HandoffManager::Config& cfg);

} // namespace handoff
} // namespace networkos

