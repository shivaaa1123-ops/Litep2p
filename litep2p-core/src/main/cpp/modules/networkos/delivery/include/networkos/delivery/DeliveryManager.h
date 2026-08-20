#pragma once

// Network OS Phase 5 - DeliveryManager (master doc §22 delivery state machine,
// §23 signed receipts, §57 direct vs store-and-forward, §58 push, §61 failure
// semantics, §63 final delivery handoff, §64 replica release).
//
// The three delivery paths converge here into ONE object-delivery path. The
// genuinely new primitive is the **signed destination receipt** (a first-class,
// signed, store-and-forward object). Direct delivery reuses the Phase 4
// transfer frames (OBJECT_OFFER/ACCEPT/DATA) but the peer named in the object's
// `destination` field replies with RECEIVED_ACK (0x39) instead of a storage
// lease, then issues a signed receipt object on the reverse path toward origin.

#include "networkos/Runtime.h"
#include "networkos/IPlatformAdapter.h"
#include "networkos/delivery/delivery_frames.h"
#include "networkos/handoff/handoff_frames.h"
#include "networkos/object/envelope.h"
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
namespace delivery {

class DeliveryManager {
public:
    struct Config {
        bool delivery_enabled{true};
        bool direct_delivery_enabled{true};     // push directly when B connected
        bool store_and_forward_enabled{true};   // offer via carriers when offline
        int64_t replica_retention_window_ms{300000};  // 5 min after DELIVERED
        int64_t receipt_ttl_ms{24LL * 3600 * 1000};
        uint8_t receipt_priority{220};
        bool require_receipt{true};
        bool require_destination_signature{true};
        bool enforce_last_replica{true};
        std::string local_peer_id;
        std::vector<std::string> trusted_origins;
    };

    struct Outcome {
        Result rc{Result::kOk};
        uint8_t failure_class{kFailNone};
        bool retryable{false};
        int64_t retry_after_ms{0};
        std::string detail;
    };

    using SendFn = std::function<bool(const std::string&, MessageType, const std::string&)>;
    using ConnectedPeersFn = std::function<std::vector<std::string>()>;
    using LocalSignKeysFn =
        std::function<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>()>;
    using PeerSignKeyFn = std::function<std::vector<uint8_t>(const std::string&)>;
    using EventFn = std::function<void(const std::string&, const std::string&)>;

    explicit DeliveryManager(ObjectStore* store, const Config& cfg);
    ~DeliveryManager();

    void setSendFn(SendFn fn);
    void setConnectedPeersFn(ConnectedPeersFn fn);
    void setSigningKeysFns(LocalSignKeysFn local, PeerSignKeyFn peer);
    void setEventFn(EventFn fn);

    // Single object-delivery entry point: durable local commit + cheapest-path
    // dispatch (direct to destination if connected, else store-and-forward).
    Outcome storeAndDeliver(const ObjectMeta& meta, const std::string& envelope_blob,
                            int64_t requested_lease_ms = 0);

    // Carrier role: push stored-but-not-yet-delivered objects to a destination
    // that just connected. Returns number of offers sent.
    size_t forwardPending(const std::string& destination);

    // Replica release (§64): GC objects that were durably delivered to their
    // destination and are now past the retention window. The last-useful-
    // replica rule is enforced by only ever removing objects already marked
    // DELIVERED (i.e. there is delivery proof) — never a still-queued/not-yet
    // delivered copy merely because bytes hit a socket. Returns replicas freed.
    size_t sweepReplicas(int64_t now_ms_value);

    // Receive path (from the runtime frame hook). Never blocks.
    void onFrame(const std::string& peer_id, MessageType type,
                 const std::string& payload, bool i_am_destination);

    // Origin role: retry objects still pending (no reachable dest / carrier).
    size_t retryPending(int64_t now_ms_value, const std::vector<std::string>& peers);

    struct Counters {
        uint64_t direct_deliveries{0};
        uint64_t store_and_forwards{0};
        uint64_t received_acks{0};
        uint64_t receipts_created{0};
        uint64_t receipts_delivered{0};
        uint64_t receipts_verified{0};
        uint64_t confirmed_objects{0};
        uint64_t duplicate_data_rejected{0};
        uint64_t no_carrier{0};
        uint64_t no_route{0};
        uint64_t ttl_expired{0};
        uint64_t destination_rejected{0};
        uint64_t auth_failed{0};
        uint64_t delivered_replicas_released{0};
        uint64_t retransmissions{0};
    };
    Counters counters() const;
    std::string telemetryJson() const;
private:
    // ORIGIN side.
    void handleReceivedAck_(const std::string& peer_id, const ReceivedAckFrame& f);
    void handleAcceptDirect_(const std::string& peer_id, const handoff::AcceptFrame& f);

    // DESTINATION side (direct delivery to me).
    void handleOfferMe_(const std::string& peer_id, const handoff::OfferFrame& f);
    void handleDataMe_(const std::string& peer_id, const handoff::DataFrame& f);

    // Receipt reverse path.
    bool issueReceipt_(const std::string& delivered_object_id_hex,
                       const ObjectMeta& delivered_meta);
    Result routeReceipt_(const ObjectMeta& receipt_meta,
                         const std::string& receipt_envelope);
    void handleReceipt_(const std::string& origin,
                        const obj::NetworkObject& receipt_obj, bool reachable);

    // Helpers.
    bool verifyReceipt_(const ReceiptPayload& receipt) const;
    void emit_(const std::string& kind, const std::string& payload);
    bool send_(const std::string& peer_id, MessageType type, const std::string& payload);
    std::vector<std::string> peers_() const;
    static int64_t now_ms_();

    ObjectStore* m_store{nullptr};
    Config m_cfg;
    mutable std::mutex m_mu;
    SendFn m_send;
    ConnectedPeersFn m_connected;
    LocalSignKeysFn m_local_keys;
    PeerSignKeyFn m_peer_key;
    EventFn m_event;
    Counters m_ctr;
    // In-flight DIRECT delivery offers (origin side): object_id_hex ->
    // envelope_blob, so an OBJECT_ACCEPT from the destination can be answered
    // with OBJECT_DATA. (Store-and-forward offers are handled by HandoffManager.)
    std::unordered_map<std::string, std::string> m_direct_pending;
};

// Error-model wrapper exposing retryable/retry_after/failure_class (§84).
struct DeliveryError {
    DeliveryManager::Outcome outcome;
    bool retryable() const { return outcome.retryable; }
    int64_t retry_after() const { return outcome.retry_after_ms; }
    uint8_t failure_class() const { return outcome.failure_class; }
};

std::unique_ptr<DeliveryManager> createDeliveryManager(ObjectStore* store,
                                                       const DeliveryManager::Config& cfg);

} // namespace delivery
} // namespace networkos
