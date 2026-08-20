#pragma once

// Network OS — IObjectStore (master doc §24 storage architecture, §89
// Phase 1 declaration / Phase 3 implementation).
//
// Declared now so later phases code against a stable seam. The SQLite/WAL
// implementation lands in Phase 3; today only the interface exists. The
// interface is intentionally small and transaction-oriented: never ACK
// before a durable commit (invariant 2) is enforced inside transactions.

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "Runtime.h"
#include "networkos/object/object_id.h"

namespace networkos {

// Object identity = NetworkID + OriginPeerID + 128-bit nonce (Phase 3).
// See networkos/object/object_id.h.

enum class ObjectStatus : uint8_t {
    kQueuedLocal = 0,  // durably persisted locally
    kStored,           // committed
    kRejected,         // policy/quota/validation rejection
    kExpired,
    // Phase 4: two-phase durable handoff states (master doc §22/§93 inv. 4).
    kRemoteAccepted = 4,    // a carrier accepted and is storing/transferring
    kDurabilityReached = 5, // >=1 validated signed lease persisted (target met)
    // Phase 5: direct destination delivery states (§22).
    kDeliveryAttempted = 6, // an offer was sent to the destination
    kDelivered = 7,         // destination durably committed (RECEIVED_ACK seen)
    kConfirmed = 8,         // signed receipt returned; origin knows delivery
    kFailed = 9,            // terminal failure (e.g. TTL_EXPIRED before delivery)
    kCancelled = 10,        // policy/user cancellation (reserved; set externally)
};

struct ObjectMeta {
    ObjectId id;
    std::string namespace_id;
    std::string origin;
    std::optional<std::string> destination;
    std::string object_type;           // e.g. "message", "receipt" (P3)
    int64_t created_at_ms{0};
    int64_t ttl_ms{0};
    uint32_t priority{0};
    uint64_t payload_size{0};
    ObjectStatus status{ObjectStatus::kQueuedLocal};
    // Phase 3 store columns (envelope data + lease/replica hints).
    std::string payload_hash;              // 32-byte raw hash
    std::string origin_header_blob;        // serialized origin header (envelope)
    std::string origin_signature;          // Ed25519 signature
    std::string forwarding_header_blob;    // serialized forwarding header
    // Phase 4: the full serialized, origin-signed obj::NetworkObject envelope
    // (origin + forwarding headers + payload + signature + recipient keys).
    // Persisted so the sender can re-transfer OBJECT_DATA after a crash, and
    // the carrier can forward on delivery (Phase 5).
    std::string envelope_blob;
    int64_t lease_expires_at_ms{0};
    int64_t replica_hint{0};
};

// Quota snapshot for a namespace or origin (Phase 3 semantics).
struct QuotaInfo {
    uint64_t used_bytes{0};
    uint64_t max_bytes{0};
    uint64_t used_entries{0};
    uint64_t max_entries{0};
    bool within_limits{true};
};

// Transaction handle: begin()/commit()/rollback(). The durable commit is the
// atomicity point; callers must commit before acknowledging anything.
class IObjectStore {
public:
    virtual ~IObjectStore() = default;

    // Put an object (payload + metadata). Honors quotas inside the same
    // transaction as the insert (invariant 6). Returns kRejected on quota.
    virtual Result put(const ObjectMeta& meta, std::string_view payload) = 0;

    // Get payload + metadata for id. kNotFound when absent or expired.
    virtual Result get(const ObjectId& id, ObjectMeta& meta_out,
                       std::string& payload_out) = 0;

    // Remove an object (subject to lease/replica rules in later phases).
    virtual Result remove(const ObjectId& id) = 0;

    // Expiry iterator: yields ids that expired at or before `now_ms`.
    virtual Result forEachExpired(int64_t now_ms,
                                  const std::function<Result(const ObjectId&)>& fn) = 0;

    // Quota snapshot for a namespace/origin (used by admission policy, P4).
    virtual Result quota(const std::string& namespace_id,
                         const std::string& origin,
                         QuotaInfo& out) const = 0;

    // Durable commit gate (invariant 2): flushes pending writes. Callers that
    // need the never-ACK-before-commit property call this before ACKing.
    virtual Result commit() = 0;
};

} // namespace networkos
