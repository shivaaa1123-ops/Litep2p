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

namespace networkos {

// Object identity (Phase 3 defines the full ObjectID = NetworkID + OriginPeerID
// + 128-bit nonce; today we only need an opaque key type).
using ObjectId = std::string;

enum class ObjectStatus : uint8_t {
    kQueuedLocal = 0,  // durably persisted locally
    kStored,           // committed
    kRejected,         // policy/quota/validation rejection
    kExpired,
};

struct ObjectMeta {
    ObjectId id;
    std::string namespace_id;
    std::string origin;
    std::optional<std::string> destination;
    int64_t created_at_ms{0};
    int64_t ttl_ms{0};
    uint32_t priority{0};
    uint64_t payload_size{0};
    ObjectStatus status{ObjectStatus::kQueuedLocal};
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
