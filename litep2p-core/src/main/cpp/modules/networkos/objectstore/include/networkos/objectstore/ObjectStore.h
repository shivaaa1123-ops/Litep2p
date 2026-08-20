#pragma once

// Network OS — Durable object store (master doc §24/§25/§26/§27/§28/§29,
// §89 Phase 3; implements the Phase 1 IObjectStore).
//
// SQLite (WAL, via the existing dynamic loader sqlite3_dyn) backed store with:
//   - crash-safe transactions (never ACK before durable commit — invariant 2)
//   - namespace/origin/global quotas enforced inside the insert transaction
//   - TTL expiry indexed by expires_at_ms, never refreshed by gossip (§21)
//   - dedup table (bounded) checked BEFORE expensive work (§65/§29)
//   - score-based eviction (§27)
//   - explicit backpressure outcomes (§28)
//   - schema versioning + forward migration
//
// The quota/eviction semantics generalize overlay_mailbox's proven bounded
// carrier logic (locked decision 9) — not a parallel system.

#include "networkos/IObjectStore.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace networkos {

class ObjectStore : public IObjectStore {
public:
    static constexpr int kSchemaVersion = 3;

    struct Options {
        std::string path;                          // sqlite file path
        bool enable_wal{true};
        int busy_timeout_ms{5000};
        uint64_t global_quota_bytes{256ull * 1024ull * 1024ull};
        uint64_t system_reserve_bytes{4ull * 1024ull * 1024ull};  // peers can't consume
        uint64_t default_namespace_quota_bytes{64ull * 1024ull * 1024ull};
        uint64_t default_origin_quota_bytes{16ull * 1024ull * 1024ull};
        int dedup_ttl_hours{24 * 7};               // TTL + receipt window + margin
        size_t max_dedup_entries{200000};
        size_t max_object_bytes{16ull * 1024ull * 1024ull};  // §34 memory bound
    };

    // Backpressure outcomes (§28) — every receiving path reports one; never
    // silently drop after pretending to accept.
    enum class Outcome {
        Accepted = 0,
        RejectedAuth,
        RejectedPolicy,
        RejectedQuota,
        Busy,
        RetryAfter,
        Unsupported,
    };
    static const char* outcome_name(Outcome o);

    ObjectStore();
    ~ObjectStore() override;
    ObjectStore(const ObjectStore&) = delete;
    ObjectStore& operator=(const ObjectStore&) = delete;

    // Open (creates schema if needed; runs integrity check + WAL). Returns
    // false if SQLite cannot be loaded or the file is corrupt.
    bool open(const Options& options);
    void close();
    bool is_open() const { return m_open; }

    // ---- IObjectStore ------------------------------------------------------
    Result put(const ObjectMeta& meta, std::string_view payload) override;
    Result get(const ObjectId& id, ObjectMeta& meta_out,
               std::string& payload_out) override;
    Result remove(const ObjectId& id) override;
    Result forEachExpired(int64_t now_ms,
                          const std::function<Result(const ObjectId&)>& fn) override;
    Result quota(const std::string& namespace_id, const std::string& origin,
                 QuotaInfo& out) const override;
    Result commit() override;

    // ---- Phase 3 extras ----------------------------------------------------
    // put + explicit backpressure outcome (the receive-path contract §28).
    Result putWithOutcome(const ObjectMeta& meta, std::string_view payload,
                          Outcome& out);

    // Read metadata only (no payload).
    Result getMeta(const ObjectId& id, ObjectMeta& meta_out) const;

    // True when the object (or its dedup record) is known.
    bool contains(const ObjectId& id) const;
    bool isDuplicate(const ObjectId& id) const;

    // ---- Phase 4: confirmed remote storage + replica leases ----------------
    // A signed storage lease (master doc §11). The signature is the carrier's
    // Ed25519 signature over canonical_lease_bytes (see handoff module).
    struct LeaseInfo {
        std::string object_id_hex;
        std::string carrier_id;
        int64_t accepted_until_ms{0};
        int64_t storage_class{0};
        std::string signature;      // carrier Ed25519 (64 bytes raw)
        std::string carrier_id_hex; // optional carrier public key hex (audit)
    };

    // Carrier-side atomic accept: object + dedup + usage + lease row committed
    // in ONE transaction. Returns kOk only after COMMIT — never ACK before this
    // returns (invariant 2). Idempotent: a duplicate object refreshes the lease
    // row without a second copy (§65/§29).
    Result putWithLease(const ObjectMeta& meta, std::string_view payload,
                        const LeaseInfo& lease, Outcome& out);

    // Sender-side: record a validated remote lease for an object we hold and
    // bump the object's lease_expires_at_ms. Idempotent upsert.
    Result recordLease(const ObjectId& id, const LeaseInfo& lease);

    // All leases for an object (sender: carriers holding our object; carrier:
    // our own promises). Empty vector when none.
    Result getLeases(const ObjectId& id, std::vector<LeaseInfo>& out) const;

    // Object status transition (handoff state machine; replay after crash
    // converges — §93 invariant 4).
    Result updateObjectState(const ObjectId& id, ObjectStatus status);

    // Lease-expiry sweep: yields every lease whose accepted_until_ms is at or
    // before `before_ms` (event-triggered; the Phase 7 planner hooks this).
    Result forEachExpiringLease(
        int64_t before_ms, const std::function<Result(const LeaseInfo&)>& fn) const;

    // Record that a carrier-eviction happened while a lease was still live
    // (EVICTED_EARLY, §27) so Phase 7 repair can re-replicate.
    Result markEvictedEarly(const ObjectId& id, const std::string& carrier_id,
                            int64_t lease_was_until_ms);
    uint64_t evictedEarlyCount() const;

    // Remove all objects expired at or before now_ms. Returns count removed.
    Result purgeExpired(int64_t now_ms, uint64_t* removed = nullptr);

    // Evict lowest-scoring objects until `need_bytes` are freed within the
    // namespace+origin (or system reserve is hit). §27.
    Result evictForQuota(const std::string& namespace_id,
                         const std::string& origin,
                         uint64_t need_bytes, uint64_t* freed = nullptr);

    // Configure a namespace quota (hierarchical quotas §26/§53).
    Result setNamespaceQuota(const std::string& namespace_id, uint64_t quota_bytes);

    uint64_t countObjects() const;
    uint64_t totalBytes() const;
    int schemaVersion() const;
    const Options& options() const { return m_options; }

    // ---- Phase 5: direct delivery + signed receipts ---------------------
    // A signed receipt linking a delivered object to its receipt object
    // (master doc §23). The receipt itself is a system-namespace NetworkObject
    // stored in `objects`; this row tracks the linkage + signature for
    // verification and dedup.
    struct ReceiptRow {
        std::string delivered_object_id_hex;
        std::string receipt_object_id_hex;
        std::string origin;             // origin PeerID of the delivered object
        std::string destination;        // who received + signed
        uint8_t receipt_type{0};        // delivery::ReceiptType
        int64_t received_at_ms{0};
        std::string object_hash_hex;    // delivered object's payload hash
        std::string signature;          // destination Ed25519 (64 bytes raw)
        std::string signer_pk_hex;
    };

    // Persist a receipt (idempotent by delivered_object_id — a duplicate
    // delivery never produces a duplicate CONFIRMED/dup receipt).
    Result recordReceipt(const ReceiptRow& row);

    // Lookup the receipt for a delivered object. kNotFound when none.
    Result getReceipt(const std::string& delivered_object_id_hex,
                      ReceiptRow& out) const;

    // Every receipt aimed at `destination` (origin side: the receipts for our
    // delivered objects). Used by the origin to mark CONFIRMED on replay.
    Result forEachReceiptToward(
        const std::string& destination,
        const std::function<Result(const ReceiptRow&)>& fn) const;

    // Every object whose destination == target that has NOT yet reached a
    // terminal delivery state (still kStored/kDurabilityReached and not
    // delivered/confirmed/failed). The carrier/delivery manager uses this to
    // offer stored objects to a destination that just connected.
    Result forEachUndelivered(
        const std::string& destination,
        const std::function<Result(const ObjectId&)>& fn) const;

    // Every object that is DELIVERED and whose delivered_at_ms <= before_ms
    // (carrier replica-release sweep, §64). Only already-delivered replicas
    // are candidates — the last-useful-replica rule is enforced by the caller.
    Result forEachDeliveredReplica(
        int64_t before_ms, const std::function<Result(const ObjectId&)>& fn) const;

    // Phase 6: inventory enumeration for anti-entropy (§12). Yields up to
    // `limit` held objects (id, state, created_at_ms), oldest-first, so a peer
    // can build a compact inventory summary. Bounded by `limit` — never builds
    // an unbounded list internally.
    Result enumerateInventory(
        uint32_t limit,
        const std::function<Result(const ObjectId&, ObjectStatus, int64_t)>& fn)
        const;

    // Delivery-state transitions (§22) — idempotent: re-marking the same (or a
    // later) terminal state is a no-op and always converges.
    Result markDelivered(const ObjectId& id, int64_t delivered_at_ms);
    Result markDeliveryAttempted(const ObjectId& id);
    Result confirmObject(const ObjectId& id, int64_t confirmed_at_ms);
    Result failDelivery(const ObjectId& id, uint8_t failure_class);

    // Read back the delivered/confirmed timestamps + failure class (used by
    // tests and telemetry). Optional outputs may be null.
    Result deliveryReadout(const ObjectId& id, ObjectStatus* status_out,
                           int64_t* delivered_at_ms_out,
                           int64_t* confirmed_at_ms_out,
                           uint8_t* failure_class_out) const;

    // PIMPL (defined in ObjectStore.cpp). Public so the out-of-line definition
    // is reachable (matches the engine's SessionManager pattern).
    struct Impl;

private:
    // Shared put implementation. `lease` != nullptr selects the carrier-side
    // atomic path (object + dedup + usage + lease in ONE transaction). The
    // mutex is taken inside.
    Result putInternal(const ObjectMeta& meta, std::string_view payload,
                       const LeaseInfo* lease, Outcome& out);

    std::unique_ptr<Impl> m_impl;
    Options m_options;
    bool m_open{false};
};

} // namespace networkos
