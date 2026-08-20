#pragma once

// Network OS Phase 4 — confirmed remote storage: handoff frames (master doc
// §82 typed frames, §11 replica leases).
//
// Frame payloads travel inside the existing wire codec (OBJECT_OFFER /
// OBJECT_ACCEPT / OBJECT_REJECT / OBJECT_DATA / STORED_ACK = MessageType
// 0x34..0x38) over the encrypted session channel. All binary encoding is
// bounded and length-prefixed; every length is validated BEFORE allocation
// (§29). Decoders are STRICT: unknown/trailing fields are rejected (not
// silently ignored) — the frames are point-to-point within the same protocol
// version, so strictness is a security win over forward-tolerance.
//
// Lease signing: the carrier Ed25519-signs canonical_lease_bytes() with its
// origin-signing key (the same key the overlay binds peer origins to), and
// the sender verifies with the carrier's registered signing public key.

#include <cstdint>
#include <string>

namespace networkos {
namespace handoff {

// Storage classes (§11 tiers). 0 = unspecified (policy default).
enum StorageClass : int64_t {
    kStorageUnspecified = 0,
    kStorageStandard = 1,     // default carrier tier
    kStoragePinned = 2,       // long-lived (charging/always-on peers)
    kStorageEphemeral = 3,    // short-lived (low-storage peers)
};

// Structured rejection reasons (§93 invariant 7 — honest rejection).
enum RejectReason : uint8_t {
    kRejectedAuth = 1,    // origin/namespace authorization failed
    kRejectedPolicy = 2,  // carrier willingness/policy refused
    kRejectedQuota = 3,   // no quota headroom
    kBusy = 4,            // max concurrent handoffs reached
    kRetryAfter = 5,      // backpressure: retry after retry_after_ms
};
const char* reject_reason_name(uint8_t reason);

// ---------------------------------------------------------------------------
// OBJECT_OFFER payload
// ---------------------------------------------------------------------------
struct OfferFrame {
    std::string object_id_hex;       // canonical ObjectId hex (dedup key)
    std::string namespace_id;
    std::string origin;              // origin PeerID (admission: trust class)
    std::string destination;         // optional destination PeerID (empty = any)
    uint64_t size_bytes{0};
    std::string payload_hash_hex;    // 64 hex chars (32-byte blake2b)
    int64_t expires_at_ms{0};        // object TTL expiry (0 = never) — leases
                                     // must never outlive it
    int64_t requested_storage_class{kStorageStandard};
    int64_t requested_lease_ms{0};   // 0 = carrier default
};

// ---------------------------------------------------------------------------
// OBJECT_ACCEPT payload
// ---------------------------------------------------------------------------
struct AcceptFrame {
    std::string object_id_hex;
    int64_t accepted_until_ms{0};    // = now + lease_duration (carrier-chosen)
    int64_t storage_class{kStorageStandard};
    std::string carrier_id;
};

// ---------------------------------------------------------------------------
// OBJECT_REJECT payload
// ---------------------------------------------------------------------------
struct RejectFrame {
    std::string object_id_hex;
    uint8_t reason{0};               // RejectReason
    int64_t retry_after_ms{0};       // meaningful for kRetryAfter
};

// ---------------------------------------------------------------------------
// OBJECT_DATA payload — carries the full serialized obj::NetworkObject envelope
// (origin header + forwarding header + payload + origin signature), which is
// everything the carrier needs to verify and durably store.
// ---------------------------------------------------------------------------
struct DataFrame {
    std::string object_id_hex;
    std::string envelope;            // serialized obj::NetworkObject
};

// ---------------------------------------------------------------------------
// STORED_ACK payload — the signed lease (§11).
// ---------------------------------------------------------------------------
struct StoredAckFrame {
    std::string object_id_hex;
    std::string carrier_id;
    int64_t accepted_until_ms{0};
    int64_t storage_class{kStorageStandard};
    std::string signature;           // carrier Ed25519, 64 raw bytes
    std::string carrier_pk_hex;      // carrier signing pk (hex) for audit
};

// ---------------------------------------------------------------------------
// Encoding / decoding (all lengths validated; decoders return false on any
// malformed/trailing-garbage input beyond tolerated optional fields).
// ---------------------------------------------------------------------------
std::string encode_offer(const OfferFrame& f);
bool decode_offer(const std::string& data, OfferFrame& out);

std::string encode_accept(const AcceptFrame& f);
bool decode_accept(const std::string& data, AcceptFrame& out);

std::string encode_reject(const RejectFrame& f);
bool decode_reject(const std::string& data, RejectFrame& out);

std::string encode_data(const DataFrame& f);
bool decode_data(const std::string& data, DataFrame& out);

std::string encode_stored_ack(const StoredAckFrame& f);
bool decode_stored_ack(const std::string& data, StoredAckFrame& out);

// The canonical bytes a carrier signs for a lease. Bounded and unambiguous:
//   [u8 len][object_id_hex][u8 len][carrier_id][i64 accepted_until_ms][i64 storage_class]
std::string canonical_lease_bytes(const std::string& object_id_hex,
                                  const std::string& carrier_id,
                                  int64_t accepted_until_ms,
                                  int64_t storage_class);

} // namespace handoff
} // namespace networkos
