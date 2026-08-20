#pragma once

// Network OS — Network Object envelope (master doc §4, §20, §89 Phase 3).
//
// The generic durable unit everything else is built on (chat message, receipt,
// lease, manifest — all become NetworkObjects in a namespace). Per §20 the
// ORIGIN header is immutable and origin-authenticated; the FORWARDING header is
// mutable by carriers without invalidating the origin signature. The payload is
// opaque to the runtime (E2E-encrypted, §4).
//
// Security (§29): verify the origin signature BEFORE any expensive work.

#include "networkos/object/object_id.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace networkos {
namespace obj {

// Delivery classes (§55). 0 = unspecified (policy default).
enum DeliveryClass : uint8_t {
    kDeliveryUnspecified = 0,
    kDeliveryNormal = 1,
    kDeliveryUrgent = 2,
    kDeliveryBackground = 3,
};

struct OriginHeader {
    uint8_t protocol_version{1};
    std::string network_id;
    std::string namespace_id;
    std::string object_id_hex;   // canonical hex of the ObjectId
    std::string origin;          // origin PeerID
    std::string destination;     // optional destination PeerID
    std::string object_type;     // e.g. "message", "receipt", "manifest"
    int64_t created_at_ms{0};    // wall clock, durable protocol time (§21)
    int64_t ttl_ms{0};           // duration; expiry = created + ttl (§21)
    uint8_t priority{0};         // 0..255 (higher = more important)
    uint8_t delivery_class{kDeliveryUnspecified};
    uint8_t max_hops{0};         // 0 = default
    uint8_t hop_count{0};        // origin-authoritative start (0)
    uint64_t payload_size{0};
    std::string payload_hash;    // 32-byte raw blake2b (§29 cheap pre-check)
    uint8_t security_flags{0};   // bit0: payload E2E-encrypted
};

struct ForwardingHeader {
    uint8_t hop_count{0};        // carrier-incremented; NOT signed
    std::string previous_peer;
    std::string routing_hints;   // opaque local routing hints
    std::string lease_info;      // Phase 4 fills (signed lease refs)
};

struct NetworkObject {
    OriginHeader origin;
    ForwardingHeader forwarding;
    std::string payload;                     // opaque (E2E ciphertext)
    std::string origin_signature;            // 64-byte Ed25519 (§20/3.3)
    std::vector<std::pair<std::string, std::string>> recipient_keys;
    // recipient PeerID -> wrapped per-object content key (E2E model, §19.4)
};

// Canonical bytes signed by the origin (§20/3.3):
// protocol_version | network_id | namespace_id | object_id | origin |
// destination | object_type | created_at_ms | ttl_ms | priority |
// delivery_class | max_hops | payload_size | payload_hash | security_flags.
// Length-prefixed so it is unambiguous and stable.
std::string origin_canonical_bytes(const OriginHeader& h);

// Bounded binary serialization of the full object. Returns "" on failure.
// Unknown optional fields are len-prefixed and skipped by older decoders.
std::string serialize(const NetworkObject& obj);
bool deserialize(const std::string& bytes, NetworkObject& out);

// Ed25519 origin signature (libsodium crypto_sign_detached). sk = 64-byte
// secret, pk = 32-byte public. verify returns false for tampered/malformed.
bool sign_object(NetworkObject& obj, const uint8_t sk[64], const uint8_t pk[32]);
bool verify_object(const NetworkObject& obj, const uint8_t pk[32]);

// 32-byte blake2b payload hash (libsodium crypto_generichash).
std::string compute_payload_hash(const std::string& payload);

} // namespace obj
} // namespace networkos
