#pragma once

// Network OS Phase 5 — direct destination delivery + signed receipts (master
// doc §22 delivery state machine, §23 cryptographic delivery receipts,
// §63 final delivery handoff, §64 replica release).
//
// Just two frame-level primitives live here (everything else is ordinary
// objects / the Phase 4 transfer machinery):
//   - RECEIVED_ACK (MessageType 0x39): the destination's durable-commit
//     confirmation for a direct delivery. NOT a storage lease — the terminal
//     consumer acknowledges, so it carries an id + a received_at_ms.
//   - Receipt: a first-class signed object (namespace "system", type
//     "receipt") carrying the destination's Ed25519 signature over
//     (object_id, object_hash, origin, destination, received_at_ms, type).
//     It is delivered back to the origin over the ordinary store-and-forward
//     path (Phase 4 machinery), or directly when the origin is connected.
//
// All binary encoding is bounded + length-prefixed; decoders are STRICT
// (trailing/unknown fields rejected) — same posture as the Phase 4 frames.

#include <cstdint>
#include <string>

namespace networkos {
namespace delivery {

// Receipt types (§23).
enum ReceiptType : uint8_t {
    kReceived = 0,    // durably committed by the destination
    kProcessed = 1,   // consumed by an app handler (later phase, reserved)
    kRead = 2,        // surfaced to the user (reserved)
    kRejected = 3,    // destination refused the object (policy)
};

const char* receipt_type_name(uint8_t t);

// Failure classes (§61) attached to every terminal/transient outcome.
enum FailureClass : uint8_t {
    kFailTransient = 0,   // retryable (NO_CARRIER, NO_ROUTE, BUSY)
    kFailTerminal = 1,    // will not clear (TTL_EXPIRED)
    kFailPolicy = 2,      // refused by policy (DESTINATION_REJECTED)
    kFailSecurity = 3,    // auth/crypto (AUTH_FAILED, STORED_ACK_INVALID)
    kFailNone = 4,        // not yet classified / success
};
const char* failure_class_name(uint8_t c);

// ---------------------------------------------------------------------------
// RECEIVED_ACK payload
// ---------------------------------------------------------------------------
struct ReceivedAckFrame {
    std::string object_id_hex;     // the directly-delivered object
    std::string destination;       // who committed (the signer, peer id)
    int64_t received_at_ms{0};     // destination wall-clock commit time
    uint8_t receipt_type{kReceived};
};

std::string encode_received_ack(const ReceivedAckFrame& f);
bool decode_received_ack(const std::string& data, ReceivedAckFrame& out);

// ---------------------------------------------------------------------------
// Receipt — the signed, first-class reverse-path object (§23).
// ---------------------------------------------------------------------------
// The receipt is carried as the *payload* of a system-namespace NetworkObject
// (type "receipt"). The destination Ed25519-signs `canonical_receipt_bytes`
// with its origin-signing key so an origin can verify delivery without
// trusting anyone on the wire.
struct ReceiptPayload {
    std::string object_id_hex;     // the delivered object
    std::string object_hash_hex;   // 64 hex chars (payload hash of the object)
    std::string origin;            // origin PeerID of the delivered object
    std::string destination;       // who received it (signed this)
    int64_t received_at_ms{0};
    uint8_t receipt_type{kReceived};
    int64_t object_created_at_ms{0}; // context: ties to the exact object
    std::string signature;         // destination Ed25519 (64 raw bytes)
    std::string signer_pk_hex;     // destination signing pk (hex), for audit
};

// Canonical signed bytes for a receipt (bounded, unambiguous).
std::string canonical_receipt_bytes(const std::string& object_id_hex,
                                    const std::string& object_hash_hex,
                                    const std::string& origin,
                                    const std::string& destination,
                                    int64_t received_at_ms,
                                    uint8_t receipt_type);

// Binary serialize/parse the receipt payload (strict; length-pre-validated).
std::string encode_receipt(const ReceiptPayload& r);
bool decode_receipt(const std::string& data, ReceiptPayload& out);

} // namespace delivery
} // namespace networkos