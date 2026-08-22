#pragma once

// Network OS Phase 13 — offline QR contact exchange (signalling.md Phase 4,
// discovery cascade tier 5 / non-network bootstrap).
//
// Payload layout ("LPQ1"):
//   magic   "LPQ1"                       (4 bytes, plaintext prefix)
//   body    [u8 ver=1][u8 len][peer_id]  (hex key-hash)
//           [u8 len][endpoint]
//           [u8 fl]                      bit0: signaling field follows
//           [u16 len][signaling_addr]    iff fl&1
//           [32 bytes signer public key] (Ed25519, base64url in text form)
//   sig     [64 bytes Ed25519 detached signature over the body]
//
// Text encoding: base64url (no padding), QR-safe. Verification: the embedded
// signing key must verify the body AND hash-match the claimed peer_id when
// the engine's peer-id derivation is available; apps additionally pin on
// first scan (TOFU). Tampered payloads are rejected before any field is used.

#include "networkos/gossip/peer_record.h"

#include <string>

namespace networkos {
namespace gossip {

struct ContactCard {
    PeerRecord record;         // peer_id/endpoint/signaling populated
    std::string signer_pk_hex; // 64-hex Ed25519 public key (for pinning UI)
};

// Build the QR text payload. secret_seed_hex: 64-hex Ed25519 seed (the same
// origin-signing key family the overlay binds origins to). Returns "" on
// invalid input.
std::string build_contact_qr(const std::string& secret_seed_hex,
                             const PeerRecord& record);

// Parse + verify. Returns false on malformed payload, bad magic, truncated
// body, or signature failure. On success fills `out`.
bool parse_contact_qr(const std::string& qr_text, ContactCard& out);

}  // namespace gossip
}  // namespace networkos