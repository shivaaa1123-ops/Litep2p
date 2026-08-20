#pragma once

// Network OS — ObjectID (master doc §5, §89 Phase 3).
//
// ObjectID = NetworkID + OriginPeerID + random 128-bit nonce. Rules (§5):
// globally unique, cheap offline, unpredictable, transport-independent, stable
// across replication, safe as a dedup key, and bound into the signed object.
//
// Canonical text form (used as the DB key and on the wire) is the hex of:
//   [nonce:16][u8 netid_len][netid][u8 origin_len][origin]
// Bounded and unambiguous (length-prefixed), so it can be a PRIMARY KEY.

#include <cstdint>
#include <string>

namespace networkos {

struct ObjectId {
    std::string network_id;   // e.g. "chatp2p-mesh"
    std::string origin;       // origin PeerID
    uint8_t nonce[16]{0};     // 128-bit random nonce

    // Canonical hex form (bounded; the DB column type).
    std::string toHex() const;

    // Parse the canonical hex form. Returns false on malformed input.
    static bool fromHex(const std::string& hex, ObjectId& out);

    // Generate a fresh id with a random nonce.
    static ObjectId generate(const std::string& network_id,
                             const std::string& origin);

    bool empty() const { return network_id.empty() && origin.empty() && nonce_is_zero(); }
    bool operator==(const ObjectId& o) const {
        return network_id == o.network_id && origin == o.origin &&
               nonce_eq(o.nonce);
    }

    // Upper bound of toHex() output (16*2 + 2 + 255 + 2 + 255 = 562 chars).
    static constexpr size_t kMaxHexLength = 600;

private:
    bool nonce_is_zero() const;
    bool nonce_eq(const uint8_t other[16]) const;
};

} // namespace networkos
