#pragma once

// Network OS Phase 13 — PeerRecord binary serialization (signalling.md §2).
//
// The routing-directory entry format for delta gossip. Field omission rules
// keep cellular bandwidth low: long strings (FCM tokens, signaling URLs) are
// carried ONLY when their flag bit is set; peers assume unchanged values
// otherwise (version-gated merge on token_version).
//
// Wire format (little-endian, strictly bounded, trailing garbage rejected):
//   [u8  len][peer_id bytes]
//   [u8  len][primary_endpoint bytes]
//   [u64  token_version]
//   [u64  last_seen_utc seconds]
//   [u8   flags]
//   [u16 len][fcm_token_id]     present iff FLAGS & 0x01 (HAS_NEW_TOKEN)
//   [u16 len][signaling_addr]   present iff FLAGS & 0x02 (HAS_SIGNALING)

#include <cstdint>
#include <string>

namespace networkos {
namespace gossip {

struct PeerRecordFlags {
    static constexpr uint8_t kHasNewToken = 0x01;
    static constexpr uint8_t kHasSignaling = 0x02;
};

struct PeerRecord {
    std::string peer_id;            // cryptographic key-hash (hex)
    std::string primary_endpoint;   // last known reflexive IPv4/IPv6:port
    std::string fcm_token_id;       // push registration token (opaque)
    std::string signaling_addr;     // shared signaling server URL/IP (optional)
    uint64_t token_version{0};      // monotonic counter for token updates
    uint64_t last_seen_utc{0};      // unix seconds, stale-entry purge input
    uint8_t flags{0};

    bool has_new_token() const { return (flags & PeerRecordFlags::kHasNewToken) != 0; }
    bool has_signaling() const { return (flags & PeerRecordFlags::kHasSignaling) != 0; }
};

// Strict encoder. Applies the omission rules: token/signaling fields are
// emitted only when their flag bits are set (caller decides; helpers below).
std::string encode_peer_record(const PeerRecord& r);

// Positional decoder used by batch parsing (offset advances across records).
// Returns false on truncation, oversize (>512B fields), inconsistent flags.
bool decode_peer_record_at(const std::string& data, size_t& offset,
                           PeerRecord& out);

// Strict single-record decoder: positional decode + trailing-garbage
// rejection (house style — handoff/anti_entropy decoders are equally strict).
inline bool decode_peer_record(const std::string& data, PeerRecord& out) {
    size_t off = 0;
    if (!decode_peer_record_at(data, off, out)) return false;
    return off == data.size();
}

// Convenience: set/clear the omission flags to match the populated fields.
void normalize_flags(PeerRecord& r);

// Version-gated merge (signalling.md §2 delta rule): incoming wins only when
// its token_version is strictly greater, or the peer is new. Returns true if
// `into` was updated. Equal versions keep the local copy (no flapping).
bool merge_record(PeerRecord& into, const PeerRecord& incoming);

}  // namespace gossip
}  // namespace networkos