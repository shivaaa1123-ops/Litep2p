// Network OS Phase 13 — PeerRecord codec (signalling.md §2). See header for
// the wire format and omission rules.

#include "networkos/gossip/peer_record.h"

#include <cstring>

namespace networkos {
namespace gossip {

namespace {

constexpr size_t kMaxPeerIdLen = 128;      // hex key-hash; 64 typical
constexpr size_t kMaxEndpointLen = 128;    // "ipv6:port" worst case
constexpr size_t kMaxTokenLen = 4096;      // FCM tokens are ~1-4 KB
constexpr size_t kMaxSignalingLen = 256;   // URL

void put_u16(std::string& out, uint16_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}

void put_u64(std::string& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
    }
}

bool get_u16(const std::string& d, size_t& off, uint16_t& v) {
    if (off + 2 > d.size()) return false;
    v = static_cast<uint8_t>(d[off]) |
        (static_cast<uint16_t>(static_cast<uint8_t>(d[off + 1])) << 8);
    off += 2;
    return true;
}

bool get_u64(const std::string& d, size_t& off, uint64_t& v) {
    if (off + 8 > d.size()) return false;
    v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | static_cast<uint8_t>(d[off + i]);
    }
    off += 8;
    return true;
}

bool get_len_blob(const std::string& d, size_t& off, size_t len_bytes,
                  size_t max_len, std::string& out) {
    size_t len = 0;
    if (len_bytes == 1) {
        if (off + 1 > d.size()) return false;
        len = static_cast<uint8_t>(d[off]);
        off += 1;
    } else {
        uint16_t v16 = 0;
        if (!get_u16(d, off, v16)) return false;
        len = v16;
    }
    if (len > max_len || off + len > d.size()) return false;
    out.assign(d, off, len);
    off += len;
    return true;
}

}  // namespace

std::string encode_peer_record(const PeerRecord& r) {
    std::string out;
    out.reserve(32 + r.peer_id.size() + r.primary_endpoint.size() +
                r.fcm_token_id.size() + r.signaling_addr.size());
    out.push_back(static_cast<char>(r.peer_id.size()));
    out.append(r.peer_id);
    out.push_back(static_cast<char>(r.primary_endpoint.size()));
    out.append(r.primary_endpoint);
    put_u64(out, r.token_version);
    put_u64(out, r.last_seen_utc);
    out.push_back(static_cast<char>(r.flags));
    if (r.has_new_token()) {
        put_u16(out, static_cast<uint16_t>(r.fcm_token_id.size()));
        out.append(r.fcm_token_id);
    }
    if (r.has_signaling()) {
        put_u16(out, static_cast<uint16_t>(r.signaling_addr.size()));
        out.append(r.signaling_addr);
    }
    return out;
}

bool decode_peer_record_at(const std::string& data, size_t& offset,
                           PeerRecord& out) {
    PeerRecord r;
    if (!get_len_blob(data, offset, 1, kMaxPeerIdLen, r.peer_id)) return false;
    if (!get_len_blob(data, offset, 1, kMaxEndpointLen, r.primary_endpoint))
        return false;
    if (!get_u64(data, offset, r.token_version)) return false;
    if (!get_u64(data, offset, r.last_seen_utc)) return false;
    if (offset + 1 > data.size()) return false;
    r.flags = static_cast<uint8_t>(data[offset]);
    offset += 1;
    // Consistency: a flag without its field is malformed (strict decode).
    if (r.has_new_token()) {
        if (!get_len_blob(data, offset, 2, kMaxTokenLen, r.fcm_token_id))
            return false;
    } else {
        r.fcm_token_id.clear();
    }
    if (r.has_signaling()) {
        if (!get_len_blob(data, offset, 2, kMaxSignalingLen, r.signaling_addr))
            return false;
    } else {
        r.signaling_addr.clear();
    }
    out = std::move(r);
    return true;
}

void normalize_flags(PeerRecord& r) {
    uint8_t f = 0;
    if (!r.fcm_token_id.empty()) f |= PeerRecordFlags::kHasNewToken;
    if (!r.signaling_addr.empty()) f |= PeerRecordFlags::kHasSignaling;
    r.flags = f;
}

bool merge_record(PeerRecord& into, const PeerRecord& incoming) {
    if (incoming.peer_id.empty()) return false;
    if (into.peer_id != incoming.peer_id && !into.peer_id.empty()) return false;
    if (incoming.token_version <= into.token_version && !into.peer_id.empty()) {
        // Equal/older version keeps the local copy — no flapping on re-gossip.
        return false;
    }
    const bool had = !into.peer_id.empty();
    PeerRecord next = incoming;
    // Preserve locally-known fields the sender legitimately omitted.
    if (!next.has_signaling() && had) next.signaling_addr = into.signaling_addr;
    if (!next.has_new_token() && had) next.fcm_token_id = into.fcm_token_id;
    normalize_flags(next);
    into = std::move(next);
    return true;
}

}  // namespace gossip
}  // namespace networkos